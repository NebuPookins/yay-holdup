-- Test harness for holdup.lua. Runs the pure logic and the hook gating without
-- any network access. Run with: lua5.1 test_holdup.lua

local failures = 0
local checks = 0

local function ok(cond, name)
  checks = checks + 1
  if cond then
    io.write("ok   - ", name, "\n")
  else
    failures = failures + 1
    io.write("FAIL - ", name, "\n")
  end
end

local function eq(got, want, name)
  ok(got == want, name .. " (got " .. tostring(got) .. ", want " .. tostring(want) .. ")")
end

-- Load the module in "library" mode (no CLI, no hook).
_HOLDUP_LIBRARY = true
local m = dofile("holdup.lua")
local real_call_llm = m.call_llm
local real_http_post = m.http_post

-- ---------------------------------------------------------------------------
-- JSON helpers
-- ---------------------------------------------------------------------------
eq(m.json_quote('a"b\\c'), '"a\\"b\\\\c"', "json_quote escapes quote and backslash")
eq(m.json_quote("a\nb\tc"), '"a\\nb\\tc"', "json_quote escapes newline and tab")
eq(m.json_quote("x\1y"), '"x\\u0001y"', "json_quote escapes control char")

local enc = m.json_encode({ model = "claude-opus-5", max_tokens = 1024,
  messages = { { role = "user", content = "hi\n" } } })
ok(enc:find('"model":"claude-opus-5"', 1, true) ~= nil, "json_encode model key")
ok(enc:find('"max_tokens":1024', 1, true) ~= nil, "json_encode number")
ok(enc:find('"role":"user"', 1, true) ~= nil, "json_encode nested object")
ok(enc:find('"content":"hi\\n"', 1, true) ~= nil, "json_encode escapes newline in value")

-- ---------------------------------------------------------------------------
-- extract_json_string (provider envelopes + escaped values)
-- ---------------------------------------------------------------------------
eq(m.extract_json_string('{"verdict":"safe","summary":"ok"}', "verdict"), "safe",
  "extract verdict")
eq(m.extract_json_string('{"verdict":"safe","summary":"ok"}', "summary"), "ok",
  "extract summary")
eq(m.extract_json_string('{"verdict": "unsafe"}', "verdict"), "unsafe",
  "extract with spaces around colon")

local claude_env = [[{"content":[{"type":"text","text":"{\"verdict\":\"unsafe\",\"summary\":\"installs a miner\"}"}],"stop_reason":"end_turn"}]]
eq(m.extract_json_string(claude_env, "text"),
  '{"verdict":"unsafe","summary":"installs a miner"}', "extract Claude text block")

local ds_env = [[{"choices":[{"index":0,"message":{"role":"assistant","content":"{\"verdict\":\"safe\",\"summary\":\"normal\"}"}}]}]]
eq(m.extract_json_string(ds_env, "content"),
  '{"verdict":"safe","summary":"normal"}', "extract DeepSeek content")

eq(m.extract_json_string([[{"summary":"has \"quotes\" and \\ backslash"}]], "summary"),
  [[has "quotes" and \ backslash]], "extract with escaped quotes/backslash")

do
  local bs = string.char(0x5C)  -- backslash, to build the JSON \u escapes
  local json = '{"summary":"' .. bs .. 'ud83d' .. bs .. 'ude00 ok"}'
  eq(m.extract_json_string(json, "summary"),
    "\240\159\152\128 ok", "extract decodes a surrogate pair (emoji)")
end

-- ---------------------------------------------------------------------------
-- Verdict normalization + parsing (fail-closed)
-- ---------------------------------------------------------------------------
eq(m.normalize_verdict("safe"), "safe", "normalize safe")
eq(m.normalize_verdict("unsafe"), "unsafe", "normalize unsafe")
eq(m.normalize_verdict("suspicious"), "suspicious", "normalize suspicious")
eq(m.normalize_verdict("SAFE"), "safe", "normalize case-insensitive")
eq(m.normalize_verdict("  safe  "), "safe", "normalize trims whitespace")
eq(m.normalize_verdict("Malicious"), nil, "normalize rejects synonym (strict enum)")
eq(m.normalize_verdict("clean"), nil, "normalize rejects synonym (strict enum)")
eq(m.normalize_verdict("banana"), nil, "normalize unknown -> nil")
eq(m.normalize_verdict("not safe"), nil, "normalize rejects 'not safe' (fail closed)")
eq(m.normalize_verdict("unclean"), nil, "normalize rejects 'unclean' (fail closed)")
eq(m.normalize_verdict("abnormal"), nil, "normalize rejects 'abnormal' (fail closed)")

local v, s = m.parse_verdict('```json\n{"verdict":"unsafe","summary":"runs a backdoor"}\n```')
eq(v, "unsafe", "parse_verdict fenced JSON")
eq(s, "runs a backdoor", "parse_verdict fenced summary")

v = m.parse_verdict("I think this is fine")
eq(v, "error", "parse_verdict unparseable -> error (fail closed)")

-- ---------------------------------------------------------------------------
-- analyze() with a stubbed call_llm (no network)
-- ---------------------------------------------------------------------------
local function stub_llm(text, err) m.call_llm = function() return text, err end end

local claude_cfg = { provider = "claude", api_key = "k" }

stub_llm('{"verdict":"safe","summary":"normal"}')
local r = m.analyze(claude_cfg, "pkg", "pkgbuild", nil)
eq(r.safe, true, "analyze safe -> safe")

stub_llm('{"verdict":"unsafe","summary":"miner"}')
r = m.analyze(claude_cfg, "pkg", "pkgbuild", nil)
eq(r.safe, false, "analyze unsafe -> not safe")
eq(r.verdict, "unsafe", "analyze unsafe verdict")

stub_llm('{"verdict":"suspicious","summary":"odd url"}')
r = m.analyze(claude_cfg, "pkg", "pkgbuild", nil)
eq(r.safe, false, "analyze suspicious -> fail closed")

stub_llm("garbage with no json")
r = m.analyze(claude_cfg, "pkg", "pkgbuild", nil)
eq(r.verdict, "error", "analyze unparseable -> error")

stub_llm(nil, "HTTP 401: bad key")
r = m.analyze(claude_cfg, "pkg", "pkgbuild", nil)
eq(r.verdict, "error", "analyze API failure -> error")

r = m.analyze({ provider = "claude", api_key = "" }, "pkg", "pkgbuild", nil)
eq(r.verdict, "error", "analyze missing key -> error")

-- build_request sanity (no network)
local req = m.build_request({ provider = "claude", api_key = "sk-test" }, "foo", "echo hi", nil)
ok(req.url == "https://api.anthropic.com/v1/messages", "claude url")
ok(req.body:find('"model":"claude-opus-5"', 1, true) ~= nil, "claude default model opus-5")
ok(req.body:find("echo hi", 1, true) ~= nil, "claude body contains pkgbuild")
local header_has_key = false
for _, h in ipairs(req.headers) do
  if h:find("sk-test", 1, true) then header_has_key = true end
end
ok(header_has_key, "claude headers carry the api key (not the body)")
local dreq = m.build_request({ provider = "deepseek", api_key = "ds" }, "foo", "echo hi", nil)
ok(dreq.url == "https://api.deepseek.com/chat/completions", "deepseek url")
ok(dreq.body:find('"deepseek-chat"', 1, true) ~= nil, "deepseek default model")
-- Structured-output request fields (tool use / function calling enforce the enum).
ok(req.body:find('"tools"', 1, true) ~= nil, "claude request carries tools")
ok(req.body:find('"tool_choice"', 1, true) ~= nil, "claude request forces the tool")
ok(req.body:find('"enum":["safe","suspicious","unsafe"]', 1, true) ~= nil, "claude schema has verdict enum")
ok(dreq.body:find('"tools"', 1, true) ~= nil, "deepseek request carries tools")
ok(dreq.body:find('"parameters"', 1, true) ~= nil, "deepseek request carries function parameters")
ok(dreq.body:find('"enum":["safe","suspicious","unsafe"]', 1, true) ~= nil, "deepseek schema has verdict enum")

-- fetch_aur's cgit URL builder percent-encodes '+' (which cgit decodes as a
-- space), so packages like libstdc++5 resolve correctly.
eq(m.aur_cgit_url("PKGBUILD", "libstdc++5"),
  "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=libstdc%2B%2B5",
  "aur_cgit_url encodes '+' in the package base")
eq(m.aur_cgit_url(".SRCINFO", "normal-pkg"),
  "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO?h=normal-pkg",
  "aur_cgit_url leaves URL-safe package bases unchanged")

-- ---------------------------------------------------------------------------
-- Structured-output response extraction (call_llm -> analyze wiring)
-- ---------------------------------------------------------------------------
m.call_llm = real_call_llm
m.http_post = function()
  return 200, '{"content":[{"type":"tool_use","name":"report_verdict","input":{"verdict":"unsafe","summary":"miner"}}],"stop_reason":"tool_use"}'
end
do
  local r = m.analyze(claude_cfg, "p", "pb", nil)
  eq(r.verdict, "unsafe", "claude tool_use parsed by analyze")
  eq(r.safe, false, "claude tool_use unsafe -> not safe")
end
m.http_post = function()
  return 200, [[{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"report_verdict","arguments":"{\"verdict\":\"safe\",\"summary\":\"normal\"}"}}]},"finish_reason":"tool_calls"}]}]]
end
do
  local r = m.analyze({ provider = "deepseek", api_key = "k" }, "p", "pb", nil)
  eq(r.verdict, "safe", "deepseek function-call parsed by analyze")
  eq(r.safe, true, "deepseek function-call safe -> safe")
end
m.http_post = real_http_post

-- ---------------------------------------------------------------------------
-- Config file read/write
-- ---------------------------------------------------------------------------
local tmpcfg = "/tmp/holdup_test.conf"
m.write_config(tmpcfg, { provider = "deepseek", api_key = "abc", on_error = "warn" })
local cfg = m.parse_config_file(tmpcfg)
eq(cfg.provider, "deepseek", "config round-trip provider")
eq(cfg.api_key, "abc", "config round-trip key")
eq(cfg.on_error, "warn", "config round-trip on_error")
os.remove(tmpcfg)

-- Inline # comments are stripped from values, and provider/on_error are
-- lowercased, so the README's documented format works and a capitalized
-- provider still routes to the right endpoint.
do
  local f = io.open("/tmp/holdup_test_cfg2.conf", "w")
  f:write("provider = DeepSeek  # claude | deepseek\n")
  f:write("api_key = sk-test  # your API key\n")
  f:write("on_error = Warn\n")
  f:close()
  local c2 = m.parse_config_file("/tmp/holdup_test_cfg2.conf")
  eq(c2.provider, "deepseek", "parse_config lowercases provider")
  eq(c2.api_key, "sk-test", "parse_config strips inline # comment")
  eq(c2.on_error, "warn", "parse_config lowercases on_error")
  os.remove("/tmp/holdup_test_cfg2.conf")
end

-- Shebang stripping (the installed module must not carry a `#!` line, since
-- gopher-lua does not skip it).
eq(m.strip_shebang("#!/usr/bin/env lua5.1\n-- hi\nprint(1)\n"), "-- hi\nprint(1)\n",
  "strip_shebang removes shebang line")
eq(m.strip_shebang("-- no shebang\nprint(1)\n"), "-- no shebang\nprint(1)\n",
  "strip_shebang no-op without shebang")

-- ---------------------------------------------------------------------------
-- Standalone CLI
-- ---------------------------------------------------------------------------
-- run_test mirrors the hook's on_error handling: an "error" verdict proceeds
-- (exit 0) when on_error=warn, and blocks (exit 1) otherwise.
do
  local real_exit, real_fetch, real_analyze, real_parse =
    os.exit, m.fetch_aur, m.analyze, m.parse_config_file
  local exit_code
  -- os.exit is terminal in real use; throw so run_test stops at the first exit.
  os.exit = function(code) exit_code = code; error("__exit__") end
  m.parse_config_file = function() return { provider = "claude", api_key = "k", on_error = "warn" } end
  m.fetch_aur = function() return { pkgbuild = "x", srcinfo = "y" } end
  m.analyze = function() return { safe = false, verdict = "error", summary = "HTTP 500" } end
  pcall(m.run_test, "pkg")
  eq(exit_code, 0, "run_test proceeds on error with on_error=warn")

  m.parse_config_file = function() return { provider = "claude", api_key = "k", on_error = "abort" } end
  pcall(m.run_test, "pkg")
  eq(exit_code, 1, "run_test blocks on error with on_error=abort")

  os.exit, m.fetch_aur, m.analyze, m.parse_config_file =
    real_exit, real_fetch, real_analyze, real_parse
end

-- The CLI entry gate: running the script with arguments must reach M.main.
do
  local p = io.popen("lua5.1 holdup.lua -h 2>&1")
  local help = p:read("*a")
  p:close()
  ok(help:find("Usage", 1, true) ~= nil, "CLI -h prints usage")

  p = io.popen("lua5.1 holdup.lua -v 2>&1")
  local ver = p:read("*a")
  p:close()
  ok(ver:find("0.1.0", 1, true) ~= nil, "CLI -v prints version")
end

-- ---------------------------------------------------------------------------
-- run_install reuses an existing config as defaults
-- ---------------------------------------------------------------------------
do
  local real_dir, real_prompt, real_secret, real_copy, real_write =
    m.config_dir, m.prompt, m.prompt_secret, m.copy_self, m.write_config

  -- Scenario 1: empty input reuses provider, key, and hand-edited overrides.
  local tmp = "/tmp/holdup_install_test"
  local function write_conf(lines)
    os.execute("rm -rf " .. tmp)
    os.execute("mkdir -p " .. tmp .. "/yay")
    local f = io.open(tmp .. "/yay/holdup.conf", "w")
    f:write(lines)
    f:close()
  end

  m.config_dir = function() return tmp .. "/yay" end
  m.copy_self = function() return true end
  local written
  m.write_config = function(path, cfg) written = { path = path, cfg = cfg } end

  write_conf("provider=deepseek\napi_key=oldkey\non_error=warn\nmodel_id=my-model\n")
  m.prompt = function() return "" end
  m.prompt_secret = function() return "" end
  m.run_install()

  eq(written.cfg.provider, "deepseek", "re-run keeps existing provider default")
  eq(written.cfg.api_key, "oldkey", "re-run reuses existing API key on empty input")
  eq(written.cfg.on_error, "warn", "re-run preserves on_error override")
  eq(written.cfg.model_id, "my-model", "re-run preserves model_id override")
  eq(written.path, tmp .. "/yay/holdup.conf", "re-run writes to the config path")

  -- Scenario 2: typing new values overrides provider/key but keeps overrides.
  write_conf("provider=claude\napi_key=oldkey\non_error=abort\n")
  m.prompt = function() return "2" end
  m.prompt_secret = function() return "newkey" end
  written = nil
  m.run_install()
  eq(written.cfg.provider, "deepseek", "re-run lets you change provider")
  eq(written.cfg.api_key, "newkey", "re-run lets you change key")
  eq(written.cfg.on_error, "abort", "re-run keeps on_error when unchanged")

  m.config_dir, m.prompt, m.prompt_secret, m.copy_self, m.write_config =
    real_dir, real_prompt, real_secret, real_copy, real_write
  os.execute("rm -rf " .. tmp)
end

-- ---------------------------------------------------------------------------
-- Hook gating with a fake yay global
-- ---------------------------------------------------------------------------
local captured = {}
yay = {
  create_autocmd = function(event, opts)
    captured[event] = opts.callback
  end,
  log = {
    info = function(msg) captured.info = msg end,
    warn = function(msg) captured.warn = msg end,
    error = function(msg) captured.error = msg end,
  },
  abort = function(msg) captured.abort_msg = msg end,
}
local m2 = dofile("holdup.lua")  -- registers the hook, returns its module table

ok(captured.info ~= nil and captured.info:find("holdup", 1, true) ~= nil,
  "register_hook logs that it was called on load")

local function run_hook()
  captured.abort_msg = nil
  captured.AURPreInstall({
    match = "evil-pkg",
    data = { pkgbuild = "# fake", srcinfo_path = "/nonexistent" },
  })
  return captured.abort_msg
end

-- not configured -> abort
m2.parse_config_file = function() return nil end
local aborted = run_hook()
ok(aborted ~= nil and aborted:find("not configured", 1, true) ~= nil, "hook aborts when not configured")

-- safe -> no abort
m2.parse_config_file = function() return { provider = "claude", api_key = "k" } end
m2.analyze = function() return { safe = true, verdict = "safe", summary = "clean" } end
eq(run_hook(), nil, "hook does not abort on safe")

-- unsafe -> abort with verdict in message
m2.analyze = function() return { safe = false, verdict = "unsafe", summary = "miner" } end
aborted = run_hook()
ok(aborted ~= nil and aborted:find("UNSAFE", 1, true) ~= nil, "hook aborts on unsafe")

-- suspicious -> abort (fail closed)
m2.analyze = function() return { safe = false, verdict = "suspicious", summary = "odd" } end
aborted = run_hook()
ok(aborted ~= nil and aborted:find("SUSPICIOUS", 1, true) ~= nil, "hook aborts on suspicious")

-- API error with on_error=warn -> proceed (no abort)
m2.parse_config_file = function() return { provider = "claude", api_key = "k", on_error = "warn" } end
m2.analyze = function() return { safe = false, verdict = "error", summary = "HTTP 500" } end
eq(run_hook(), nil, "hook proceeds on error when on_error=warn")

-- API error with on_error=abort (default) -> abort
m2.parse_config_file = function() return { provider = "claude", api_key = "k", on_error = "abort" } end
aborted = run_hook()
ok(aborted ~= nil and aborted:find("COULD NOT VERIFY", 1, true) ~= nil, "hook aborts on error by default")

io.write("\n", checks, " checks, ", failures, " failures\n")
os.exit(failures == 0 and 0 or 1)
