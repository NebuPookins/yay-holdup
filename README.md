# yay-holdup

An LLM malware scanner for the [yay](https://github.com/Jguer/yay) AUR helper.
It uses yay v13's Lua hook API to intercept every AUR package *after* its
PKGBUILD is fetched but *before* anything runs, sends the build script to an
LLM, and blocks the install if the verdict is anything other than "safe".

```
$ yay -S some-aur-package
holdup: AURPreInstall hook registered (will scan AUR packages before install)
holdup: scanning AUR package some-aur-package ...
holdup: some-aur-package -> SAFE. Normal package, builds from official upstream.
```

The `hook registered` line appears on every yay invocation (once the module is
installed), so you can always tell yay-holdup was loaded. The per-package
`scanning`/verdict lines appear only when yay is actually about to install or
upgrade an AUR package — repository packages never trigger the hook.

```
$ yay -S sketchy-package
holdup: scanning AUR package sketchy-package ...
error: holdup: sketchy-package -> UNSAFE. install() curls a binary and runs it as root.
```

## Requirements

- **yay v13+** (the Lua hook API is new in v13.0.0; `require()` support is in
  v13.0.1)
- **curl** on `PATH`
- A **Claude** or **DeepSeek** API key
- A **Lua** interpreter (any 5.x) to run the CLI directly — the hook itself
  needs none, since yay embeds its own

## Install

Run the script with no arguments (it is directly executable):

```
./holdup.lua
```

(`lua5.1 holdup.lua` works too if you prefer to invoke the interpreter explicitly.)

It prompts for the provider (Claude or DeepSeek) and the API key, then writes
three files under `$XDG_CONFIG_HOME/yay/` (default `~/.config/yay/`):

| File           | Purpose                                              |
|----------------|------------------------------------------------------|
| `init.lua`     | `require("holdup")` — loads the hook into yay        |
| `holdup.lua`   | this plugin                                          |
| `holdup.conf`  | `provider` + `api_key` (+ optional overrides), mode 600 |

Re-running with no arguments reuses the existing config as the default: press
Enter at each prompt to keep the current provider and API key. Any hand-edited
`model_id` / `on_error` overrides are carried over too, so reinstalling the
module or updating one field won't silently reset the others.

Because `init.lua` is only consulted by yay when it exists, removing it is
enough to disable yay-holdup entirely.

## Testing (without installing)

Pass a package name to run the same analysis against the AUR, without installing
anything. This is how you confirm it actually catches a malicious sample before
trusting it:

```
./holdup.lua some-aur-package
```

It fetches the package's `PKGBUILD` and `.SRCINFO`, runs the LLM analysis,
prints the verdict, and exits non-zero (1) when blocked, zero (0) when safe — so
you can script against it.

## How it works

1. yay loads `init.lua`, which `require`s this module.
2. `holdup` registers an **`AURPreInstall`** hook.
3. For each AUR package base, the hook reads the `PKGBUILD` (provided by the
   event) and `.SRCINFO` (from `srcinfo_path`), sends them to the configured
   LLM, and parses a `{"verdict": …, "summary": …}` response.
4. **`safe`** → returns normally and the install proceeds. Anything else calls
   **`yay.abort(...)`**, which stops yay before the clean/diff/edit menus,
   source downloads, or build.

`AURPreInstall` was chosen deliberately: it runs after the PKGBUILD is fetched
but before `makepkg` ever executes it, and the PKGBUILD is where AUR malware
lives (malicious `source=` URLs, `build()`/`install()` functions that download
and run payloads).

## Configuration (`holdup.conf`)

```
provider = claude          # claude | deepseek
api_key  = sk-ant-...      # your API key
# optional overrides:
model_id = claude-opus-5   # default: claude-opus-5 / deepseek-chat
on_error = abort           # abort | warn
```

- **`model_id`** — override the concrete model. Defaults to `claude-opus-5`
  (Claude) or `deepseek-chat` (DeepSeek). For cheaper per-install scanning you
  might set `claude-sonnet-5` or `claude-haiku-4-5`.
- **`on_error`** — what to do when the LLM call itself fails (network, auth,
  rate limit). Default `abort` (fail closed). Set `warn` to log a warning and
  proceed instead.

## Verdict semantics (fail-closed)

| Model says            | holdup does                       |
|-----------------------|-----------------------------------|
| `safe`                | proceed                           |
| `unsafe`              | abort                             |
| `suspicious`          | abort (not "safe", so blocked)    |
| unparseable / API error | abort (unless `on_error = warn`) |

Security-critical scanning is fail-closed by design: if holdup can't say "safe"
with confidence, it doesn't install.

## Security notes

This is an LLM judgment, not a deterministic signature scanner, so it can miss
novel malware (false negatives) and flag unusual-but-legitimate packages (false
positives). It scans only the **PKGBUILD + `.SRCINFO`**, not the source
tarballs a package downloads. Treat it as one layer of defense, not the whole
defense.

In particular, **this is not a replacement for manually inspecting the AUR
package yourself.** It's an additional check that might help you catch things
you'd otherwise miss, but the LLM is not foolproof and can overlook some
malware — so you absolutely must review the package contents yourself as well.

This software is provided **"as is"**, without any warranty, and we are not
responsible for any damage caused to your system.

WE MAKE NO REPRESENTATIONS OR WARRANTIES AS TO THE QUALITY, SUITABILITY,
AVAILABILITY OR ADEQUACY OF THE SOFTWARE, INCLUDING, WITHOUT LIMITATION,
WARRANTIES OF MERCHANTABILITY, FITNESS FOR ANY PARTICULAR PURPOSE, TITLE,
NON-INFRINGEMENT, QUIET ENJOYMENT, NO ENCUMBRANCES AND WARRANTIES ARISING
THROUGH COURSE OF DEALING OR USAGE OF TRADE, AND WE HEREBY EXPRESSLY DISCLAIMS
ANY AND ALL SUCH REPRESENTATIONS AND WARRANTIES.
