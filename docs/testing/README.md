# End-to-end testing

Unit tests (`cargo test --lib`, 118 and counting) cover the core. These scripts cover the **real
desktop app**: every phase was verified by driving the running app and checking both the UI and the
files on disk.

## How it works

The UI is driven over the **Chrome DevTools Protocol**, never with synthetic mouse or keyboard input,
so tests cannot type into, click on or steal focus from whatever else is running on the machine.

| File | Purpose |
|---|---|
| `phase*/cdp.mjs` | Dependency-free CDP driver (Node 22 built-in `WebSocket`): `eval`, `fill`, `click`, `wait`, `shot`. `CDP_WINDOW=spotlight` targets the Quick search window. |
| `phase*/dialog.ps1` | Fills native Open/Save dialogs with window messages (`WM_SETTEXT` + `BM_CLICK`); needs no keyboard focus. |
| `phase*/win.ps1` | Win32 probes: display affinity, window visibility, posting session-lock messages, hotkey ownership. |
| `phase*/e2e-*.sh` | One script per phase; prints `PASS`/`FAIL` lines and a summary. |

## Running a phase script

```powershell
# 1. Point a debug build at a scratch vault. Never test against your real vault.
$env:SHUSH_VAULT_PATH = "$env:TEMP\shush-e2e\vault.shush"
# 2. Expose WebView2 over CDP on localhost only
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9222 --remote-debugging-address=127.0.0.1"
npx --prefix src tauri dev
```

Then, from a folder containing `cdp.mjs`, `dialog.ps1` and `win.ps1` (copy them from any phase
folder), run the phase script with that folder as its argument, e.g.
`bash docs/testing/phase4c/e2e-phase4c.sh <folder>`. Scripts expect the vault state their phase
describes in its header comment (for example "vault: e2e7, password only").

`SHUSH_VAULT_PATH` is compiled out of release builds. The CDP flag only affects the process it is
set for. Neither changes anything for a normal install.

### Running side-by-side with an installed shush

Debug builds (`npx tauri dev` or `cargo run`) can safely run while your installed `shush` is
running in the background:

- **Single-instance isolation**: Debug builds key their single-instance mutex on a distinct identifier
  (`com.shush.vault.debug` or `com.shush.vault.debug-<hash>` when `SHUSH_VAULT_PATH` is set), so they
  never hand off to the installed app's `com.shush.vault` or focus your real vault window. Automated
  testing can also bypass the single-instance plugin entirely by setting `$env:SHUSH_NO_SINGLE_INSTANCE = "1"`.
- **WebView2 data directory isolation**: When `SHUSH_VAULT_PATH` is set, WebView2 user data is directed
  to a `webview2` scratch folder alongside the scratch vault (e.g. `$env:TEMP\shush-e2e\webview2`).
  You can also override this explicitly with `$env:WEBVIEW2_USER_DATA_FOLDER`. Unset debug builds use
  `%LOCALAPPDATA%\com.shush.vault.debug`. This prevents `0x8007139F` collisions with the installed instance
  when browser arguments differ.
- Release builds strictly use `com.shush.vault` and compile out these debug overrides.

## What the scripts deliberately do not do

- **Press the global hotkey or type keys.** That would inject input into the tester's session.
  Hotkey ownership is proved by trying to register `Ctrl+Alt+Space` from another process (expects
  error 1409).
- **Copy to the clipboard.** That would overwrite the tester's clipboard. The clipboard has an
  opt-in unit test: `cargo test --lib -- --ignored clipboard`.
- **Lock the workstation or sleep the PC.** Instead they post the same `WM_WTSSESSION_CHANGE`
  message Windows sends to shush's hidden event window.

## Installer

`installer/installer-e2e.ps1` installs, reinstalls and uninstalls the NSIS installer and checks the
results on disk and in the registry (62 checks). The run covers:

- License page, per-user folder, finish-page options, shortcuts, Apps & features entry.
- Uninstalling while the app runs.
- Reinstalling over an existing install.
- The vault-deletion warning (#71), answered No and Yes.
- Silent `/S` install and uninstall.
- Removal of the WER exclusion (#60).

It never runs the real installer. Build a **QA-renamed** copy first, so every folder and registry
key differs from a real install (`%LOCALAPPDATA%\shush-qa`, `%APPDATA%\com.shush.qa`):

```powershell
npx --prefix src tauri build --bundles nsis --config '{"productName":"shush-qa","identifier":"com.shush.qa","mainBinaryName":"shush-qa"}'
powershell -File docs/testing/installer/installer-e2e.ps1 `
  -Installer src-tauri/target/release/bundle/nsis/shush-qa_<version>_x64-setup.exe -Out $env:TEMP\shush-installer-e2e
```

It drives NSIS with plain Win32 calls: `EnumWindows` (only titles containing `shush-qa`),
`WM_GETTEXT`, and `WM_COMMAND`/`BN_CLICKED` posted to the dialog. It does not use UI Automation:
NSIS controls show up there as plain panes, `BM_CLICK` fails when the dialog isn't the active
window, and a long-lived UIA client stopped seeing new top-level windows. Screenshots are
`PrintWindow` captures of the installer dialogs only. The app window captures black, which is
expected because the window is excluded from capture. Windows pops the dialogs up for a few
minutes, but no keystrokes or clicks reach the desktop.

Release binaries are also checked by `.github/scripts/check-pe-hardening.ps1` (ASLR, DEP, CFG,
CET, manifest) and a startup check in `.github/workflows/release.yml`.

## Results by phase

| Phase | Script | Result |
|---|---|---|
| 1 UX audit | screenshots in `phase1-ux-audit/` | manual audit |
| 4 dashboard | `phase4/e2e-phase4.sh` | 16/16 |
| 4b folders | `phase4b/e2e-phase4b.sh` | 13/13 |
| 4c attachments | `phase4c/e2e-phase4c.sh` | 11/11 |
| 5a desktop | `phase5/e2e-phase5.sh` | 12/12 |
| 5b Quick search | `phase5b/e2e-phase5b.sh` | 11/11 |
| 6a backups | `phase6/e2e-phase6.sh` | 14/14 |
| 6b CSV import | `phase6b/e2e-phase6b.sh` | 13/13 |
| 7a first run | `phase7a/e2e-phase7a.sh` | 10/10 |
| Design overhaul | `design-audit/audit.sh` (17-view screenshot walk, fresh vault) + 5b and 7a re-run | 11/11, 10/10 |
| Unseal unlock ritual | `unlock-ritual/e2e-unlock-ritual.sh`, reduced motion and full motion | 19/19, 19/19 |
| Multiple vaults | `multi-vault/e2e-multi-vault.sh` (fresh scratch vault; uses `cdp.mjs` from `phase5b`) | 34/34 |
| 8a duress vault | `phase8a/e2e-phase8a.sh` (fresh scratch vault, attachment rejection, decoy isolation, current-password re-auth #68) | 36/36 |
