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

## What the scripts deliberately do not do

- **Press the global hotkey or type keys.** That would inject input into the tester's session.
  Hotkey ownership is proved by trying to register `Ctrl+Alt+Space` from another process (expects
  error 1409).
- **Copy to the clipboard.** That would overwrite the tester's clipboard. The clipboard has an
  opt-in unit test: `cargo test --lib -- --ignored clipboard`.
- **Lock the workstation or sleep the PC.** Instead they post the same `WM_WTSSESSION_CHANGE`
  message Windows sends to shush's hidden event window.

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
