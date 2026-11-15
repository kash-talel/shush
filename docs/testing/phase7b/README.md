# Phase 7b: extension and host registration (issue #53)

## Automated (run by `cargo test`)

- `os::native_host` registers and unregisters the three per-user keys under a scratch
  `HKCU\Software\ShushTest\...` root (never the real browser keys), checks the manifests pin
  exactly the shush extension, and checks the pinned Chromium id matches `extension/manifest.json`.
- `bridge::pairing::javascript_extension_pairs_with_the_host` runs `extension/pairing-cli.mjs`
  under Node (skipped without Node) and redeems its SPAKE2 message and proof against the Rust
  host, proving the extension's pairing and the derived pair key interoperate.

## CDP check of the Settings toggle (manual script)

Run the debug app per `docs/testing/README.md` with a scratch `SHUSH_VAULT_PATH` and
`SHUSH_NMH_REGISTRY_ROOT=Software\ShushTest\Manual` so the real browser keys stay untouched.
Over CDP: unlock, open Settings, tick "Allow browsers to talk to shush", then confirm
`reg query HKCU\Software\ShushTest\Manual /s` lists the three `NativeMessagingHosts\com.shush.vault`
keys and the `native-messaging\` manifests exist beside the scratch vault; untick and confirm both
are gone. Delete `HKCU\Software\ShushTest\Manual` afterwards.

## Extension in a real Edge against a test page: `e2e-phase7b.sh`

Start the debug app on a fresh scratch vault (onboarding screen) with `CDP_PORT` set and
`SHUSH_NMH_REGISTRY_ROOT` unset, then:

```bash
CDP_PORT=<app CDP port> bash docs/testing/phase7b/e2e-phase7b.sh <scratch dir>
```

It loads `extension/` unpacked in a headless Edge with its own profile, serves a login form from
`page.mjs` on `127.0.0.1:8765`, and drives both the app and Edge over CDP with `edge.mjs` (no
desktop input). The 15 checks cover registration through the Settings toggle, the pinned extension
id, the popup reaching shush through the registered `shush-host.exe`, pairing, inline fill on the
item's origin, no fill on another origin, while locked, or after revoke (the extension then wipes its
key), and removal of the keys when the toggle is unticked.

Browsers only read the real `HKCU\Software\...\NativeMessagingHosts` keys, so this run writes them.
It aborts if a `com.shush.vault` key already exists and deletes the keys on exit either way.

Last run: 2026-11-13, Edge 157, 15 passed.

## Pipe listener, image check, limits and squat warning: `e2e-pipe.sh` (issue #153)

Covers what `e2e-phase7b.sh` does not: the `shush-host.exe` client-image check, the per-connection
rate limit, the connection cap and the squatted-pipe warning. It starts and stops the debug app
itself on a scratch vault, touches no browser registry keys, and aborts if a shush pipe already
exists (close an installed shush first; the pipe name is per user). Needs the bins built and Vite on
port 1420, with `CDP_PORT` set (see `docs/testing/README.md`):

```bash
cargo build --manifest-path src-tauri/Cargo.toml --bins
CDP_PORT=<port> bash docs/testing/phase7b/e2e-pipe.sh <scratch dir>
```

`pipe-probe.mjs` is its pipe-side helper. The 12 checks: a Node client (not `shush-host.exe`) is
closed without an answer; the real host is answered; 30 requests per second per connection and then
the connection is cut; 8 live connections served, the 9th dropped, and a slot frees when one closes;
with a squatter holding the pipe name the app reports `serving: false` with the warning text, and
`shush-host.exe` refuses a pipe not served by `shush.exe`.

Last run: 2026-11-15, 12 passed.
