# shush roadmap & phase status

Source of truth for "what phase are we in". Steps follow the master spec §12.
A phase is **complete** only when: Rust tests + `clippy -D warnings` + `svelte-check` +
frontend build pass, the CDP end-to-end script for the phase passes against the real app,
and its PR is merged into `main`.

| Step | Scope | Status | PR |
|-----:|-------|--------|----|
| 1 | Scaffolding: Tauri v2 + Svelte 5 + Tailwind, spec crates | ✅ complete | #28 |
| 2 | Crypto engine: Argon2id, keyfile, AES-GCM / XChaCha envelope, tests | ✅ complete | #28 |
| 3 | Vault container, binary format, atomic writer, create / unlock / lock | ✅ complete | #29 |
| 4 | Dashboard: item CRUD, TOTP + ring, generator, safe clipboard | ✅ complete | #31 |
| 5a | Desktop: auto-lock (session/suspend/display/idle), capture protection, tray, single-instance | ✅ complete | #32 |
| 5b | Desktop: Spotlight overlay + `Ctrl+Alt+Space`, window-context pre-selection (auto-type moves to 7b) | 🔨 in progress | |
| 4b | Folders: create / rename / delete, assign items, sidebar filter | ✅ implemented & verified (awaiting merge) | #37 |
| 4c | Attachments as AEAD-sealed sidecar files (#5) | ⏳ next | |
| 6a | Encrypted `.shushbackup` export (vault or separate credentials), import preview, merge / clean restore | ✅ implemented & verified (awaiting merge) | #34 |
| 6b | CSV migration (Bitwarden / 1Password / KeePass / Chrome / Firefox) with conflict handling | ✅ implemented & verified (awaiting merge) | #35 |
| 7a | First-run onboarding: browser detection (folder existence only) + guided CSV import (#17) | ✅ implemented & verified (awaiting merge) | #36 |
| 7b | Native messaging host + extension with one-time-code pairing (#16), extension-verified auto-type | ⏳ | |
| 8 | Deniable duress vault (#8), on-demand PAKE LAN sync (#18), air-gapped mode (#25) | ⏳ | |

## Owner decisions (2026-11-07)

1. **Hotkey (#14):** `Ctrl+Alt+Space` (not the spec's `Alt+Shift+S`).
2. **Auto-type (#13/#14):** only into sites verified by the browser extension; window titles are
   never used to auto-type (they may still pre-select a search result).
3. **Native messaging (#16):** one-time pairing code shown in shush; the automatic
   "try archived password" fallback is dropped.
4. **Attachments (#5):** separately AEAD-sealed sidecar files beside the vault.
5. **LAN sync (#18):** on-demand, time-boxed pairing with a PAKE one-time code; no always-on mDNS.
6. **Duress vault (#8):** undetectable: fixed-size padded slots, constant-work unlock.

## Order of remaining work

5b Spotlight → 4c attachments → 7b native messaging + extension (then auto-type) →
8 duress vault → 8 LAN sync → 8 air-gapped mode (with the first network feature).
