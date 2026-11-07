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
| 5b | Desktop: Spotlight overlay + global hotkey, window-context search, auto-type | ⏸ blocked on owner decisions (#13 / #14) | |
| 4b | Folders: create / rename / delete, assign items, sidebar filter | 🔨 in progress | |
| 4c | Attachments stored as separately sealed blobs (#5) | ⏳ needs format decision (sidecar files vs. in-container section) | |
| 6a | Encrypted `.shushbackup` export (vault or separate credentials), import preview, merge / clean restore | ✅ implemented & verified (awaiting merge) | #34 |
| 6b | CSV migration (Bitwarden / 1Password / KeePass / Chrome / Firefox) with conflict handling | ✅ implemented & verified (awaiting merge) | #35 |
| 7a | First-run onboarding: browser detection (folder existence only) + guided CSV import (#17) | ✅ implemented & verified (awaiting merge) | #36 |
| 7b | Native messaging host + companion browser extension (#16) | ⏸ blocked on owner decisions (IPC auth / pairing) | |
| 8 | Duress / decoy vault (#8), LAN sync (#18), air-gapped mode (#25) | ⏳ | |

## Decisions still needed from the owner

- **5b hotkey:** spec says `Alt+Shift+S`, which collides with the Windows input-language
  switch (#14). Proposed default: `Ctrl+Alt+Space`, user-configurable.
- **5b auto-type:** only from the browser extension's verified origin, or also from window
  titles (phishing risk, #14)?
- **7b native messaging (#16):** pairing model for the extension ↔ app channel (proposed:
  named pipe restricted to the user SID + one-time pairing code shown in shush), and whether
  the spec's automatic "try archived password" fallback is dropped (recommended: drop it).
- **8 duress vault:** fixed-slot deniable format (bigger files) vs. a non-deniable decoy (#8).
