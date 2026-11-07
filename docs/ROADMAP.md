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
| 5a | Desktop: auto-lock (session/suspend/display/idle), capture protection, tray, single-instance | ✅ implemented & verified (awaiting merge) | #32 |
| 5b | Desktop: Spotlight overlay + global hotkey, window-context search, auto-type | ⏸ blocked on owner decisions (#13 / #14) | |
| 4b | Attachments (stored outside the JSON payload, #5), folders | ⏳ after 6 (attachment storage needs a format decision) | |
| 6a | Encrypted `.shushbackup` export (vault or separate credentials), import preview, merge / clean restore | ✅ implemented & verified (awaiting merge) | #34 |
| 6b | CSV migration (Bitwarden / 1Password / KeePass / Chrome / Firefox) with conflict handling | ⏳ next | |
| 7 | First-run onboarding (guided CSV import, #17), native messaging host (#16) | ⏳ | |
| 8 | Duress / decoy vault (#8), LAN sync (#18), air-gapped mode (#25) | ⏳ | |

## Decisions still needed from the owner

- **5b hotkey:** spec says `Alt+Shift+S`, which collides with the Windows input-language
  switch (#14). Proposed default: `Ctrl+Alt+Space`, user-configurable.
- **5b auto-type:** only from the browser extension's verified origin, or also from window
  titles (phishing risk, #14)?
- **8 duress vault:** fixed-slot deniable format (bigger files) vs. a non-deniable decoy (#8).
