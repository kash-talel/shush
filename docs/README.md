# shush docs

| Document | Read it for |
|---|---|
| [This page](#using-shush) | Using shush, building it, testing it |
| [`FORMAT.md`](FORMAT.md) | The `.shush` container byte by byte (normative) |
| [`spec/security-model.md`](spec/security-model.md) | Authentication design, cipher suite choice, downgrade defense |
| [`spec/master-specification.md`](spec/master-specification.md) | Full product specification (phases, UI, data model) |
| [`spec/architecture-plan.md`](spec/architecture-plan.md) | Crate layout and IPC design |
| [`spec/windows-hello.md`](spec/windows-hello.md) | Windows Hello quick unlock design (ADR, not yet built) |
| [`ROADMAP.md`](ROADMAP.md) | Phase status, owner decisions, the 7b and 8 plans |
| [`testing/README.md`](testing/README.md) | The CDP end-to-end harness and per-phase results |

## Using shush

### Create a vault

1. **Master password.** Normalized to Unicode NFC, so the same password typed on different keyboard
   layouts derives the same key. Minimum 8 characters.
2. **Keyfile (optional).** Generate a new 32-byte keyfile or pick any existing file. Its SHA-256
   becomes Argon2id's secret input. Store it away from the vault (a USB drive); shush warns when they
   share a folder. Without it the vault cannot be opened.
3. **Cipher.** AES-256-GCM (default, AES-NI accelerated) or XChaCha20-Poly1305 (192-bit nonces,
   constant-time in software), under *Advanced cryptography*.

There is no recovery. Forgetting the password or losing the keyfile locks the vault for good.

The vault lives at `%APPDATA%\com.shush.vault\vault.shush`. Attachments sit beside it in
`vault.shush.d\`. The previous version is kept as `vault.shush.bak` on every save.

More vaults can live anywhere, a USB drive included. `vaults.json` beside the default vault lists them
by name, path and disc colour only (nothing secret), and remembers which one was opened last. Deleting a
vault needs its typed name and its master password (plus keyfile), is throttled after three wrong tries,
and moves the vault, its `.bak` and its attachments to the Recycle Bin.

### Import passwords

The first-run screen lists the browsers it finds (it checks that a profile folder exists; it never
reads a browser's password store) with the steps to export a CSV. Supported formats: Chrome, Edge,
Brave, Firefox, Bitwarden, 1Password, KeePass, KeePassXC.

Import shows a preview (new, identical, conflicting) before writing anything. A conflicting login
keeps its current password; the imported one is archived in that login's history. Afterwards shush
offers to overwrite and delete the plaintext CSV. That is best effort: SSDs, cloud sync and shadow
copies can keep old copies.

### Quick search

`Ctrl+Alt+Space` opens Quick search over any app. It matches titles, usernames and hosts.

| Key | Copies |
|---|---|
| `Enter` | password |
| `Ctrl+Enter` | username |
| `Alt+Enter` | current 2FA code |

If the active window's title contains a saved host or title, that login is pre-selected and a
banner says so. Titles never cause typing. If the vault is locked, `Enter` opens the main window.

### 2FA codes

Paste a Base32 secret or an `otpauth://totp/` link into a login. Codes are computed in Rust (RFC
6238); the secret never reaches the UI. The ring counts down the seconds left in the period.

### Clipboard

Copies are marked to stay out of Win+V history and Cloud Clipboard. After 30 seconds shush clears
the clipboard, but only if it still holds what shush put there (checked by clipboard sequence
number). Locking clears it immediately.

### Locking

The vault locks and wipes its keys on `Ctrl+L`, Win+L, sign-out, RDP disconnect, sleep, display off
and after 15 minutes idle. Closing the window hides it to the tray without locking.

### Backups

*Backup & import → Create encrypted backup* writes a `.shushbackup` file with the whole vault and its
attachments, sealed either with the vault's own credentials or a separate password and keyfile.
Importing decrypts and previews first, then either **merges** (adds new items, archives conflicting
passwords) or does a **clean restore** (replaces the contents; the old vault is kept as `.bak`).

## Security architecture

```
password ──NFC──┐
                ├─► Argon2id v1.3 ─► master key ─► HKDF-SHA256 ─┬─► vault key ──────► vault.shush
keyfile ─SHA-256┘   64 MiB · t=3 · p=4                          ├─► canary key ─────► 33-byte canary
                    32-byte salt per vault                       └─► attachment key ─► vault.shush.d/*.blob
```

- **KDF bounds.** Argon2id parameters in a header are checked against fixed limits before any
  hashing, so a crafted file cannot exhaust memory or stall the unlock.
- **Authenticated header.** Every header byte is AEAD associated data. Changing the cipher id, KDF
  parameters or salt makes the vault fail to open rather than downgrade.
- **Canary.** A small sealed record that tells a wrong password apart from a modified file.
- **Nonces.** 96-bit (AES-GCM) or 192-bit (XChaCha20) from the OS CSPRNG on every write.
- **Padding.** PADMÉ, so file size reveals little about item count.
- **Rust owns the secrets.** The UI gets list rows and redacted item views. Copying, TOTP and
  password generation run in Rust. Editing an item never loads its current password into the UI.
- **Memory (best effort).** Keys and decrypted data live in `zeroize` types and are wiped on lock.
  Vault keys sit on a `VirtualLock`ed page, and crash reports exclude the heap. Text typed or
  revealed in the UI lives in WebView2 and can't be wiped; see spec §6.1 for the residual risks.

## Building

Windows 10/11, Rust 1.80+, Node.js 22, WebView2.

```powershell
npm ci --prefix src
npx --prefix src tauri dev                    # debug app with hot reload
npx --prefix src tauri build --no-bundle      # src-tauri\target\release\shush.exe
npx --prefix src tauri build                  # NSIS + MSI installers
```

GNU toolchain: ship `WebView2Loader.dll` next to `shush.exe`.

## Checks

All of these run in CI and must pass before a merge:

```powershell
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml --lib
npm run --prefix src check
npm run --prefix src build
```

UI work is also verified against the running app over the Chrome DevTools Protocol, never with
synthetic mouse or keyboard input. Point a debug build at a scratch vault with `SHUSH_VAULT_PATH`
(compiled out of release builds). See [`testing/README.md`](testing/README.md).

## Reporting a vulnerability

Privately, as described in [`SECURITY.md`](../SECURITY.md).
