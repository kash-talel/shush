# shush Documentation

Welcome to the **shush** documentation. shush is an offline-first, zero-knowledge password manager and 2FA authenticator designed specifically for Windows, built with **Tauri v2**, **Rust**, and **Svelte 5**.

> [!IMPORTANT]
> **The Zero-Knowledge Pledge**
> - **Zero Network Footprint**: shush makes no network connections. The UI is strictly restricted to communicating with its local Rust core via Tauri IPC.
> - **Ephemeral Secrets**: The master key is never stored on disk. It is derived in-memory on demand via Argon2id and securely wiped with `zeroize` upon vault lock.
> - **Authenticated Container**: Every byte of the vault container—including the header—is authenticated. Any external tampering or bit flips are detected and refused.

---

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
  - [Initial Vault Setup](#initial-vault-setup)
- [Core Workflows](#core-workflows)
  - [Global Quick Search](#global-quick-search)
  - [2FA / TOTP Authenticator](#2fa--totp-authenticator)
  - [Safe Clipboard & Auto-Type](#safe-clipboard--auto-type)
  - [Encrypted Backups & Migration](#encrypted-backups--migration)
- [Security Architecture](#security-architecture)
  - [Key Derivation (KDF)](#key-derivation-kdf)
  - [AEAD Envelopes](#aead-envelopes)
  - [Integrity & Canary Verification](#integrity--canary-verification)
  - [Win32 Hardening](#win32-hardening)
- [Keyboard & Shortcut Reference](#keyboard--shortcut-reference)
- [Codebase Architecture](#codebase-architecture)
- [Specifications & Normative References](#specifications--normative-references)

---

## Getting Started

### Prerequisites

To build and run shush, ensure your system has:
* **Operating System**: Windows 10 (version 1903+) or Windows 11.
* **Rust**: Stable toolchain (1.80+) via [rustup](https://rustup.rs).
* **Node.js**: v20 or v22 LTS with `npm` via [nodejs.org](https://nodejs.org).
* **WebView2 Runtime**: Standard on Windows 11 and modern Windows 10 installations.

### Building from Source

```powershell
# 1. Clone the repository
git clone https://github.com/kash-talel/shush.git
cd shush

# 2. Install frontend dependencies
npm ci --prefix src

# 3. Verify core crypto & unit tests
cd src-tauri
cargo test --lib
cd ..

# 4. Launch in development mode
npx --prefix src tauri dev

# 5. Build optimized standalone release executable
npx --prefix src tauri build --no-bundle
```

The resulting standalone executable will be located at:
`src-tauri\target\release\shush.exe`

> [!TIP]
> When compiling with the GNU toolchain (`x86_64-pc-windows-gnu`), ensure `WebView2Loader.dll` from the target directory is placed alongside `shush.exe`. MSVC builds link this library statically.

### Initial Vault Setup

Upon first launch, shush guides you through creating a vault:
1. **Master Password**: Normalized via Unicode NFC.
2. **Optional Keyfile**: Any local file (e.g., on a dedicated hardware USB token); its SHA-256 hash serves as an independent secret input to Argon2id.
3. **Cipher Selection**: Choose between **AES-256-GCM** (hardware-accelerated via AES-NI) or **XChaCha20-Poly1305** (software-constant-time).
4. **Browser Migration**: The first-run wizard detects installed browsers (Chrome, Edge, Brave, Firefox) and facilitates clean CSV migration.

---

## Core Workflows

### Global Quick Search

Press **`Ctrl+Alt+Space`** from any application to summon the spotlight HUD:
* **Fuzzy Search**: Instant lookup across titles, usernames, URLs, and tags.
* **Window Context Detection**: Automatically detects the focused browser tab or app title to pre-select matching credentials.
* **Direct Actions**:
  * `Enter` $\rightarrow$ Copies password to clipboard.
  * `Ctrl+Enter` $\rightarrow$ Copies username.
  * `Alt+Enter` $\rightarrow$ Copies 6-digit TOTP token.
  * `Esc` $\rightarrow$ Dismisses HUD back into the tray.

### 2FA / TOTP Authenticator

* Implements standard **RFC 6238** time-based one-time passwords.
* Supports manual Base32 secret keys and `otpauth://totp/` URI formats.
* Visual countdown ring with automatic drift synchronization.

### Safe Clipboard & Auto-Type

* **Clipboard Quarantine**: Secrets copied to the clipboard are tagged to exclude them from Windows Cloud Clipboard and the Win+V clipboard history buffer.
* **Sequence-Aware Auto-Wipe**: shush records the Win32 `GetClipboardSequenceNumber()`. When the wipe countdown (default: 30 seconds) expires, it wipes the clipboard *only if* the clipboard content still belongs to shush.
* **Screen Capture Protection**: Windows are rendered with `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` to prevent background spyware or screenshot utilities from recording unmasked secrets.

### Encrypted Backups & Migration

* **Encrypted Sidecars (`.shushbackup`)**: Atomic encrypted archives containing your vault database and sidecar attachment blobs.
* **CSV Importer**: Clean imports with duplicate detection from Bitwarden, 1Password, KeePassXC, Chrome, Edge, and Firefox.

---

## Security Architecture

```
                       [ Master Password (NFC) ]
                                  │
                                  ▼
[ Keyfile (Optional) ] ──► SHA-256 Secret (K)
                                  │
                                  ▼
                     [ Argon2id v1.3 (RFC 9106) ]
                     (64 MiB, t=3, p=4, 32-byte Salt)
                                  │
                                  ▼
                          [ Master Key (MK) ]
                                  │
                                  ▼
                         [ HKDF-SHA256 ]
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
               [ Vault Key ] [ Canary Key ] [ Attachment Key ]
                    │             │             │
                    ▼             ▼             ▼
              vault.shush    Canary Check   *.blob (Sidecars)
```

### Key Derivation (KDF)
* **Algorithm**: Argon2id v1.3 (RFC 9106).
* **Parameters**: 64 MiB memory cost, 3 iterations, 4 parallel lanes, 32-byte cryptographic salt.
* **Hardening**: Header parameters are validated against strict safety bounds before execution to prevent resource exhaustion attacks.

### AEAD Envelopes
* **Ciphers**: AES-256-GCM or XChaCha20-Poly1305.
* **Nonces**: 96-bit (AES-GCM) or 192-bit (XChaCha20) CSPRNG nonces generated per write transaction.
* **Padding**: Payloads are padded according to the PADMÉ standard to prevent leaking secret counts via file length.

### Integrity & Canary Verification
* Every single byte of the header is included in the AEAD additional authenticated data (AAD).
* A 33-byte encrypted canary enables unambiguous distinction between an incorrect master password and file tampering.

### Win32 Hardening
* **Process Isolation**: Single-instance mutex prevents concurrent writers from corrupting database state.
* **Auto-Lock Triggers**: Immediate lock on `Win+L`, user sign-out, RDP disconnect, workstation lock, display sleep, lid close, and user idle.

---

## Keyboard & Shortcut Reference

| Shortcut | Scope | Description |
| :--- | :--- | :--- |
| **`Ctrl+Alt+Space`** | Global (OS-wide) | Open Quick search spotlight overlay |
| **`Ctrl+N`** | App Window | Create a new credential entry |
| **`Ctrl+F`** | App Window | Focus vault search field |
| **`Ctrl+L`** | App Window | Immediately lock vault and purge memory |
| **`Enter`** | Quick Search | Copy password and dismiss |
| **`Ctrl+Enter`** | Quick Search | Copy username |
| **`Alt+Enter`** | Quick Search | Copy current 2FA / TOTP token |
| **`Esc`** | Quick Search | Dismiss overlay to tray |

---

## Codebase Architecture

```
shush/
├── src-tauri/                 # Rust Core & Win32 Integration
│   ├── src/
│   │   ├── crypto/            # Argon2id KDF, AEAD ciphers, HKDF, CSPRNG
│   │   ├── vault/             # Binary format, crash-safe fsync writer, items
│   │   ├── os/                # Win32 clipboard, auto-lock, display affinity
│   │   ├── totp/              # RFC 6238 TOTP engine
│   │   ├── lib.rs             # Tauri IPC command definitions
│   │   └── main.rs            # Application entrypoint & single instance
│   └── Cargo.toml             # Rust dependencies
├── src/                       # Frontend Presentation Layer
│   ├── src/                   # Svelte 5 reactive components & state
│   ├── vite.config.ts         # Vite bundler configuration
│   └── package.json           # Frontend dependencies
├── site/                      # Public documentation & landing portal
└── docs/                      # Technical specifications & roadmap
    ├── FORMAT.md              # Normative binary container specification
    ├── ROADMAP.md             # Development milestone tracker
    └── spec/                  # Formal security model & threat analysis
```

---

## Specifications & Normative References

For deep technical specifications, refer to the companion documents:
* **[FORMAT.md](FORMAT.md)**: Exact byte-level binary container specification.
* **[spec/security-model.md](spec/security-model.md)**: Formal adversarial threat model and cryptographic proofs.
* **[ROADMAP.md](ROADMAP.md)**: Architectural decisions and upcoming milestones.
* **[testing/README.md](testing/README.md)**: End-to-end testing harness and verification suites.

---

## Security Disclosure

If you discover a potential vulnerability in shush, please refer to our [Security Policy](../SECURITY.md) to report it responsibly. All valid security issues are addressed with high priority.
