# ADR: Windows Hello quick unlock

Status: **accepted** (design only; not implemented). Issue #7.
This document is normative. Where `master-specification.md`, `architecture-plan.md` or
`security-model.md` say anything else about Windows Hello, this document wins.

## Context

The earlier specs disagreed and were partly wrong:

- `NCRYPT_USER_PROTECTION_STRONG` is not a CNG constant. CNG offers `NCRYPT_UI_POLICY`
  (`NCRYPT_UI_PROTECT_KEY_FLAG`, `NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG`), which prompts for a
  per-key password, not for Hello.
- The architecture plan said DPAPI. DPAPI unwraps silently for any process running as the user,
  which `security-model.md` §2 rejects.
- No spec said what is wrapped, where the result is stored, or whether a "locked" vault still
  holds its key.

## Decision

### 1. API

`Windows.Security.Credentials.KeyCredentialManager` (WinRT, public and documented since
Windows 10 1507), called from Rust through the `windows` crate:

- `IsSupportedAsync()` gates the feature. If it is false, the setting is hidden.
- `RequestCreateAsync("shush-hello", KeyCredentialCreationOption::FailIfExists)` creates one
  RSA-2048 key pair in the user's Hello container (TPM-backed when a TPM is present). This is done
  once, when the user turns Hello on, and prompts for Hello.
- `OpenAsync("shush-hello")` + `KeyCredential::RequestSignAsync(challenge)` prompts for Hello
  (fingerprint, face or PIN) and returns an RSASSA-PKCS1-v1_5 / SHA-256 signature.
- `DeleteAsync("shush-hello")` when the user turns Hello off.

No CNG key-storage-provider calls, no DPAPI, no `NCRYPT_UI_POLICY`.

The Hello key pair is the only thing Hello-related that persists. It is not vault-specific and
carries no vault secret: on its own it decrypts nothing.

### 2. Deriving a key from a signature

`RequestSignAsync` signs; it does not decrypt. A key is derived from the signature, which works
because PKCS#1 v1.5 signatures are deterministic: the same key over the same message always gives
the same bytes.

```
challenge  = 32 random bytes (OsRng), fresh per Hello session, kept in process memory only
msg        = "shush-hello-v1" ‖ vault_id ‖ challenge
sig        = Hello.RequestSignAsync(msg)                     // 256 bytes, user gesture
KEK        = HKDF-SHA256(ikm = sig, salt = challenge, info = "shush-hello-kek-v1")
blob       = XChaCha20-Poly1305(KEK, nonce = random 24 B, aad = vault_id ‖ header_hash,
                                plaintext = VEK ‖ canary key ‖ attachment key)
```

`sig` and `KEK` are wiped as soon as `blob` is built or opened. The challenge is a secret: a
process that gets a Hello signature over any other message learns nothing about `KEK`.

When a session is armed, shush verifies `sig` against `KeyCredential::RetrievePublicKey()`. On
unlock, a signature that verifies but does not open `blob` means the signature was not
deterministic: shush evicts the session, reports it, and falls back to the password.

### 3. What is wrapped

The vault **sub-keys** (VEK, canary key, attachment key), never the master key and never the
password. The master key is already discarded once the sub-keys are derived. The wrap key is the
per-session `KEK` above, which is random per session because the challenge is.

### 4. Where the blob is kept

**Process memory only**: `{challenge, nonce, blob, vault_id, header_hash, armed_at}`. It is never
written to disk, the registry, `vaults.json` or the Credential Manager. App exit, sign-out,
restart and a crash all destroy it, so every cold start needs the password (and keyfile).

### 5. Lock = wipe

Lock always wipes the plaintext sub-keys and the decrypted vault, exactly as today
(`VaultState::lock`). A Hello session never keeps a plaintext key across a lock. What survives a
lock is the ciphertext `blob` and the challenge; a memory dump of a locked shush yields neither a
key nor a way to make one without the TPM-held Hello key and a user gesture.

A Hello unlock rebuilds `KEK`, opens `blob`, re-reads the vault file and checks the canary, then
installs the vault through the same `begin_unlock` / `finish_unlock` path as a password unlock, so
the #10 state machine rules apply unchanged.

### 6. Arming

A Hello session is armed only:

- right after a successful **password** unlock (never after a Hello unlock),
- when `enable_windows_hello` is on for this vault,
- by one Hello prompt at that moment (to produce `sig`); if the user cancels, no session.

### 7. Eviction

The session (challenge and blob) is wiped when any of these happen:

| Event | Why |
|---|---|
| **8 hours** since `armed_at` | Hard cap. Hello unlocks do not extend it. The setting can shorten it (1–8 h), never lengthen it. |
| App exit, crash, sign-out, restart | Memory only. |
| Suspend / hibernate (`PBT_APMSUSPEND`, `WTS_SESSION_LOGOFF`) | Bounds what `hiberfil.sys` and a stolen sleeping laptop carry. Session lock (`WTS_SESSION_LOCK`) and idle auto-lock keep it. |
| "Lock & forget" (`Ctrl+Shift+L`, tray menu) | User-chosen full lock. |
| Switching to another vault, removing or deleting this vault | `vault_id` binding. |
| Password change, keyfile change, rekey, cipher change, format migration | Sub-keys change. |
| Vault header changed on disk (`header_hash` mismatch) | The file is not the one the session was armed for. |
| 3 failed or cancelled Hello prompts in a row | Limits prompt-fatigue attacks. |
| Hello key missing or `KeyCredentialStatus` not `Success` | Enrollment changed or key deleted. |
| Hello turned off | Also deletes the key pair. |

### 8. Prompting rules

- shush calls `RequestSignAsync` only in response to a user action in shush's own foreground
  window (button or `F` on the unlock screen). Never on startup, on a timer, from Quick search
  while the main window is hidden, or from a native-messaging request.
- The browser bridge never triggers Hello. A locked vault answers `locked` to the extension.
- The unlock screen shows the Hello button only while a session is armed, with the time left
  (`HELLO · 5h 12m`). Otherwise the screen asks for the password and does not mention Hello.

## Consequences

- **Keyfile vaults.** For up to 8 hours after a password + keyfile unlock, Hello reopens the vault
  without the keyfile. This is the convenience being bought, and it is shown in the setting's
  description. The session cannot outlive the process, so the keyfile still guards every cold start.
- **Strength.** During a session, the Hello PIN and the TPM's anti-hammering stand in for the master
  password, for this process only. Off the machine, or after the process exits, Hello adds nothing.
- **Same-user malware.** Malware can show a Hello prompt with shush's key name, but it cannot
  derive `KEK` without the challenge, which lives only in shush's memory. Malware that can read
  shush's memory while the vault is unlocked already has the keys; Hello does not change that.
- **No TPM.** `KeyCredentialManager` falls back to a software-protected key on machines without a
  TPM. The Hello PIN still gates it, and the blob is still memory-only. The setting says
  `software key` instead of `TPM` in that case (`KeyCredential` attestation: `RequestAttestationAsync`
  returns `NotSupported`).
- **Duress vault (#8).** The session is bound to the slot that was opened by password. A duress
  unlock arms a session for the decoy slot only.
- **Deterministic-signature risk.** If a future Windows build randomized Hello signatures, every
  Hello unlock would fall back to the password (section 2). That fails safe.

## Implementation notes

- Module `src-tauri/src/os/win_hello.rs`; the session struct lives next to `VaultState` and is
  wiped (`Zeroize`) on every eviction path above.
- `WTS_SESSION_LOGOFF` and `PBT_APMSUSPEND` need the HWND message pump from #15.
- Tests: arming, unlock, every eviction trigger, the 8 h cap with an injected clock, wrong
  `header_hash`, non-deterministic signature fallback (mocked signer).
