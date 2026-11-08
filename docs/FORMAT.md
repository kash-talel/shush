# `vault.shush` format — version 2

This is the normative description of the on-disk format as implemented in
`src-tauri/src/vault/container.rs` and `src-tauri/src/crypto/`. It refines spec §3–§4
with the decisions taken during the spec review (issues #1, #2, #3, #4, #5).

## Key derivation

```
P = UTF-8(NFC(master password))          # issue #3: Unicode NFC normalization
K = SHA-256(keyfile bytes) or empty      # issue #3: Argon2 secret input, not concatenation
S = KDF_SALT (32 random bytes)

MasterKey   = Argon2id v1.3 (P, S, secret=K, m=ARGON2_MEM_KIB, t=ARGON2_ITERATIONS, p=ARGON2_PARALLELISM, 32 bytes)
VEK         = HKDF-SHA256(ikm=MasterKey, salt=none, info="shush/v1/vault-encryption-key",    32 bytes)
CanaryKey   = HKDF-SHA256(ikm=MasterKey, salt=none, info="shush/v1/canary-verification-key", 32 bytes)
PayloadKey  = HKDF-SHA256(ikm=VEK, salt=SAVE_ID, info="shush/v2/payload-save-key",         32 bytes)   # v2, per write
```

KDF parameters are bounds-checked **before** Argon2 runs (m ≤ 2 GiB, 1 ≤ t ≤ 64,
1 ≤ p ≤ 16, m ≥ 8·p). New vaults must meet the policy floor (m ≥ 19 MiB, t ≥ 2).

## Binary layout

All integers little-endian.

| Offset | Len | Field | Notes |
|-------:|----:|-------|-------|
| 0x00 | 5  | MAGIC | `SHUSH` (vault) or `SHBKP` (backup) |
| 0x05 | 2  | FORMAT_VERSION | `2` (written); `1` is still read; anything else is rejected |
| 0x07 | 1  | CIPHER_SUITE_ID | `0x01` AES-256-GCM, `0x02` XChaCha20-Poly1305 |
| 0x08 | 1  | FLAGS | bit 0 = keyfile required; other bits must be 0 |
| 0x09 | 4  | ARGON2_MEM_KIB | |
| 0x0D | 4  | ARGON2_ITERATIONS | |
| 0x11 | 4  | ARGON2_PARALLELISM | |
| 0x15 | 32 | KDF_SALT | |
| 0x35 | 24 | CANARY_NONCE | 12 or 24 bytes used; remaining bytes must be 0 |
| 0x4D | 33 | CANARY_CIPHERTEXT | AEAD(`SHUSH_CANARY_V001`) = 17 + 16 tag |
| 0x6E | 32 | SAVE_ID | random, regenerated on every write (issue #2) |
| 0x8E | 24 | PAYLOAD_NONCE | 12 or 24 bytes used; remaining bytes must be 0 |
| 0xA6 | 4  | PAYLOAD_LENGTH | ciphertext length incl. tag; ≤ 512 MiB; must equal remaining bytes |
| 0xAA | N  | PAYLOAD_CIPHERTEXT | |

**Version 1 (legacy, read-only).** Identical except that there is no `SAVE_ID`: `PAYLOAD_NONCE`
is at 0x6E, `PAYLOAD_LENGTH` at 0x86 and the ciphertext at 0x8A, and the payload is encrypted
directly under the VEK. v1 files open normally; the next save rewrites them as v2.

## Header authentication (issue #1)

| Block | Key | AAD |
|-------|-----|-----|
| Canary  | CanaryKey | bytes `[0x00, 0x35)` |
| Payload | PayloadKey (v2) / VEK (v1) | bytes `[0x00, 0x6E)` ‖ PAYLOAD_LENGTH |

An AEAD cannot include its own nonce in its AAD, but a modified nonce makes that
AEAD fail anyway, and nonce padding must be zero. A modified `SAVE_ID` selects a
different payload key, so it fails the payload AEAD the same way. `FORMAT_VERSION`
is in the canary AAD, so relabelling a v1 file as v2 (or back) is detected. Therefore **no byte of the file
can change without detection.** A tampered `FLAGS`, KDF parameter or salt fails the
canary (reported as wrong credentials); a tampered payload fails only the payload
(reported as an integrity failure).

## Nonces (issue #2)

Every save draws fresh random nonces for both the canary and the payload from the
OS CSPRNG. The encryption API does not accept caller-supplied nonces.

Defense in depth (format v2): the VEK is static for the life of the vault, so every
save also draws a fresh 32-byte `SAVE_ID` and encrypts the payload under
`PayloadKey = HKDF(VEK, salt=SAVE_ID)`. Each write therefore uses its own AEAD key: a
repeated nonce (RNG fault, VM snapshot restore, implementation bug) cannot produce a
two-time pad or leak the GCM authentication key, and the NIST bound of 2^32 random
96-bit nonces per key applies per save rather than per vault. The `SAVE_ID` is
generated inside the encryption API and cannot be supplied by callers.

The canary is re-sealed under the static CanaryKey on every save with a fresh random
nonce. It encrypts a constant, so it is far below the 2^32-messages-per-key bound for
any realistic number of saves.

Attachment blobs use the static attachment key with a fresh random nonce per blob write.
Blobs are written when an attachment is added or imported, not on every vault save, so the
same bound applies.

## Payload plaintext (issues #4, #5)

```
plaintext = u32 compressed_len ‖ zstd(JSON(VaultData), level 3) ‖ zero padding
total     = max(4096, PADMÉ(4 + compressed_len))
```

- PADMÉ padding leaks at most O(log log n) bits of the size; tiny vaults all pad to 4 KiB.
- The zstd frame must declare its content size; frames declaring more than 256 MiB are
  rejected before any allocation (decompression-bomb guard).
- `VaultData` is the JSON model from spec §5 (`version: 1`).

## Writing (issue #11)

1. Write `vault.shush.tmp`, `fsync`.
2. Read it back; require byte equality; decrypt it and require the same data.
3. Copy the current `vault.shush` to `vault.shush.bak` (previous generation), `fsync`.
4. Rename the tmp file over `vault.shush`, retrying briefly on sharing violations.

At every point either the old or the new vault is intact on disk.

## Concurrent writers (issue #9)

- **One process per vault.** While a vault is unlocked, shush holds `vault.shush.lock`
  open with no sharing and `FILE_FLAG_DELETE_ON_CLOSE`. Another process that tries to
  open the vault is refused (`VAULT_IN_USE`). The OS releases the lock if shush crashes,
  so it cannot go stale. A second app launch is also redirected to the running instance
  (single-instance plugin).
- **Optimistic check before every save.** The open vault remembers a fingerprint of the
  file it loaded or last wrote: SHA-256 of the file's first `0xAA` bytes, which contain
  the nonces and `SAVE_ID` drawn fresh on every save. Between steps 2 and 3 above, the
  fingerprint of the file currently on disk must match. If it doesn't (a sync client or
  other program replaced or removed the file), the save is refused
  (`VAULT_CHANGED_ON_DISK`), nothing on disk changes, and the edit is rolled back in
  memory. No header field was added: the random per-save header already identifies a save.

## Attachments (sidecar blobs, issue #5)

Each attachment is stored as `vault.shush.d/<attachment-uuid>.blob` beside the vault:

| Off | Len | Field |
|----:|----:|-------|
| 0 | 5 | MAGIC `SHATT` |
| 5 | 2 | VERSION (1) |
| 7 | 1 | CIPHER_SUITE_ID (same as the vault) |
| 8 | 24 | NONCE (zero-padded) |
| 32 | N | AEAD ciphertext of `u32 len ‖ zstd(file) ‖ zero padding (PADMÉ, ≥ 4 KiB)` |

- Key: `HKDF-SHA256(MasterKey, info="shush/v1/attachment-key")`.
- AAD: `blob[0..8) ‖ vault KDF_SALT ‖ attachment id (ASCII)`, binding the blob to its vault and id.
- Files ≤ 10 MiB; decompression bounded by the zstd frame size.
- Metadata (`filename`, `mime_type`, `size_bytes`) lives in the encrypted payload; `data_base64` is
  empty for stored attachments and only filled inside `.shushbackup` manifests (self-contained backups).
- Add: blob written (and verified) before the metadata is saved. Delete: metadata saved first.
  Unreferenced blobs are removed on unlock, after item deletion and after import.

## Not yet covered

- Decoy / duress slots (issue #8).
