# `vault.shush` format — version 1

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
```

KDF parameters are bounds-checked **before** Argon2 runs (m ≤ 2 GiB, 1 ≤ t ≤ 64,
1 ≤ p ≤ 16, m ≥ 8·p). New vaults must meet the policy floor (m ≥ 19 MiB, t ≥ 2).

## Binary layout

All integers little-endian.

| Offset | Len | Field | Notes |
|-------:|----:|-------|-------|
| 0x00 | 5  | MAGIC | `SHUSH` (vault) or `SHBKP` (backup) |
| 0x05 | 2  | FORMAT_VERSION | `1`; any other value is rejected |
| 0x07 | 1  | CIPHER_SUITE_ID | `0x01` AES-256-GCM, `0x02` XChaCha20-Poly1305 |
| 0x08 | 1  | FLAGS | bit 0 = keyfile required; other bits must be 0 |
| 0x09 | 4  | ARGON2_MEM_KIB | |
| 0x0D | 4  | ARGON2_ITERATIONS | |
| 0x11 | 4  | ARGON2_PARALLELISM | |
| 0x15 | 32 | KDF_SALT | |
| 0x35 | 24 | CANARY_NONCE | 12 or 24 bytes used; remaining bytes must be 0 |
| 0x4D | 33 | CANARY_CIPHERTEXT | AEAD(`SHUSH_CANARY_V001`) = 17 + 16 tag |
| 0x6E | 24 | PAYLOAD_NONCE | 12 or 24 bytes used; remaining bytes must be 0 |
| 0x86 | 4  | PAYLOAD_LENGTH | ciphertext length incl. tag; ≤ 512 MiB; must equal remaining bytes |
| 0x8A | N  | PAYLOAD_CIPHERTEXT | |

## Header authentication (issue #1)

| Block | Key | AAD |
|-------|-----|-----|
| Canary  | CanaryKey | bytes `[0x00, 0x35)` |
| Payload | VEK       | bytes `[0x00, 0x6E)` ‖ PAYLOAD_LENGTH |

An AEAD cannot include its own nonce in its AAD, but a modified nonce makes that
AEAD fail anyway, and nonce padding must be zero. Therefore **no byte of the file
can change without detection.** A tampered `FLAGS`, KDF parameter or salt fails the
canary (reported as wrong credentials); a tampered payload fails only the payload
(reported as an integrity failure).

## Nonces (issue #2)

Every save draws fresh random nonces for both the canary and the payload from the
OS CSPRNG. The encryption API does not accept caller-supplied nonces.

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

## Not yet covered

- Cross-process locking / generation counter (issue #9).
- Attachments stored outside the JSON payload (issue #5, attachments part).
- Decoy / duress slots (issue #8).
