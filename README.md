# shush

Offline-first, zero-knowledge password manager & 2FA authenticator for Windows.
Tauri v2 · Rust · Svelte 5 · Tailwind v4.

Specifications live in [`docs/`](docs/). Design risks found during spec review are
tracked as GitHub issues labelled `spec-review`.

## Layout

```
src/         Svelte 5 + Vite frontend project (spec §8)
src-tauri/   Rust core + Tauri shell
  src/crypto/  Phase 1 cryptographic engine (Argon2id, keyfile, AEAD envelope)
docs/        Specifications
```

## Development

```sh
# frontend deps
cd src && npm install

# crypto engine tests (no WebView needed)
cd src-tauri && cargo test --lib

# run the desktop app (from repo root)
npx --prefix src tauri dev
```

## Status

- [x] Phase 1 — Crypto engine: Argon2id KDF, keyfile generator, AES-256-GCM /
      XChaCha20-Poly1305 envelope with canary, unit tests + independent KATs
- [ ] Phase 3 — `vault.shush` container & atomic writer
- [ ] Phase 4+ — UI, OS integration, backup/import, sync
