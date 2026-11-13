# shush roadmap & phase status

Source of truth for "what phase are we in". Steps follow the master spec §12.
A phase is **complete** only when Rust tests, `clippy -D warnings`, `svelte-check` and the
frontend build pass (all enforced by CI), the CDP end-to-end script for the phase passes against
the real app (see [`testing/`](testing/README.md)), and its PR is merged into `main`.

| Step | Scope | Status | PR |
|-----:|-------|--------|----|
| 1 | Scaffolding: Tauri v2 + Svelte 5 + Tailwind, spec crates | ✅ complete | #28 |
| 2 | Crypto engine: Argon2id, keyfile, AES-GCM / XChaCha envelope, tests | ✅ complete | #28 |
| 3 | Vault container, binary format, atomic writer, create / unlock / lock | ✅ complete | #29 |
| 4 | Dashboard: item CRUD, TOTP + ring, generator, safe clipboard | ✅ complete | #31 |
| 5a | Desktop: auto-lock (session/suspend/display/idle), capture protection, tray, single-instance | ✅ complete | #32 |
| 5b | Desktop: Spotlight overlay + `Ctrl+Alt+Space`, window-context pre-selection (auto-type moves to 7b) | ✅ complete | #38 |
| 4b | Folders: create / rename / delete, assign items, sidebar filter | ✅ complete | #37 |
| 4c | Attachments as AEAD-sealed sidecar files (#5) | ✅ complete | #39 |
| 6a | Encrypted `.shushbackup` export (vault or separate credentials), import preview, merge / clean restore | ✅ complete | #34 |
| 6b | CSV migration (Bitwarden / 1Password / KeePass / Chrome / Firefox) with conflict handling | ✅ complete | #35 |
| 7a | First-run onboarding: browser detection (folder existence only) + guided CSV import (#17) | ✅ complete | #36 |
| 7b | Native messaging host + extension with one-time-code pairing (#16), extension-verified auto-type | 🔨 in progress (steps 1-5, 7 done; 6 built, E2E pending), [plan](#phase-7b-plan) | #50 |
| 8 | Deniable duress vault (#8), on-demand PAKE LAN sync (#18), air-gapped mode (#25) | 🔨 8a duress vault done, [plan](#phase-8-plan) | |

Not a phase: the punk industrial UI redesign and the liner-notes site (branch `design/punk-industrial`) are
verified with a 17-view CDP screenshot audit and the 5b and 7a scripts; see `testing/design-audit/`.

## Owner decisions (2026-11-07)

1. **Hotkey (#14):** `Ctrl+Alt+Space` (not the spec's `Alt+Shift+S`).
2. **Auto-type (#13/#14):** only into sites verified by the browser extension; window titles are
   never used to auto-type (they may still pre-select a search result).
3. **Native messaging (#16):** one-time pairing code shown in shush; the automatic
   "try archived password" fallback is dropped.
4. **Attachments (#5):** separately AEAD-sealed sidecar files beside the vault.
5. **LAN sync (#18):** on-demand, time-boxed pairing with a PAKE one-time code; no always-on mDNS.
6. **Duress vault (#8):** undetectable: fixed-size padded slots, constant-work unlock.
7. **Recovery Kit (#27):** in-window render and direct print (`window.print()`), never write intermediate PDF/HTML to disk by default (avoids unallocated cluster / shadow copy / cloud sync residue); handwritten master password field is an explicit opt-in with a single-point-of-compromise warning (safe-deposit box use case); never include key material.

## Order of remaining work

~~5b Spotlight~~ → ~~4c attachments~~ → 7b native messaging + extension (then auto-type) →
8 duress vault → 8 LAN sync → 8 air-gapped mode (with the first network feature).

## Phase 7b plan

**Goal:** a browser extension can list and fill logins for the tab it is on, and can offer to save
new ones, through a paired, authenticated channel to the running shush. Nothing is filled or saved
without a user action, and every origin decision is made in Rust.

### Architecture

```
extension (MV3)                    shush-host.exe                     shush.exe (main instance)
service worker  ──stdio, 4-byte──►  thin relay, no vault, no UI  ──named pipe──►  vault state, origin
content script     LE length + JSON  verifies pipe server PID/path    per-user DACL     checks, pairing,
                                                                     FIRST_PIPE_INSTANCE  approvals in UI
```

- **Separate host binary.** Browsers start the host as a new process per connection. It cannot be
  `shush.exe`: the single-instance plugin would hand it to the running app and exit, breaking stdio,
  and a second process must never open the vault (#9). `shush-host.exe` is a small extra `[[bin]]`
  in `src-tauri` with no Tauri, no WebView and no vault code.
- **The main instance is the only writer.** The host relays bytes; saves go through the same
  transactional path as the UI.
- **Pipe.** `\\.\pipe\shush-<user SID>`, created by the main instance with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL granting only the current user. If creation fails
  because the name is taken, shush treats it as squatting: no pipe, and a warning in the UI.
  The host checks `GetNamedPipeServerProcessId` resolves to `shush.exe` in its own install folder;
  the server checks the client is `shush-host.exe` from the same folder.
- **Registration.** Per-user, no admin: `HKCU\Software\{Google\Chrome, Microsoft\Edge,
  Mozilla}\NativeMessagingHosts\com.shush.vault` → a manifest whose `allowed_origins` /
  `allowed_extensions` pins the shush extension id (stable id from the manifest `key`). Written by
  a Settings toggle, removed on uninstall.

### Protocol (v1)

All requests carry `v`, a request id and, after pairing, `mac = HMAC-SHA256(pair_key, counter ‖
body)` with a strictly increasing counter (replays rejected).

| Request | Answer | Rules |
|---|---|---|
| `hello` | `{locked, paired, version}` | No secrets. Works unpaired. |
| `pair {ext_nonce, proof}` | `{pair_id}` | `proof = HMAC(code, ext_nonce ‖ host_nonce)`. The code is shown in shush after *Settings → Pair browser*: 8 Base32 characters, 2 minutes, 3 attempts, one use. Then both sides hold `pair_key = HKDF(code, nonces)`. |
| `match {tab_origin}` | `[{id, title, username}]` | Exact origin match in Rust against the item URL (scheme + host + port; subdomains only if the item opts in). No passwords. |
| `fill {id, tab_origin}` | `{username, password, totp?}` | Vault unlocked, origin re-checked, request from a user gesture in the extension. Archived passwords are never returned (owner decision 3). |
| `save {tab_origin, username, password}` | `{queued}` | Goes to an approval list in shush. Nothing is written until the user approves in the app. |
| `revoke` | `{}` | Deletes the pairing on both sides. |

Revocation and the paired-browser list live in *Settings → Browsers*. Pairings are stored in the
vault (encrypted), so a restored backup brings them back only with the vault.

### Extension-verified auto-type

Auto-type is a fill done by the extension, never `SendInput`. When Quick search is opened over a
browser window and the user presses `Ctrl+Shift+Enter`, shush asks the paired extension for the
active tab's origin (from the tabs API, not the window title). If it matches the item, the content
script fills the fields; otherwise nothing is typed and Quick search says why. This removes the
focus race, keyboard-layout and UIPI problems of #13. Non-browser auto-type stays out of scope.

### Steps

1. ✅ **Vault lock file and single writer** (#50: `vault/lock.rs`, save-time fingerprint check). `LockFileEx` on `vault.shush.lock` while unlocked; a
   second process that somehow opens the vault fails cleanly (#9). Unit test with two handles.
2. ✅ **Pipe server** (`os/pipe.rs`; rate limit and app wiring still open) in the main instance: DACL, first-instance flag, squat detection, PID and path
   checks, framing, request size cap (64 KiB) and per-connection rate limit. Rust tests over a real
   pipe.
3. ✅ **`shush-host.exe`** (#51: `src/bin/shush-host.rs`, `bridge/relay.rs`; bundling beside `shush.exe` still open): stdio framing (4-byte little-endian length, 1 MiB cap for host → browser),
   relay, exits when either side closes. Tests feed it framed stdin.
4. ✅ **Protocol and origin matching** (`bridge/`; pairings not yet persisted in the vault) in Rust: `match`, `fill`, `save`, `revoke`, HMAC counter,
   origin normalization (IDNA, default ports, trailing dots). Table-driven tests including
   look-alike and subdomain cases.
5. **Pairing UI** in shush: *Pair browser* shows the code with a countdown; paired browsers list
   with revoke; save-approval list with approve / reject.
6. **MV3 extension** (`extension/`): service worker owns the port and pairing secret; content
   script detects login forms and shows a shush button; popup for pairing and status. No remote
   code, no network permission, minimal host permissions.
7. **Registration**: Settings toggle writes and removes the three HKCU keys and manifests.
8. **Auto-type** via the extension as described above.
9. **E2E** `docs/testing/phase7b/`: Edge launched with `--load-extension` against a local test
   page, driven over CDP (no OS input), plus the main app over CDP.

### Acceptance criteria

- [ ] Pairing succeeds with the code shown in shush; a wrong code fails, three wrong codes or 2
      minutes void it, and a used code cannot be reused.
- [ ] An unpaired or revoked extension gets `hello` only; every other request is refused.
- [ ] A replayed request (same counter) is refused.
- [ ] `match` on `https://github.com` lists the GitHub login; on `https://github.com.evil.test`
      and `http://github.com` it lists nothing.
- [ ] `fill` returns nothing while locked, for a mismatched origin, or for an archived password.
- [ ] `save` never changes the vault until the user approves it in shush; approval goes through
      the normal transactional save, exactly like an edit in the UI.
- [ ] With the pipe name pre-created by another process, shush refuses to serve and says so.
- [ ] `shush-host.exe` run outside a browser and talking to a pipe not owned by `shush.exe`
      refuses to relay.
- [ ] Quick search auto-type fills only when the extension reports a matching tab origin; a
      window title alone never fills.
- [ ] Registry keys are created and removed by the Settings toggle, under HKCU only.
- [ ] `cargo test`, clippy `-D warnings`, `svelte-check`, build, and the phase 7b CDP script pass;
      PR merged.

## Phase 8 plan

Owner order: duress vault → LAN sync → air-gapped mode (lands with the first network feature).

### 8a. Deniable duress vault (#8)

- **Format v2 with fixed slots.** Every vault has N = 2 payload slots of one fixed size, written in
  full on every save; an unused slot is random bytes. One salt and one Argon2id run per unlock,
  then HKDF per slot index and a canary trial on **every** slot, so the real password and the
  duress password cost the same work and time.
- **Saves.** The open slot is re-sealed; the other slot is rewritten unchanged, byte for byte,
  without being readable. Both slots get fresh-looking framing on every write.
- **Attachments.** Sidecar blob counts would reveal hidden items. Owner decision (2026-11-08):
  disable attachments while a duress slot exists; the decoy starts empty.
- **Migration.** v1 → v2 on the first save after an explicit upgrade prompt (#26), keeping v1 as
  `.bak`.
- **Accept when:** a v2 file with and without a duress slot is indistinguishable by size, structure
  and unlock timing (statistical test over many unlocks); the duress password opens the decoy with
  no visual difference; saving from either slot leaves the other bit-identical.

### 8b. On-demand LAN sync (#18, #19)

- **Design:** [`docs/spec/lan-sync.md`](spec/lan-sync.md) (normative).
- **Pairing.** *Sync → Pair device* opens a 2-minute window. Discovery is mDNS only inside that
  window, or manual address entry; nothing is advertised otherwise. Pairing runs SPAKE2 over a
  one-time code shown on one device and typed on the other, keying a Noise `XXpsk3` handshake;
  then both pin each other's static key.
- **Transport.** Noise XX (`snow`) with pinned static keys; peers can be revoked.
- **Merge.** Needs an authenticated generation counter in the header (#9) before any two vaults
  are merged. Tombstones, bounded history and the no-wall-clock rules are in place (#19); the
  merge orders edits with the hybrid logical clock set in `master-specification.md` §9.2.
- **Accept when:** a MITM without the code cannot complete pairing (test with a relaying peer);
  revoked peers are refused; deletes propagate and do not resurrect; no mDNS traffic outside the
  pairing window (packet capture).

### 8c. Air-gapped mode (#25)

- One Rust-side network gate that every socket, HTTP and mDNS path must pass. **Default on**: every
  network feature is opt-in. Native messaging is local stdio and a pipe, so it stays available.
- A build without the `network` cargo feature links no socket code at all.
- **Accept when:** with air-gapped on, sync controls are disabled with an explanation and a test
  harness confirms no socket is opened; the no-`network` build has no networking symbols.
