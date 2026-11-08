# ADR: LAN sync pairing, transport and discovery

Status: **accepted** (design only; not implemented, Phase 8b). Issue #18.
This document is normative. Where `master-specification.md`, `architecture-plan.md` or
`security-model.md` say anything else about LAN sync pairing, transport or discovery, this
document wins. Merging is out of scope here; it needs #9 and #19 first (see §8).

## Context

The master specification described sync as "mDNS `_shush-sync._tcp` + ephemeral TLS 1.3 +
confirm an identical 6-digit PIN on both screens". That design had three problems:

- **The PIN is grindable.** With self-signed certificates, a PIN computed from the handshake
  (for example `hash(certA ‖ certB)` truncated to 6 digits) is only a 20-bit check. A
  man-in-the-middle generates key pairs until both of its connections show the same PIN, about
  10^6 tries, which takes seconds. A short authentication string is safe only with a commitment
  step (ZRTP-style: each side commits to its key before seeing the other's), and the spec had none.
- **Always-on discovery.** Advertising `_shush-sync._tcp` all the time tells everyone on a café
  or hotel network that this machine runs a password manager, and keeps a listening socket open.
- **No peer lifecycle.** Nothing said what is stored after pairing, where, or how a lost device
  is cut off.

## Decision

### 1. Building blocks

| Part | Choice | Crate |
|---|---|---|
| Pairing | SPAKE2 over Ed25519, one-time code | `spake2` (RustCrypto PAKEs) |
| Channel | Noise `XXpsk3` (pairing) and `XX` (sync), X25519 / ChaCha20-Poly1305 / BLAKE2s | `snow` |
| Discovery | mDNS / DNS-SD, only inside an open window | `mdns-sd` |
| Framing | `u16` big-endian length + Noise message, 65 535 bytes max (the Noise limit) | — |

No TLS and no certificates. Crate versions are pinned exactly, and both `spake2` and `snow` get
known-answer tests in `src-tauri` before any release that enables sync. Neither crate has had an
independent audit; that is accepted for an opt-in, LAN-only feature and stated in the release
notes.

### 2. Sync identity

Each vault has one **sync identity**: an X25519 static key pair generated (OsRng) the first time
the user pairs a device from that vault. The secret is stored inside the encrypted vault payload
(§6), so it exists only while the vault is unlocked, is wiped on lock like every other vault
secret, and is separate per vault and per duress slot (#8). A decoy vault has its own identity
and its own peer list, or none.

The **device fingerprint** shown in the UI is the first 10 bytes of
`BLAKE2s-256("shush-sync-fp-v1" ‖ static_public)`, as 4 groups of 4 Base32 characters (same
alphabet as the pairing code).

### 3. Pairing

Roles: the **responder** shows the code, the **initiator** types it.

1. On the responder, *Sync → Pair device* opens a **pairing window**: 2 minutes, one TCP
   listener on an ephemeral port, at most one connection at a time, at most **3 failed
   attempts**, one success. It shows the code (`XXXX-XXXX`) and the address
   (`192.168.1.20:53124`) for manual entry.
2. The code is 8 characters of RFC 4648 Base32 (40 bits, OsRng), the same alphabet as browser
   pairing. Input is normalized: uppercase, separators and spaces dropped, `0`→`O`, `1`→`I`,
   `8`→`B`.
3. On the initiator, *Sync → Join device* lists windows found over mDNS (§5) or takes a typed
   address, then asks for the code.
4. The initiator connects and the two run, in order:

   ```
   sid   = 16 random bytes, chosen by the responder, sent first in clear
   SPAKE2-Ed25519:  A = initiator, B = responder
                    id_A = "shush-sync-v1/initiator", id_B = "shush-sync-v1/responder"
                    password = normalized code
                    → msgA (I→R), msgB (R→I), both derive K (32 bytes)
   psk   = HKDF-SHA256(ikm = K, salt = sid, info = "shush-sync-psk-v1")
   Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s
         prologue = "shush-sync-pair-v1" ‖ sid ‖ msgA ‖ msgB
         s        = each side's sync identity
   then one transport message each way: { "v": 1, "name": "<device name>" }
   ```

5. If the codes differ, the keys differ: the responder fails to decrypt Noise message 3 and the
   initiator gets no confirmation. Either failure counts as one failed attempt on the responder
   and is reported to both users as "wrong code"; no other detail.
6. **Neither side stores anything** until it has decrypted the other side's confirmation
   message. Then each stores the other's static public key as a pinned peer (§6) and shows
   "Paired with *name* (fingerprint …)". The window closes on success, after 3 failures, after
   2 minutes, on vault lock, or when the user cancels.

**Why this resists a MITM.** SPAKE2 gives an active attacker one guess at the code per protocol
run, and a recorded transcript allows no offline test (unlike the browser pairing proof, #54). A
relaying attacker must run SPAKE2 separately with each side, so it must guess the code; a wrong
guess yields a different `psk` and the Noise handshake fails. The prologue binds the SPAKE2
messages and `sid` into the Noise transcript, so the two runs cannot be spliced. With 40-bit
codes and 3 attempts per window, an attacker wins with probability about 3 / 2^40 per window the
user opens.

### 4. Sync sessions

After pairing, sessions use `Noise_XX_25519_ChaChaPoly_BLAKE2s` with prologue
`"shush-sync-v1"` and the sync identity as the static key. After the handshake, each side looks
up the remote static key in its pinned peers. An unknown or revoked key ends the connection at
once: no payload, no error detail, and the event is logged in the sync screen.

- *Sync now* on a device opens a **sync window** (2 minutes, same listener rules as pairing,
  failed handshakes count toward the 3) and also dials each peer's last-known address.
- If both devices dial each other, the session in which the peer with the lower static public
  key (byte order) is the initiator is kept; the other is closed.
- Every message is a Noise transport message; nonces are Noise's counters, so replays and
  reordering fail decryption. A session ends after 5 minutes or on vault lock.

XX sends the responder's static public key to whoever connects. It is a public key, but it is a
stable identifier, so the listener exists only inside a window.

### 5. Discovery and network exposure

- **Nothing listens and nothing is advertised outside a pairing or sync window.** No background
  listener, no always-on mDNS, no periodic browsing.
- Inside a window, the responder may advertise `_shush-sync._tcp.local` with a random 8-character
  instance name and a random host name (fresh each window), and a TXT record of `v=1` only: no
  user name, computer name or vault id. When the window closes, shush sends the mDNS goodbye
  (TTL 0) and stops the responder.
- *Advertise on the local network* is a sync setting (default **on**). Off means manual
  address entry only, so nothing about shush is ever broadcast.
- If Windows reports the active network profile as **Public**, shush warns before opening a
  window and does not advertise there.
- **Air-gapped mode** (#25) disables all of it: no listener, no mDNS, no outbound connection.
  The sync controls are disabled with an explanation. Every socket and mDNS call goes through the
  single network gate described for #25.

### 6. Stored state

Added to the encrypted vault payload (documented in `docs/FORMAT.md` when implemented):

```json
"sync": {
  "identity": { "secret": "<32 B, base64>", "created_at": "2026-11-08T12:00:00Z" },
  "peers": [
    {
      "id": "<fingerprint>",
      "name": "Laptop",
      "public_key": "<32 B, base64>",
      "paired_at": "2026-11-08T12:00:00Z",
      "last_sync_at": null,
      "last_address": "192.168.1.31:53124"
    }
  ]
}
```

Being in the payload, the peer list is encrypted, authenticated by the vault AEAD and written
by the normal transactional save. `identity.secret` is a `Zeroizing` buffer in memory, like the
other payload secrets.

### 7. Revocation

- *Forget device* removes the peer from the list. Its next handshake fails the pin check (§4).
  If a session with that peer is open, shush first sends `{"v":1,"revoke":true}` so the other side
  also forgets this device; that is a courtesy, not the security mechanism.
- A lost or stolen device must be forgotten on every remaining device. The UI says so, and also
  says that forgetting does not take back the vault copy already on it; the user should consider
  changing the master password and important account passwords.
- *Reset sync identity* generates a new key pair and clears the peer list, which cuts off every
  peer at once. Re-pairing is the only way back in, for a forgotten or reset peer alike.

### 8. Merge (out of scope here)

Inside a session, each side sends its decrypted item set and merges with NDHM
(`master-specification.md` §9.2), then saves under its own keys with the normal save. This needs
an authenticated generation counter (#9) and deletion tombstones with bounded history (#19);
sync is not enabled before both land.

### 9. Memory

The code, the SPAKE2 state, `K`, `psk`, Noise handshake and transport state, and the sync
identity secret live in zeroizing buffers and are dropped when the window or session ends, or on
vault lock, whichever is first.

## Rejected alternatives

- **TLS 1.3 + short PIN from the certificates.** Grindable (see Context).
- **ZRTP-style commitment + 6-digit SAS.** Sound, but both users must compare strings and the
  commitment adds a round trip. A PAKE needs one typed code and lets the code be single-use.
- **Always-on mDNS with a disguised service type.** Any stable service type still fingerprints
  shush and keeps a socket open; windows are simpler and leak less.
- **Noise KK for sessions.** The responder would need to know who is calling before the
  handshake, which means sending a peer id in clear. XX plus a pin check avoids that.

## Acceptance

From `docs/ROADMAP.md` Phase 8b, plus:

- A relaying peer that does not know the code cannot complete pairing.
- A test that records a successful pairing transcript cannot confirm a code guess from it
  offline (no check value derived from the code alone appears on the wire).
- A wrong code fails both sides; 3 failures or 2 minutes close the window; a used code fails.
- A forgotten or reset peer is refused with no payload sent.
- Packet capture shows no mDNS traffic and no listening socket outside a window, and none at all
  with advertising off or in air-gapped mode.
