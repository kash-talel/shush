//! Browser bridge core (issue #16, roadmap Phase 7b).
//!
//! The companion extension talks to a thin native-messaging relay
//! (`shush-host.exe`), which forwards framed requests over an authenticated
//! named pipe ([`crate::os::pipe`]) to the running shush. Everything that
//! decides what a browser may learn lives here, in Rust:
//!
//! - [`frame`]: 4-byte little-endian length + JSON framing with size caps.
//! - [`origin`]: exact origin matching (scheme + host + port, IDNA, default
//!   ports, trailing dots). The extension's own matching is never trusted.
//! - [`pairing`]: SPAKE2 PAKE (Ed25519) pairing with an 8-character one-time
//!   code shown in shush (issue #54), then an HMAC-SHA256 session key with a
//!   strictly increasing counter (replays are refused).
//! - [`protocol`]: `hello` / `pair` / `match` / `fill` / `save` / `revoke`.
//!   Unpaired callers get `hello` and `pair` only. `fill` never returns an
//!   archived password: the spec's automatic "smart fallback" is dropped
//!   (owner decision 3), because a phishing page that always fails the login
//!   could otherwise harvest the whole password history.

pub mod frame;
pub mod origin;
pub mod pairing;
pub mod protocol;
#[cfg(windows)]
pub mod server;
pub mod state;
