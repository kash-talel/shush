//! The pipe server that connects the browser relay to the [`Bridge`] (issue #52).
//!
//! One background thread accepts connections on `\\.\pipe\shush-<SID>`; each
//! connection gets its own short-lived thread. Before a single byte is read the
//! client must be `shush-host.exe` from shush's own install folder, and each
//! connection is rate limited and the number of live connections capped.
//! Requests run under the vault state's lock so that the vault read, the
//! answer and the persisting of pairing counters are one step relative to
//! `lock()`.

use std::collections::VecDeque;
use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use super::frame::{read_frame, write_frame, MAX_REQUEST, MAX_TO_BROWSER};
use super::protocol::Bridge;
use super::state::{BridgeState, Serving};
use crate::os::pipe::{is_sibling_exe, pipe_name, PipeConn, PipeError, PipeListener};
use crate::vault::state::{Unlocked, VaultState};
use crate::vault::VaultError;

/// File name of the relay shipped next to shush.
const HOST_EXE: &str = "shush-host.exe";
/// Most requests one connection may send per [`RATE_WINDOW`].
const RATE_LIMIT: usize = 30;
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Most connections served at once; more are dropped unread.
const MAX_CONNECTIONS: usize = 8;

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Sliding-window rate limiter for one connection.
pub struct RateLimit {
    seen: VecDeque<Instant>,
}

impl RateLimit {
    /// A limiter with an empty window.
    pub fn new() -> Self {
        Self {
            seen: VecDeque::new(),
        }
    }

    /// Records a request; `false` if the connection is over its budget.
    pub fn allow(&mut self, now: Instant) -> bool {
        while self
            .seen
            .front()
            .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
        {
            self.seen.pop_front();
        }
        if self.seen.len() >= RATE_LIMIT {
            return false;
        }
        self.seen.push_back(now);
        true
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self::new()
    }
}

/// Starts serving in the background. Records the outcome in [`BridgeState`].
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let state = app.state::<BridgeState>();
        let bound = pipe_name()
            .map_err(PipeError::from)
            .and_then(|n| PipeListener::bind(&n));
        let mut listener = match bound {
            Ok(l) => l,
            Err(PipeError::NameTaken) => {
                state.set_serving(Serving::NameTaken);
                return;
            }
            Err(e) => {
                state.set_serving(Serving::Failed(e.to_string()));
                return;
            }
        };
        state.set_serving(Serving::Yes);
        loop {
            match listener.accept() {
                Ok(conn) => {
                    if LIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        LIVE.fetch_sub(1, Ordering::SeqCst);
                        continue; // dropped: closes the pipe
                    }
                    let app = app.clone();
                    std::thread::spawn(move || {
                        serve(&app, conn);
                        LIVE.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    });
}

fn serve(app: &AppHandle, conn: PipeConn) {
    let Ok(own) = std::env::current_exe() else {
        return;
    };
    let allowed = conn
        .client_image()
        .is_ok_and(|peer| is_sibling_exe(&peer, &own, HOST_EXE));
    if !allowed {
        return;
    }
    let mut pipe: File = conn.pipe;
    let mut limit = RateLimit::new();
    while let Ok(Some(raw)) = read_frame(&mut pipe, MAX_REQUEST) {
        if !limit.allow(Instant::now()) {
            return;
        }
        let answer = process(app, &raw);
        if write_frame(&mut pipe, &answer, MAX_TO_BROWSER).is_err() {
            return;
        }
    }
}

/// Runs one request against the live vault (or the locked state).
pub fn process(app: &AppHandle, raw: &[u8]) -> Zeroizing<Vec<u8>> {
    let vault = app.state::<VaultState>();
    let bridge = app.state::<BridgeState>();
    let now = Instant::now();
    let answered = vault.with_mut(|u| {
        let mut b = bridge.bridge();
        b.load_pairings(&u.vault.data().browser_pairings);
        let out = b.handle(raw, Some(u.vault.data()), now);
        if b.take_dirty() {
            persist(&mut b, u);
        }
        out
    });
    match answered {
        Some(out) => out,
        None => bridge.bridge().handle(raw, None, now),
    }
}

/// Saves the bridge's pairings (ids, keys, counters) into the unlocked vault.
/// A read-only vault is not written; the pairing then lasts until lock.
pub fn persist(b: &mut Bridge, u: &mut Unlocked) {
    if u.read_only {
        return;
    }
    let path = u.path.clone();
    let stored = b.export_pairings();
    let saved = u.vault.modify::<_, VaultError>(&path, |d| {
        d.browser_pairings = stored;
        Ok(())
    });
    if saved.is_err() {
        b.mark_dirty(); // retried with the next request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_is_a_sliding_window() {
        let mut r = RateLimit::new();
        let t = Instant::now();
        for _ in 0..RATE_LIMIT {
            assert!(r.allow(t));
        }
        assert!(!r.allow(t));
        assert!(r.allow(t + RATE_WINDOW));
    }
}
