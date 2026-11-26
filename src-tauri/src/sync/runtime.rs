//! A pairing window at run time (`lan-sync.md` §3, §5): one listener on an
//! ephemeral port, one connection at a time, closed after one success, three
//! failures, two minutes, a cancel, a vault lock, or air-gapped mode coming
//! back on. The optional discovery advertisement lives exactly as long as the
//! window's listener loop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(feature = "network")]
use std::time::Duration;
use std::time::Instant;

use serde::Serialize;
use zeroize::Zeroizing;

use super::window::{Window, WindowState};
#[cfg(feature = "network")]
use {
    super::identity::{fingerprint, Identity},
    super::pairing::{self, PairError, Paired},
    crate::net::{LanListener, NetError, NetGate},
};

/// Longest a single pairing connection may stall on a read or write.
#[cfg(feature = "network")]
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Where an in-flight pairing connection can be shut down from another
/// thread. Once closed it stays closed: a connection registered afterwards
/// is shut down at once, so a cancel cannot miss a connection that is just
/// being set up.
#[derive(Default)]
pub struct ConnSlot(Mutex<(bool, Option<Closer>)>);

type Closer = Box<dyn FnOnce() + Send>;

impl ConnSlot {
    /// Registers the connection's closer (runs it now if already closed).
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn register(&self, closer: Closer) {
        let mut g = lock(&self.0);
        if g.0 {
            drop(g);
            closer();
        } else {
            g.1 = Some(closer);
        }
    }

    /// Forgets the closer once the connection ended.
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn clear(&self) {
        lock(&self.0).1 = None;
    }

    /// Shuts the registered connection down and refuses later ones.
    pub fn close(&self) {
        let c = {
            let mut g = lock(&self.0);
            g.0 = true;
            g.1.take()
        };
        if let Some(c) = c {
            c();
        }
    }
}

/// The open (or just closed) pairing window, as the UI sees it.
struct Active {
    conn: Arc<ConnSlot>,
    code: Zeroizing<String>,
    addresses: Vec<String>,
    advertised: bool,
    window: Arc<Mutex<Window>>,
    cancel: Arc<AtomicBool>,
}

/// What the Sync card shows about the pairing window. The code is included
/// only while the window is open.
#[derive(Debug, Serialize)]
pub struct WindowView {
    /// `XXXX-XXXX` while open.
    pub code: Option<String>,
    /// `ip:port` addresses for manual entry.
    pub addresses: Vec<String>,
    /// Whether the window is advertised on the local network.
    pub advertised: bool,
    /// Seconds until it closes.
    pub seconds_left: u64,
    /// Failed attempts so far (3 close it).
    pub failures: u8,
    /// `open`, `paired`, `too_many_failures`, `expired`, `cancelled` or `failed`.
    pub state: &'static str,
    /// The paired device, once `paired`.
    pub peer_name: Option<String>,
    /// Its fingerprint, once `paired`.
    pub peer_fingerprint: Option<String>,
    /// Why the listener failed, once `failed`.
    pub error: Option<String>,
}

/// Pairing-window state shared by the commands and the listener thread.
#[derive(Default)]
pub struct SyncRuntime {
    active: Mutex<Option<Active>>,
    /// The join (initiator) connection in flight, and its generation.
    join: Mutex<(u64, Arc<ConnSlot>)>,
}

/// One join attempt; `abort_join` (vault lock) invalidates it.
pub struct JoinGuard {
    /// Shut down by `abort_join`.
    pub conn: Arc<ConnSlot>,
    generation: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The handles the listener thread needs.
pub struct WindowHandles {
    /// Shared window rules and state.
    pub window: Arc<Mutex<Window>>,
    /// Set to stop the listener.
    pub cancel: Arc<AtomicBool>,
    /// Shut down on cancel so an in-flight connection ends at once.
    pub conn: Arc<ConnSlot>,
}

impl SyncRuntime {
    /// Registers a new window (cancelling any earlier one) and returns the
    /// handles for its listener thread.
    pub fn begin(
        &self,
        code: Zeroizing<String>,
        addresses: Vec<String>,
        advertised: bool,
    ) -> WindowHandles {
        let window = Arc::new(Mutex::new(Window::new(Instant::now())));
        let cancel = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(ConnSlot::default());
        let mut a = lock(&self.active);
        if let Some(old) = a.take() {
            old.cancel.store(true, Ordering::SeqCst);
            lock(&old.window).close(WindowState::Cancelled);
            old.conn.close();
        }
        *a = Some(Active {
            conn: conn.clone(),
            code,
            addresses,
            advertised,
            window: window.clone(),
            cancel: cancel.clone(),
        });
        WindowHandles {
            window,
            cancel,
            conn,
        }
    }

    /// Closes the window (user cancel or vault lock) and forgets its code.
    pub fn cancel(&self) {
        if let Some(old) = lock(&self.active).take() {
            old.cancel.store(true, Ordering::SeqCst);
            lock(&old.window).close(WindowState::Cancelled);
            old.conn.close();
        }
    }

    /// Starts a join attempt, replacing the record of any earlier one.
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn begin_join(&self) -> JoinGuard {
        let mut j = lock(&self.join);
        j.0 += 1;
        j.1 = Arc::new(ConnSlot::default());
        JoinGuard {
            conn: j.1.clone(),
            generation: j.0,
        }
    }

    /// Vault lock: shuts the in-flight join connection down and makes its
    /// attempt unable to store a peer.
    pub fn abort_join(&self) {
        let mut j = lock(&self.join);
        j.0 += 1;
        let conn = std::mem::take(&mut j.1);
        drop(j);
        conn.close();
    }

    /// Whether `g` is still the live join attempt (no lock since it began).
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn join_is_current(&self, g: &JoinGuard) -> bool {
        lock(&self.join).0 == g.generation
    }

    /// The window for the UI, if one was opened since the last cancel.
    pub fn view(&self) -> Option<WindowView> {
        let now = Instant::now();
        let mut a = lock(&self.active);
        let active = a.as_mut()?;
        let mut w = lock(&active.window);
        let open = w.accepting(now);
        if !open {
            // The code is single-use: wipe it as soon as the window closes.
            active.code = Zeroizing::new(String::new());
        }
        let (state, peer_name, peer_fingerprint, error) = match w.state() {
            WindowState::Open => ("open", None, None, None),
            WindowState::Done { name, fingerprint } => (
                "paired",
                Some(name.clone()),
                Some(fingerprint.clone()),
                None,
            ),
            WindowState::TooManyFailures => ("too_many_failures", None, None, None),
            WindowState::Expired => ("expired", None, None, None),
            WindowState::Cancelled => ("cancelled", None, None, None),
            WindowState::Failed(e) => ("failed", None, None, Some(e.clone())),
        };
        Some(WindowView {
            code: open.then(|| crate::bridge::pairing::format_code(&active.code)),
            addresses: active.addresses.clone(),
            advertised: active.advertised,
            seconds_left: w.seconds_left(now),
            failures: w.failures(),
            state,
            peer_name,
            peer_fingerprint,
            error,
        })
    }
}

/// Runs a pairing window's listener until the window closes. Each accepted
/// connection is handled to the end before the next is accepted. `store`
/// saves a peer (with its address) once its confirmation was decrypted.
#[cfg(feature = "network")]
pub fn run_pairing_window(
    gate: &NetGate,
    listener: LanListener,
    handles: &WindowHandles,
    code: &str,
    id: &Identity,
    my_name: &str,
    mut store: impl FnMut(&Paired, &str) -> Result<(), PairError>,
) {
    let WindowHandles {
        window,
        cancel,
        conn,
    } = handles;
    loop {
        let mut keep = || !cancel.load(Ordering::SeqCst) && lock(window).accepting(Instant::now());
        let mut stream = match listener.accept(gate, &mut keep) {
            Ok(Some(s)) => s,
            Ok(None) => {
                lock(window).close(WindowState::Cancelled);
                return;
            }
            Err(NetError::AirGapped | NetError::NotCompiledIn) => {
                lock(window).close(WindowState::Cancelled);
                return;
            }
            Err(e) => {
                lock(window).close(WindowState::Failed(e.to_string()));
                return;
            }
        };
        let left = lock(window)
            .deadline()
            .saturating_duration_since(Instant::now());
        let timeout = left.clamp(Duration::from_secs(1), CONNECTION_TIMEOUT);
        if stream.set_timeout(timeout).is_err() {
            lock(window).fail();
            continue;
        }
        let peer = stream.peer().to_owned();
        match stream.closer() {
            Ok(c) => conn.register(c),
            Err(_) => {
                lock(window).fail();
                continue;
            }
        }
        let result = pairing::respond(&mut stream, code, id, my_name, |p| {
            // A window cancelled meanwhile (vault lock) must not store anything.
            if cancel.load(Ordering::SeqCst)
                || gate.is_air_gapped()
                || !lock(window).accepting(Instant::now())
            {
                return Err(PairError::StoreFailed);
            }
            store(p, &peer)
        });
        conn.clear();
        drop(stream);
        let mut w = lock(window);
        match result {
            Ok(p) => {
                w.succeed(p.name, fingerprint(&p.public_key));
                return;
            }
            // Air-gapped mode cut the connection (issue #191): not a wrong code.
            Err(_) if gate.is_air_gapped() => {
                w.close(WindowState::Cancelled);
                return;
            }
            Err(_) => w.fail(),
        }
    }
}

#[cfg(all(test, feature = "network"))]
mod tests {
    use super::*;

    fn open_gate() -> NetGate {
        let g = NetGate::default();
        g.set_air_gapped(false);
        g
    }

    /// End to end over real loopback sockets through the gate: three wrong
    /// codes close the window, and the listener is gone afterwards.
    #[test]
    fn three_wrong_codes_close_the_window() {
        let gate = open_gate();
        let rt = SyncRuntime::default();
        let code = pairing::new_code().unwrap();
        let listener = gate.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", listener.port());
        let handles = rt.begin(code.clone(), vec![addr.clone()], false);
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        std::thread::scope(|s| {
            s.spawn(|| {
                run_pairing_window(&gate, listener, &handles, &code, &r, "R", |_, _| {
                    panic!("nothing may be stored")
                })
            });
            let wrong = if code.starts_with('A') {
                "BBBBBBBB"
            } else {
                "AAAAAAAA"
            };
            for _ in 0..3 {
                let mut c = gate.lan_connect(&addr, Duration::from_secs(5)).unwrap();
                c.set_timeout(Duration::from_secs(10)).unwrap();
                let out = pairing::initiate(&mut c, wrong, &i, "I", |_| Ok(()));
                assert_eq!(out, Err(PairError::WrongCode));
            }
        });
        let v = rt.view().unwrap();
        assert_eq!(v.state, "too_many_failures");
        assert_eq!(v.failures, 3);
        assert!(v.code.is_none());
        // The listener was dropped with the window: nobody answers any more.
        assert!(gate.lan_connect(&addr, Duration::from_secs(2)).is_err());
    }

    /// A cancel (vault lock) ends a connection a stalled peer is holding open
    /// well before the 30 s connection timeout (issue #276).
    #[test]
    fn cancel_closes_an_in_flight_connection() {
        let gate = open_gate();
        let rt = SyncRuntime::default();
        let code = pairing::new_code().unwrap();
        let listener = gate.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", listener.port());
        let handles = rt.begin(code.clone(), vec![addr.clone()], false);
        let r = Identity::generate().unwrap();
        let started = Instant::now();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                run_pairing_window(&gate, listener, &handles, &code, &r, "R", |_, _| {
                    panic!("nothing may be stored")
                })
            });
            // Connects, then says nothing: the listener blocks reading.
            let _stalled = gate.lan_connect(&addr, Duration::from_secs(5)).unwrap();
            std::thread::sleep(Duration::from_millis(500));
            assert!(!h.is_finished());
            rt.cancel();
            h.join().unwrap();
        });
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(rt.view().map(|v| v.state), None);
    }

    /// The right code pairs once; the window then closes, so the code cannot
    /// be used again.
    #[test]
    fn right_code_pairs_once() {
        let gate = open_gate();
        let rt = SyncRuntime::default();
        let code = pairing::new_code().unwrap();
        let listener = gate.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", listener.port());
        let handles = rt.begin(code.clone(), vec![], false);
        let r = Identity::generate().unwrap();
        let i = Identity::generate().unwrap();
        let stored = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            s.spawn(|| {
                run_pairing_window(&gate, listener, &handles, &code, &r, "Desktop", |p, a| {
                    lock(&stored).push((p.public_key, a.to_owned()));
                    Ok(())
                })
            });
            let mut c = gate.lan_connect(&addr, Duration::from_secs(5)).unwrap();
            c.set_timeout(Duration::from_secs(10)).unwrap();
            let p =
                pairing::initiate(&mut c, &code.to_lowercase(), &i, "Laptop", |_| Ok(())).unwrap();
            assert_eq!(&p.public_key, r.public());
            assert_eq!(p.name, "Desktop");
        });
        let st = lock(&stored);
        assert_eq!(st.len(), 1);
        assert_eq!(&st[0].0, i.public());
        assert!(st[0].1.starts_with("127.0.0.1:"));
        let v = rt.view().unwrap();
        assert_eq!(v.state, "paired");
        assert_eq!(v.peer_name.as_deref(), Some("Laptop"));
        assert_eq!(v.peer_fingerprint, Some(i.fingerprint()));
        assert!(gate.lan_connect(&addr, Duration::from_secs(2)).is_err());
    }

    /// Cancelling (as a vault lock does) stops the listener and wipes the code.
    #[test]
    fn cancel_stops_the_listener() {
        let gate = open_gate();
        let rt = SyncRuntime::default();
        let listener = gate.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", listener.port());
        let handles = rt.begin(pairing::new_code().unwrap(), vec![], false);
        let r = Identity::generate().unwrap();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                run_pairing_window(
                    &gate,
                    listener,
                    &handles,
                    "ABCDEFGH",
                    &r,
                    "R",
                    |_, _| Ok(()),
                )
            });
            assert_eq!(rt.view().unwrap().state, "open");
            rt.cancel();
            h.join().unwrap();
        });
        assert!(rt.view().is_none());
        assert_eq!(lock(&handles.window).state(), &WindowState::Cancelled);
        assert!(gate.lan_connect(&addr, Duration::from_secs(2)).is_err());
    }

    /// Turning air-gapped mode back on closes an open window.
    #[test]
    fn air_gap_closes_the_window() {
        let gate = open_gate();
        let rt = SyncRuntime::default();
        let listener = gate.lan_listen(true).unwrap();
        let handles = rt.begin(pairing::new_code().unwrap(), vec![], false);
        let r = Identity::generate().unwrap();
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                run_pairing_window(
                    &gate,
                    listener,
                    &handles,
                    "ABCDEFGH",
                    &r,
                    "R",
                    |_, _| Ok(()),
                )
            });
            gate.set_air_gapped(true);
            h.join().unwrap();
        });
        assert_eq!(rt.view().unwrap().state, "cancelled");
        assert_eq!(crate::net::discovery_daemons_live(), 0);
    }
}
