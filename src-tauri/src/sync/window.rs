//! Pairing and sync windows (`lan-sync.md` §3, §4): 2 minutes, at most one
//! connection at a time, at most 3 failed attempts, one success. A window
//! also closes on vault lock or when the user cancels.

use std::time::{Duration, Instant};

/// How long a window stays open.
pub const WINDOW_TTL: Duration = Duration::from_secs(120);
/// Failed attempts that close a window.
pub const MAX_FAILURES: u8 = 3;

/// Where a window stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowState {
    /// Waiting for a connection.
    Open,
    /// Paired (or synced) with this device; the window is closed.
    Done {
        /// The peer's name.
        name: String,
        /// The peer's fingerprint.
        fingerprint: String,
    },
    /// Three failed attempts.
    TooManyFailures,
    /// Two minutes passed.
    Expired,
    /// The user cancelled, the vault locked, or air-gapped mode came back on.
    Cancelled,
    /// The listener failed.
    Failed(String),
}

/// The rules of one window.
#[derive(Debug, Clone)]
pub struct Window {
    deadline: Instant,
    failures: u8,
    state: WindowState,
}

impl Window {
    /// A window opened at `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            deadline: now + WINDOW_TTL,
            failures: 0,
            state: WindowState::Open,
        }
    }

    /// The deadline.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Whether another connection may be accepted. Moves an expired window
    /// to [`WindowState::Expired`].
    pub fn accepting(&mut self, now: Instant) -> bool {
        if self.state == WindowState::Open && now >= self.deadline {
            self.state = WindowState::Expired;
        }
        self.state == WindowState::Open
    }

    /// Counts one failed attempt; the third closes the window.
    pub fn fail(&mut self) {
        if self.state != WindowState::Open {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_FAILURES {
            self.state = WindowState::TooManyFailures;
        }
    }

    /// One success closes the window: the code cannot be used again.
    pub fn succeed(&mut self, name: String, fingerprint: String) {
        if self.state == WindowState::Open {
            self.state = WindowState::Done { name, fingerprint };
        }
    }

    /// Closes the window for another reason.
    pub fn close(&mut self, why: WindowState) {
        if self.state == WindowState::Open {
            self.state = why;
        }
    }

    /// Current state.
    pub fn state(&self) -> &WindowState {
        &self.state
    }

    /// Failed attempts so far.
    pub fn failures(&self) -> u8 {
        self.failures
    }

    /// Whole seconds left while open, else 0.
    pub fn seconds_left(&self, now: Instant) -> u64 {
        if self.state != WindowState::Open {
            return 0;
        }
        self.deadline.saturating_duration_since(now).as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_failures_close() {
        let t = Instant::now();
        let mut w = Window::new(t);
        assert!(w.accepting(t));
        w.fail();
        w.fail();
        assert!(w.accepting(t));
        w.fail();
        assert!(!w.accepting(t));
        assert_eq!(w.state(), &WindowState::TooManyFailures);
        assert_eq!(w.seconds_left(t), 0);
    }

    #[test]
    fn expires_after_two_minutes() {
        let t = Instant::now();
        let mut w = Window::new(t);
        assert_eq!(w.seconds_left(t), 120);
        assert!(w.accepting(t + Duration::from_secs(119)));
        assert!(!w.accepting(t + WINDOW_TTL));
        assert_eq!(w.state(), &WindowState::Expired);
    }

    #[test]
    fn one_success_closes_and_sticks() {
        let t = Instant::now();
        let mut w = Window::new(t);
        w.succeed("Laptop".into(), "AAAA".into());
        assert!(!w.accepting(t));
        w.fail();
        w.close(WindowState::Cancelled);
        assert!(matches!(w.state(), WindowState::Done { .. }));
        assert_eq!(w.failures(), 0);
    }
}
