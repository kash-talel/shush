//! Thread-safe in-memory vault state (spec §8 `state.rs`, issue #10).
//!
//! Unlocking runs Argon2id for hundreds of milliseconds *outside* the lock.
//! A generation counter makes the transition race-free: `lock()` bumps the
//! generation, and an unlock that started before it is discarded (and wiped)
//! instead of resurrecting an unlocked vault the user just locked.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use super::OpenVault;

/// An unlocked vault and where it lives on disk.
pub struct Unlocked {
    /// Vault file path.
    pub path: PathBuf,
    /// Decrypted vault (wiped on drop).
    pub vault: OpenVault,
}

#[derive(Default)]
struct Inner {
    generation: u64,
    unlocked: Option<Unlocked>,
}

/// Shared vault state, managed by Tauri.
#[derive(Default)]
pub struct VaultState {
    inner: Mutex<Inner>,
}

/// Ticket proving an unlock started at a particular generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockTicket(u64);

/// The unlock lost a race with `lock()`; its result was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superseded;

impl VaultState {
    fn guard(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock must not brick the app; the data is
        // still consistent because every mutation is a single assignment.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Call before starting a slow unlock.
    pub fn begin_unlock(&self) -> UnlockTicket {
        UnlockTicket(self.guard().generation)
    }

    /// Installs an unlocked vault if no `lock()` happened since `ticket`.
    /// Otherwise the vault is dropped (and wiped).
    pub fn finish_unlock(
        &self,
        ticket: UnlockTicket,
        unlocked: Unlocked,
    ) -> Result<(), Superseded> {
        let mut g = self.guard();
        if g.generation != ticket.0 {
            return Err(Superseded);
        }
        g.generation += 1;
        g.unlocked = Some(unlocked);
        Ok(())
    }

    /// Locks immediately: wipes keys and data and invalidates in-flight unlocks.
    pub fn lock(&self) {
        let previous = {
            let mut g = self.guard();
            g.generation += 1;
            g.unlocked.take()
        };
        // Wipe outside the mutex so a large vault doesn't block other callers.
        drop(previous);
    }

    /// Whether a vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.guard().unlocked.is_some()
    }

    /// Runs `f` against the unlocked vault, if any.
    pub fn with<R>(&self, f: impl FnOnce(&Unlocked) -> R) -> Option<R> {
        self.guard().unlocked.as_ref().map(f)
    }

    /// Runs `f` with mutable access while holding the lock, so a mutation and
    /// its save to disk are one atomic step relative to other commands and
    /// to `lock()` (issue #10).
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut Unlocked) -> R) -> Option<R> {
        self.guard().unlocked.as_mut().map(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::CreateOptions;

    fn unlocked() -> Unlocked {
        let opts = CreateOptions {
            kdf: KdfParams {
                mem_kib: 256,
                iterations: 1,
                parallelism: 1,
            },
            ..CreateOptions::default()
        };
        Unlocked {
            path: PathBuf::from("v.shush"),
            vault: OpenVault::create(b"pw", None, opts).unwrap(),
        }
    }

    #[test]
    fn unlock_then_lock() {
        let s = VaultState::default();
        assert!(!s.is_unlocked());
        let t = s.begin_unlock();
        s.finish_unlock(t, unlocked()).unwrap();
        assert!(s.is_unlocked());
        assert_eq!(s.with(|u| u.path.clone()), Some(PathBuf::from("v.shush")));
        s.lock();
        assert!(!s.is_unlocked());
        assert!(s.with(|_| ()).is_none());
    }

    #[test]
    fn lock_during_unlock_wins() {
        let s = VaultState::default();
        let t = s.begin_unlock();
        s.lock(); // user hits Ctrl+L while Argon2 is running
        assert_eq!(s.finish_unlock(t, unlocked()), Err(Superseded));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn stale_ticket_cannot_replace_a_newer_unlock() {
        let s = VaultState::default();
        let old = s.begin_unlock();
        let new = s.begin_unlock();
        s.finish_unlock(new, unlocked()).unwrap();
        assert_eq!(s.finish_unlock(old, unlocked()), Err(Superseded));
    }
}
