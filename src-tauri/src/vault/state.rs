//! Thread-safe in-memory vault state (spec §8 `state.rs`, issue #10).
//!
//! Unlocking runs Argon2id for hundreds of milliseconds *outside* the lock.
//! A generation counter makes the transition race-free: `lock()` bumps the
//! generation, and an unlock that started before it is discarded (and wiped)
//! instead of resurrecting an unlocked vault the user just locked.
//!
//! Every mutation and its save run inside [`VaultState::with_mut`], so
//! `lock()` (including the suspend and idle paths) waits for an in-flight
//! save to finish and never wipes keys out from under it.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use super::lock::VaultLock;
use super::OpenVault;

/// An unlocked vault and where it lives on disk.
pub struct Unlocked {
    /// Vault file path.
    pub path: PathBuf,
    /// Decrypted vault (wiped on drop).
    pub vault: OpenVault,
    /// Exclusive cross-process lock on the file, released on lock (issue #9).
    /// `None` when opened in read-only mode (issue #48).
    pub lock: Option<VaultLock>,
    /// Whether the vault was opened in read-only mode (issue #48).
    pub read_only: bool,
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
        // A vault whose encryption key was never derived (or was already
        // wiped) must not become the live state (issue #10).
        debug_assert!(
            !unlocked.vault.keys().vault_encryption_key().is_all_zero(),
            "unlocked vault has an all-zero encryption key"
        );
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
        let path = std::env::temp_dir().join("shush-state-test.shush");
        Unlocked {
            lock: Some(VaultLock::acquire(&path).unwrap()),
            path,
            vault: OpenVault::create(b"pw", None, opts).unwrap(),
            read_only: false,
        }
    }

    #[test]
    fn unlock_then_lock() {
        let s = VaultState::default();
        assert!(!s.is_unlocked());
        let t = s.begin_unlock();
        s.finish_unlock(t, unlocked()).unwrap();
        assert!(s.is_unlocked());
        assert!(s
            .with(|u| u.path.ends_with("shush-state-test.shush"))
            .unwrap());
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
    fn lock_waits_for_an_in_flight_mutation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc};

        let s = Arc::new(VaultState::default());
        let t = s.begin_unlock();
        s.finish_unlock(t, unlocked()).unwrap();

        // A mutation (apply + save) is in progress while `lock()` is requested.
        let finished = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = mpsc::channel();
        let writer = {
            let s = Arc::clone(&s);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                s.with_mut(|_| {
                    started_tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    finished.store(true, Ordering::SeqCst);
                    42
                })
            })
        };
        started_rx.recv().unwrap();
        s.lock();
        // `lock()` could only take the state after the mutation released it, so
        // the mutation never observes a wiped key or vault.
        assert!(finished.load(Ordering::SeqCst));
        assert!(!s.is_unlocked());
        assert_eq!(writer.join().unwrap(), Some(42));
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
