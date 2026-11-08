//! Cross-process exclusive lock on a vault file (issue #9).
//!
//! While a vault is unlocked, shush holds `vault.shush.lock` open with no
//! sharing allowed. A second process (another shush started around the
//! single-instance guard, a future native-messaging host, a sync helper) that
//! tries to open the same vault gets a sharing violation and is refused with
//! [`VaultError::InUse`] instead of loading a snapshot it would later write
//! back over the first process's changes.
//!
//! The handle is opened with `FILE_FLAG_DELETE_ON_CLOSE`, so the lock file
//! disappears when the vault is locked and the OS releases it if shush
//! crashes: a lock can never go stale.
//!
//! Within one process the lock is shared: acquiring a vault this process
//! already holds returns another reference to the same handle, so re-opening
//! the open vault does not lock itself out.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use super::container::sibling;
use super::VaultError;

/// Held while a vault is unlocked; releasing the last reference unlocks the file.
#[derive(Debug, Clone)]
pub struct VaultLock {
    _handle: Arc<File>,
}

fn held() -> &'static Mutex<HashMap<PathBuf, Weak<File>>> {
    static HELD: OnceLock<Mutex<HashMap<PathBuf, Weak<File>>>> = OnceLock::new();
    HELD.get_or_init(Default::default)
}

impl VaultLock {
    /// Takes the exclusive lock for the vault at `vault_path`.
    pub fn acquire(vault_path: &Path) -> Result<Self, VaultError> {
        let lock_path = sibling(vault_path, "lock");
        let mut map = held().lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, w| w.strong_count() > 0);
        if let Some(handle) = map.get(&lock_path).and_then(Weak::upgrade) {
            return Ok(Self { _handle: handle });
        }
        if let Some(dir) = vault_path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let handle = Arc::new(open_exclusive(&lock_path)?);
        map.insert(lock_path, Arc::downgrade(&handle));
        Ok(Self { _handle: handle })
    }
}

#[cfg(windows)]
fn open_exclusive(path: &Path) -> Result<File, VaultError> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => VaultError::InUse,
            // A lock file whose holder is closing it is "delete pending" for
            // an instant; report that as in use rather than as an I/O error.
            Some(ERROR_ACCESS_DENIED) if path.exists() => VaultError::InUse,
            _ => e.into(),
        })
}

#[cfg(not(windows))]
fn open_exclusive(path: &Path) -> Result<File, VaultError> {
    // shush targets Windows; elsewhere (CI, tests) the lock is advisory only.
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_process_shares_and_releases() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.shush");
        let lock_file = sibling(&vault, "lock");
        let a = VaultLock::acquire(&vault).unwrap();
        let b = VaultLock::acquire(&vault).unwrap();
        assert!(lock_file.exists());
        drop(a);
        assert!(lock_file.exists(), "still held by the second reference");
        drop(b);
        #[cfg(windows)]
        assert!(!lock_file.exists(), "deleted when the last reference closes");
        // And it can be taken again.
        VaultLock::acquire(&vault).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn another_opener_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.shush");
        let _held = VaultLock::acquire(&vault).unwrap();
        // Simulate a second process: open the lock file without the
        // in-process registry.
        let err = open_exclusive(&sibling(&vault, "lock")).unwrap_err();
        assert_eq!(err, VaultError::InUse);
    }

    #[test]
    fn creates_missing_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("new").join("v.shush");
        VaultLock::acquire(&vault).unwrap();
    }
}
