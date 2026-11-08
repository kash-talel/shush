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
        match Self::try_acquire(vault_path)? {
            Some(lock) => Ok(lock),
            None => Err(VaultError::Io(std::io::ErrorKind::PermissionDenied)),
        }
    }

    /// Tries to take the exclusive lock for the vault at `vault_path`.
    ///
    /// Returns:
    /// - `Ok(Some(lock))` if the lock was acquired.
    /// - `Ok(None)` if the lock could not be created because the location is
    ///   read-only or access was denied (not a sharing violation, issue #48).
    /// - `Err(VaultError::InUse)` if another process holds the lock.
    /// - `Err(VaultError::Io(...))` for other I/O errors.
    pub fn try_acquire(vault_path: &Path) -> Result<Option<Self>, VaultError> {
        let lock_path = sibling(vault_path, "lock");
        let mut map = held().lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, w| w.strong_count() > 0);
        if let Some(handle) = map.get(&lock_path).and_then(Weak::upgrade) {
            return Ok(Some(Self { _handle: handle }));
        }
        if let Some(dir) = vault_path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Err(e) = std::fs::create_dir_all(dir) {
                if is_read_only_error(&e, &lock_path) {
                    return Ok(None);
                }
                return Err(e.into());
            }
        }
        let handle = match open_exclusive(&lock_path) {
            Ok(f) => Arc::new(f),
            Err(ExclusiveOpenError::InUse) => return Err(VaultError::InUse),
            Err(ExclusiveOpenError::ReadOnly) => return Ok(None),
            Err(ExclusiveOpenError::Io(e)) => return Err(e.into()),
        };
        map.insert(lock_path, Arc::downgrade(&handle));
        Ok(Some(Self { _handle: handle }))
    }
}

#[derive(Debug)]
enum ExclusiveOpenError {
    InUse,
    ReadOnly,
    Io(std::io::Error),
}

fn is_read_only_kind(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

fn is_read_only_error(e: &std::io::Error, path: &Path) -> bool {
    #[cfg(windows)]
    {
        const ERROR_ACCESS_DENIED: i32 = 5;
        const ERROR_WRITE_PROTECT: i32 = 19;
        const ERROR_READ_ONLY_VOLUME: i32 = 4309;
        match e.raw_os_error() {
            Some(ERROR_ACCESS_DENIED) if path.exists() => false,
            Some(ERROR_ACCESS_DENIED | ERROR_WRITE_PROTECT | ERROR_READ_ONLY_VOLUME) => true,
            _ => is_read_only_kind(e),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        is_read_only_kind(e)
    }
}

#[cfg(windows)]
fn open_exclusive(path: &Path) -> Result<File, ExclusiveOpenError> {
    use std::os::windows::fs::OpenOptionsExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_WRITE_PROTECT: i32 = 19;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const ERROR_READ_ONLY_VOLUME: i32 = 4309;

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => ExclusiveOpenError::InUse,
            // A lock file whose holder is closing it is "delete pending" for
            // an instant; report that as in use rather than as an I/O error.
            Some(ERROR_ACCESS_DENIED) if path.exists() => ExclusiveOpenError::InUse,
            Some(ERROR_ACCESS_DENIED | ERROR_WRITE_PROTECT | ERROR_READ_ONLY_VOLUME) => {
                ExclusiveOpenError::ReadOnly
            }
            _ if is_read_only_kind(&e) => ExclusiveOpenError::ReadOnly,
            _ => ExclusiveOpenError::Io(e),
        })
}

#[cfg(not(windows))]
fn open_exclusive(path: &Path) -> Result<File, ExclusiveOpenError> {
    // shush targets Windows; elsewhere (CI, tests) the lock is advisory only.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            if is_read_only_kind(&e) {
                ExclusiveOpenError::ReadOnly
            } else {
                ExclusiveOpenError::Io(e)
            }
        })
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
        assert!(
            !lock_file.exists(),
            "deleted when the last reference closes"
        );
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
        assert!(matches!(err, ExclusiveOpenError::InUse));
    }

    #[test]
    fn try_acquire_writable_returns_some() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.shush");
        let lock = VaultLock::try_acquire(&vault).unwrap();
        assert!(lock.is_some());
    }

    #[test]
    fn try_acquire_returns_none_on_read_only_location() {
        let dir = tempfile::tempdir().unwrap();
        let readonly_vault = dir.path().join("shush_test_ro_vault.shush");

        #[cfg(windows)]
        {
            // Deny write on directory so creating a sibling lock file fails with access denied
            let status = std::process::Command::new("icacls")
                .arg(dir.path())
                .arg("/deny")
                .arg("*S-1-1-0:(W)")
                .status();
            if status.is_err() || !status.unwrap().success() {
                return;
            }
        }
        #[cfg(not(windows))]
        {
            let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
            perms.set_readonly(true);
            let _ = std::fs::set_permissions(dir.path(), perms);
        }

        let res = VaultLock::try_acquire(&readonly_vault).unwrap();
        assert!(res.is_none());
        assert!(VaultLock::acquire(&readonly_vault).is_err());

        #[cfg(windows)]
        {
            let _ = std::process::Command::new("icacls")
                .arg(dir.path())
                .arg("/remove:d")
                .arg("*S-1-1-0")
                .status();
        }
    }

    #[cfg(windows)]
    #[test]
    fn try_acquire_when_in_use_reports_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.shush");
        let _held = VaultLock::acquire(&vault).unwrap();
        // A direct open simulates another process holding the lock file
        let lock_path = sibling(&vault, "lock");
        let err = open_exclusive(&lock_path).unwrap_err();
        assert!(matches!(err, ExclusiveOpenError::InUse));
    }

    #[test]
    fn creates_missing_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("new").join("v.shush");
        VaultLock::acquire(&vault).unwrap();
    }
}
