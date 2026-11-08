//! Send files to the Windows Recycle Bin instead of destroying them.
//!
//! Used when a vault is deleted: the files are still encrypted, and a
//! recoverable delete is the last line of defence against a mistaken or
//! malicious deletion.

#![allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.

use std::path::Path;

/// Why a recycle did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecycleError {
    /// The user cancelled Windows' "permanently delete?" prompt (shown when
    /// the drive has no Recycle Bin, e.g. some USB sticks).
    Cancelled,
    /// The shell reported an error code.
    Failed(i32),
}

/// Moves every path in `paths` (files or folders) to the Recycle Bin in one
/// undoable operation. Paths that do not exist must be filtered out first.
#[cfg(windows)]
pub fn recycle(paths: &[&Path]) -> Result<(), RecycleError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{
        SHFileOperationW, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT,
        FOF_WANTNUKEWARNING, FO_DELETE, SHFILEOPSTRUCTW,
    };

    if paths.is_empty() {
        return Ok(());
    }
    // pFrom: NUL-separated absolute paths, terminated by a double NUL.
    let mut from: Vec<u16> = Vec::new();
    for p in paths {
        let abs = std::path::absolute(p).map_err(|_| RecycleError::Failed(-1))?;
        from.extend(abs.as_os_str().encode_wide());
        from.push(0);
    }
    from.push(0);

    let mut op = SHFILEOPSTRUCTW {
        hwnd: 0,
        wFunc: FO_DELETE as _,
        pFrom: from.as_ptr(),
        pTo: std::ptr::null(),
        // ALLOWUNDO = Recycle Bin. WANTNUKEWARNING makes Windows ask before it
        // would permanently delete (no Recycle Bin on that drive) despite
        // NOCONFIRMATION, so nothing is ever destroyed silently.
        fFlags: (FOF_ALLOWUNDO
            | FOF_NOCONFIRMATION
            | FOF_WANTNUKEWARNING
            | FOF_SILENT
            | FOF_NOERRORUI) as _,
        fAnyOperationsAborted: 0,
        hNameMappings: std::ptr::null_mut(),
        lpszProgressTitle: std::ptr::null(),
    };
    // SAFETY: `op` is fully initialised; `from` is double-NUL terminated and
    // outlives the call; pTo / mappings / title are allowed to be null.
    let rc = unsafe { SHFileOperationW(&mut op) };
    if op.fAnyOperationsAborted != 0 {
        return Err(RecycleError::Cancelled);
    }
    if rc != 0 {
        return Err(RecycleError::Failed(rc));
    }
    Ok(())
}

/// Non-Windows builds (tests on CI): plain removal.
#[cfg(not(windows))]
pub fn recycle(paths: &[&Path]) -> Result<(), RecycleError> {
    for p in paths {
        let r = if p.is_dir() {
            std::fs::remove_dir_all(p)
        } else {
            std::fs::remove_file(p)
        };
        r.map_err(|_| RecycleError::Failed(-1))?;
    }
    Ok(())
}
