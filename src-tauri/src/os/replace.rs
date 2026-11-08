//! Atomic file replacement with write-through (issue #11).
//!
//! `std::fs::rename` on Windows does not ask for `MOVEFILE_WRITE_THROUGH`, so a
//! power cut right after the rename can lose the directory-entry update. This
//! module calls `MoveFileExW` directly with that flag.

#![allow(unsafe_code)] // Win32 FFI; the single unsafe block carries a SAFETY comment.

use std::path::Path;

/// Renames `from` over `to`, replacing `to` if it exists, and does not return
/// until the change has been written through to disk.
#[cfg(windows)]
pub fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let wide = |p: &Path| -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let (src, dst) = (wide(from), wide(to));
    // SAFETY: both buffers are NUL-terminated and outlive the call.
    let ok = unsafe {
        MoveFileExW(
            src.as_ptr(),
            dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Non-Windows fallback (tests and tooling only; the app ships on Windows).
#[cfg(not(windows))]
pub fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}
