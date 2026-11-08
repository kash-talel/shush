//! Sequence-aware clipboard with history / cloud exclusion (spec §6.3, issue #12).
//!
//! Copying a secret:
//! 1. places `CF_UNICODETEXT` **plus** the formats Windows honours to keep the
//!    data out of Clipboard History (Win+V), Cloud Clipboard sync and
//!    monitoring clipboard managers;
//! 2. records `GetClipboardSequenceNumber()`;
//! 3. after the timeout (or on vault lock), empties the clipboard **only if the
//!    sequence number is unchanged**, i.e. the user has not copied anything else.

#![allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.

use std::sync::Mutex;
use std::time::Duration;

use zeroize::Zeroizing;

/// Sequence number of the clipboard content shush last placed, if still ours.
static OWNED_SEQUENCE: Mutex<Option<u32>> = Mutex::new(None);

/// Clipboard failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClipboardError {
    /// Another application kept the clipboard open.
    #[error("the clipboard is busy; try again")]
    Busy,
    /// A Win32 call failed.
    #[error("clipboard operation failed")]
    Failed,
    /// Not supported on this platform.
    #[error("clipboard is not supported on this platform")]
    Unsupported,
}

#[cfg(windows)]
mod imp {
    use super::ClipboardError;
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
        RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Holds the clipboard open; closes it on drop.
    struct Open;

    impl Open {
        fn acquire() -> Result<Self, ClipboardError> {
            for attempt in 0..10 {
                // SAFETY: OpenClipboard with a null owner window is valid; it
                // associates the clipboard with the current task.
                if unsafe { OpenClipboard(0) } != 0 {
                    return Ok(Self);
                }
                std::thread::sleep(std::time::Duration::from_millis(15 * (attempt + 1)));
            }
            Err(ClipboardError::Busy)
        }
    }

    impl Drop for Open {
        fn drop(&mut self) {
            // SAFETY: we hold the clipboard open (constructed only after a
            // successful OpenClipboard).
            unsafe { CloseClipboard() };
        }
    }

    /// Copies `bytes` into a movable global block and hands it to the clipboard.
    /// On success the system owns the memory; on failure we free it.
    fn set_data(format: u32, bytes: &[u8]) -> Result<(), ClipboardError> {
        // SAFETY: GlobalAlloc returns a valid handle or null; we check for null.
        let hmem = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) };
        if hmem.is_null() {
            return Err(ClipboardError::Failed);
        }
        // SAFETY: hmem is a live movable block; GlobalLock returns a pointer to
        // at least `bytes.len()` bytes or null.
        let dst = unsafe { GlobalLock(hmem) } as *mut u8;
        if dst.is_null() {
            // SAFETY: we still own hmem.
            unsafe { GlobalFree(hmem) };
            return Err(ClipboardError::Failed);
        }
        // SAFETY: dst points to a block of >= bytes.len() bytes that does not
        // overlap `bytes`; then unlock the block we locked.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
            GlobalUnlock(hmem);
        }
        // SAFETY: the clipboard is open (caller holds `Open`); on success the
        // system takes ownership of hmem.
        if unsafe { SetClipboardData(format, hmem as HANDLE) } == 0 {
            // SAFETY: ownership was not transferred.
            unsafe { GlobalFree(hmem) };
            return Err(ClipboardError::Failed);
        }
        Ok(())
    }

    fn register(name: &str) -> u32 {
        let w = wide(name);
        // SAFETY: `w` is a NUL-terminated UTF-16 string that outlives the call.
        unsafe { RegisterClipboardFormatW(w.as_ptr()) }
    }

    pub(super) fn set_secret(utf16_nul: &[u16]) -> Result<u32, ClipboardError> {
        let open = Open::acquire()?;
        // SAFETY: clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(ClipboardError::Failed);
        }
        if let Err(e) = place_formats(utf16_nul) {
            // A half-formatted secret (text without the exclusion formats) must
            // not stay on the clipboard: it would be untracked and unexcluded.
            // SAFETY: clipboard is still open (we hold `open`).
            unsafe { EmptyClipboard() };
            return Err(e);
        }
        drop(open);
        Ok(sequence())
    }

    /// Writes the secret text and every format that keeps it out of Clipboard
    /// History, Cloud Clipboard and monitoring apps. Caller holds the clipboard.
    fn place_formats(utf16_nul: &[u16]) -> Result<(), ClipboardError> {
        // SAFETY: reinterpreting a &[u16] as bytes is valid (no padding, u8 alignment).
        let text = unsafe {
            std::slice::from_raw_parts(utf16_nul.as_ptr().cast::<u8>(), utf16_nul.len() * 2)
        };
        set_data(u32::from(CF_UNICODETEXT), text)?;

        // Documented by Microsoft (clipboard formats "Cloud Clipboard and
        // Clipboard History Formats"): presence of the first format, or a DWORD 0
        // in the others, excludes the content from history / cloud / monitors.
        let zero = 0u32.to_le_bytes();
        set_data(
            register("ExcludeClipboardContentFromMonitorProcessing"),
            &zero,
        )?;
        set_data(register("CanIncludeInClipboardHistory"), &zero)?;
        set_data(register("CanUploadToCloudClipboard"), &zero)?;
        Ok(())
    }

    pub(super) fn sequence() -> u32 {
        // SAFETY: no preconditions.
        unsafe { GetClipboardSequenceNumber() }
    }

    pub(super) fn clear() -> Result<(), ClipboardError> {
        let _open = Open::acquire()?;
        // SAFETY: clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(ClipboardError::Failed);
        }
        Ok(())
    }
}

/// Copies a secret and schedules its removal after `clear_after`.
#[cfg(windows)]
pub fn copy_secret(secret: &str, clear_after: Duration) -> Result<(), ClipboardError> {
    let utf16 = Zeroizing::new(
        secret
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>(),
    );
    let seq = imp::set_secret(&utf16)?;
    *OWNED_SEQUENCE.lock().unwrap_or_else(|e| e.into_inner()) = Some(seq);
    std::thread::spawn(move || {
        std::thread::sleep(clear_after);
        clear_if_unchanged(seq);
    });
    Ok(())
}

/// Copies a secret (unsupported platform stub).
#[cfg(not(windows))]
pub fn copy_secret(_secret: &str, _clear_after: Duration) -> Result<(), ClipboardError> {
    Err(ClipboardError::Unsupported)
}

/// Empties the clipboard if it still holds the content placed with sequence `seq`.
fn clear_if_unchanged(seq: u32) {
    let mut owned = OWNED_SEQUENCE.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(windows)]
    if *owned == Some(seq) && imp::sequence() == seq && imp::clear().is_ok() {
        *owned = None;
    }
    #[cfg(not(windows))]
    let _ = (&mut owned, seq);
}

/// Called on vault lock / app exit: clears the clipboard if shush's secret is
/// still on it, and never touches anything the user copied since.
pub fn clear_if_ours() {
    let seq = *OWNED_SEQUENCE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(seq) = seq {
        clear_if_unchanged(seq);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// Touches the real system clipboard, so it is opt-in:
    /// `cargo test -- --ignored clipboard`
    #[test]
    #[ignore = "modifies the system clipboard"]
    fn clipboard_roundtrip_and_conditional_clear() {
        copy_secret("hunter2", Duration::from_secs(3600)).unwrap();
        let seq = imp::sequence();
        assert_eq!(*OWNED_SEQUENCE.lock().unwrap(), Some(seq));
        clear_if_ours();
        assert_eq!(*OWNED_SEQUENCE.lock().unwrap(), None);
    }
}
