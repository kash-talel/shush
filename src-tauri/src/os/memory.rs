//! Process-level memory hygiene (spec §6.1, issue #6).
//!
//! Best effort, not a guarantee:
//! - [`LockedBox`] keeps long-lived key material on its own page-aligned,
//!   `VirtualLock`ed pages, so it is not written to the pagefile while the
//!   vault is unlocked. Hibernation (`hiberfil.sys`) still captures locked
//!   pages; that is out of scope (the vault locks on suspend instead).
//! - [`harden_process`] keeps heap memory out of Windows Error Reporting
//!   crash reports and opts the executable out of WER uploads.
//!
//! Neither covers the WebView2 processes, which hold every secret the UI
//! has displayed or the user has typed.

#![allow(unsafe_code)] // Allocator + Win32 FFI; every block carries a SAFETY comment.

use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use zeroize::Zeroize;

/// Page size used for alignment. 4 KiB on every Windows target; a larger
/// real page size only means two boxes may share a page, which is still
/// correct (see [`LockedBox`] drop) but locks slightly less precisely.
const PAGE: usize = 4096;

/// A heap value on its own locked pages, zeroized before it is freed.
///
/// Each box owns whole pages, so unlocking one box on drop never unlocks
/// another box's memory. `T` should be plain data (keys, not `Vec`s): only
/// the inline bytes are locked.
pub struct LockedBox<T: Zeroize> {
    ptr: NonNull<T>,
    locked: bool,
}

// SAFETY: `LockedBox<T>` owns its `T` exclusively, like `Box<T>`.
unsafe impl<T: Zeroize + Send> Send for LockedBox<T> {}
unsafe impl<T: Zeroize + Sync> Sync for LockedBox<T> {}

impl<T: Zeroize> LockedBox<T> {
    fn layout() -> Layout {
        let size = core::mem::size_of::<T>().max(1).next_multiple_of(PAGE);
        let align = core::mem::align_of::<T>().max(PAGE);
        Layout::from_size_align(size, align).expect("valid page layout")
    }

    /// Moves `value` onto locked pages. Prefer passing a zeroed value and
    /// filling it in place through `DerefMut`, so the secret never exists
    /// outside the locked pages.
    pub fn new(value: T) -> Self {
        let layout = Self::layout();
        // SAFETY: layout has non-zero size.
        let raw = unsafe { alloc(layout) } as *mut T;
        let Some(ptr) = NonNull::new(raw) else {
            handle_alloc_error(layout)
        };
        // SAFETY: freshly allocated, correctly aligned for T.
        unsafe { ptr.as_ptr().write(value) };
        let locked = sys::lock(ptr.as_ptr().cast(), layout.size());
        Self { ptr, locked }
    }

    /// Whether `VirtualLock` succeeded. Failure (working-set quota) leaves
    /// the value usable but pageable.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Zeroize> Deref for LockedBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: ptr is valid and initialized for the life of self.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Zeroize> DerefMut for LockedBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: ptr is valid, initialized and uniquely owned.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: Zeroize> Drop for LockedBox<T> {
    fn drop(&mut self) {
        let layout = Self::layout();
        let p = self.ptr.as_ptr();
        // SAFETY: p is valid and initialized; it is never used after this.
        unsafe {
            (*p).zeroize();
            core::ptr::drop_in_place(p);
        }
        if self.locked {
            sys::unlock(p.cast(), layout.size());
        }
        // SAFETY: allocated in `new` with the same layout.
        unsafe { dealloc(p.cast(), layout) };
    }
}

impl<T: Zeroize> core::fmt::Debug for LockedBox<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LockedBox([REDACTED])")
    }
}

/// Keeps heap memory out of crash reports and opts out of WER uploads.
/// Call once at startup. Failures are ignored: hardening is best effort.
pub fn harden_process() {
    sys::harden_process();
}

#[cfg(windows)]
mod sys {
    use windows_sys::Win32::System::ErrorReporting::{
        WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
    };
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    pub fn lock(p: *const core::ffi::c_void, len: usize) -> bool {
        // SAFETY: [p, p+len) is a live allocation owned by the caller.
        unsafe { VirtualLock(p, len) != 0 }
    }

    pub fn unlock(p: *const core::ffi::c_void, len: usize) {
        // SAFETY: same range that was locked.
        unsafe { VirtualUnlock(p, len) };
    }

    pub fn harden_process() {
        // SAFETY: plain flag setter on the current process.
        unsafe { WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP) };
        // Per-user (HKCU) exclusion of this executable name from WER
        // reporting; no elevation needed.
        if let Some(name) = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_owned()))
        {
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
            // SAFETY: NUL-terminated UTF-16 string alive for the call.
            unsafe { WerAddExcludedApplication(wide.as_ptr(), 0) };
        }
    }
}

#[cfg(not(windows))]
mod sys {
    pub fn lock(_: *const core::ffi::c_void, _: usize) -> bool {
        false
    }
    pub fn unlock(_: *const core::ffi::c_void, _: usize) {}
    pub fn harden_process() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Zeroize)]
    struct Keys([u8; 96]);

    impl Default for Keys {
        fn default() -> Self {
            Keys([0; 96])
        }
    }

    #[test]
    fn page_aligned_and_locked() {
        let mut b = LockedBox::new(Keys::default());
        b.0.fill(0x5A);
        assert_eq!(b.0[95], 0x5A);
        assert_eq!((&*b as *const Keys as usize) % PAGE, 0);
        #[cfg(windows)]
        assert!(b.is_locked(), "VirtualLock of one page should succeed");
        assert_eq!(format!("{b:?}"), "LockedBox([REDACTED])");
    }

    #[test]
    fn boxes_do_not_share_pages() {
        let a = LockedBox::new(Keys::default());
        let b = LockedBox::new(Keys::default());
        let (pa, pb) = (&*a as *const Keys as usize, &*b as *const Keys as usize);
        assert!(pa.abs_diff(pb) >= PAGE);
    }

    #[test]
    fn drop_runs_zeroize() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WIPED: AtomicBool = AtomicBool::new(false);
        struct Probe;
        impl Zeroize for Probe {
            fn zeroize(&mut self) {
                WIPED.store(true, Ordering::SeqCst);
            }
        }
        drop(LockedBox::new(Probe));
        assert!(WIPED.load(Ordering::SeqCst));
    }
}
