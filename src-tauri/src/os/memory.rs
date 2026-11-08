//! Process-level memory hygiene (spec §6.1, issue #6, issue #59).
//!
//! Best effort, not a guarantee:
//! - [`LockedBox`] keeps long-lived key material on its own page-aligned,
//!   `VirtualLock`ed pages, so it is not written to the pagefile while the
//!   vault is unlocked. Hibernation (`hiberfil.sys`) still captures locked
//!   pages; that is out of scope (the vault locks on suspend instead).
//! - [`LockedBytes`] provides page-aligned, `VirtualLock`ed dynamically sized
//!   storage for secret buffers (such as decrypted payloads, JSON representations,
//!   and IPC credentials) up to [`MAX_LOCKED_BYTES`]. All memory is zeroized on drop.
//! - [`harden_process`] raises the working-set quota (`SetProcessWorkingSetSize`),
//!   keeps heap memory out of Windows Error Reporting crash reports, and opts
//!   the executable out of WER uploads.
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

/// Maximum payload size that will be page-locked with `VirtualLock` (32 MiB).
/// Payloads exceeding this cap remain in zeroized memory but are pageable,
/// preventing exhaustion of the working-set quota (issue #59).
pub const MAX_LOCKED_BYTES: usize = 32 * 1024 * 1024;

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

/// A dynamically sized, page-aligned byte buffer that locks its memory
/// with `VirtualLock` (up to [`MAX_LOCKED_BYTES`]) and zeroizes all allocated
/// memory on drop before freeing it (spec §6.1, issue #59).
pub struct LockedBytes {
    ptr: NonNull<u8>,
    len: usize,
    capacity: usize,
    locked: bool,
}

// SAFETY: `LockedBytes` owns its allocation exclusively.
unsafe impl Send for LockedBytes {}
unsafe impl Sync for LockedBytes {}

impl LockedBytes {
    fn alloc_layout(capacity: usize) -> (Layout, usize) {
        let size = capacity.max(PAGE).next_multiple_of(PAGE);
        let layout = Layout::from_size_align(size, PAGE).expect("valid page layout");
        (layout, size)
    }

    /// Creates an empty buffer with zero capacity.
    pub fn empty() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            capacity: 0,
            locked: false,
        }
    }

    /// Allocates page-aligned, locked memory with at least `capacity` bytes.
    pub fn with_capacity(capacity: usize) -> Self {
        if capacity == 0 {
            return Self::empty();
        }
        let (layout, cap) = Self::alloc_layout(capacity);
        // SAFETY: layout has non-zero size and valid page alignment.
        let raw = unsafe { alloc(layout) };
        let Some(ptr) = NonNull::new(raw) else {
            handle_alloc_error(layout);
        };
        // Zero all memory up front so uninitialized capacity never leaks secrets.
        unsafe { ptr.as_ptr().write_bytes(0, cap) };
        let locked = if cap <= MAX_LOCKED_BYTES {
            sys::lock(raw.cast(), cap)
        } else {
            false
        };
        Self {
            ptr,
            len: 0,
            capacity: cap,
            locked,
        }
    }

    /// Creates a `LockedBytes` from an existing `Vec<u8>`, copying into locked memory
    /// and zeroizing the source `Vec`.
    pub fn new(mut v: Vec<u8>) -> Self {
        let mut lb = Self::with_capacity(v.len());
        lb.extend_from_slice(&v);
        v.zeroize();
        lb
    }

    /// Creates a `LockedBytes` by copying from a slice.
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut lb = Self::with_capacity(slice.len());
        lb.extend_from_slice(slice);
        lb
    }

    /// Number of bytes currently written in the buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Total allocated capacity in bytes (always page-aligned).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns `true` if the buffer contains zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether `VirtualLock` succeeded for this buffer.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Borrows the buffer's contents as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        if self.capacity == 0 {
            &[]
        } else {
            // SAFETY: ptr is valid and initialized for `self.len` bytes.
            unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
    }

    /// Borrows the buffer's contents as a mutable byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.capacity == 0 {
            &mut []
        } else {
            // SAFETY: ptr is valid and initialized for `self.len` bytes.
            unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }
    }

    /// Reserves capacity for at least `additional` more bytes.
    pub fn reserve(&mut self, additional: usize) {
        let needed = self.len.checked_add(additional).expect("capacity overflow");
        if needed <= self.capacity {
            return;
        }
        let new_cap = (self.capacity * 2).max(PAGE).max(needed);
        let (new_layout, actual_cap) = Self::alloc_layout(new_cap);
        // SAFETY: layout has non-zero size.
        let raw = unsafe { alloc(new_layout) };
        let Some(new_ptr) = NonNull::new(raw) else {
            handle_alloc_error(new_layout);
        };
        unsafe { new_ptr.as_ptr().write_bytes(0, actual_cap) };
        let new_locked = if actual_cap <= MAX_LOCKED_BYTES {
            sys::lock(raw.cast(), actual_cap)
        } else {
            false
        };

        if self.capacity > 0 {
            // Copy existing bytes to the new locked allocation
            unsafe {
                core::ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr.as_ptr(), self.len);
                // Zeroize entire old buffer before deallocation
                core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity).zeroize();
            }
            if self.locked {
                sys::unlock(self.ptr.as_ptr().cast(), self.capacity);
            }
            let (old_layout, _) = Self::alloc_layout(self.capacity);
            unsafe { dealloc(self.ptr.as_ptr(), old_layout) };
        }

        self.ptr = new_ptr;
        self.capacity = actual_cap;
        self.locked = new_locked;
    }

    /// Appends a single byte to the buffer.
    pub fn push(&mut self, byte: u8) {
        self.reserve(1);
        unsafe {
            self.ptr.as_ptr().add(self.len).write(byte);
        }
        self.len += 1;
    }

    /// Appends a slice of bytes to the buffer.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.reserve(slice.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                slice.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                slice.len(),
            );
        }
        self.len += slice.len();
    }

    /// Resizes the buffer in place so that `len` equals `new_len`.
    /// New bytes are initialized with `value`; truncated bytes are zeroized.
    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len > self.len {
            let additional = new_len - self.len;
            self.reserve(additional);
            unsafe {
                core::ptr::write_bytes(self.ptr.as_ptr().add(self.len), value, additional);
            }
        } else if new_len < self.len {
            // Zeroize truncated portion
            unsafe {
                core::slice::from_raw_parts_mut(self.ptr.as_ptr().add(new_len), self.len - new_len)
                    .zeroize();
            }
        }
        self.len = new_len;
    }

    /// Shortens the buffer, keeping the first `len` elements and zeroizing the rest.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            unsafe {
                core::slice::from_raw_parts_mut(self.ptr.as_ptr().add(len), self.len - len)
                    .zeroize();
            }
            self.len = len;
        }
    }

    /// Clears the buffer, truncating its length to 0 and zeroizing its content.
    pub fn clear(&mut self) {
        self.truncate(0);
    }
}

impl Default for LockedBytes {
    fn default() -> Self {
        Self::empty()
    }
}

impl Clone for LockedBytes {
    fn clone(&self) -> Self {
        Self::from_slice(self.as_slice())
    }
}

impl Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for LockedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for LockedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl std::io::Write for LockedBytes {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Zeroize for LockedBytes {
    fn zeroize(&mut self) {
        if self.capacity > 0 {
            unsafe {
                core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.capacity).zeroize();
            }
            self.len = 0;
        }
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        if self.capacity > 0 {
            let (layout, _) = Self::alloc_layout(self.capacity);
            let p = self.ptr.as_ptr();
            unsafe {
                // Wipe entire capacity so unused padding bytes are also cleared.
                core::slice::from_raw_parts_mut(p, self.capacity).zeroize();
            }
            if self.locked {
                sys::unlock(p.cast(), self.capacity);
            }
            unsafe { dealloc(p, layout) };
        }
    }
}

impl core::fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LockedBytes([REDACTED; {}])", self.len)
    }
}

/// Keeps heap memory out of crash reports, raises working set quota, and opts out of WER uploads.
/// Call once at startup. Failures are ignored: hardening is best effort.
pub fn harden_process() {
    sys::harden_process();
}

/// Scans committed process memory for occurrences of `needle`.
/// Returns the number of occurrences found outside the memory occupied by `needle` itself.
/// Used by memory-hygiene regression tests to verify that secrets do not linger in heap.
pub fn count_occurrences_in_process_memory(needle: &[u8]) -> usize {
    sys::count_occurrences_in_process_memory(needle)
}

/// Wipes an IPC raw body buffer in place before Tauri drops it, eliminating plaintext
/// credentials from intermediate heap buffers (issue #59).
pub fn wipe_ipc_buffer(bytes: &[u8]) {
    if !bytes.is_empty() {
        // SAFETY: caller passes a slice from Tauri's incoming InvokeBody::Raw buffer
        // that will be discarded. We overwrite its contents with zeroes in place.
        unsafe {
            core::slice::from_raw_parts_mut(bytes.as_ptr() as *mut u8, bytes.len()).zeroize();
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::PAGE;
    use windows_sys::Win32::System::ErrorReporting::{
        WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
    };
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};

    pub fn lock(p: *const core::ffi::c_void, len: usize) -> bool {
        // SAFETY: [p, p+len) is a live allocation owned by the caller.
        if unsafe { VirtualLock(p, len) != 0 } {
            return true;
        }
        // If VirtualLock failed (working set quota), try raising working set size and retry
        let h = unsafe { GetCurrentProcess() };
        let min_ws = (len + 32 * 1024 * 1024).next_multiple_of(PAGE);
        let max_ws = min_ws * 4;
        unsafe {
            SetProcessWorkingSetSize(h, min_ws, max_ws);
            VirtualLock(p, len) != 0
        }
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
        // Raise working-set quota so VirtualLock can lock payloads up to 32 MiB.
        let h = unsafe { GetCurrentProcess() };
        unsafe {
            SetProcessWorkingSetSize(h, 32 * 1024 * 1024, 128 * 1024 * 1024);
        }
    }

    pub fn count_occurrences_in_process_memory(needle: &[u8]) -> usize {
        if needle.is_empty() {
            return 0;
        }
        use core::mem::size_of;
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Memory::{
            VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
            PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let needle_start = needle.as_ptr() as usize;
        let needle_end = needle_start + needle.len();
        let hprocess = unsafe { GetCurrentProcess() };

        let mut count = 0;
        let mut address = 0usize;
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let mut chunk = [0u8; 8192];

        const READABLE: u32 = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;

        while unsafe {
            VirtualQuery(
                address as *const core::ffi::c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } != 0
        {
            let is_accessible = (mbi.State == MEM_COMMIT)
                && ((mbi.Protect & READABLE) != 0)
                && ((mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0);

            if is_accessible && mbi.RegionSize > 0 {
                let base = mbi.BaseAddress as usize;
                let region_end = base + mbi.RegionSize;
                let mut cur = base;

                // Read safely in chunks with overlap so needles spanning chunk boundaries match
                let overlap = needle.len().saturating_sub(1);
                while cur < region_end {
                    let to_read = (region_end - cur).min(chunk.len());
                    let mut bytes_read = 0usize;
                    let ok = unsafe {
                        ReadProcessMemory(
                            hprocess,
                            cur as *const core::ffi::c_void,
                            chunk.as_mut_ptr() as *mut core::ffi::c_void,
                            to_read,
                            &mut bytes_read,
                        )
                    };
                    if ok != 0 && bytes_read >= needle.len() {
                        let valid = &chunk[..bytes_read];
                        for i in 0..=(valid.len() - needle.len()) {
                            let match_addr = cur + i;
                            if match_addr >= needle_start && match_addr < needle_end {
                                continue;
                            }
                            if &valid[i..i + needle.len()] == needle {
                                count += 1;
                            }
                        }
                    }
                    if to_read <= overlap {
                        break;
                    }
                    cur += to_read - overlap;
                }
            }
            let next_addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if next_addr <= address {
                break;
            }
            address = next_addr;
        }
        count
    }
}

#[cfg(not(windows))]
mod sys {
    pub fn lock(_: *const core::ffi::c_void, _: usize) -> bool {
        false
    }
    pub fn unlock(_: *const core::ffi::c_void, _: usize) {}
    pub fn harden_process() {}
    pub fn count_occurrences_in_process_memory(_needle: &[u8]) -> usize {
        0
    }
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

    #[test]
    fn locked_bytes_page_aligned_and_locked() {
        let mut b = LockedBytes::with_capacity(64);
        assert_eq!(b.len(), 0);
        assert!(b.capacity() >= PAGE);
        assert_eq!((b.as_mut_slice().as_ptr() as usize) % PAGE, 0);
        #[cfg(windows)]
        assert!(b.is_locked(), "VirtualLock of one page should succeed");
        b.extend_from_slice(b"hello locked world");
        assert_eq!(&b[..], b"hello locked world");
        assert_eq!(format!("{b:?}"), "LockedBytes([REDACTED; 18])");
    }

    #[test]
    fn locked_bytes_resizing_and_growth() {
        let mut b = LockedBytes::new(b"initial".to_vec());
        assert_eq!(&b[..], b"initial");
        b.extend_from_slice(&[42; 5000]); // crosses page boundary
        assert_eq!(b.len(), 5007);
        assert_eq!(b[0..7], *b"initial");
        assert_eq!(b[7], 42);
        assert_eq!(b[5006], 42);
        #[cfg(windows)]
        assert!(b.is_locked(), "Growth retains VirtualLock");

        b.truncate(4);
        assert_eq!(&b[..], b"init");
        b.clear();
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn memory_scanner_detects_and_verifies_wiping() {
        // High entropy distinct canary token
        let canary = b"__CANARY_SECRET_MEM_HYGIENE_TEST_1234567890__";
        // Initially before allocation, it shouldn't be found
        #[cfg(windows)]
        {
            let count_before = count_occurrences_in_process_memory(canary);
            assert_eq!(
                count_before, 0,
                "Canary should not exist prior to allocation"
            );
        }

        // Allocate canary inside LockedBytes
        {
            let locked = LockedBytes::from_slice(canary);
            #[cfg(windows)]
            {
                let count_during = count_occurrences_in_process_memory(canary);
                assert!(
                    count_during >= 1,
                    "Canary must be detected while active in memory"
                );
            }
            drop(locked);
        }

        // After dropping LockedBytes, canary must be wiped
        #[cfg(windows)]
        {
            let count_after = count_occurrences_in_process_memory(canary);
            assert_eq!(count_after, 0, "Canary must be zeroized after drop");
        }
    }
}
