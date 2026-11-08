//! Memory-scrubbing primitives for secret material (spec §6.1).
//!
//! Scope and limits (see issue #6): these types guarantee that *our* copy of a
//! secret is overwritten when dropped. They cannot scrub copies made by the
//! OS (pagefile, hibernation), by the WebView, or by third-party code that
//! does not zeroize its internal state. Long-lived keys are additionally
//! page-locked by `os::memory::LockedBox`.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length in bytes of every symmetric key in shush (256 bits).
pub const KEY_LEN: usize = 32;

/// Heap buffer for variable-length secrets (passwords, decrypted payloads),
/// wiped on drop.
///
/// Note: growing a `Vec` reallocates and leaves the old allocation unwiped.
/// Allocate with the final capacity up front wherever possible.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// A 256-bit symmetric key, wiped on drop and redacted in `Debug`.
///
/// Intentionally not `Clone`/`Copy`, so key material is never duplicated
/// implicitly.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// An all-zero key, to be filled in place by a KDF so the key never
    /// exists as an unscrubbed temporary on the stack.
    pub(crate) fn zeroed() -> Self {
        Self([0u8; KEY_LEN])
    }

    /// Mutable access for in-place derivation.
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }

    /// Borrows the raw key bytes. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// True if every byte is zero, which means the key was never derived or
    /// has already been wiped. Encrypting with such a key is a bug (issue #10).
    pub(crate) fn is_all_zero(&self) -> bool {
        self.0.iter().fold(0u8, |acc, b| acc | b) == 0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let mut k = SecretKey::zeroed();
        k.as_mut_bytes().fill(0xAB);
        let s = format!("{k:?}");
        assert_eq!(s, "SecretKey([REDACTED])");
        assert!(!s.to_lowercase().contains("ab"));
    }

    #[test]
    fn zeroize_wipes_key() {
        let mut k = SecretKey::zeroed();
        k.as_mut_bytes().fill(0x42);
        assert!(!k.is_all_zero());
        k.zeroize();
        assert!(k.is_all_zero());
    }
}
