//! Vault format v3: two fixed-size slots (deniable duress vault, issue #8).
//!
//! ```text
//! | 0x00 | 0x35 | fixed header: MAGIC, VERSION=3, SUITE, FLAGS, Argon2 params, KDF_SALT |
//! | 0x35 | S    | slot 0 |
//! | +S   | S    | slot 1 |
//!
//! slot (S bytes) = SLOT_NONCE (nonce_len) ‖ SLOT_HEADER_CT (93) ‖ PAYLOAD_CT (L) ‖ fill
//! SLOT_HEADER    = CANARY "SHUSH_CANARY_V001" ‖ SAVE_ID (32) ‖ PAYLOAD_NONCE (24, zero-padded) ‖ L (u32)
//! ```
//!
//! Every vault has exactly two slots of the same size `S = (file_len - 0x35) / 2`
//! (no length field: a tampered length moves the second slot and fails it). The
//! slot header is sealed under the canary key and the payload under the per-save
//! key (format v2, issue #2) of the credentials that own the slot. An unused slot
//! is uniformly random bytes, which is indistinguishable from AEAD output, and
//! `fill` is random too. So the file looks the same whether or not a second
//! (duress) vault exists.
//!
//! Unlock runs Argon2id once (one salt, one set of parameters for both slots),
//! then tries the slot header of **both** slots, so the real password and the
//! duress password cost exactly the same work. A save re-seals its own slot and
//! copies the other slot byte for byte: it cannot read it, and must not change it.
//!
//! `S` is at least [`MIN_SLOT_LEN`] (1 MiB holds thousands of items), so for most
//! vaults it never changes. It only grows (PADMÉ-rounded) when a payload does not
//! fit, by appending random bytes to the other slot; it never shrinks.

use crate::crypto::cipher::{self, CANARY_PLAINTEXT, MAX_NONCE_LEN, SAVE_ID_LEN, TAG_LEN};
use crate::crypto::{fill_random, CipherSuite, CryptoError, SecretBytes, VaultKeys};

use super::container::{
    read_version, FileKind, Header, FIXED_LEN, FORMAT_VERSION, MAX_PAYLOAD_LEN,
};
use super::{padme, VaultError};

/// Number of slots in every v3 vault.
pub const SLOT_COUNT: usize = 2;
/// Smallest slot, so typical vaults never change size.
pub const MIN_SLOT_LEN: usize = 1 << 20;
const SLOT_HEADER_PLAIN_LEN: usize = CANARY_PLAINTEXT.len() + SAVE_ID_LEN + MAX_NONCE_LEN + 4;
/// Sealed slot header length.
pub const SLOT_HEADER_CT_LEN: usize = SLOT_HEADER_PLAIN_LEN + TAG_LEN;
/// Largest slot accepted when reading.
pub const MAX_SLOT_LEN: usize = MAX_NONCE_LEN + SLOT_HEADER_CT_LEN + MAX_PAYLOAD_LEN as usize;
/// Largest v3 file accepted when reading.
pub const MAX_FILE_LEN: u64 = (FIXED_LEN + SLOT_COUNT * MAX_SLOT_LEN) as u64;

fn overhead(suite: CipherSuite) -> usize {
    suite.nonce_len() + SLOT_HEADER_CT_LEN
}

fn header_aad(fixed: &[u8], index: usize) -> Vec<u8> {
    let mut aad = Vec::with_capacity(fixed.len() + 2);
    aad.extend_from_slice(fixed);
    aad.extend_from_slice(&[b'H', index as u8]);
    aad
}

fn payload_aad(fixed: &[u8], index: usize, payload_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(fixed.len() + 6);
    aad.extend_from_slice(fixed);
    aad.extend_from_slice(&[b'P', index as u8]);
    aad.extend_from_slice(&payload_len.to_le_bytes());
    aad
}

fn random_bytes(n: usize) -> Result<Vec<u8>, VaultError> {
    let mut v = vec![0u8; n];
    fill_random(&mut v)?;
    Ok(v)
}

/// Seals `plaintext` as the content of slot `index` (no fill): nonce, sealed
/// slot header and payload. Fresh nonces and `SAVE_ID` on every call.
pub fn seal_slot(
    header: &Header,
    keys: &VaultKeys,
    index: usize,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    debug_assert!(index < SLOT_COUNT);
    let payload_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .filter(|&n| n <= MAX_PAYLOAD_LEN as usize)
        .ok_or(VaultError::TooLarge)? as u32;
    let fixed = header.fixed_bytes(FORMAT_VERSION);
    let suite = header.suite;
    let payload = cipher::seal_payload(
        suite,
        keys,
        &payload_aad(&fixed, index, payload_len),
        plaintext,
    )?;

    let mut slot_header = Vec::with_capacity(SLOT_HEADER_PLAIN_LEN);
    slot_header.extend_from_slice(CANARY_PLAINTEXT);
    slot_header.extend_from_slice(&payload.save_id);
    let mut nonce = [0u8; MAX_NONCE_LEN];
    nonce[..payload.sealed.nonce.len()].copy_from_slice(&payload.sealed.nonce);
    slot_header.extend_from_slice(&nonce);
    slot_header.extend_from_slice(&payload_len.to_le_bytes());
    let sealed_header = cipher::seal(
        suite,
        keys.canary_key(),
        &header_aad(&fixed, index),
        &slot_header,
    )?;

    let mut out = Vec::with_capacity(overhead(suite) + payload_len as usize);
    out.extend_from_slice(&sealed_header.nonce);
    out.extend_from_slice(&sealed_header.ciphertext);
    out.extend_from_slice(&payload.sealed.ciphertext);
    debug_assert_eq!(out.len(), overhead(suite) + payload_len as usize);
    Ok(out)
}

/// The slot size for a file whose slots must hold `needed` bytes (and at
/// least `current`): never shrinks, at least [`MIN_SLOT_LEN`], PADMÉ-rounded.
fn slot_len_for(needed: usize, current: usize) -> usize {
    let grown = if needed <= MIN_SLOT_LEN {
        MIN_SLOT_LEN
    } else {
        padme(needed).min(MAX_SLOT_LEN).max(needed)
    };
    grown.max(current)
}

/// Builds a complete v3 file image: `own` (from [`seal_slot`]) in slot `index`,
/// and `other` copied verbatim into the other slot. Both are extended with
/// random bytes to the common slot size, which is at least `current_len`.
/// `other` may be empty (no other slot yet): it is then all random.
pub fn assemble(
    header: &Header,
    index: usize,
    own: &[u8],
    other: &[u8],
    current_len: usize,
) -> Result<Vec<u8>, VaultError> {
    let len = slot_len_for(own.len().max(other.len()), current_len);
    if len > MAX_SLOT_LEN {
        return Err(VaultError::TooLarge);
    }
    let mut out = Vec::with_capacity(FIXED_LEN + SLOT_COUNT * len);
    out.extend_from_slice(&header.fixed_bytes(FORMAT_VERSION));
    for i in 0..SLOT_COUNT {
        let content = if i == index { own } else { other };
        out.extend_from_slice(content);
        out.extend_from_slice(&random_bytes(len - content.len())?);
    }
    Ok(out)
}

/// Decrypted slot header: where the payload is and how to open it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotHeader {
    save_id: [u8; SAVE_ID_LEN],
    nonce: [u8; MAX_NONCE_LEN],
    payload_len: u32,
}

/// A structurally valid v3 file that has not been decrypted yet.
#[derive(Debug)]
pub struct SlotFile<'a> {
    /// Fixed header fields (authenticated by every slot).
    pub header: Header,
    slot_len: usize,
    bytes: &'a [u8],
}

/// Parses a v3 file image. Needs no key.
pub fn parse(bytes: &[u8]) -> Result<SlotFile<'_>, VaultError> {
    let header = Header::parse(bytes)?;
    let version = read_version(bytes);
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let body = bytes.len() - FIXED_LEN;
    let slot_len = body / SLOT_COUNT;
    if body % SLOT_COUNT != 0 {
        return Err(VaultError::Malformed("slots differ in size"));
    }
    if slot_len < overhead(header.suite) + TAG_LEN {
        return Err(VaultError::Truncated);
    }
    if slot_len > MAX_SLOT_LEN {
        return Err(VaultError::TooLarge);
    }
    Ok(SlotFile {
        header,
        slot_len,
        bytes,
    })
}

impl SlotFile<'_> {
    /// Size of each slot.
    pub fn slot_len(&self) -> usize {
        self.slot_len
    }

    /// The raw bytes of slot `index`.
    pub fn slot(&self, index: usize) -> &[u8] {
        let start = FIXED_LEN + index * self.slot_len;
        &self.bytes[start..start + self.slot_len]
    }

    fn fixed(&self) -> &[u8] {
        &self.bytes[..FIXED_LEN]
    }

    /// Tries `keys` on slot `index`'s header. Any failure to authenticate is
    /// [`CryptoError::WrongCredentials`]: an unused slot is random bytes.
    pub fn open_header(&self, index: usize, keys: &VaultKeys) -> Result<SlotHeader, VaultError> {
        let suite = self.header.suite;
        let nl = suite.nonce_len();
        let slot = self.slot(index);
        let plain = cipher::open(
            suite,
            keys.canary_key(),
            &slot[..nl],
            &header_aad(self.fixed(), index),
            &slot[nl..nl + SLOT_HEADER_CT_LEN],
        )
        .map_err(|e| match e {
            CryptoError::AuthenticationFailed => VaultError::Crypto(CryptoError::WrongCredentials),
            other => other.into(),
        })?;
        let (canary, rest) = plain.split_at(CANARY_PLAINTEXT.len());
        if canary != CANARY_PLAINTEXT {
            return Err(CryptoError::WrongCredentials.into());
        }
        let mut save_id = [0u8; SAVE_ID_LEN];
        save_id.copy_from_slice(&rest[..SAVE_ID_LEN]);
        let mut nonce = [0u8; MAX_NONCE_LEN];
        nonce.copy_from_slice(&rest[SAVE_ID_LEN..SAVE_ID_LEN + MAX_NONCE_LEN]);
        let len_at = SAVE_ID_LEN + MAX_NONCE_LEN;
        let payload_len = u32::from_le_bytes([
            rest[len_at],
            rest[len_at + 1],
            rest[len_at + 2],
            rest[len_at + 3],
        ]);
        // Authenticated, so a violation here is a writer bug, not an attack.
        if nonce[nl..].iter().any(|&b| b != 0) {
            return Err(VaultError::CorruptPayload("nonzero nonce padding"));
        }
        if (payload_len as usize) < TAG_LEN
            || payload_len as usize > self.slot_len - overhead(suite)
        {
            return Err(VaultError::CorruptPayload("payload length out of range"));
        }
        Ok(SlotHeader {
            save_id,
            nonce,
            payload_len,
        })
    }

    /// Tries `keys` on **every** slot (constant work, whichever slot matches)
    /// and returns the first slot they open.
    pub fn find_slot(&self, keys: &VaultKeys) -> Result<(usize, SlotHeader), VaultError> {
        let tries: [Result<SlotHeader, VaultError>; SLOT_COUNT] =
            std::array::from_fn(|i| self.open_header(i, keys));
        let mut first_err = None;
        for (i, t) in tries.into_iter().enumerate() {
            match t {
                Ok(h) => return Ok((i, h)),
                Err(e) => {
                    // Prefer a structural error over "wrong password" if one
                    // slot authenticated but was malformed.
                    if first_err.is_none() || e != CryptoError::WrongCredentials.into() {
                        first_err = Some(e);
                    }
                }
            }
        }
        Err(first_err.unwrap_or(CryptoError::WrongCredentials.into()))
    }

    /// Decrypts slot `index`'s payload. Call [`Self::open_header`] first.
    pub fn open_payload(
        &self,
        index: usize,
        h: &SlotHeader,
        keys: &VaultKeys,
    ) -> Result<SecretBytes, VaultError> {
        let suite = self.header.suite;
        let start = overhead(suite);
        let slot = self.slot(index);
        Ok(cipher::open_payload(
            suite,
            keys,
            Some(&h.save_id),
            &h.nonce[..suite.nonce_len()],
            &payload_aad(self.fixed(), index, h.payload_len),
            &slot[start..start + h.payload_len as usize],
        )?)
    }

    /// Whether this is a vault (not a backup) file.
    pub fn is_vault(&self) -> bool {
        self.header.kind == FileKind::Vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KdfParams, SecretKey, SALT_LEN};

    fn keys(b: u8) -> VaultKeys {
        let mut mk = SecretKey::zeroed();
        mk.as_mut_bytes().fill(b);
        VaultKeys::derive(&mk)
    }

    fn header(suite: CipherSuite) -> Header {
        Header {
            kind: FileKind::Vault,
            suite,
            keyfile_required: false,
            kdf: KdfParams::INTERACTIVE,
            salt: [9u8; SALT_LEN],
        }
    }

    fn open(file: &[u8], k: &VaultKeys) -> Result<(usize, Vec<u8>), VaultError> {
        let f = parse(file)?;
        let (i, h) = f.find_slot(k)?;
        Ok((i, f.open_payload(i, &h, k)?.to_vec()))
    }

    #[test]
    fn roundtrip_in_either_slot_both_suites() {
        let k = keys(1);
        for suite in CipherSuite::ALL {
            let h = header(suite);
            for index in 0..SLOT_COUNT {
                let own = seal_slot(&h, &k, index, b"payload").unwrap();
                let file = assemble(&h, index, &own, &[], 0).unwrap();
                assert_eq!(file.len(), FIXED_LEN + 2 * MIN_SLOT_LEN);
                assert_eq!(&file[5..7], &[3, 0]);
                assert_eq!(open(&file, &k).unwrap(), (index, b"payload".to_vec()));
            }
        }
    }

    #[test]
    fn two_vaults_share_a_file_and_saves_keep_the_other_slot_bit_identical() {
        let (real, decoy) = (keys(2), keys(3));
        let h = header(CipherSuite::XChaCha20Poly1305);
        let real_slot = seal_slot(&h, &real, 1, b"real").unwrap();
        let decoy_slot = seal_slot(&h, &decoy, 0, b"decoy").unwrap();
        let file = assemble(&h, 1, &real_slot, &decoy_slot, 0).unwrap();
        assert_eq!(open(&file, &real).unwrap(), (1, b"real".to_vec()));
        assert_eq!(open(&file, &decoy).unwrap(), (0, b"decoy".to_vec()));
        assert_eq!(
            open(&file, &keys(4)).unwrap_err(),
            VaultError::Crypto(CryptoError::WrongCredentials)
        );

        // A save from the decoy copies the real slot verbatim.
        let f = parse(&file).unwrap();
        let real_bytes = f.slot(1).to_vec();
        let resealed = seal_slot(&h, &decoy, 0, b"decoy edited").unwrap();
        let next = assemble(&h, 0, &resealed, &real_bytes, f.slot_len()).unwrap();
        let g = parse(&next).unwrap();
        assert_eq!(g.slot(1), real_bytes.as_slice());
        assert_ne!(g.slot(0), f.slot(0));
        assert_eq!(open(&next, &real).unwrap(), (1, b"real".to_vec()));
        assert_eq!(open(&next, &decoy).unwrap(), (0, b"decoy edited".to_vec()));
    }

    #[test]
    fn slots_are_bound_to_their_index() {
        // Swapping the slots must not open either one.
        let k = keys(5);
        let h = header(CipherSuite::Aes256Gcm);
        let own = seal_slot(&h, &k, 0, b"x").unwrap();
        let file = assemble(&h, 0, &own, &[], 0).unwrap();
        let f = parse(&file).unwrap();
        let mut swapped = file[..FIXED_LEN].to_vec();
        swapped.extend_from_slice(f.slot(1));
        swapped.extend_from_slice(f.slot(0));
        assert!(open(&swapped, &k).is_err());
    }

    #[test]
    fn growth_extends_the_other_slot_with_random_bytes() {
        let k = keys(6);
        let h = header(CipherSuite::Aes256Gcm);
        let small = assemble(&h, 0, &seal_slot(&h, &k, 0, b"x").unwrap(), &[], 0).unwrap();
        let f = parse(&small).unwrap();
        let other = f.slot(1).to_vec();
        let big_plain = vec![7u8; MIN_SLOT_LEN + 10];
        let big_own = seal_slot(&h, &k, 0, &big_plain).unwrap();
        let big = assemble(&h, 0, &big_own, &other, f.slot_len()).unwrap();
        let g = parse(&big).unwrap();
        assert!(g.slot_len() > MIN_SLOT_LEN);
        assert_eq!(&g.slot(1)[..other.len()], other.as_slice(), "prefix kept");
        assert_eq!(open(&big, &k).unwrap().1, big_plain);

        // It never shrinks back.
        let again = assemble(
            &h,
            0,
            &seal_slot(&h, &k, 0, b"x").unwrap(),
            g.slot(1),
            g.slot_len(),
        )
        .unwrap();
        assert_eq!(again.len(), big.len());
    }

    #[test]
    fn header_and_slot_tampering_is_detected() {
        let k = keys(7);
        for suite in CipherSuite::ALL {
            let h = header(suite);
            let own = seal_slot(&h, &k, 0, b"secret payload").unwrap();
            let used = own.len();
            let file = assemble(&h, 0, &own, &[], 0).unwrap();
            // Every byte of the fixed header and of the used part of the slot.
            for i in (0..FIXED_LEN).chain(FIXED_LEN..FIXED_LEN + used) {
                let mut t = file.clone();
                t[i] ^= 0x01;
                assert!(open(&t, &k).is_err(), "{suite:?}: byte {i:#x} undetected");
            }
            // Fill bytes are not authenticated (they are random padding).
            let mut fill = file.clone();
            fill[FIXED_LEN + used + 5] ^= 1;
            assert!(open(&fill, &k).is_ok());
        }
    }

    #[test]
    fn structural_validation() {
        let k = keys(8);
        let h = header(CipherSuite::Aes256Gcm);
        let file = assemble(&h, 0, &seal_slot(&h, &k, 0, b"x").unwrap(), &[], 0).unwrap();
        let mut odd = file.clone();
        odd.push(0);
        assert_eq!(
            parse(&odd).unwrap_err(),
            VaultError::Malformed("slots differ in size")
        );
        assert_eq!(
            parse(&file[..FIXED_LEN + 20]).unwrap_err(),
            VaultError::Truncated
        );
        let mut v2 = file.clone();
        v2[5] = 2;
        assert_eq!(parse(&v2).unwrap_err(), VaultError::UnsupportedVersion(2));
    }

    #[test]
    fn with_and_without_a_second_vault_look_alike() {
        // Same size, same header, and no fixed structure in either slot.
        let (real, decoy) = (keys(9), keys(10));
        let h = header(CipherSuite::Aes256Gcm);
        let own = seal_slot(&h, &real, 0, b"real").unwrap();
        let alone = assemble(&h, 0, &own, &[], 0).unwrap();
        let with = assemble(&h, 0, &own, &seal_slot(&h, &decoy, 1, b"d").unwrap(), 0).unwrap();
        assert_eq!(alone.len(), with.len());
        assert_eq!(alone[..FIXED_LEN], with[..FIXED_LEN]);
        // Byte-level statistics of the second slot: roughly uniform either way.
        for file in [&alone, &with] {
            let slot = parse(file).unwrap().slot(1).to_vec();
            let mut counts = [0usize; 256];
            for b in &slot {
                counts[*b as usize] += 1;
            }
            let expected = slot.len() as f64 / 256.0;
            let chi2: f64 = counts
                .iter()
                .map(|&c| (c as f64 - expected).powi(2) / expected)
                .sum();
            // 255 degrees of freedom; p < 1e-9 above ~420.
            assert!(chi2 < 420.0, "slot 1 is not uniform: chi2 = {chi2}");
        }
    }
}
