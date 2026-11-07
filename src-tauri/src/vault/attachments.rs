//! Encrypted file attachments as sidecar blobs (issue #5, owner decision 4).
//!
//! Each attachment lives in its own file next to the vault:
//! `vault.shush.d/<attachment-id>.blob`, so the main payload stays small and
//! adding or removing a file never rewrites every other attachment.
//!
//! Blob layout (little-endian):
//!
//! | Off | Len | Field |
//! |----:|----:|-------|
//! | 0   | 5   | MAGIC `SHATT` |
//! | 5   | 2   | VERSION (1) |
//! | 7   | 1   | CIPHER_SUITE_ID |
//! | 8   | 24  | NONCE (zero-padded) |
//! | 32  | N   | AEAD ciphertext of `u32 len ‖ zstd(file) ‖ zero padding (PADMÉ)` |
//!
//! Key: the vault's HKDF attachment sub-key. AAD: `blob[0..8) ‖ vault salt ‖
//! attachment id`, so a blob cannot be moved to another item, another vault,
//! or have its cipher byte changed. Metadata (name, type, size) lives in the
//! encrypted vault payload; the blob file name is a random UUID.
//!
//! Crash ordering: on add, the blob is written (crash-safely) **before** the
//! metadata is saved; on delete, the metadata goes **first**. A crash can only
//! leave an unreferenced blob, which [`gc_orphans`] removes.

use std::path::{Path, PathBuf};

use base64::Engine;
use zeroize::Zeroizing;

use super::container::{self, sibling};
use super::items::new_id;
use super::models::{now_rfc3339, Attachment, VaultData, VaultItem};
use super::{padme, OpenVault, VaultError};
use crate::crypto::cipher::{self, MAX_NONCE_LEN};
use crate::crypto::{CipherSuite, VaultKeys, SALT_LEN};

/// Largest attachment (spec §5: up to 10 MB).
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
const MAGIC: [u8; 5] = *b"SHATT";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + MAX_NONCE_LEN;
const MIN_PADDED: usize = 4096;

/// Directory holding the blobs of the vault at `vault_path`.
pub fn blob_dir(vault_path: &Path) -> PathBuf {
    sibling(vault_path, "d")
}

/// Only canonical lower-case UUIDs may become file names (no path traversal).
fn valid_id(id: &str) -> bool {
    id.len() == 36
        && id.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
        })
}

/// Path of one blob. Errors for ids that are not canonical UUIDs.
pub fn blob_path(vault_path: &Path, id: &str) -> Result<PathBuf, VaultError> {
    if !valid_id(id) {
        return Err(VaultError::Malformed("invalid attachment id"));
    }
    Ok(blob_dir(vault_path).join(format!("{id}.blob")))
}

fn aad(header: &[u8], salt: &[u8; SALT_LEN], id: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(8 + SALT_LEN + id.len());
    a.extend_from_slice(&header[..8]);
    a.extend_from_slice(salt);
    a.extend_from_slice(id.as_bytes());
    a
}

/// Seals file bytes into a blob image.
pub fn seal_blob(
    keys: &VaultKeys,
    suite: CipherSuite,
    salt: &[u8; SALT_LEN],
    id: &str,
    data: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if data.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::TooLarge);
    }
    let compressed = Zeroizing::new(
        zstd::bulk::compress(data, 3)
            .map_err(|_| VaultError::CorruptPayload("compression failed"))?,
    );
    let total = padme(4 + compressed.len()).max(MIN_PADDED);
    let mut plain = Zeroizing::new(Vec::with_capacity(total));
    plain.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    plain.extend_from_slice(&compressed);
    plain.resize(total, 0);

    let mut header = [0u8; 8];
    header[..5].copy_from_slice(&MAGIC);
    header[5..7].copy_from_slice(&VERSION.to_le_bytes());
    header[7] = suite.id();
    let sealed = cipher::seal(
        suite,
        keys.attachment_key(),
        &aad(&header, salt, id),
        &plain,
    )?;

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.ciphertext.len());
    out.extend_from_slice(&header);
    let mut nonce = [0u8; MAX_NONCE_LEN];
    nonce[..sealed.nonce.len()].copy_from_slice(&sealed.nonce);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

/// Opens a blob image; any tampering, wrong vault or wrong id fails.
pub fn open_blob(
    keys: &VaultKeys,
    salt: &[u8; SALT_LEN],
    id: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if blob.len() < HEADER_LEN || blob[..5] != MAGIC {
        return Err(VaultError::Malformed("not an attachment blob"));
    }
    let version = u16::from_le_bytes([blob[5], blob[6]]);
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let suite = CipherSuite::from_id(blob[7])?;
    let nl = suite.nonce_len();
    if blob[8 + nl..HEADER_LEN].iter().any(|&b| b != 0) {
        return Err(VaultError::Malformed("nonzero nonce padding"));
    }
    let plain = cipher::open(
        suite,
        keys.attachment_key(),
        &blob[8..8 + nl],
        &aad(blob, salt, id),
        &blob[HEADER_LEN..],
    )?;
    let n = plain
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or(VaultError::CorruptPayload("missing length prefix"))?;
    let compressed = plain
        .get(4..4 + n)
        .ok_or(VaultError::CorruptPayload("length out of range"))?;
    let size = zstd::zstd_safe::get_frame_content_size(compressed)
        .ok()
        .flatten()
        .ok_or(VaultError::CorruptPayload(
            "zstd frame without content size",
        ))?;
    if size > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::TooLarge);
    }
    Ok(Zeroizing::new(
        zstd::bulk::decompress(compressed, size as usize)
            .map_err(|_| VaultError::CorruptPayload("decompression failed"))?,
    ))
}

fn attachments_of<'a>(
    data: &'a mut VaultData,
    item_id: &str,
) -> Result<&'a mut Vec<Attachment>, VaultError> {
    data.items
        .iter_mut()
        .find_map(|i| match i {
            VaultItem::Login(l) if l.base.id == item_id => Some(&mut l.base.attachments),
            VaultItem::SecureNote(n) if n.base.id == item_id => Some(&mut n.base.attachments),
            _ => None,
        })
        .ok_or(VaultError::Malformed("item not found"))
}

fn all_attachment_ids(data: &VaultData) -> impl Iterator<Item = &str> {
    data.items.iter().flat_map(|i| {
        let b = match i {
            VaultItem::Login(l) => &l.base,
            VaultItem::SecureNote(n) => &n.base,
        };
        b.attachments.iter().map(|a| a.id.as_str())
    })
}

fn write_blob(
    vault: &OpenVault,
    vault_path: &Path,
    id: &str,
    data: &[u8],
) -> Result<(), VaultError> {
    let h = vault.header();
    let blob = seal_blob(vault.keys(), h.suite, &h.salt, id, data)?;
    let path = blob_path(vault_path, id)?;
    container::write_atomic(&path, &blob, |written| {
        let back = open_blob(vault.keys(), &h.salt, id, written)?;
        if back.as_slice() == data {
            Ok(())
        } else {
            Err(VaultError::WriteVerifyFailed)
        }
    })
}

impl OpenVault {
    /// Adds a file to an item: blob first, then metadata (see module docs).
    pub fn add_attachment(
        &mut self,
        vault_path: &Path,
        item_id: &str,
        filename: &str,
        mime_type: &str,
        data: &[u8],
    ) -> Result<Attachment, VaultError> {
        if data.len() as u64 > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::TooLarge);
        }
        let meta = Attachment {
            id: new_id(),
            filename: filename
                .chars()
                .filter(|c| !c.is_control())
                .take(255)
                .collect(),
            mime_type: mime_type.chars().take(127).collect(),
            size_bytes: data.len() as u64,
            data_base64: String::new(),
            created_at: now_rfc3339(),
        };
        write_blob(self, vault_path, &meta.id, data)?;
        let saved = meta.clone();
        let result = self.modify(vault_path, |d| {
            attachments_of(d, item_id)?.push(saved);
            Ok::<_, VaultError>(())
        });
        if let Err(e) = result {
            let _ = std::fs::remove_file(blob_path(vault_path, &meta.id)?);
            return Err(e);
        }
        Ok(meta)
    }

    /// Decrypts an attachment's bytes.
    pub fn read_attachment(
        &self,
        vault_path: &Path,
        attachment_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if !all_attachment_ids(self.data()).any(|a| a == attachment_id) {
            return Err(VaultError::NotFound);
        }
        let blob = std::fs::read(blob_path(vault_path, attachment_id)?)?;
        open_blob(self.keys(), &self.header().salt, attachment_id, &blob)
    }

    /// Removes an attachment: metadata first, then the blob (best effort).
    pub fn delete_attachment(
        &mut self,
        vault_path: &Path,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(), VaultError> {
        self.modify(vault_path, |d| {
            let list = attachments_of(d, item_id)?;
            let before = list.len();
            list.retain(|a| a.id != attachment_id);
            if list.len() == before {
                return Err(VaultError::NotFound);
            }
            Ok(())
        })?;
        let _ = std::fs::remove_file(blob_path(vault_path, attachment_id)?);
        Ok(())
    }

    /// Fills `data_base64` for every attachment in a copy of the data, for
    /// self-contained `.shushbackup` export.
    pub fn data_with_embedded_attachments(
        &self,
        vault_path: &Path,
    ) -> Result<VaultData, VaultError> {
        let mut data = self.data().clone();
        for item in &mut data.items {
            let b = match item {
                VaultItem::Login(l) => &mut l.base,
                VaultItem::SecureNote(n) => &mut n.base,
            };
            for a in &mut b.attachments {
                let bytes = self.read_attachment(vault_path, &a.id)?;
                a.data_base64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_slice());
            }
        }
        Ok(data)
    }

    /// Writes every embedded attachment in `data` (from a backup) as a blob of
    /// this vault and clears `data_base64`, so the data can be merged/restored.
    pub fn materialize_embedded(
        &self,
        vault_path: &Path,
        data: &mut VaultData,
    ) -> Result<usize, VaultError> {
        let mut written = 0;
        for item in &mut data.items {
            let b = match item {
                VaultItem::Login(l) => &mut l.base,
                VaultItem::SecureNote(n) => &mut n.base,
            };
            for a in &mut b.attachments {
                if a.data_base64.is_empty() {
                    continue;
                }
                let bytes = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(a.data_base64.as_bytes())
                        .map_err(|_| VaultError::CorruptPayload("invalid attachment encoding"))?,
                );
                write_blob(self, vault_path, &a.id, &bytes)?;
                a.size_bytes = bytes.len() as u64;
                a.data_base64.clear();
                written += 1;
            }
        }
        Ok(written)
    }
}

/// Deletes blobs that no attachment references (crash leftovers, deleted
/// items, merge conflicts). Returns how many were removed.
pub fn gc_orphans(vault_path: &Path, data: &VaultData) -> usize {
    let Ok(entries) = std::fs::read_dir(blob_dir(vault_path)) else {
        return 0;
    };
    let live: std::collections::HashSet<&str> = all_attachment_ids(data).collect();
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name.strip_suffix(".blob") else {
            continue;
        };
        if valid_id(id) && !live.contains(id) && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::items::{ItemDraft, ItemKind};
    use crate::vault::{create_vault_file, CreateOptions};

    const FAST: CreateOptions = CreateOptions {
        suite: CipherSuite::XChaCha20Poly1305,
        kdf: KdfParams {
            mem_kib: 1024,
            iterations: 1,
            parallelism: 1,
        },
    };

    fn setup() -> (tempfile::TempDir, PathBuf, OpenVault, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.shush");
        let mut v = create_vault_file(&path, b"pw", None, FAST).unwrap();
        let id = v
            .modify(&path, |d| {
                d.create_item(
                    ItemKind::Login,
                    &ItemDraft {
                        title: "Bank".into(),
                        ..Default::default()
                    },
                )
                .map_err(|_| VaultError::NotFound)
            })
            .unwrap();
        (dir, path, v, id)
    }

    #[test]
    fn add_read_delete_roundtrip() {
        let (_d, path, mut v, item) = setup();
        let data = b"%PDF-1.7 statement".repeat(1000);
        let meta = v
            .add_attachment(&path, &item, "statement.pdf", "application/pdf", &data)
            .unwrap();
        assert_eq!(meta.size_bytes, data.len() as u64);
        let blob_file = blob_path(&path, &meta.id).unwrap();
        let on_disk = std::fs::read(&blob_file).unwrap();
        assert_eq!(&on_disk[..5], b"SHATT");
        assert!(
            !on_disk.windows(8).any(|w| w == b"%PDF-1.7"),
            "plaintext must not reach disk"
        );
        assert_eq!(
            v.read_attachment(&path, &meta.id).unwrap().as_slice(),
            data.as_slice()
        );

        // Metadata persisted in the encrypted vault.
        let reopened = OpenVault::unlock(&std::fs::read(&path).unwrap(), b"pw", None).unwrap();
        assert_eq!(
            reopened
                .read_attachment(&path, &meta.id)
                .unwrap()
                .as_slice(),
            data.as_slice()
        );

        v.delete_attachment(&path, &item, &meta.id).unwrap();
        assert!(!blob_file.exists());
        assert_eq!(
            v.read_attachment(&path, &meta.id).err(),
            Some(VaultError::NotFound)
        );
    }

    #[test]
    fn blob_is_bound_to_vault_id_and_contents() {
        let (_d, path, mut v, item) = setup();
        let a = v
            .add_attachment(&path, &item, "a.txt", "text/plain", b"alpha")
            .unwrap();
        let b = v
            .add_attachment(&path, &item, "b.txt", "text/plain", b"bravo")
            .unwrap();
        // Swap blob files on disk: each must fail to open under the other id.
        let (pa, pb) = (
            blob_path(&path, &a.id).unwrap(),
            blob_path(&path, &b.id).unwrap(),
        );
        let (ba, bb) = (std::fs::read(&pa).unwrap(), std::fs::read(&pb).unwrap());
        std::fs::write(&pa, &bb).unwrap();
        std::fs::write(&pb, &ba).unwrap();
        assert!(v.read_attachment(&path, &a.id).is_err());
        // Every single-byte flip is detected.
        for i in (0..ba.len()).step_by(97) {
            let mut t = ba.clone();
            t[i] ^= 1;
            assert!(
                open_blob(v.keys(), &v.header().salt, &a.id, &t).is_err(),
                "byte {i}"
            );
        }
        // A different vault (different salt + keys) cannot open it.
        let other = OpenVault::create(b"pw", None, FAST).unwrap();
        assert!(open_blob(other.keys(), &other.header().salt, &a.id, &ba).is_err());
    }

    #[test]
    fn size_limit_and_bad_ids() {
        let (_d, path, mut v, item) = setup();
        let big = vec![0u8; MAX_ATTACHMENT_BYTES as usize + 1];
        assert_eq!(
            v.add_attachment(&path, &item, "big", "x", &big).err(),
            Some(VaultError::TooLarge)
        );
        assert!(blob_path(&path, "../../evil").is_err());
        assert!(blob_path(&path, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());
        assert!(v
            .add_attachment(&path, "no-such-item", "f", "x", b"d")
            .is_err());
        assert_eq!(
            std::fs::read_dir(blob_dir(&path))
                .map(|d| d.count())
                .unwrap_or(0),
            0,
            "failed add leaves no blob"
        );
    }

    #[test]
    fn embed_for_backup_then_materialize_into_another_vault() {
        let (_d, path, mut v, item) = setup();
        let meta = v
            .add_attachment(
                &path,
                &item,
                "key.pem",
                "application/x-pem-file",
                b"-----BEGIN KEY-----",
            )
            .unwrap();
        let mut embedded = v.data_with_embedded_attachments(&path).unwrap();
        let VaultItem::Login(l) = &embedded.items[0] else {
            panic!()
        };
        assert!(
            !l.base.attachments[0].data_base64.is_empty(),
            "backup copy embeds the file"
        );

        let dir2 = tempfile::tempdir().unwrap();
        let path2 = dir2.path().join("vault.shush");
        let mut v2 = create_vault_file(&path2, b"pw2", None, FAST).unwrap();
        assert_eq!(v2.materialize_embedded(&path2, &mut embedded).unwrap(), 1);
        v2.modify(&path2, |d| {
            d.items = embedded.items.clone();
            Ok::<_, VaultError>(())
        })
        .unwrap();
        assert_eq!(
            v2.read_attachment(&path2, &meta.id).unwrap().as_slice(),
            b"-----BEGIN KEY-----"
        );
    }

    #[test]
    fn gc_removes_only_unreferenced_blobs() {
        let (_d, path, mut v, item) = setup();
        let keep = v.add_attachment(&path, &item, "k", "x", b"keep").unwrap();
        let orphan = blob_path(&path, &new_id()).unwrap();
        std::fs::write(&orphan, b"leftover").unwrap();
        std::fs::write(blob_dir(&path).join("notes.txt"), b"not ours").unwrap();
        assert_eq!(gc_orphans(&path, v.data()), 1);
        assert!(!orphan.exists());
        assert!(blob_path(&path, &keep.id).unwrap().exists());
        assert!(blob_dir(&path).join("notes.txt").exists());
    }
}
