//! Windows Hello through `KeyCredentialManager` (docs/spec/windows-hello.md
//! section 1, issue #66).
//!
//! One RSA-2048 key pair named [`KEY_NAME`] lives in the user's Hello container
//! (TPM-backed when a TPM is present). Signing prompts for Hello. No CNG
//! key-storage-provider calls, no DPAPI, no `NCRYPT_UI_POLICY`.
//!
//! Every call blocks on a WinRT async operation, so call this module only from
//! a worker thread (the `blocking` helper), never from the UI event loop, and
//! only in response to a user action in shush's own foreground window
//! (spec section 8).
//!
//! Nothing here can be exercised without Hello hardware and a user gesture;
//! the session logic around it is tested in `vault::hello` with a mocked
//! [`HelloSigner`].

use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::Core::{
    AsymmetricAlgorithmNames, AsymmetricKeyAlgorithmProvider, CryptographicEngine,
    CryptographicPublicKeyBlobType,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Storage::Streams::{DataReader, IBuffer};
use zeroize::Zeroizing;

use crate::vault::hello::{HelloSigner, SignError};

/// Name of the Hello key credential.
pub const KEY_NAME: &str = "shush-hello";

/// Whether Windows Hello can be used on this machine. If false, the setting is hidden.
pub fn is_supported() -> bool {
    KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| op.join())
        .unwrap_or(false)
}

/// Creates the Hello key pair (prompts for Hello). An existing key of the same
/// name is kept.
pub fn create_key() -> Result<(), SignError> {
    let r = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(KEY_NAME),
        KeyCredentialCreationOption::FailIfExists,
    )
    .and_then(|op| op.join())
    .map_err(|_| SignError::Failed)?;
    match r.Status().map_err(|_| SignError::Failed)? {
        KeyCredentialStatus::Success | KeyCredentialStatus::CredentialAlreadyExists => Ok(()),
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            Err(SignError::Cancelled)
        }
        _ => Err(SignError::Failed),
    }
}

/// Deletes the Hello key pair. A key that is already gone is not an error.
pub fn delete_key() -> Result<(), SignError> {
    KeyCredentialManager::DeleteAsync(&HSTRING::from(KEY_NAME))
        .and_then(|op| op.join())
        .map_err(|_| SignError::Failed)
}

fn open_key() -> Result<KeyCredential, SignError> {
    let r = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))
        .and_then(|op| op.join())
        .map_err(|_| SignError::Failed)?;
    match r.Status().map_err(|_| SignError::Failed)? {
        KeyCredentialStatus::Success => r.Credential().map_err(|_| SignError::Failed),
        KeyCredentialStatus::NotFound => Err(SignError::KeyMissing),
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            Err(SignError::Cancelled)
        }
        // Enrollment changed or the key is unusable: treat like a missing key.
        _ => Err(SignError::KeyMissing),
    }
}

fn to_buffer(bytes: &[u8]) -> Result<IBuffer, SignError> {
    CryptographicBuffer::CreateFromByteArray(bytes).map_err(|_| SignError::Failed)
}

fn from_buffer(buf: &IBuffer) -> Result<Zeroizing<Vec<u8>>, SignError> {
    let len = buf.Length().map_err(|_| SignError::Failed)? as usize;
    let mut out = Zeroizing::new(vec![0u8; len]);
    let reader = DataReader::FromBuffer(buf).map_err(|_| SignError::Failed)?;
    reader.ReadBytes(&mut out).map_err(|_| SignError::Failed)?;
    Ok(out)
}

/// The real Hello key.
pub struct WinHelloSigner;

impl HelloSigner for WinHelloSigner {
    fn sign(&self, msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignError> {
        let cred = open_key()?;
        let data = to_buffer(msg)?;
        let r = cred
            .RequestSignAsync(&data)
            .and_then(|op| op.join())
            .map_err(|_| SignError::Failed)?;
        match r.Status().map_err(|_| SignError::Failed)? {
            KeyCredentialStatus::Success => {
                from_buffer(&r.Result().map_err(|_| SignError::Failed)?)
            }
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
                Err(SignError::Cancelled)
            }
            KeyCredentialStatus::NotFound => Err(SignError::KeyMissing),
            _ => Err(SignError::Failed),
        }
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let check = || -> windows::core::Result<bool> {
            let cred = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME))?
                .join()?
                .Credential()?;
            let blob = CryptographicPublicKeyBlobType::X509SubjectPublicKeyInfo;
            let public = cred.RetrievePublicKeyWithBlobType(blob)?;
            let provider = AsymmetricKeyAlgorithmProvider::OpenAlgorithm(
                &AsymmetricAlgorithmNames::RsaSignPkcs1Sha256()?,
            )?;
            let key = provider.ImportPublicKeyWithBlobType(&public, blob)?;
            let data = CryptographicBuffer::CreateFromByteArray(msg)?;
            let signature = CryptographicBuffer::CreateFromByteArray(sig)?;
            CryptographicEngine::VerifySignature(&key, &data, &signature)
        };
        check().unwrap_or(false)
    }
}
