//! shush — offline-first, zero-knowledge password manager core.
//!
//! Phase 1 delivers the cryptographic engine ([`crypto`]). Vault container,
//! OS integration, sync and TOTP modules land in later phases (spec §12).

#![deny(unsafe_code)] // OS modules opt in locally with a SAFETY comment.
#![warn(missing_docs)]

pub mod crypto;

use serde::Serialize;

/// Static, non-sensitive build information for the UI status bar.
#[derive(Debug, Serialize)]
struct AppInfo {
    version: &'static str,
    supported_ciphers: [crypto::CipherSuite; 2],
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        supported_ciphers: [
            crypto::CipherSuite::Aes256Gcm,
            crypto::CipherSuite::XChaCha20Poly1305,
        ],
    }
}

/// Builds and runs the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![app_info])
        .run(tauri::generate_context!())
        .expect("error while running shush");
}
