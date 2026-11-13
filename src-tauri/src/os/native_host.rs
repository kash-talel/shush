//! Per-user native-messaging host registration (issue #53, roadmap Phase 7b step 7).
//!
//! Browsers find `shush-host.exe` through a registry key whose default value
//! is the path of a JSON host manifest. Everything is written under `HKCU`,
//! so no administrator rights are needed and other users are not affected:
//!
//! | Browser | Key under `HKCU` |
//! |---|---|
//! | Chrome | `Software\Google\Chrome\NativeMessagingHosts\com.shush.vault` |
//! | Edge | `Software\Microsoft\Edge\NativeMessagingHosts\com.shush.vault` |
//! | Firefox | `Software\Mozilla\NativeMessagingHosts\com.shush.vault` |
//!
//! The manifests pin the shush extension: Chromium browsers only let
//! [`EXTENSION_ID`] (derived from the `key` in `extension/manifest.json`)
//! start the host, Firefox only [`FIREFOX_EXTENSION_ID`]. The extension itself
//! is still untrusted until the user pairs it with a one-time code.

use std::path::{Path, PathBuf};

/// Native messaging host name; the extension passes it to `connectNative`.
pub const HOST_NAME: &str = "com.shush.vault";
/// Chromium extension id, a function of the public key in `extension/manifest.json`.
pub const EXTENSION_ID: &str = "kmcbplfcpijmfohfojkajnmejadkcipe";
/// Firefox add-on id from `browser_specific_settings.gecko.id`.
pub const FIREFOX_EXTENSION_ID: &str = "shush@shush.invalid";
/// The real registry root for browser keys.
pub const HKCU_SOFTWARE: &str = "Software";

/// Browsers shush registers its host with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    /// Google Chrome.
    Chrome,
    /// Microsoft Edge.
    Edge,
    /// Mozilla Firefox.
    Firefox,
}

/// Every supported browser.
pub const ALL: [Browser; 3] = [Browser::Chrome, Browser::Edge, Browser::Firefox];

impl Browser {
    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
        }
    }

    fn vendor_path(self) -> &'static str {
        match self {
            Self::Chrome => r"Google\Chrome",
            Self::Edge => r"Microsoft\Edge",
            Self::Firefox => "Mozilla",
        }
    }

    /// Registry subkey (relative to `HKCU`) under `root`, e.g. `Software`.
    pub fn key_path(self, root: &str) -> String {
        format!(
            r"{root}\{}\NativeMessagingHosts\{HOST_NAME}",
            self.vendor_path()
        )
    }

    /// File name of this browser's manifest inside the manifest folder.
    pub fn manifest_file(self) -> String {
        format!("{HOST_NAME}.{}.json", self.name().to_ascii_lowercase())
    }
}

/// The host manifest JSON for `browser`, pointing at `host_exe`.
pub fn manifest_json(browser: Browser, host_exe: &Path) -> String {
    let mut m = serde_json::json!({
        "name": HOST_NAME,
        "description": "shush password manager: relays browser extension requests to the running app",
        "path": host_exe.to_string_lossy(),
        "type": "stdio",
    });
    match browser {
        Browser::Firefox => m["allowed_extensions"] = serde_json::json!([FIREFOX_EXTENSION_ID]),
        _ => {
            m["allowed_origins"] =
                serde_json::json!([format!("chrome-extension://{EXTENSION_ID}/")])
        }
    }
    serde_json::to_string_pretty(&m).expect("a JSON value always serializes")
}

/// `shush-host.exe` next to the running `shush.exe`.
pub fn host_exe_beside_app() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe
        .parent()
        .ok_or_else(|| std::io::Error::other("the app has no folder"))?;
    Ok(dir.join("shush-host.exe"))
}

#[cfg(windows)]
pub use imp::{is_registered, register, unregister};

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 registry FFI; every block carries a SAFETY comment.
mod imp {
    use super::{manifest_json, Browser, ALL};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    fn check(code: u32) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    /// Closes the key on drop.
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open/create call.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn set_default(subkey: &str, value: &Path) -> io::Result<()> {
        let sub = wide(subkey.as_ref());
        let mut h: HKEY = 0;
        // SAFETY: `sub` is nul-terminated; `h` receives the opened key.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut h,
                std::ptr::null_mut(),
            )
        })?;
        let key = Key(h);
        let data = wide(value.as_os_str());
        // SAFETY: `data` holds `len * 2` bytes of nul-terminated UTF-16.
        check(unsafe {
            RegSetValueExW(
                key.0,
                std::ptr::null(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        })
    }

    fn get_default(subkey: &str) -> Option<String> {
        let sub = wide(subkey.as_ref());
        let mut h: HKEY = 0;
        // SAFETY: `sub` is nul-terminated; `h` receives the opened key.
        let rc =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_QUERY_VALUE, &mut h) };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let key = Key(h);
        let mut buf = vec![0u16; 1024];
        let mut bytes = (buf.len() * 2) as u32;
        let mut kind = 0u32;
        // SAFETY: `buf` has `bytes` bytes of room.
        let rc = unsafe {
            RegQueryValueExW(
                key.0,
                std::ptr::null(),
                std::ptr::null(),
                &mut kind,
                buf.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if rc != ERROR_SUCCESS || kind != REG_SZ {
            return None;
        }
        let n = (bytes as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]);
        Some(s.trim_end_matches('\0').to_string())
    }

    /// Writes one manifest per browser into `manifest_dir` and points each
    /// browser's `HKCU` key at it. `root` is `Software` outside tests.
    pub fn register(root: &str, manifest_dir: &Path, host_exe: &Path) -> io::Result<()> {
        std::fs::create_dir_all(manifest_dir)?;
        for b in ALL {
            let file = manifest_dir.join(b.manifest_file());
            std::fs::write(&file, manifest_json(b, host_exe))?;
            set_default(&b.key_path(root), &file)?;
        }
        Ok(())
    }

    /// Removes the keys and manifests. Missing ones are fine, so it can be
    /// repeated and partly done registrations are cleaned up too.
    pub fn unregister(root: &str, manifest_dir: &Path) -> io::Result<()> {
        let mut first_err = None;
        for b in ALL {
            let sub = wide(b.key_path(root).as_ref());
            // SAFETY: `sub` is nul-terminated.
            let rc = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, sub.as_ptr()) };
            if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                first_err.get_or_insert(io::Error::from_raw_os_error(rc as i32));
            }
            match std::fs::remove_file(manifest_dir.join(b.manifest_file())) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Browsers whose key currently points at our manifest in `manifest_dir`.
    pub fn is_registered(root: &str, manifest_dir: &Path) -> Vec<Browser> {
        ALL.into_iter()
            .filter(|b| {
                let expect = manifest_dir.join(b.manifest_file());
                get_default(&b.key_path(root))
                    .is_some_and(|v| v.eq_ignore_ascii_case(&expect.to_string_lossy()))
                    && expect.is_file()
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::System::Registry::RegDeleteTreeW;

        /// A scratch registry root under HKCU, removed afterwards. Never the real
        /// browser keys.
        struct Scratch(String);
        impl Scratch {
            fn new(tag: &str) -> Self {
                Self(format!(r"Software\ShushTest\{tag}-{}", std::process::id()))
            }
        }
        impl Drop for Scratch {
            fn drop(&mut self) {
                let sub = wide(self.0.as_ref());
                // SAFETY: `sub` is nul-terminated.
                unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, sub.as_ptr()) };
                let parent = wide(r"Software\ShushTest".as_ref());
                // SAFETY: as above; fails harmlessly while other tests' keys remain.
                unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, parent.as_ptr()) };
            }
        }

        fn temp_dir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("shush-nmh-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            d
        }

        #[test]
        fn register_then_unregister() {
            let root = Scratch::new("reg");
            let dir = temp_dir("reg");
            let exe = Path::new(r"C:\Program Files\shush\shush-host.exe");

            assert!(is_registered(&root.0, &dir).is_empty());
            register(&root.0, &dir, exe).unwrap();
            assert_eq!(is_registered(&root.0, &dir), ALL.to_vec());

            // The key's default value is the manifest path, and the manifest pins the extension.
            let chrome = get_default(&Browser::Chrome.key_path(&root.0)).unwrap();
            assert_eq!(
                std::path::PathBuf::from(&chrome),
                dir.join("com.shush.vault.chrome.json")
            );
            let m: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&chrome).unwrap()).unwrap();
            assert_eq!(m["path"], exe.to_string_lossy().as_ref());

            unregister(&root.0, &dir).unwrap();
            assert!(is_registered(&root.0, &dir).is_empty());
            assert!(!dir.join("com.shush.vault.edge.json").exists());
            // Repeating is harmless.
            unregister(&root.0, &dir).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn registering_twice_updates_the_path() {
            let root = Scratch::new("twice");
            let dir = temp_dir("twice");
            register(&root.0, &dir, Path::new(r"C:\old\shush-host.exe")).unwrap();
            register(&root.0, &dir, Path::new(r"D:\new\shush-host.exe")).unwrap();
            let text = std::fs::read_to_string(dir.join("com.shush.vault.firefox.json")).unwrap();
            assert!(text.contains(r"D:\\new\\shush-host.exe"), "{text}");
            unregister(&root.0, &dir).unwrap();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_paths_are_the_documented_hkcu_locations() {
        assert_eq!(
            Browser::Chrome.key_path(HKCU_SOFTWARE),
            r"Software\Google\Chrome\NativeMessagingHosts\com.shush.vault"
        );
        assert_eq!(
            Browser::Edge.key_path(HKCU_SOFTWARE),
            r"Software\Microsoft\Edge\NativeMessagingHosts\com.shush.vault"
        );
        assert_eq!(
            Browser::Firefox.key_path(HKCU_SOFTWARE),
            r"Software\Mozilla\NativeMessagingHosts\com.shush.vault"
        );
    }

    #[test]
    fn manifests_pin_exactly_the_shush_extension() {
        let exe = Path::new(r"C:\shush\shush-host.exe");
        for b in [Browser::Chrome, Browser::Edge] {
            let m: serde_json::Value = serde_json::from_str(&manifest_json(b, exe)).unwrap();
            assert_eq!(m["name"], HOST_NAME);
            assert_eq!(m["type"], "stdio");
            assert_eq!(
                m["allowed_origins"],
                serde_json::json!([format!("chrome-extension://{EXTENSION_ID}/")])
            );
            assert!(m.get("allowed_extensions").is_none());
        }
        let m: serde_json::Value =
            serde_json::from_str(&manifest_json(Browser::Firefox, exe)).unwrap();
        assert_eq!(
            m["allowed_extensions"],
            serde_json::json!([FIREFOX_EXTENSION_ID])
        );
        assert!(m.get("allowed_origins").is_none());
    }

    /// The pinned ids must match the extension manifest in the repo.
    #[test]
    fn pinned_ids_match_extension_manifest() {
        let text = include_str!("../../../extension/manifest.json");
        let m: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(
            m["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION_ID
        );

        // Chromium derives the id from SHA-256 of the DER public key: first 16
        // bytes, each nibble mapped to 'a'..'p'.
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let der = B64.decode(m["key"].as_str().unwrap()).unwrap();
        let id: String = Sha256::digest(&der)[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| char::from(b'a' + n))
            .collect();
        assert_eq!(id, EXTENSION_ID);
    }
}
