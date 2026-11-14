//! A fresh per-user directory with a private, non-inherited ACL (issue #197).
//!
//! Downloaded installers are staged here instead of `%TEMP%`: a shared download or temp folder
//! can hold planted DLLs that an installer would load from its own directory. The directory is
//! deleted and recreated empty for every download, and its DACL is protected (no inherited
//! entries) and grants full control to the current user and SYSTEM only.

use std::io;
use std::path::Path;

/// Deletes `dir` (if present) and recreates it empty with the private ACL. Parents are created
/// with their default (inherited) permissions.
pub fn create_fresh(dir: &Path) -> io::Result<()> {
    remove(dir)?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    imp::create(dir)
}

/// Deletes `dir` and everything in it; a missing directory is fine.
pub fn remove(dir: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    /// Memory from `LocalAlloc`, freed on drop.
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the API that documents LocalFree.
                unsafe { LocalFree(self.0 as _) };
            }
        }
    }

    /// `P`: protected (nothing inherited from the parent). `OICI`: files and subfolders inherit
    /// these entries. `FA`: full access, for this user and SYSTEM only.
    pub(super) fn sddl(user_sid: &str) -> String {
        format!("D:P(A;OICI;FA;;;{user_sid})(A;OICI;FA;;;SY)")
    }

    pub(super) fn create(dir: &Path) -> io::Result<()> {
        let sid = crate::os::pipe::current_user_sid()?;
        let sddl: Vec<u16> = std::ffi::OsStr::new(&sddl(&sid))
            .encode_wide()
            .chain([0])
            .collect();
        let mut sd: *mut c_void = ptr::null_mut();
        // SAFETY: valid NUL-terminated SDDL; `sd` receives a LocalAlloc'd descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sd = Local(sd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: NUL-terminated path; `sa` and its descriptor outlive the call.
        if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The directory's DACL as SDDL (tests).
    #[cfg(test)]
    pub(super) fn dacl_sddl(dir: &Path) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let path: Vec<u16> = dir.as_os_str().encode_wide().chain([0]).collect();
        let mut sd: *mut c_void = ptr::null_mut();
        // SAFETY: out pointers are valid; `sd` receives a LocalAlloc'd descriptor.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let sd = Local(sd);
        let mut s: *mut u16 = ptr::null_mut();
        // SAFETY: `sd` is a valid descriptor; `s` receives a LocalAlloc'd wide string.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let s = Local(s.cast());
        let p = s.0.cast::<u16>();
        // SAFETY: NUL-terminated wide string from the OS.
        let n = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        // SAFETY: `n` u16s are readable.
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(p, n)
        }))
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;
    use std::path::Path;

    pub(super) fn create(dir: &Path) -> io::Result<()> {
        std::fs::create_dir(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recreated_empty() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("a").join("updates");
        create_fresh(&dir).unwrap();
        std::fs::write(dir.join("planted.dll"), b"x").unwrap();
        create_fresh(&dir).unwrap();
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "leftovers removed"
        );
        remove(&dir).unwrap();
        assert!(!dir.exists());
        remove(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn acl_is_private_and_protected() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("updates");
        create_fresh(&dir).unwrap();
        let sid = crate::os::pipe::current_user_sid().unwrap();
        let dacl = imp::dacl_sddl(&dir).unwrap();
        assert!(dacl.starts_with("D:P"), "inheritance not blocked: {dacl}");
        assert!(dacl.contains(&sid), "{dacl}");
        assert!(dacl.contains(";SY)"), "{dacl}");
        // No broad principals: Users, Authenticated Users, Everyone, Administrators.
        for broad in [";BU)", ";AU)", ";WD)", ";BA)"] {
            assert!(!dacl.contains(broad), "{broad} in {dacl}");
        }
        // A file created inside inherits the private entries.
        let f = dir.join("x.exe");
        std::fs::write(&f, b"x").unwrap();
        let file_dacl = imp::dacl_sddl(&f).unwrap();
        assert!(
            file_dacl.contains(&sid) && !file_dacl.contains(";BU)"),
            "{file_dacl}"
        );
        assert_eq!(
            imp::sddl("S-1-5-21-1"),
            "D:P(A;OICI;FA;;;S-1-5-21-1)(A;OICI;FA;;;SY)"
        );
    }
}
