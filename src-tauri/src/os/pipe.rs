//! Authenticated local pipe between `shush-host.exe` and shush (issue #16).
//!
//! - Name `\\.\pipe\shush-<user SID>`, so each user has their own.
//! - DACL `D:P(A;;GA;;;<user SID>)`: only the current user can connect or
//!   create further instances. Remote clients are rejected.
//! - The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`. If
//!   the name already exists, someone else got there first (squatting):
//!   [`PipeListener::bind`] fails with [`PipeError::NameTaken`] and shush
//!   serves nothing.
//! - Each side can ask for the peer's process id and executable path
//!   ([`PipeConn::client_image`], [`server_image`]) and refuse a stranger.
//!
//! Framing on top is [`crate::bridge::frame`].

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Why the pipe could not be served or reached.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    /// Another process already owns the pipe name.
    #[error("the shush pipe name is already taken by another program")]
    NameTaken,
    /// The peer is not the expected executable.
    #[error("unexpected peer process: {0}")]
    UnexpectedPeer(PathBuf),
    /// Any other OS error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Whether `peer` is the executable `expected_name` in the same folder as `own`
/// (case-insensitive, as Windows paths are). If either path traverses a junction
/// or symlink, their canonical paths are compared so junctioned installations
/// match correctly.
pub fn is_sibling_exe(peer: &Path, own: &Path, expected_name: &str) -> bool {
    if !peer
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(expected_name))
    {
        return false;
    }
    let (Some(peer_dir), Some(own_dir)) = (peer.parent(), own.parent()) else {
        return false;
    };
    if peer_dir.as_os_str().eq_ignore_ascii_case(own_dir.as_os_str()) {
        return true;
    }
    let peer_canon = peer_dir
        .canonicalize()
        .unwrap_or_else(|_| peer_dir.to_path_buf());
    let own_canon = own_dir
        .canonicalize()
        .unwrap_or_else(|_| own_dir.to_path_buf());
    peer_canon
        .as_os_str()
        .eq_ignore_ascii_case(own_canon.as_os_str())
}

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 FFI; every block carries a SAFETY comment.
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const BUFFER: u32 = 64 * 1024;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain([0]).collect()
    }

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    /// Closes a raw handle on drop.
    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle was returned valid by the OS and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Memory from `LocalAlloc` (SID strings, security descriptors).
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the API that documented LocalFree.
                unsafe { LocalFree(self.0 as _) };
            }
        }
    }
    // SAFETY: an immutable security descriptor; only read by the OS.
    unsafe impl Send for Local {}

    /// String SID of the user running this process, e.g. `S-1-5-21-…`.
    pub fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = 0;
        // SAFETY: pseudo-handle for this process; `token` is a valid out pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_error());
        }
        let token = Owned(token);
        let mut len = 0u32;
        // SAFETY: size query with a null buffer; fails with the needed length.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(last_error());
        }
        // u64 storage keeps TOKEN_USER suitably aligned.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` has at least `len` bytes.
        if unsafe {
            GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
        } == 0
        {
            return Err(last_error());
        }
        // SAFETY: the call filled a TOKEN_USER at the start of `buf`.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut s: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` points into `buf`, alive for this call.
        if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
            return Err(last_error());
        }
        let s = Local(s.cast());
        let p = s.0.cast::<u16>();
        // SAFETY: NUL-terminated wide string from the OS.
        let n = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        // SAFETY: `n` u16s are readable.
        let slice = unsafe { std::slice::from_raw_parts(p, n) };
        Ok(String::from_utf16_lossy(slice))
    }

    /// The per-user pipe path.
    pub fn pipe_name() -> io::Result<String> {
        Ok(format!(r"\\.\pipe\shush-{}", current_user_sid()?))
    }

    /// Executable path of process `pid`.
    pub fn process_image(pid: u32) -> io::Result<PathBuf> {
        // SAFETY: plain call; the result is checked.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h == 0 {
            return Err(last_error());
        }
        let h = Owned(h);
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` u16s.
        if unsafe {
            QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        } == 0
        {
            return Err(last_error());
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &buf[..len as usize],
        )))
    }

    /// Accepts connections on the shush pipe.
    pub struct PipeListener {
        name: Vec<u16>,
        sd: Local,
        next: Option<File>,
    }

    impl PipeListener {
        /// Creates the first pipe instance. Fails with [`PipeError::NameTaken`]
        /// if any process already created this name.
        pub fn bind(name: &str) -> Result<Self, PipeError> {
            let sddl = wide(&format!("D:P(A;;GA;;;{})", current_user_sid()?));
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
                return Err(last_error().into());
            }
            let mut l = Self {
                name: wide(name),
                sd: Local(sd),
                next: None,
            };
            l.next = Some(l.instance(true)?);
            Ok(l)
        }

        fn instance(&self, first: bool) -> Result<File, PipeError> {
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.sd.0,
                bInheritHandle: 0,
            };
            let flags = PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            // SAFETY: valid name and security attributes that outlive the call.
            let h = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    flags,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    BUFFER,
                    BUFFER,
                    0,
                    &sa,
                )
            };
            if h == INVALID_HANDLE_VALUE {
                // SAFETY: plain call.
                let code = unsafe { GetLastError() };
                // FIRST_PIPE_INSTANCE on an existing name, or an instance of a
                // pipe whose DACL (someone else's) denies us.
                return Err(if code == ERROR_ACCESS_DENIED {
                    PipeError::NameTaken
                } else {
                    io::Error::from_raw_os_error(code as i32).into()
                });
            }
            // SAFETY: a fresh, owned handle; File closes it.
            Ok(unsafe { File::from_raw_handle(h as _) })
        }

        /// Blocks until a client connects, then returns that connection and
        /// prepares the next instance.
        pub fn accept(&mut self) -> Result<PipeConn, PipeError> {
            let pipe = match self.next.take() {
                Some(p) => p,
                None => self.instance(false)?,
            };
            // SAFETY: a valid pipe handle; synchronous (no OVERLAPPED).
            let ok = unsafe { ConnectNamedPipe(pipe.as_raw_handle() as HANDLE, ptr::null_mut()) };
            // SAFETY: plain call.
            if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                return Err(last_error().into());
            }
            self.next = Some(self.instance(false)?);
            Ok(PipeConn { pipe })
        }
    }

    /// One accepted connection; read and write it as a [`File`].
    pub struct PipeConn {
        /// The connected pipe.
        pub pipe: File,
    }

    impl PipeConn {
        /// Executable of the connected client.
        pub fn client_image(&self) -> io::Result<PathBuf> {
            let mut pid = 0u32;
            // SAFETY: connected pipe handle and a valid out pointer.
            if unsafe { GetNamedPipeClientProcessId(self.pipe.as_raw_handle() as HANDLE, &mut pid) }
                == 0
            {
                return Err(last_error());
            }
            process_image(pid)
        }
    }

    /// Connects to the pipe as a client (what `shush-host.exe` does).
    pub fn connect(name: &str) -> io::Result<File> {
        let name = wide(name);
        // SAFETY: valid NUL-terminated name; the result is checked.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        // SAFETY: a fresh, owned handle.
        Ok(unsafe { File::from_raw_handle(h as _) })
    }

    /// Executable of the process serving a pipe the caller connected to.
    pub fn server_image(pipe: &File) -> io::Result<PathBuf> {
        let mut pid = 0u32;
        // SAFETY: connected pipe handle and a valid out pointer.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
            return Err(last_error());
        }
        process_image(pid)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::bridge::frame::{read_frame, write_frame, MAX_REQUEST};

        fn test_name(tag: &str) -> String {
            let mut r = [0u8; 8];
            crate::crypto::fill_random(&mut r).unwrap();
            let r: String = r.iter().map(|b| format!("{b:02x}")).collect();
            format!(r"\\.\pipe\shush-test-{tag}-{r}")
        }

        #[test]
        fn sid_and_name() {
            let sid = current_user_sid().unwrap();
            assert!(sid.starts_with("S-1-"), "{sid}");
            assert!(pipe_name().unwrap().ends_with(&sid));
        }

        #[test]
        fn framed_roundtrip_with_peer_checks() {
            let name = test_name("rt");
            let mut l = PipeListener::bind(&name).unwrap();
            let client_name = name.clone();
            let client = std::thread::spawn(move || {
                let mut c = connect(&client_name).unwrap();
                let server = server_image(&c).unwrap();
                write_frame(&mut c, b"{\"ping\":1}", MAX_REQUEST).unwrap();
                let reply = read_frame(&mut c, MAX_REQUEST).unwrap().unwrap();
                (server, reply.to_vec())
            });
            let mut conn = l.accept().unwrap();
            let me = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
            let client_exe = std::fs::canonicalize(conn.client_image().unwrap()).unwrap();
            assert!(client_exe.as_os_str().eq_ignore_ascii_case(me.as_os_str()));
            let req = read_frame(&mut conn.pipe, MAX_REQUEST).unwrap().unwrap();
            assert_eq!(&**req, b"{\"ping\":1}");
            write_frame(&mut conn.pipe, b"{\"pong\":1}", MAX_REQUEST).unwrap();
            let (server, reply) = client.join().unwrap();
            let server = std::fs::canonicalize(server).unwrap();
            assert!(server.as_os_str().eq_ignore_ascii_case(me.as_os_str()));
            assert_eq!(reply, b"{\"pong\":1}");
        }

        #[test]
        fn squatted_name_is_detected() {
            let name = test_name("squat");
            let _squatter = PipeListener::bind(&name).unwrap();
            assert!(matches!(
                PipeListener::bind(&name),
                Err(PipeError::NameTaken)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_exe_check() {
        let own = Path::new(r"C:\Program Files\shush\shush.exe");
        assert!(is_sibling_exe(
            Path::new(r"c:\program files\SHUSH\shush-host.exe"),
            own,
            "shush-host.exe"
        ));
        assert!(!is_sibling_exe(
            Path::new(r"C:\Temp\shush-host.exe"),
            own,
            "shush-host.exe"
        ));
        assert!(!is_sibling_exe(
            Path::new(r"C:\Program Files\shush\evil.exe"),
            own,
            "shush-host.exe"
        ));
    }

    #[test]
    fn sibling_exe_junction() {
        let own = std::env::current_exe().unwrap();
        let target = std::fs::canonicalize(&own).unwrap();
        let exe_name = own.file_name().unwrap().to_str().unwrap();
        assert!(is_sibling_exe(&target, &own, exe_name));
        assert!(is_sibling_exe(&own, &target, exe_name));
    }
}
