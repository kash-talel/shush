//! The relay loop behind `shush-host.exe` (issue #51).
//!
//! The browser starts the host with stdio pipes. The host forwards each framed
//! request to the running shush over the authenticated pipe and returns the
//! reply, one request at a time. It decides nothing and never inspects, logs
//! or keeps a message body beyond the zeroized frame buffers.

use std::io::{self, Read, Write};

use super::frame::{read_frame, write_frame, MAX_REQUEST, MAX_TO_BROWSER};

/// Executable name the pipe server must have (in the host's own folder).
pub const SERVER_EXE: &str = "shush.exe";

/// Forwards frames from `browser_in` to `pipe` and replies to `browser_out`
/// until either side closes. Returns `Ok(())` when the browser closed stdin
/// (clean exit) and an error when the pipe closed or a frame was invalid.
pub fn relay(
    browser_in: &mut impl Read,
    browser_out: &mut impl Write,
    pipe: &mut (impl Read + Write),
) -> io::Result<()> {
    while let Some(request) = read_frame(browser_in, MAX_REQUEST)? {
        write_frame(pipe, &request, MAX_REQUEST)?;
        let reply = read_frame(pipe, MAX_TO_BROWSER)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "shush closed the pipe"))?;
        write_frame(browser_out, &reply, MAX_TO_BROWSER)?;
    }
    Ok(())
}

/// Connects to the shush pipe `name` and refuses it unless the serving process
/// is `shush.exe` from the same folder as the running host.
#[cfg(windows)]
pub fn connect_verified(name: &str) -> Result<std::fs::File, crate::os::pipe::PipeError> {
    use crate::os::pipe::{connect, is_sibling_exe, server_image, PipeError};
    let pipe = connect(name)?;
    let server = server_image(&pipe)?;
    let own = std::env::current_exe()?;
    if !is_sibling_exe(&server, &own, SERVER_EXE) {
        return Err(PipeError::UnexpectedPeer(server));
    }
    Ok(pipe)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scripted pipe: replays `replies`, records what was written.
    struct FakePipe {
        replies: io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Read for FakePipe {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.replies.read(b)
        }
    }
    impl Write for FakePipe {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.sent.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(bodies: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for b in bodies {
            write_frame(&mut v, b, MAX_TO_BROWSER).unwrap();
        }
        v
    }

    #[test]
    fn relays_in_lockstep_and_exits_on_stdin_eof() {
        let stdin = framed(&[b"{\"a\":1}", b"{\"b\":2}"]);
        let mut pipe = FakePipe {
            replies: io::Cursor::new(framed(&[b"{\"r\":1}", b"{\"r\":2}"])),
            sent: Vec::new(),
        };
        let mut out = Vec::new();
        relay(&mut stdin.as_slice(), &mut out, &mut pipe).unwrap();
        assert_eq!(out, framed(&[b"{\"r\":1}", b"{\"r\":2}"]));
        assert_eq!(pipe.sent, stdin);
    }

    #[test]
    fn pipe_closing_ends_the_relay_with_an_error() {
        let stdin = framed(&[b"{}"]);
        let mut pipe = FakePipe {
            replies: io::Cursor::new(Vec::new()),
            sent: Vec::new(),
        };
        let mut out = Vec::new();
        let err = relay(&mut stdin.as_slice(), &mut out, &mut pipe).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(out.is_empty());
    }

    #[test]
    fn oversized_browser_frame_is_refused_before_the_pipe() {
        let stdin = (MAX_REQUEST as u32 + 1).to_le_bytes().to_vec();
        let mut pipe = FakePipe {
            replies: io::Cursor::new(Vec::new()),
            sent: Vec::new(),
        };
        assert!(relay(&mut stdin.as_slice(), &mut Vec::new(), &mut pipe).is_err());
        assert!(pipe.sent.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn pipe_served_by_a_non_shush_executable_is_refused() {
        use crate::os::pipe::{PipeError, PipeListener};
        let mut r = [0u8; 8];
        crate::crypto::fill_random(&mut r).unwrap();
        let name = format!(
            r"\\.\pipe\shush-test-relay-{}",
            r.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let _listener = PipeListener::bind(&name).unwrap();
        // The server is this test executable, which is not `shush.exe`.
        match connect_verified(&name) {
            Err(PipeError::UnexpectedPeer(p)) => {
                assert!(!p.file_name().unwrap().eq_ignore_ascii_case(SERVER_EXE));
            }
            other => panic!("expected UnexpectedPeer, got {other:?}"),
        }
    }
}
