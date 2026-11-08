//! Native-messaging framing: a 4-byte little-endian length, then that many
//! bytes of UTF-8 JSON. Used on the browser ↔ host stdio leg and on the
//! host ↔ shush pipe leg.

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// Largest request accepted from a browser or the pipe (64 KiB).
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest message a browser accepts from a native host (1 MiB, Chromium limit).
pub const MAX_TO_BROWSER: usize = 1024 * 1024;

/// Reads one frame. Returns `Ok(None)` on a clean end of stream before a frame
/// starts. A zero-length or oversized frame is an error and nothing of it is
/// buffered, so a hostile length cannot make us allocate.
pub fn read_frame(r: &mut impl Read, max: usize) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let n = u32::from_le_bytes(len) as usize;
    if n == 0 || n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame size out of range",
        ));
    }
    // Requests can carry a password (`save`); keep the buffer wipeable.
    let mut buf = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Writes one frame and flushes.
pub fn write_frame(w: &mut impl Write, body: &[u8], max: usize) -> io::Result<()> {
    if body.is_empty() || body.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame size out of range",
        ));
    }
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_clean_eof() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"{\"a\":1}", MAX_REQUEST).unwrap();
        write_frame(&mut wire, b"[]", MAX_REQUEST).unwrap();
        let mut r = wire.as_slice();
        assert_eq!(
            &**read_frame(&mut r, MAX_REQUEST).unwrap().unwrap(),
            b"{\"a\":1}"
        );
        assert_eq!(&**read_frame(&mut r, MAX_REQUEST).unwrap().unwrap(), b"[]");
        assert!(read_frame(&mut r, MAX_REQUEST).unwrap().is_none());
    }

    #[test]
    fn hostile_lengths_are_refused() {
        for len in [0u32, MAX_REQUEST as u32 + 1, u32::MAX] {
            let wire = len.to_le_bytes();
            assert!(
                read_frame(&mut wire.as_slice(), MAX_REQUEST).is_err(),
                "{len}"
            );
        }
        // Truncated length prefix and truncated body.
        assert!(read_frame(&mut [1u8, 0].as_slice(), MAX_REQUEST).is_err());
        assert!(read_frame(&mut [5u8, 0, 0, 0, b'x'].as_slice(), MAX_REQUEST).is_err());
        assert!(write_frame(&mut Vec::new(), &[0; 17], 16).is_err());
    }
}
