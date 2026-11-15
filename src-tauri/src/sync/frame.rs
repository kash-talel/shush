//! Wire framing (`lan-sync.md` §1): each Noise message (or clear pairing
//! message) is sent as a `u16` big-endian length followed by that many bytes.
//! 65 535 bytes is the Noise message limit, so a frame can never exceed it.

use std::io::{self, Read, Write};

/// Largest frame body (the Noise message size limit).
pub const MAX_FRAME: usize = 65_535;

/// Writes one frame and flushes it.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u16::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    let mut buf = Vec::with_capacity(2 + body.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

/// Reads one frame. Fails on end of stream, including a truncated frame.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
    r.read_exact(&mut body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_limits() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"hello").unwrap();
        write_frame(&mut wire, &[]).unwrap();
        write_frame(&mut wire, &vec![7u8; MAX_FRAME]).unwrap();
        assert_eq!(&wire[..7], b"\x00\x05hello");
        let mut r = &wire[..];
        assert_eq!(read_frame(&mut r).unwrap(), b"hello");
        assert!(read_frame(&mut r).unwrap().is_empty());
        assert_eq!(read_frame(&mut r).unwrap().len(), MAX_FRAME);
        assert!(read_frame(&mut r).is_err());

        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, &vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(sink.is_empty());
        // Truncated body.
        assert!(read_frame(&mut &b"\x00\x05hel"[..]).is_err());
    }
}
