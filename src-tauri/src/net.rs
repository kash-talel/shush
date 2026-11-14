//! Air-gapped mode (issue #157, Phase 8c): the single network gate.
//!
//! Every socket, HTTP or mDNS path in shush must go through this module.
//! Nothing else in the crate may name socket types (a unit test scans the
//! source tree for that). **Air-gapped is the default**: until the user turns it
//! off in Settings, every opener returns [`NetError::AirGapped`] and no socket
//! is created. A missing or unreadable setting also means air-gapped (fail
//! closed).
//!
//! Native messaging (stdio relay plus the local named pipe) is not network and
//! does not use this gate.
//!
//! Without the `network` cargo feature the socket openers are compiled out, so
//! such a build contains no socket code of ours.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// File (next to `vaults.json`) holding the user's choice.
pub const SETTINGS_FILE: &str = "network.json";

/// Room for response headers on top of the body cap.
#[cfg(feature = "network")]
const HEADER_ALLOWANCE: usize = 16 * 1024;

/// Extracts the body of a complete `HTTP/1.1 200` response. Rejects every other status
/// (redirects included), bodies over `max_body`, and truncated bodies.
pub(crate) fn parse_http_response(raw: &[u8], max_body: usize) -> Result<Vec<u8>, &'static str> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed response")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "malformed response")?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or("malformed response")?;
    let mut parts = status.split(' ');
    let version_ok = matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0"));
    if !version_ok || parts.next() != Some("200") {
        return Err("unexpected HTTP status");
    }
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            return Err("malformed response");
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "content-length" {
            let n = v.parse().map_err(|_| "malformed response")?;
            if content_length.replace(n).is_some_and(|p| p != n) {
                return Err("malformed response");
            }
        } else if k == "transfer-encoding" {
            if v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err("unsupported transfer encoding");
            }
        } else if k == "content-encoding" && !v.eq_ignore_ascii_case("identity") {
            return Err("unsupported content encoding");
        }
    }
    let out = if chunked {
        if content_length.is_some() {
            return Err("malformed response");
        }
        decode_chunked(body, max_body)?
    } else {
        if content_length.is_some_and(|n| n != body.len()) {
            return Err("truncated response");
        }
        body.to_vec()
    };
    if out.len() > max_body {
        return Err("response too large");
    }
    Ok(out)
}

fn decode_chunked(mut b: &[u8], max_body: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    loop {
        let eol = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("truncated response")?;
        let size_str = std::str::from_utf8(&b[..eol]).map_err(|_| "malformed response")?;
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| "malformed response")?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > max_body || out.len() + size > max_body {
            return Err("response too large");
        }
        if b.len() < size + 2 || &b[size..size + 2] != b"\r\n" {
            return Err("truncated response");
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

/// Redirects a download may follow (GitHub release assets redirect once, to their CDN).
pub const MAX_REDIRECTS: usize = 5;
/// Largest response head a download accepts.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Host, path and user agent are plain printable ASCII with no room for header injection.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn valid_request(host: &str, path: &str, user_agent: &str) -> bool {
    let ok_host = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let ok_path = path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic());
    let ok_ua = user_agent.bytes().all(|b| (0x20..0x7f).contains(&b));
    ok_host && ok_path && ok_ua
}

/// Parses a download URL: `https` on the default port, a host name, no credentials.
pub(crate) fn download_target(url: &str) -> Result<url::Url, NetError> {
    let bad = || NetError::Io("download URL is not an allowed https URL".into());
    let u = url::Url::parse(url).map_err(|_| bad())?;
    let named_host = matches!(u.host(), Some(url::Host::Domain(h)) if !h.is_empty());
    if u.scheme() != "https"
        || !named_host
        || u.port().is_some_and(|p| p != 443)
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return Err(bad());
    }
    Ok(u)
}

/// `(host, path?query)` of a URL accepted by [`download_target`]; the fragment is dropped.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
fn request_parts(u: &url::Url) -> Result<(String, String), NetError> {
    let host = u.host_str().ok_or_else(|| NetError::Io("bad URL".into()))?;
    let mut path = u.path().to_owned();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    Ok((host.to_owned(), path))
}

/// What one HTTP exchange of a download produced.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hop {
    /// The whole body was written.
    Done,
    /// The server redirected to this `Location`.
    Redirect(String),
}

/// Pull-based reader over a response: bytes already read past the head first, then the socket.
/// Checks the deadline and the gate before every socket read.
struct Pull<'a, R> {
    r: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    deadline: std::time::Instant,
    gate: &'a dyn Fn() -> Result<(), NetError>,
}

impl<R: std::io::Read> Pull<'_, R> {
    /// Unconsumed bytes, reading more if none are buffered. Empty means end of stream.
    fn fill(&mut self) -> Result<&[u8], NetError> {
        if self.pos == self.buf.len() && !self.eof {
            (self.gate)()?;
            if std::time::Instant::now() > self.deadline {
                return Err(NetError::Io("timed out".into()));
            }
            self.buf.resize(64 * 1024, 0);
            self.pos = 0;
            match self.r.read(&mut self.buf) {
                Ok(n) => {
                    self.buf.truncate(n);
                    self.eof = n == 0;
                }
                // A peer that closes without close_notify: completeness is checked by length.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.buf.clear();
                    self.eof = true;
                }
                Err(e) => {
                    self.buf.clear();
                    return Err(NetError::Io(e.to_string()));
                }
            }
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }

    /// One CRLF-terminated line of at most `max` bytes, without the CRLF.
    fn line(&mut self, max: usize) -> Result<Vec<u8>, NetError> {
        let mut line = Vec::new();
        loop {
            let b = self.fill()?;
            if b.is_empty() {
                return Err(NetError::Io("truncated response".into()));
            }
            let (take, end) = match b.iter().position(|&c| c == b'\n') {
                Some(i) => (i + 1, true),
                None => (b.len(), false),
            };
            line.extend_from_slice(&b[..take]);
            self.consume(take);
            if line.len() > max + 2 {
                return Err(NetError::Io("malformed response".into()));
            }
            if end {
                if line.ends_with(b"\r\n") {
                    line.truncate(line.len() - 2);
                    return Ok(line);
                }
                return Err(NetError::Io("malformed response".into()));
            }
        }
    }
}

/// Reads one HTTP/1.1 response for a download and streams its body into `out`.
///
/// A `200` body must total exactly `expected_len` bytes: a larger `Content-Length` is refused
/// before any body byte is written, and delivery stops at the cap. A redirect status returns its
/// `Location` without reading the body; every other status is an error.
#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(crate) fn read_download<R: std::io::Read>(
    r: &mut R,
    out: &mut dyn std::io::Write,
    expected_len: u64,
    deadline: std::time::Instant,
    gate: &dyn Fn() -> Result<(), NetError>,
) -> Result<Hop, NetError> {
    let err = |m: &str| NetError::Io(m.into());
    let mut p = Pull {
        r,
        buf: Vec::new(),
        pos: 0,
        eof: false,
        deadline,
        gate,
    };
    let status = p.line(MAX_HEAD_BYTES)?;
    let status = std::str::from_utf8(&status).map_err(|_| err("malformed response"))?;
    let mut parts = status.split(' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(err("malformed response"));
    }
    let code = parts.next().unwrap_or("");
    let mut head_len = status.len();
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    let mut location: Option<String> = None;
    loop {
        let l = p.line(MAX_HEAD_BYTES)?;
        head_len += l.len() + 2;
        if head_len > MAX_HEAD_BYTES {
            return Err(err("response head too large"));
        }
        if l.is_empty() {
            break;
        }
        let l = std::str::from_utf8(&l).map_err(|_| err("malformed response"))?;
        let (k, v) = l.split_once(':').ok_or_else(|| err("malformed response"))?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "content-length" => {
                let n: u64 = v.parse().map_err(|_| err("malformed response"))?;
                if content_length.replace(n).is_some_and(|prev| prev != n) {
                    return Err(err("malformed response"));
                }
            }
            "transfer-encoding" if v.eq_ignore_ascii_case("chunked") => chunked = true,
            "transfer-encoding" => return Err(err("unsupported transfer encoding")),
            "content-encoding" if !v.eq_ignore_ascii_case("identity") => {
                return Err(err("unsupported content encoding"))
            }
            "location" => location = Some(v.to_owned()),
            _ => {}
        }
    }
    match code {
        "200" => {}
        "301" | "302" | "303" | "307" | "308" => {
            return location
                .filter(|l| !l.is_empty())
                .map(Hop::Redirect)
                .ok_or_else(|| err("redirect without a location"));
        }
        _ => return Err(err("unexpected HTTP status")),
    }
    if chunked && content_length.is_some() {
        return Err(err("malformed response"));
    }
    if content_length.is_some_and(|n| n != expected_len) {
        return Err(err("response size does not match the signed size"));
    }

    let mut written: u64 = 0;
    let mut sink = |written: &mut u64, b: &[u8]| -> Result<(), NetError> {
        *written += b.len() as u64;
        if *written > expected_len {
            return Err(err("response too large"));
        }
        out.write_all(b)
            .map_err(|_| err("could not write the download"))
    };
    if chunked {
        loop {
            let line = p.line(1024)?;
            let line = std::str::from_utf8(&line).map_err(|_| err("malformed response"))?;
            let size_str = line.split(';').next().unwrap_or("").trim();
            let mut left =
                u64::from_str_radix(size_str, 16).map_err(|_| err("malformed response"))?;
            if left == 0 {
                break; // Trailers, if any, are ignored: the body is complete.
            }
            while left > 0 {
                let b = p.fill()?;
                if b.is_empty() {
                    return Err(err("truncated response"));
                }
                let n = b.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                sink(&mut written, &b[..n])?;
                p.consume(n);
                left -= n as u64;
            }
            if !p.line(0)?.is_empty() {
                return Err(err("malformed response"));
            }
        }
    } else {
        loop {
            let b = p.fill()?;
            if b.is_empty() {
                break;
            }
            let n = b.len();
            sink(&mut written, b)?;
            p.consume(n);
            if content_length.is_some() && written == expected_len {
                break;
            }
        }
    }
    if written != expected_len {
        return Err(err("truncated response"));
    }
    Ok(Hop::Done)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
/// Why the gate refused or a socket failed.
pub enum NetError {
    #[error("Air-gapped mode is on, so shush will not use the network.")]
    /// Air-gapped mode is on.
    AirGapped,
    #[error("This build of shush was made without network support.")]
    /// Built without the `network` feature.
    NotCompiledIn,
    #[error("Network error: {0}")]
    /// The OS refused the socket.
    Io(String),
}

/// The one switch. Starts air-gapped.
#[derive(Debug)]
pub struct NetGate {
    air_gapped: AtomicBool,
    /// Sockets the gate has let through (test harness evidence).
    opened: AtomicU64,
}

impl Default for NetGate {
    fn default() -> Self {
        Self {
            air_gapped: AtomicBool::new(true),
            opened: AtomicU64::new(0),
        }
    }
}

impl NetGate {
    /// True while the gate is closed.
    pub fn is_air_gapped(&self) -> bool {
        self.air_gapped.load(Ordering::SeqCst)
    }

    /// Opens or closes the gate (in memory only; see `save_and_set`).
    pub fn set_air_gapped(&self, on: bool) {
        self.air_gapped.store(on, Ordering::SeqCst);
    }

    /// Whether this binary can use the network at all.
    pub const fn compiled_in() -> bool {
        cfg!(feature = "network")
    }

    /// How many sockets the gate has opened since start.
    pub fn sockets_opened(&self) -> u64 {
        self.opened.load(Ordering::SeqCst)
    }

    /// Every network feature calls this before doing anything.
    pub fn check(&self) -> Result<(), NetError> {
        if !Self::compiled_in() {
            return Err(NetError::NotCompiledIn);
        }
        if self.is_air_gapped() {
            return Err(NetError::AirGapped);
        }
        Ok(())
    }

    /// Binds a TCP listener, or refuses while air-gapped.
    #[cfg(feature = "network")]
    pub fn tcp_listen(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<std::net::TcpListener, NetError> {
        self.check()?;
        let l = std::net::TcpListener::bind(addr).map_err(|e| NetError::Io(e.to_string()))?;
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(l)
    }

    /// Connects a TCP stream, or refuses while air-gapped.
    #[cfg(feature = "network")]
    pub fn tcp_connect(
        &self,
        addr: &std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<std::net::TcpStream, NetError> {
        self.check()?;
        let s = std::net::TcpStream::connect_timeout(addr, timeout)
            .map_err(|e| NetError::Io(e.to_string()))?;
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(s)
    }

    /// Binds a UDP socket (mDNS discovery), or refuses while air-gapped.
    #[cfg(feature = "network")]
    pub fn udp_bind(&self, addr: std::net::SocketAddr) -> Result<std::net::UdpSocket, NetError> {
        self.check()?;
        let s = std::net::UdpSocket::bind(addr).map_err(|e| NetError::Io(e.to_string()))?;
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(s)
    }

    /// HTTPS GET of `https://<host><path>` through the gate (issue #78): resolves, connects and
    /// speaks TLS (certificates checked against the bundled web roots; no redirects, no cookies,
    /// no client identity). Returns the body of a `200` response, capped at `max_body` bytes.
    /// Refuses while air-gapped, before any DNS lookup or socket.
    pub fn https_get(
        &self,
        host: &str,
        path: &str,
        user_agent: &str,
        max_body: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, NetError> {
        self.check()?;
        #[cfg(not(feature = "network"))]
        {
            let _ = (host, path, user_agent, max_body, timeout);
            Err(NetError::NotCompiledIn)
        }
        #[cfg(feature = "network")]
        {
            self.https_get_inner(host, path, user_agent, max_body, timeout)
        }
    }

    #[cfg(feature = "network")]
    fn https_get_inner(
        &self,
        host: &str,
        path: &str,
        user_agent: &str,
        max_body: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, NetError> {
        use std::io::Read;

        if !valid_request(host, path, user_agent) {
            return Err(NetError::Io("invalid request".into()));
        }
        let io = |e: &dyn std::fmt::Display| NetError::Io(e.to_string());
        let deadline = std::time::Instant::now() + timeout * 3;
        let mut tls = self.tls_request(host, path, user_agent, timeout, deadline)?;

        let cap = max_body.saturating_add(HEADER_ALLOWANCE);
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            if std::time::Instant::now() > deadline {
                return Err(NetError::Io("timed out".into()));
            }
            match tls.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if raw.len() > cap {
                        return Err(NetError::Io("response too large".into()));
                    }
                }
                // A peer that closes without close_notify: completeness is checked below.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(io(&e)),
            }
        }
        parse_http_response(&raw, max_body).map_err(|m| NetError::Io(m.into()))
    }

    /// Streams the body of `url` (an `https://` URL) into `out` through the gate (issue #197).
    ///
    /// For installer downloads: the body must be exactly `expected_len` bytes. A larger declared
    /// or delivered body is aborted at the cap, a shorter one is an error. Up to
    /// [`MAX_REDIRECTS`] redirects are followed, each to `https` only. Every read checks the gate
    /// first, so turning air-gapped mode on stops the download before the next socket call.
    /// `stall` bounds each connect and read; `total` bounds the whole transfer.
    pub fn https_download(
        &self,
        url: &str,
        user_agent: &str,
        expected_len: u64,
        stall: std::time::Duration,
        total: std::time::Duration,
        out: &mut dyn std::io::Write,
    ) -> Result<(), NetError> {
        self.check()?;
        let first = download_target(url)?;
        #[cfg(not(feature = "network"))]
        {
            let _ = (first, user_agent, expected_len, stall, total, out);
            Err(NetError::NotCompiledIn)
        }
        #[cfg(feature = "network")]
        {
            let deadline = std::time::Instant::now() + total;
            let mut target = first;
            for _ in 0..=MAX_REDIRECTS {
                let (host, path) = request_parts(&target)?;
                if !valid_request(&host, &path, user_agent) {
                    return Err(NetError::Io("invalid request".into()));
                }
                let mut tls = self.tls_request(&host, &path, user_agent, stall, deadline)?;
                match read_download(&mut tls, out, expected_len, deadline, &|| self.check())? {
                    Hop::Done => return Ok(()),
                    Hop::Redirect(location) => {
                        target = target
                            .join(&location)
                            .map_err(|_| NetError::Io("bad redirect".into()))
                            .and_then(|u| download_target(u.as_str()))?;
                    }
                }
            }
            Err(NetError::Io("too many redirects".into()))
        }
    }

    /// Resolves, connects and speaks TLS to `host:443`, then sends one `GET path`.
    #[cfg(feature = "network")]
    fn tls_request(
        &self,
        host: &str,
        path: &str,
        user_agent: &str,
        timeout: std::time::Duration,
        deadline: std::time::Instant,
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>, NetError> {
        use std::io::Write;
        use std::net::ToSocketAddrs;
        use std::sync::Arc;

        let io = |e: &dyn std::fmt::Display| NetError::Io(e.to_string());
        let addrs: Vec<_> = (host, 443u16)
            .to_socket_addrs()
            .map_err(|e| io(&e))?
            .collect();
        // Every address shares the one deadline, so a network that silently drops (say) IPv6
        // cannot stretch a request to minutes. The last real error is kept for the user.
        let mut tcp = None;
        let mut last_err = NetError::Io("could not connect".into());
        for a in &addrs {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                last_err = NetError::Io("timed out".into());
                break;
            }
            match self.tcp_connect(a, timeout.min(left)) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e @ (NetError::AirGapped | NetError::NotCompiledIn)) => return Err(e),
                Err(e) => last_err = e,
            }
        }
        let tcp = tcp.ok_or(last_err)?;
        tcp.set_read_timeout(Some(timeout)).map_err(|e| io(&e))?;
        tcp.set_write_timeout(Some(timeout)).map_err(|e| io(&e))?;

        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| io(&e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| io(&e))?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| io(&e))?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).map_err(|e| io(&e))?;
        Ok(tls)
    }

    /// Loads the saved choice. Anything but an explicit `false` stays air-gapped.
    pub fn load(&self, dir: &Path) {
        let off = std::fs::read(dir.join(SETTINGS_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("air_gapped").and_then(|x| x.as_bool()))
            == Some(false);
        self.set_air_gapped(!off);
    }

    /// Saves the choice, then applies it. A failed save leaves the gate unchanged.
    pub fn save_and_set(&self, dir: &Path, on: bool) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{SETTINGS_FILE}.tmp"));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(
                serde_json::json!({ "air_gapped": on })
                    .to_string()
                    .as_bytes(),
            )?;
            f.sync_all()?;
        }
        // Write-through rename, so a power cut cannot bring back the old choice.
        crate::os::replace::replace_file(&tmp, &dir.join(SETTINGS_FILE))?;
        self.set_air_gapped(on);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_air_gapped_and_opens_nothing() {
        let g = NetGate::default();
        assert!(g.is_air_gapped());
        assert!(g.check().is_err());
        #[cfg(feature = "network")]
        {
            let a: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
            assert_eq!(g.check(), Err(NetError::AirGapped));
            assert_eq!(g.tcp_listen(a).unwrap_err(), NetError::AirGapped);
            assert_eq!(
                g.tcp_connect(&a, std::time::Duration::from_millis(10))
                    .unwrap_err(),
                NetError::AirGapped
            );
            assert_eq!(g.udp_bind(a).unwrap_err(), NetError::AirGapped);
        }
        assert_eq!(g.sockets_opened(), 0);
    }

    #[cfg(feature = "network")]
    #[test]
    fn turning_it_off_allows_sockets() {
        let g = NetGate::default();
        g.set_air_gapped(false);
        let a: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let l = g.tcp_listen(a).unwrap();
        assert_eq!(g.sockets_opened(), 1);
        drop(l);
        g.set_air_gapped(true);
        assert_eq!(g.tcp_listen(a).unwrap_err(), NetError::AirGapped);
        assert_eq!(g.sockets_opened(), 1);
    }

    #[test]
    fn http_response_parsing() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(parse_http_response(ok, 10).unwrap(), b"abc");
        assert!(parse_http_response(ok, 2).is_err(), "over cap");
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc";
        assert!(parse_http_response(short, 10).is_err(), "truncated");
        let redirect = b"HTTP/1.1 301 Moved\r\nLocation: http://x\r\n\r\n";
        assert!(parse_http_response(redirect, 10).is_err(), "no redirects");
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(chunked, 10).unwrap(), b"abc");
        let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n";
        assert!(parse_http_response(cut, 10).is_err(), "chunked cut off");
        let gz = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx";
        assert!(parse_http_response(gz, 10).is_err());
        assert!(parse_http_response(b"garbage", 10).is_err());
    }

    fn far() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(60)
    }

    fn dl(raw: &[u8], expected: u64) -> (Result<Hop, NetError>, Vec<u8>) {
        let mut out = Vec::new();
        let r = read_download(
            &mut std::io::Cursor::new(raw),
            &mut out,
            expected,
            far(),
            &|| Ok(()),
        );
        (r, out)
    }

    #[test]
    fn download_streams_exact_bodies() {
        let (r, out) = dl(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3);
        assert_eq!((r, out.as_slice()), (Ok(Hop::Done), &b"abc"[..]));
        // No length header: read to the end, which must be exactly the expected size.
        let (r, out) = dl(b"HTTP/1.1 200 OK\r\n\r\nabcd", 4);
        assert_eq!((r, out.as_slice()), (Ok(Hop::Done), &b"abcd"[..]));
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1;x\r\nc\r\n0\r\n\r\n";
        let (r, out) = dl(chunked, 3);
        assert_eq!((r, out.as_slice()), (Ok(Hop::Done), &b"abc"[..]));
    }

    #[test]
    fn download_refuses_wrong_sizes_and_statuses() {
        // A declared length other than the signed size is refused before any byte is written.
        let (r, out) = dl(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabcdefghi", 3);
        assert!(r.is_err());
        assert!(out.is_empty());
        // Undeclared overlong body: stops at the cap.
        let (r, out) = dl(b"HTTP/1.1 200 OK\r\n\r\nabcdefghi", 3);
        assert!(r.is_err());
        assert!(out.len() <= 3);
        let (r, _) = dl(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nabcdefghi\r\n0\r\n\r\n",
            3,
        );
        assert!(r.is_err(), "chunked overlong");
        // Cut short.
        assert!(dl(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc", 5)
            .0
            .is_err());
        assert!(dl(b"HTTP/1.1 200 OK\r\n\r\nabc", 5).0.is_err());
        assert!(dl(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
            5
        )
        .0
        .is_err());
        assert!(dl(b"HTTP/1.1 404 Not Found\r\n\r\n", 3).0.is_err());
        assert!(
            dl(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc", 3)
                .0
                .is_err()
        );
        assert!(dl(b"garbage", 3).0.is_err());
        let huge_head = [b"HTTP/1.1 200 OK\r\nX: ".as_slice(), &[b'a'; 20_000]].concat();
        assert!(dl(&huge_head, 3).0.is_err());
    }

    #[test]
    fn download_reports_redirects() {
        let (r, out) = dl(
            b"HTTP/1.1 302 Found\r\nLocation: https://cdn.example/x?sig=1\r\nContent-Length: 4\r\n\r\nmove",
            3,
        );
        assert_eq!(r, Ok(Hop::Redirect("https://cdn.example/x?sig=1".into())));
        assert!(out.is_empty());
        assert!(
            dl(b"HTTP/1.1 301 Moved\r\n\r\n", 3).0.is_err(),
            "no location"
        );
    }

    /// Air-gapped mode switched on mid-download stops before the next read.
    #[test]
    fn download_stops_when_the_gate_closes() {
        struct Slow<'a> {
            data: &'a [u8],
            reads: &'a std::cell::Cell<usize>,
        }
        impl std::io::Read for Slow<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                let n = self.data.len().min(buf.len()).min(8);
                buf[..n].copy_from_slice(&self.data[..n]);
                self.data = &self.data[n..];
                Ok(n)
            }
        }
        let body = vec![b'x'; 200];
        let raw = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n".as_slice(),
            &body,
        ]
        .concat();
        let reads = std::cell::Cell::new(0);
        let gate = NetGate::default();
        gate.set_air_gapped(false);
        let mut out = Vec::new();
        let r = read_download(
            &mut Slow {
                data: &raw,
                reads: &reads,
            },
            &mut out,
            200,
            far(),
            &|| {
                if reads.get() == 10 {
                    gate.set_air_gapped(true);
                }
                gate.check()
            },
        );
        assert_eq!(r, Err(NetError::AirGapped));
        assert_eq!(reads.get(), 10, "no read after the gate closed");
        // A passed deadline also stops it.
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let r = read_download(
            &mut std::io::Cursor::new(&raw),
            &mut Vec::new(),
            200,
            past,
            &|| Ok(()),
        );
        assert!(r.is_err());
    }

    #[test]
    fn download_urls_are_https_only() {
        assert!(download_target("https://github.com/a/b/releases/download/v1/x.exe").is_ok());
        for bad in [
            "http://github.com/x.exe",
            "https://user:pw@github.com/x.exe",
            "https://github.com:8443/x.exe",
            "https://127.0.0.1/x.exe",
            "file:///c:/x.exe",
            "not a url",
        ] {
            assert!(download_target(bad).is_err(), "{bad} accepted");
        }
        let u = download_target("https://cdn.example/a/b?x=1&y=2#frag").unwrap();
        assert_eq!(
            request_parts(&u).unwrap(),
            ("cdn.example".into(), "/a/b?x=1&y=2".into())
        );
    }

    #[test]
    fn download_refuses_while_air_gapped() {
        let g = NetGate::default();
        let r = g.https_download(
            "https://example.com/x",
            "shush/test",
            3,
            std::time::Duration::from_millis(10),
            std::time::Duration::from_millis(10),
            &mut Vec::new(),
        );
        assert_eq!(r, Err(NetError::AirGapped));
        assert_eq!(g.sockets_opened(), 0);
    }

    /// Live TLS check against the real site (run with `--ignored`; needs internet).
    #[cfg(feature = "network")]
    #[test]
    #[ignore]
    fn https_get_live() {
        let g = NetGate::default();
        g.set_air_gapped(false);
        let t = std::time::Duration::from_secs(15);
        let body = g
            .https_get("kash-talel.github.io", "/shush/", "shush/test", 4 << 20, t)
            .unwrap();
        assert!(!body.is_empty());
        // A name the web roots do not vouch for must fail closed.
        for host in [
            "self-signed.badssl.com",
            "wrong.host.badssl.com",
            "expired.badssl.com",
            "untrusted-root.badssl.com",
        ] {
            let bad = g.https_get(host, "/", "shush/test", 1 << 20, t);
            assert!(bad.is_err(), "{host} was accepted");
        }
    }

    #[test]
    fn https_get_refuses_while_air_gapped() {
        let g = NetGate::default();
        let r = g.https_get(
            "example.com",
            "/",
            "shush/test",
            1024,
            std::time::Duration::from_millis(10),
        );
        assert!(r.is_err());
        assert_eq!(g.sockets_opened(), 0);
    }

    #[test]
    fn setting_persists_and_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let g = NetGate::default();
        g.load(d.path());
        assert!(g.is_air_gapped(), "missing file");
        g.save_and_set(d.path(), false).unwrap();
        let g2 = NetGate::default();
        g2.load(d.path());
        assert!(!g2.is_air_gapped());
        std::fs::write(d.path().join(SETTINGS_FILE), b"garbage").unwrap();
        g2.load(d.path());
        assert!(g2.is_air_gapped(), "corrupt file");
        std::fs::write(d.path().join(SETTINGS_FILE), br#"{"air_gapped":"no"}"#).unwrap();
        g2.load(d.path());
        assert!(g2.is_air_gapped(), "wrong type");
    }

    /// No other source file may open sockets: everything goes through the gate.
    #[test]
    fn no_socket_types_outside_the_gate() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("src");
        let gate = root.join("net.rs");
        let extra = [
            "TcpListener",
            "TcpStream",
            "TcpSocket",
            "UdpSocket",
            "std::net",
            "tokio::net",
            "socket2",
            "WinSock",
            "WinHttp",
            "WinINet",
            "reqwest",
            "hyper::",
            "ureq",
            "mdns",
        ];
        // Crates and Windows APIs that open sockets on their own; adding one
        // must route it through the gate and then update this list.
        let cargo = std::fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
        for n in [
            "reqwest",
            "hyper",
            "ureq",
            "socket2",
            "mdns",
            "tauri-plugin-http",
            "tauri-plugin-updater",
            "tauri-plugin-websocket",
            "Win32_Networking",
        ] {
            assert!(
                !cargo.contains(n),
                "Cargo.toml adds {n}; network code must go through net::NetGate"
            );
        }
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") && p != gate {
                    let text = std::fs::read_to_string(&p).unwrap();
                    for n in extra {
                        assert!(
                            !text.contains(n),
                            "{} mentions {n}; use net::NetGate",
                            p.display()
                        );
                    }
                }
            }
        }
    }
}
