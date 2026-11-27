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
#[cfg_attr(not(feature = "network"), allow(dead_code))]
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

#[cfg_attr(not(feature = "network"), allow(dead_code))]
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

/// Tries each address in turn, every attempt capped by what is left of the one shared
/// `deadline`, so a network that silently drops (say) IPv6 cannot stretch a request to
/// minutes. The last real error is kept for the user; a gate refusal ends the loop at once.
#[cfg(feature = "network")]
fn connect_within<T>(
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
    deadline: std::time::Instant,
    mut connect: impl FnMut(&std::net::SocketAddr, std::time::Duration) -> Result<T, NetError>,
) -> Result<T, NetError> {
    let mut last_err = NetError::Io("could not connect".into());
    for a in addrs {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            last_err = NetError::Io("timed out".into());
            break;
        }
        match connect(a, timeout.min(left)) {
            Ok(s) => return Ok(s),
            Err(e @ (NetError::AirGapped | NetError::NotCompiledIn)) => return Err(e),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
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
    /// Every socket still open, each with the closure that closes it (issue #191).
    open: std::sync::Arc<std::sync::Mutex<Registry>>,
}

type Closer = Box<dyn FnOnce() + Send>;

/// The gate's list of open sockets.
#[derive(Default)]
struct Registry {
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    next: u64,
    closers: std::collections::HashMap<u64, Closer>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Registry({} open)", self.closers.len())
    }
}

fn lock_registry(r: &std::sync::Mutex<Registry>) -> std::sync::MutexGuard<'_, Registry> {
    r.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Membership of one socket in the gate's registry. Dropping it removes the entry.
#[derive(Debug)]
#[cfg_attr(not(feature = "network"), allow(dead_code))]
pub(crate) struct Tracked {
    id: u64,
    open: std::sync::Arc<std::sync::Mutex<Registry>>,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        let closer = lock_registry(&self.open).closers.remove(&self.id);
        drop(closer);
    }
}

impl Default for NetGate {
    fn default() -> Self {
        Self {
            air_gapped: AtomicBool::new(true),
            opened: AtomicU64::new(0),
            open: std::sync::Arc::default(),
        }
    }
}

impl NetGate {
    /// True while the gate is closed.
    pub fn is_air_gapped(&self) -> bool {
        self.air_gapped.load(Ordering::SeqCst)
    }

    /// Opens or closes the gate (in memory only; see `save_and_set`).
    ///
    /// Turning air-gapped mode on closes every socket the gate opened (listeners, streams, mDNS
    /// daemons) and returns only once they are all closed (issue #191). A socket being opened at
    /// the same moment either lands in the list before the close, or sees the flag when it tries
    /// to register and closes itself.
    pub fn set_air_gapped(&self, on: bool) {
        self.air_gapped.store(on, Ordering::SeqCst);
        if on {
            let closers: Vec<Closer> = lock_registry(&self.open)
                .closers
                .drain()
                .map(|(_, c)| c)
                .collect();
            for c in closers {
                c();
            }
        }
    }

    /// Sockets (and discovery daemons) currently open through the gate.
    pub fn sockets_open(&self) -> usize {
        lock_registry(&self.open).closers.len()
    }

    /// Lists a freshly opened socket with the closure that closes it. Fails (running the closure)
    /// if air-gapped mode came on since the caller's `check()`.
    #[cfg(feature = "network")]
    fn track(&self, closer: Closer) -> Result<Tracked, NetError> {
        // Counted before the race check: the socket did reach the network.
        self.opened.fetch_add(1, Ordering::SeqCst);
        let mut reg = lock_registry(&self.open);
        if self.is_air_gapped() {
            drop(reg);
            closer();
            return Err(NetError::AirGapped);
        }
        reg.next += 1;
        let id = reg.next;
        reg.closers.insert(id, closer);
        Ok(Tracked {
            id,
            open: self.open.clone(),
        })
    }

    #[cfg(feature = "network")]
    fn track_stream(&self, s: std::net::TcpStream) -> Result<TrackedStream, NetError> {
        let clone = s.try_clone().map_err(io_err)?;
        let t = self.track(Box::new(move || {
            let _ = clone.shutdown(std::net::Shutdown::Both);
        }))?;
        Ok(TrackedStream { inner: s, _t: t })
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
    pub(crate) fn tcp_listen(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<TrackedListener, NetError> {
        self.check()?;
        let l = std::net::TcpListener::bind(addr).map_err(io_err)?;
        let slot = Shared::new(l);
        let t = self.track(slot.closer())?;
        Ok(TrackedListener { slot, _t: t })
    }

    /// Connects a TCP stream, or refuses while air-gapped.
    #[cfg(feature = "network")]
    pub(crate) fn tcp_connect(
        &self,
        addr: &std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> Result<TrackedStream, NetError> {
        self.check()?;
        let s = std::net::TcpStream::connect_timeout(addr, timeout).map_err(io_err)?;
        self.track_stream(s)
    }

    /// Binds a UDP socket, or refuses while air-gapped.
    #[cfg(feature = "network")]
    #[allow(dead_code)]
    pub(crate) fn udp_bind(&self, addr: std::net::SocketAddr) -> Result<TrackedUdp, NetError> {
        self.check()?;
        let s = std::net::UdpSocket::bind(addr).map_err(io_err)?;
        let slot = Shared::new(s);
        let t = self.track(slot.closer())?;
        Ok(TrackedUdp { slot, _t: t })
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
                Err(e) => {
                    // Air-gapped mode shuts the socket down mid-read (issue #191).
                    self.check()?;
                    return Err(io(&e));
                }
            }
        }
        // A shutdown by air-gapped mode can look like a clean end: never return that body.
        self.check()?;
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
    ) -> Result<rustls::StreamOwned<rustls::ClientConnection, TrackedStream>, NetError> {
        use std::io::Write;
        use std::net::ToSocketAddrs;
        use std::sync::Arc;

        let io = |e: &dyn std::fmt::Display| NetError::Io(e.to_string());
        let addrs: Vec<_> = (host, 443u16)
            .to_socket_addrs()
            .map_err(|e| io(&e))?
            .collect();
        let tcp = connect_within(&addrs, timeout, deadline, |a, t| self.tcp_connect(a, t))?;
        tcp.inner
            .set_read_timeout(Some(timeout))
            .map_err(|e| io(&e))?;
        tcp.inner
            .set_write_timeout(Some(timeout))
            .map_err(|e| io(&e))?;

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

// --- LAN sync sockets and discovery (issue #156, docs/spec/lan-sync.md Â§5) ---

/// DNS-SD service type of a shush pairing or sync window.
#[cfg(feature = "network")]
pub const SYNC_SERVICE: &str = "_shush-sync._tcp.local.";

/// Discovery daemons alive right now (test-harness evidence that nothing is
/// advertised or browsed outside a window).
static DISCOVERY_LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many discovery daemons are running (0 outside a window).
pub fn discovery_daemons_live() -> usize {
    DISCOVERY_LIVE.load(Ordering::SeqCst)
}

/// The listening socket of one pairing or sync window. Dropping it closes it.
#[cfg(feature = "network")]
pub struct LanListener {
    inner: TrackedListener,
}

/// One LAN connection (accepted or dialled).
#[cfg(feature = "network")]
pub struct LanStream {
    inner: TrackedStream,
    peer: String,
    /// Whole-connection deadline set by [`LanStream::set_timeout`]: a peer
    /// trickling one byte at a time cannot keep the connection (and the
    /// window's listener, code and identity) alive past it.
    deadline: Option<std::time::Instant>,
    /// Set by [`LanStream::closer`]: reads and writes then fail at once.
    /// Windows does not wake a blocked `recv` on `shutdown`, so reads under a
    /// deadline ([`LanStream::set_timeout`]) run in short slices that look at
    /// this flag.
    closed: std::sync::Arc<AtomicBool>,
}

/// How long a blocking read or write waits before it re-checks `closed`.
#[cfg(feature = "network")]
const CLOSE_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// A socket the gate can close from outside: the owner and the gate's closer share it, and
/// closing drops it.
#[cfg(feature = "network")]
#[derive(Debug)]
struct Shared<T>(std::sync::Arc<std::sync::Mutex<Option<T>>>);

#[cfg(feature = "network")]
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "network")]
impl<T: Send + 'static> Shared<T> {
    fn new(v: T) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Some(v))))
    }

    fn closer(&self) -> Closer {
        let me = self.clone();
        Box::new(move || {
            me.0.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        })
    }

    /// Runs `f` on the socket, or `None` if the gate closed it.
    fn with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let g = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        g.as_ref().map(f)
    }
}

/// A TCP listener the gate can close.
#[cfg(feature = "network")]
#[derive(Debug)]
pub(crate) struct TrackedListener {
    slot: Shared<std::net::TcpListener>,
    _t: Tracked,
}

/// A UDP socket the gate can close.
#[cfg(feature = "network")]
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct TrackedUdp {
    slot: Shared<std::net::UdpSocket>,
    _t: Tracked,
}

/// A TCP stream the gate can shut down (the gate holds a second handle to the same socket).
#[cfg(feature = "network")]
#[derive(Debug)]
pub(crate) struct TrackedStream {
    inner: std::net::TcpStream,
    _t: Tracked,
}

#[cfg(feature = "network")]
impl std::io::Read for TrackedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

#[cfg(feature = "network")]
impl std::io::Write for TrackedStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A window found by discovery.
#[cfg(feature = "network")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Discovered {
    /// Random instance name the window advertised.
    pub instance: String,
    /// `ip:port` to dial.
    pub address: String,
}

/// A running discovery daemon (an advertised window, or a browse). Dropping
/// it sends the goodbye (TTL 0) for an advertised window and stops the daemon.
#[cfg(feature = "network")]
pub struct Advertisement {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
    _t: Tracked,
}

#[cfg(feature = "network")]
fn io_err(e: impl std::fmt::Display) -> NetError {
    NetError::Io(e.to_string())
}

#[cfg(feature = "network")]
impl NetGate {
    /// Binds the listener of a window on an ephemeral port: on every IPv4
    /// interface, or on loopback only (tests).
    pub fn lan_listen(&self, loopback_only: bool) -> Result<LanListener, NetError> {
        let ip = if loopback_only {
            std::net::Ipv4Addr::LOCALHOST
        } else {
            std::net::Ipv4Addr::UNSPECIFIED
        };
        let inner = self.tcp_listen(std::net::SocketAddr::from((ip, 0)))?;
        inner
            .slot
            .with(|l| l.set_nonblocking(true))
            .ok_or(NetError::AirGapped)?
            .map_err(io_err)?;
        Ok(LanListener { inner })
    }

    /// Dials `ip:port` (no host names, so no DNS lookup).
    pub fn lan_connect(
        &self,
        addr: &str,
        timeout: std::time::Duration,
    ) -> Result<LanStream, NetError> {
        let sa: std::net::SocketAddr = addr
            .trim()
            .parse()
            .map_err(|_| NetError::Io("enter an address like 192.168.1.20:53124".into()))?;
        let inner = self.tcp_connect(&sa, timeout)?;
        Ok(LanStream {
            inner,
            peer: sa.to_string(),
            deadline: None,
            closed: std::sync::Arc::default(),
        })
    }

    /// Starts a discovery daemon (counted as one opened socket).
    fn discovery_daemon(&self, fullname: String) -> Result<Advertisement, NetError> {
        self.check()?;
        let daemon = mdns_sd::ServiceDaemon::new().map_err(io_err)?;
        let handle = daemon.clone();
        let t = self.track(Box::new(move || {
            // A full command queue answers Again: retry rather than leave the daemon running.
            for _ in 0..50 {
                match handle.shutdown() {
                    Ok(rx) => {
                        let _ = rx.recv_timeout(std::time::Duration::from_secs(1));
                        return;
                    }
                    Err(mdns_sd::Error::Again) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        }))?;
        DISCOVERY_LIVE.fetch_add(1, Ordering::SeqCst);
        Ok(Advertisement {
            daemon,
            fullname,
            _t: t,
        })
    }

    /// Advertises a window as `<instance>._shush-sync._tcp.local.` on host
    /// `<host>.local.` with TXT `v=1` only (no user, computer or vault name).
    pub fn advertise_sync(
        &self,
        port: u16,
        instance: &str,
        host: &str,
    ) -> Result<Advertisement, NetError> {
        self.check()?;
        let info = mdns_sd::ServiceInfo::new(
            SYNC_SERVICE,
            instance,
            &format!("{host}.local."),
            (),
            port,
            &[("v", "1")][..],
        )
        .map_err(io_err)?
        .enable_addr_auto();
        let ad = self.discovery_daemon(info.get_fullname().to_owned())?;
        ad.daemon.register(info).map_err(io_err)?;
        Ok(ad)
    }

    /// Browses for open windows for `wait`, then stops (time-boxed; nothing
    /// keeps listening afterwards).
    pub fn discover_sync(&self, wait: std::time::Duration) -> Result<Vec<Discovered>, NetError> {
        let guard = self.discovery_daemon(String::new())?;
        let rx = guard.daemon.browse(SYNC_SERVICE).map_err(io_err)?;
        let deadline = std::time::Instant::now() + wait;
        let mut found: Vec<Discovered> = Vec::new();
        loop {
            self.check()?;
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok(ev) = rx.recv_timeout(left.min(std::time::Duration::from_millis(200))) else {
                continue;
            };
            let mdns_sd::ServiceEvent::ServiceResolved(s) = ev else {
                continue;
            };
            if s.get_property_val_str("v") != Some("1") {
                continue;
            }
            let instance = s
                .get_fullname()
                .split('.')
                .next()
                .unwrap_or_default()
                .to_owned();
            for ip in s.addresses.iter().filter(|ip| ip.is_ipv4()) {
                let d = Discovered {
                    instance: instance.clone(),
                    address: std::net::SocketAddr::new(ip.to_ip_addr(), s.port).to_string(),
                };
                if !found.contains(&d) {
                    found.push(d);
                }
            }
        }
        let _ = guard.daemon.stop_browse(SYNC_SERVICE);
        Ok(found)
    }
}

#[cfg(feature = "network")]
impl Drop for Advertisement {
    fn drop(&mut self) {
        let wait = std::time::Duration::from_secs(1);
        if !self.fullname.is_empty() {
            if let Ok(rx) = self.daemon.unregister(&self.fullname) {
                let _ = rx.recv_timeout(wait);
            }
        }
        if let Ok(rx) = self.daemon.shutdown() {
            let _ = rx.recv_timeout(wait);
        }
        DISCOVERY_LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// This machine's IPv4 addresses a peer could dial (up, not loopback or
/// link-local), for the pairing screen's manual-entry hint.
#[cfg(feature = "network")]
pub fn lan_addresses() -> Vec<String> {
    let mut v: Vec<String> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.is_oper_up() && !i.is_loopback() && !i.is_link_local())
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(a) => Some(a.to_string()),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(feature = "network")]
impl LanListener {
    /// The port peers dial.
    pub fn port(&self) -> u16 {
        self.inner
            .slot
            .with(|l| l.local_addr().map_or(0, |a| a.port()))
            .unwrap_or(0)
    }

    /// Waits for one connection, polling every 100 ms, while `keep_waiting()`
    /// is true and the gate is open. `Ok(None)`: stopped without a connection.
    pub fn accept(
        &self,
        gate: &NetGate,
        keep_waiting: &mut dyn FnMut() -> bool,
    ) -> Result<Option<LanStream>, NetError> {
        loop {
            gate.check()?;
            if !keep_waiting() {
                return Ok(None);
            }
            let Some(r) = self.inner.slot.with(|l| l.accept()) else {
                return Err(NetError::AirGapped);
            };
            match r {
                Ok((s, peer)) => {
                    // Accepted sockets inherit non-blocking mode on Windows.
                    s.set_nonblocking(false).map_err(io_err)?;
                    return Ok(Some(LanStream {
                        inner: gate.track_stream(s)?,
                        peer: peer.to_string(),
                        deadline: None,
                        closed: std::sync::Arc::default(),
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(e) => return Err(io_err(e)),
            }
        }
    }
}

#[cfg(feature = "network")]
impl LanStream {
    /// The other end, `ip:port`.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// A closure that shuts this connection down from another thread, so a
    /// blocked read fails within [`CLOSE_POLL`] (cancel, vault lock). Needs
    /// [`LanStream::set_timeout`] first: without a deadline a read is not
    /// sliced, and Windows does not wake it on `shutdown`.
    pub fn closer(&self) -> Result<Box<dyn FnOnce() + Send>, NetError> {
        let clone = self.inner.inner.try_clone().map_err(io_err)?;
        let closed = self.closed.clone();
        Ok(Box::new(move || {
            closed.store(true, Ordering::SeqCst);
            let _ = clone.shutdown(std::net::Shutdown::Both);
        }))
    }

    /// Limits the whole rest of the connection to `d`: every later read or
    /// write fails with `TimedOut` once `d` has passed, however the peer
    /// paces its bytes.
    pub fn set_timeout(&mut self, d: std::time::Duration) -> Result<(), NetError> {
        self.inner.inner.set_read_timeout(Some(d)).map_err(io_err)?;
        self.inner
            .inner
            .set_write_timeout(Some(d))
            .map_err(io_err)?;
        // A duration too large for an `Instant` means no deadline beyond the
        // socket timeouts, not a panic.
        self.deadline = std::time::Instant::now().checked_add(d);
        Ok(())
    }

    /// Time left before the deadline, or `TimedOut` once it passed.
    fn left(&self) -> std::io::Result<Option<std::time::Duration>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "connection closed",
            ));
        }
        let Some(deadline) = self.deadline else {
            return Ok(None);
        };
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection deadline passed",
            ));
        }
        Ok(Some(left))
    }
}

/// A socket timeout (Unix reports an expired receive/send timeout as `WouldBlock`).
#[cfg(feature = "network")]
fn is_timeout<T>(r: &std::io::Result<T>) -> bool {
    matches!(r, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
}

#[cfg(feature = "network")]
impl std::io::Read for LanStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(left) = self.left()? {
                self.inner
                    .inner
                    .set_read_timeout(Some(left.min(CLOSE_POLL)))?;
            }
            let r = self.inner.read(buf);
            if self.deadline.is_some() && is_timeout(&r) {
                continue;
            }
            return r;
        }
    }
}

#[cfg(feature = "network")]
impl std::io::Write for LanStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Writes are not sliced: on Windows a timed-out `send` may have queued
        // part of `buf` without saying how much, so retrying could duplicate
        // bytes. A send timeout ends the connection instead. Pairing frames fit
        // in the socket buffer, so a write does not block long enough to delay
        // a cancel.
        if let Some(left) = self.left()? {
            self.inner.inner.set_write_timeout(Some(left))?;
        }
        let r = self.inner.write(buf);
        if self.deadline.is_some() && is_timeout(&r) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection deadline passed",
            ));
        }
        r
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "network")]
    #[test]
    fn connect_loop_stays_inside_the_request_deadline() {
        use std::time::{Duration, Instant};
        let addrs: Vec<std::net::SocketAddr> = (1..=6)
            .map(|i| format!("127.0.0.{i}:443").parse().unwrap())
            .collect();
        // Every attempt "blackholes": it burns its whole allowance, as a dropped IPv6 would.
        let start = Instant::now();
        let deadline = start + Duration::from_millis(45);
        let mut attempts = 0;
        let r: Result<(), _> =
            connect_within(&addrs, Duration::from_millis(20), deadline, |_, t| {
                attempts += 1;
                assert!(t <= Duration::from_millis(20));
                std::thread::sleep(t);
                Err(NetError::Io("blackhole".into()))
            });
        assert!(r.is_err());
        assert!(attempts < addrs.len(), "later addresses must be skipped");
        assert!(start.elapsed() < Duration::from_millis(300));
        // A refusal by the gate is not retried on the next address.
        let mut n = 0;
        let r: Result<(), _> = connect_within(
            &addrs,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(5),
            |_, _| {
                n += 1;
                Err(NetError::AirGapped)
            },
        );
        assert_eq!(r, Err(NetError::AirGapped));
        assert_eq!(n, 1);
    }

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

    /// Issue #191: turning air-gapped mode on closes every open socket before it returns.
    #[cfg(feature = "network")]
    #[test]
    fn air_gapped_closes_open_sockets() {
        use std::io::Read;
        let d = std::time::Duration::from_secs(2);
        let g = NetGate::default();
        g.set_air_gapped(false);
        let l = g.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", l.port());
        let mut client = g.lan_connect(&addr, d).unwrap();
        let mut server = l.accept(&g, &mut || true).unwrap().unwrap();
        client.set_timeout(d).unwrap();
        server.set_timeout(d).unwrap();
        let udp = g.udp_bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_eq!(g.sockets_open(), 4);

        g.set_air_gapped(true);
        assert_eq!(g.sockets_open(), 0);
        // The listener is gone: nobody can connect.
        let sa: std::net::SocketAddr = addr.parse().unwrap();
        assert!(std::net::TcpStream::connect_timeout(&sa, d).is_err());
        // Both ends of the stream are shut down.
        let mut b = [0u8; 1];
        assert!(matches!(client.read(&mut b), Ok(0) | Err(_)));
        assert!(matches!(server.read(&mut b), Ok(0) | Err(_)));
        assert!(udp.slot.with(|_| ()).is_none());
        assert!(l.accept(&g, &mut || true).is_err());
        // Dropping the dead handles is harmless, and opening stays refused.
        drop((client, server, l, udp));
        assert_eq!(g.sockets_open(), 0);
        assert_eq!(g.lan_listen(true).err(), Some(NetError::AirGapped));
    }

    /// Dropping a socket takes it off the gate's list.
    #[cfg(feature = "network")]
    #[test]
    fn dropped_sockets_leave_the_list() {
        let g = NetGate::default();
        g.set_air_gapped(false);
        let l = g.lan_listen(true).unwrap();
        assert_eq!(g.sockets_open(), 1);
        drop(l);
        assert_eq!(g.sockets_open(), 0);
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
    #[cfg(feature = "network")]
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

    #[cfg(feature = "network")]
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

    /// Issue #156: no LAN listener, connection or discovery while air-gapped.
    #[cfg(feature = "network")]
    #[test]
    fn lan_sync_refuses_while_air_gapped() {
        let g = NetGate::default();
        assert!(matches!(g.lan_listen(true), Err(NetError::AirGapped)));
        assert!(matches!(
            g.lan_connect("127.0.0.1:9", std::time::Duration::from_millis(10)),
            Err(NetError::AirGapped)
        ));
        assert!(matches!(
            g.advertise_sync(1, "abcdefgh", "ijklmnop"),
            Err(NetError::AirGapped)
        ));
        assert!(matches!(
            g.discover_sync(std::time::Duration::from_millis(10)),
            Err(NetError::AirGapped)
        ));
        assert_eq!(g.sockets_opened(), 0);
    }

    /// The window listener stops accepting as soon as the gate closes.
    #[cfg(feature = "network")]
    #[test]
    fn lan_listener_stops_when_the_gate_closes() {
        let g = NetGate::default();
        g.set_air_gapped(false);
        let l = g.lan_listen(true).unwrap();
        assert_ne!(l.port(), 0);
        let mut polls = 0;
        let r = l.accept(&g, &mut || {
            polls += 1;
            if polls == 2 {
                g.set_air_gapped(true);
            }
            true
        });
        assert!(matches!(r, Err(NetError::AirGapped)));
        g.set_air_gapped(false);
        assert!(matches!(l.accept(&g, &mut || false), Ok(None)));
        assert!(g
            .lan_connect("not an address", std::time::Duration::from_millis(10))
            .is_err());
    }

    /// A peer trickling one byte at a time cannot hold a connection past its
    /// deadline (each read would otherwise restart the per-read timeout).
    #[cfg(feature = "network")]
    #[test]
    fn lan_stream_deadline_covers_the_whole_connection() {
        use std::io::{Read, Write};
        let g = NetGate::default();
        g.set_air_gapped(false);
        let l = g.lan_listen(true).unwrap();
        let addr = format!("127.0.0.1:{}", l.port());
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut c = g
                    .lan_connect(&addr, std::time::Duration::from_secs(5))
                    .unwrap();
                for _ in 0..40 {
                    if c.write_all(&[0]).is_err() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            });
            let mut stream = l.accept(&g, &mut || true).unwrap().unwrap();
            stream
                .set_timeout(std::time::Duration::from_millis(400))
                .unwrap();
            let started = std::time::Instant::now();
            let mut buf = [0u8; 64];
            let err = stream.read_exact(&mut buf).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() < std::time::Duration::from_millis(1500));
            // A duration past what an `Instant` can hold must not panic.
            stream.set_timeout(std::time::Duration::MAX).unwrap();
        });
    }

    /// Live check of advertise + browse on this machine's network (multicast
    /// must be allowed, so not run in CI): the window is found while
    /// advertised, and no daemon is left once it is dropped.
    #[cfg(feature = "network")]
    #[test]
    #[ignore = "needs multicast on a real network interface"]
    fn discovery_live() {
        let g = NetGate::default();
        g.set_air_gapped(false);
        let ad = g.advertise_sync(40123, "shushtst", "shushhst").unwrap();
        let found = g.discover_sync(std::time::Duration::from_secs(4)).unwrap();
        assert!(
            found
                .iter()
                .any(|d| d.instance == "shushtst" && d.address.ends_with(":40123")),
            "{found:?}"
        );
        drop(ad);
        assert_eq!(discovery_daemons_live(), 0);
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
        // `mdns-sd` (issue #156) is allowed: its daemon is created only by
        // `NetGate::advertise_sync` / `discover_sync` above, and only this
        // file may name it (the text scan below still forbids "mdns" elsewhere).
        let cargo = std::fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
        let cargo = cargo
            .replace("mdns-sd = {", "")
            .replace("\"dep:mdns-sd\"", "");
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
