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
        use std::io::{Read, Write};
        use std::net::ToSocketAddrs;
        use std::sync::Arc;

        let ok_host = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        let ok_path = path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic());
        let ok_ua = user_agent.bytes().all(|b| (0x20..0x7f).contains(&b));
        if !ok_host || !ok_path || !ok_ua {
            return Err(NetError::Io("invalid request".into()));
        }
        let io = |e: &dyn std::fmt::Display| NetError::Io(e.to_string());
        let deadline = std::time::Instant::now() + timeout * 3;

        let addrs: Vec<_> = (host, 443u16)
            .to_socket_addrs()
            .map_err(|e| io(&e))?
            .collect();
        let mut tcp = None;
        for a in &addrs {
            if let Ok(s) = self.tcp_connect(a, timeout) {
                tcp = Some(s);
                break;
            }
        }
        let tcp = tcp.ok_or_else(|| NetError::Io("could not connect".into()))?;
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
        let bad = g.https_get("self-signed.badssl.com", "/", "shush/test", 1 << 20, t);
        assert!(bad.is_err());
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
