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
