use super::*;
use crate::update::client::FEED_PREFIX;
use crate::update::PinnedKey;
use base64::Engine as _;
use minisign::KeyPair;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Cursor;

const NOW: i64 = 1_800_000_000;
const URL: &str = "https://example.invalid/shush_x64-setup.exe";

struct Key {
    sk: minisign::SecretKey,
    pin: PinnedKey,
}

fn key() -> Key {
    let kp = KeyPair::generate_unencrypted_keypair().unwrap();
    let pin = PinnedKey::from_base64(&kp.pk.to_base64()).unwrap();
    Key { sk: kp.sk, pin }
}

fn sign(k: &Key, data: &[u8]) -> String {
    minisign::sign(None, &k.sk, Cursor::new(data), None, None)
        .unwrap()
        .to_string()
}

fn rfc(unix: i64) -> String {
    let t = time::OffsetDateTime::from_unix_timestamp(unix).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

struct Fx {
    rel: Key,
    ts: Key,
    installer: Vec<u8>,
}

/// How `latest.json` is built for a feed.
struct Latest<'a> {
    version: &'a str,
    url: &'a str,
    /// The `signature` field (base64 of minisign text); `None` leaves the platform out.
    sig: Option<String>,
}

impl Fx {
    fn new() -> Self {
        Self {
            rel: key(),
            ts: key(),
            installer: (0..5000u32).map(|i| (i % 251) as u8).collect(),
        }
    }

    fn anchors(&self) -> TrustAnchors {
        TrustAnchors {
            release: vec![self.rel.pin.clone()],
            timestamp: vec![self.ts.pin.clone()],
        }
    }

    fn good_sig(&self) -> String {
        b64(&sign(&self.rel, &self.installer))
    }

    fn feed(&self, version: &str) -> HashMap<String, Vec<u8>> {
        self.feed_with(
            version,
            Latest {
                version,
                url: URL,
                sig: Some(self.good_sig()),
            },
        )
    }

    fn feed_with(&self, version: &str, latest: Latest<'_>) -> HashMap<String, Vec<u8>> {
        let release = format!(
            r#"{{"schema":1,"channel":"stable","version":"{version}","released_at":"{}","artifact":{{"target":"windows-x86_64-nsis","url":"{URL}","sha256":"{}","size":{}}}}}"#,
            rfc(NOW - 100),
            crate::update::sha256_hex(&self.installer),
            self.installer.len()
        )
        .into_bytes();
        let fresh = format!(
            r#"{{"schema":1,"channel":"stable","release_sha256":"{}","issued_at":"{}","expires_at":"{}"}}"#,
            crate::update::sha256_hex(&release),
            rfc(NOW - 50),
            rfc(NOW + 3600)
        )
        .into_bytes();
        let platforms = match latest.sig {
            Some(sig) => format!(
                r#"{{"windows-x86_64":{{"signature":"{sig}","url":"{}"}}}}"#,
                latest.url
            ),
            None => "{}".into(),
        };
        let latest = format!(
            r#"{{"version":"{}","notes":"n","pub_date":"{}","platforms":{platforms}}}"#,
            latest.version,
            rfc(NOW - 100)
        );
        let p = |n: &str| format!("{FEED_PREFIX}/stable/{n}");
        let mut m = HashMap::new();
        m.insert(
            p("release.json.minisig"),
            sign(&self.rel, &release).into_bytes(),
        );
        m.insert(
            p("freshness.json.minisig"),
            sign(&self.ts, &fresh).into_bytes(),
        );
        m.insert(p("release.json"), release);
        m.insert(p("freshness.json"), fresh);
        m.insert(p("latest.json"), latest.into_bytes());
        m
    }
}

/// One download attempt's behaviour.
#[derive(Clone)]
enum Dl {
    /// Write the whole body and succeed.
    Ok,
    /// Write these bytes instead and succeed (tampered or short body the gate missed).
    Body(Vec<u8>),
    /// Write half, then a network error.
    NetErr,
    /// Write half, then the gate closes.
    AirGap,
}

struct Src {
    files: RefCell<HashMap<String, Vec<u8>>>,
    /// Replaces `files` after the first complete feed fetch (a deploy between two checks).
    next: RefCell<Option<HashMap<String, Vec<u8>>>>,
    body: Vec<u8>,
    script: RefCell<Vec<Dl>>,
    downloads: Cell<usize>,
}

impl Src {
    fn new(fx: &Fx, files: HashMap<String, Vec<u8>>, script: Vec<Dl>) -> Self {
        Self {
            files: RefCell::new(files),
            next: RefCell::new(None),
            body: fx.installer.clone(),
            script: RefCell::new(script),
            downloads: Cell::new(0),
        }
    }
}

impl Fetch for Src {
    fn get(&self, path: &str, _max: usize) -> Result<Vec<u8>, NetError> {
        let r = self
            .files
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| NetError::Io("404".into()));
        if path.ends_with("release.json.minisig") {
            if let Some(n) = self.next.borrow_mut().take() {
                *self.files.borrow_mut() = n;
            }
        }
        r
    }
}

impl Source for Src {
    fn download(&self, url: &str, size: u64, out: &mut dyn Write) -> Result<(), NetError> {
        assert_eq!(url, URL);
        assert_eq!(size, self.body.len() as u64);
        self.downloads.set(self.downloads.get() + 1);
        let step = {
            let mut s = self.script.borrow_mut();
            if s.is_empty() {
                Dl::Ok
            } else {
                s.remove(0)
            }
        };
        let half = &self.body[..self.body.len() / 2];
        match step {
            Dl::Ok => out
                .write_all(&self.body)
                .map_err(|e| NetError::Io(e.to_string())),
            Dl::Body(b) => out.write_all(&b).map_err(|e| NetError::Io(e.to_string())),
            Dl::NetErr => {
                out.write_all(half).unwrap();
                Err(NetError::Io("connection reset".into()))
            }
            Dl::AirGap => {
                out.write_all(half).unwrap();
                Err(NetError::AirGapped)
            }
        }
    }
}

struct Dirs {
    _t: tempfile::TempDir,
    dir: PathBuf,
    state: PathBuf,
}

fn dirs() -> Dirs {
    let t = tempfile::tempdir().unwrap();
    Dirs {
        dir: t.path().join("local").join("updates"),
        state: t.path().join("roaming"),
        _t: t,
    }
}

fn run(fx: &Fx, src: &Src, d: &Dirs, expected: &str) -> Result<Staged, Fail> {
    download(
        src,
        &Request {
            anchors: &fx.anchors(),
            installed: "0.1.2",
            expected,
            now_unix: NOW,
            dir: &d.dir,
            state_dir: &d.state,
        },
    )
}

/// Nothing left in the private directory and `highest_seen` untouched.
fn assert_clean(d: &Dirs) {
    let left = std::fs::read_dir(&d.dir).map(|r| r.count()).unwrap_or(0);
    assert_eq!(left, 0, "files left behind");
    assert_eq!(load_highest_seen(&d.state), None, "highest_seen moved");
}

fn code(r: Result<Staged, Fail>) -> &'static str {
    r.map(|s| s.version().to_owned()).unwrap_err().code
}

#[test]
fn valid_update_is_staged_sealed_and_ratchets_highest_seen() {
    let fx = Fx::new();
    let d = dirs();
    let src = Src::new(&fx, fx.feed("0.2.0"), vec![]);
    let mut s = run(&fx, &src, &d, "0.2.0").unwrap();
    assert_eq!(s.version(), "0.2.0");
    assert_eq!(s.path().parent(), Some(d.dir.as_path()));
    assert_eq!(std::fs::read(s.path()).unwrap(), fx.installer);
    assert_eq!(load_highest_seen(&d.state).as_deref(), Some("0.2.0"));
    s.recheck(&fx.anchors()).unwrap();
    #[cfg(windows)]
    {
        // While staged, nobody can rewrite or delete the verified bytes.
        assert!(std::fs::OpenOptions::new()
            .write(true)
            .open(s.path())
            .is_err());
        assert!(std::fs::remove_file(s.path()).is_err());
    }
    let path = s.path().to_owned();
    s.discard();
    assert!(!path.exists());
}

#[test]
fn feed_changed_since_the_check_is_refused_after_one_recheck() {
    let fx = Fx::new();
    let d = dirs();
    let src = Src::new(&fx, fx.feed("0.3.0"), vec![]);
    let f = run(&fx, &src, &d, "0.2.0").unwrap_err();
    assert_eq!(f.code, "UPDATE_FEED_MISMATCH");
    assert!(matches!(
        f.status,
        Some(UpdateStatus::Available { ref version, .. }) if version == "0.3.0"
    ));
    assert_eq!(src.downloads.get(), 0, "never downloads unagreed bytes");
    assert_clean(&d);

    // A deploy that settles back on the agreed version during the re-check proceeds.
    let src = Src::new(&fx, fx.feed("0.3.0"), vec![]);
    *src.next.borrow_mut() = Some(fx.feed("0.2.0"));
    assert_eq!(run(&fx, &src, &d, "0.2.0").unwrap().version(), "0.2.0");
}

#[test]
fn latest_json_must_agree_with_release_json() {
    let fx = Fx::new();
    let d = dirs();
    let other_version = fx.feed_with(
        "0.2.0",
        Latest {
            version: "0.2.1",
            url: URL,
            sig: Some(fx.good_sig()),
        },
    );
    let src = Src::new(&fx, other_version, vec![]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_FEED_MISMATCH");
    let other_url = fx.feed_with(
        "0.2.0",
        Latest {
            version: "0.2.0",
            url: "https://evil.invalid/x.exe",
            sig: Some(fx.good_sig()),
        },
    );
    let src2 = Src::new(&fx, other_url, vec![]);
    assert_eq!(code(run(&fx, &src2, &d, "0.2.0")), "UPDATE_FEED_MISMATCH");
    assert_eq!(src.downloads.get() + src2.downloads.get(), 0);
    assert_clean(&d);
}

#[test]
fn missing_or_wrong_signature_is_rejected_and_deleted() {
    let fx = Fx::new();
    let d = dirs();
    for sig in [None, Some(b64("not a signature")), Some("%%%".into())] {
        let feed = fx.feed_with(
            "0.2.0",
            Latest {
                version: "0.2.0",
                url: URL,
                sig,
            },
        );
        let src = Src::new(&fx, feed, vec![]);
        assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_DOWNLOAD_INVALID");
        assert_eq!(src.downloads.get(), 0, "undecodable signature: no download");
    }
    // A well-formed signature by a key that is not pinned.
    let stranger = key();
    let feed = fx.feed_with(
        "0.2.0",
        Latest {
            version: "0.2.0",
            url: URL,
            sig: Some(b64(&sign(&stranger, &fx.installer))),
        },
    );
    let src = Src::new(&fx, feed, vec![]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_DOWNLOAD_INVALID");
    // The pinned key, but over other bytes.
    let feed = fx.feed_with(
        "0.2.0",
        Latest {
            version: "0.2.0",
            url: URL,
            sig: Some(b64(&sign(&fx.rel, b"something else"))),
        },
    );
    let src = Src::new(&fx, feed, vec![]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_DOWNLOAD_INVALID");
    assert_clean(&d);
}

#[test]
fn tampered_or_wrong_size_bytes_are_rejected_and_deleted() {
    let fx = Fx::new();
    let d = dirs();
    let mut tampered = fx.installer.clone();
    tampered[100] ^= 1;
    let short = fx.installer[..fx.installer.len() - 1].to_vec();
    for body in [tampered, short] {
        let src = Src::new(&fx, fx.feed("0.2.0"), vec![Dl::Body(body)]);
        assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_DOWNLOAD_INVALID");
        assert_clean(&d);
    }
}

#[test]
fn network_failures_retry_then_clean_up() {
    let fx = Fx::new();
    let d = dirs();
    // One failure, then success: the partial bytes from the first try are discarded.
    let src = Src::new(&fx, fx.feed("0.2.0"), vec![Dl::NetErr]);
    let s = run(&fx, &src, &d, "0.2.0").unwrap();
    assert_eq!(src.downloads.get(), 2);
    assert_eq!(std::fs::read(s.path()).unwrap(), fx.installer);
    s.discard();

    let d = dirs();
    let src = Src::new(&fx, fx.feed("0.2.0"), vec![Dl::NetErr; ATTEMPTS + 2]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_DOWNLOAD_FAILED");
    assert_eq!(src.downloads.get(), ATTEMPTS, "retries are capped");
    assert_clean(&d);
}

#[test]
fn air_gap_mid_download_stops_without_retry() {
    let fx = Fx::new();
    let d = dirs();
    let src = Src::new(&fx, fx.feed("0.2.0"), vec![Dl::AirGap]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_AIR_GAPPED");
    assert_eq!(src.downloads.get(), 1, "no further connection");
    assert_clean(&d);
}

#[test]
fn rollback_floor_comes_from_highest_seen() {
    let fx = Fx::new();
    let d = dirs();
    save_highest_seen(&d.state, "0.5.0").unwrap();
    let src = Src::new(&fx, fx.feed("0.2.0"), vec![]);
    assert_eq!(code(run(&fx, &src, &d, "0.2.0")), "UPDATE_ROLLBACK");
    assert_eq!(src.downloads.get(), 0);
    assert_eq!(load_highest_seen(&d.state).as_deref(), Some("0.5.0"));
}

#[test]
fn up_to_date_feed_offers_nothing_to_download() {
    let fx = Fx::new();
    let d = dirs();
    let src = Src::new(&fx, fx.feed("0.1.2"), vec![]);
    let f = run(&fx, &src, &d, "0.1.2").unwrap_err();
    assert_eq!(f.code, "UPDATE_NONE");
    assert!(matches!(f.status, Some(UpdateStatus::UpToDate { .. })));
}

#[test]
fn highest_seen_only_rises_and_fails_closed_to_none() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(load_highest_seen(d.path()), None);
    save_highest_seen(d.path(), "0.3.0").unwrap();
    save_highest_seen(d.path(), "0.2.0").unwrap();
    assert_eq!(load_highest_seen(d.path()).as_deref(), Some("0.3.0"));
    save_highest_seen(d.path(), "0.3.1").unwrap();
    assert_eq!(load_highest_seen(d.path()).as_deref(), Some("0.3.1"));
    std::fs::write(d.path().join(HIGHEST_SEEN_FILE), b"garbage").unwrap();
    assert_eq!(load_highest_seen(d.path()), None);
    assert!(save_highest_seen(d.path(), "not-semver").is_err());
}

#[test]
fn disk_full_has_its_own_message() {
    for code in [39, 112] {
        let f = storage_fail(&std::io::Error::from_raw_os_error(code));
        assert_eq!(f.code, "UPDATE_DISK_FULL");
    }
    let f = storage_fail(&std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(f.code, "UPDATE_STORAGE_FAILED");
}

/// The sealed handle (read share only) still lets Windows start the file, and the arguments
/// reach it. Uses a copy of `cmd.exe` as the "installer".
#[cfg(windows)]
#[test]
fn sealed_installer_can_still_be_launched() {
    let d = tempfile::tempdir().unwrap();
    let sys = std::env::var_os("SystemRoot").unwrap();
    let path = d.path().join("setup.exe");
    std::fs::copy(Path::new(&sys).join("System32").join("cmd.exe"), &path).unwrap();
    let release: ReleaseManifest = serde_json::from_str(&format!(
        r#"{{"schema":1,"channel":"stable","version":"0.2.0","released_at":"x","artifact":{{"target":"t","url":"{URL}","sha256":"00","size":1}}}}"#
    ))
    .unwrap();
    let s = Staged {
        version: "0.2.0".into(),
        file: open_sealed(&path).unwrap(),
        path,
        release,
        sig: String::new(),
    };
    let status = s.launch_with(&["/c", "exit", "7"]).unwrap().wait().unwrap();
    assert_eq!(status.code(), Some(7));
    s.discard();
}

/// End to end against the deployed stable feed and the real GitHub release asset: real gate, TLS,
/// redirect to the asset CDN, pinned keys, installer signature (run with `--ignored`; needs
/// internet; downloads the installer once).
#[cfg(feature = "network")]
#[test]
#[ignore]
fn live_download_verifies_with_pinned_keys() {
    let gate = crate::net::NetGate::default();
    gate.set_air_gapped(false);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let anchors = crate::update::client::pinned_anchors();
    let src = GateFetch(&gate);
    let version = match crate::update::client::check(&src, &anchors, "0.0.1", None, now) {
        UpdateStatus::Available { version, .. } => version,
        s => panic!("live feed did not verify: {s:?}"),
    };
    let d = dirs();
    let s = download(
        &src,
        &Request {
            anchors: &anchors,
            installed: "0.0.1",
            expected: &version,
            now_unix: now,
            dir: &d.dir,
            state_dir: &d.state,
        },
    )
    .unwrap();
    assert_eq!(s.version(), version);
    assert_eq!(load_highest_seen(&d.state), Some(version));
    s.discard();
}
