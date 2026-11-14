use super::*;
use minisign::KeyPair;
use std::collections::HashMap;
use std::io::Cursor;

const NOW: i64 = 1_800_000_000;

struct Key {
    sk: minisign::SecretKey,
    pin: PinnedKey,
}

fn key() -> Key {
    let kp = KeyPair::generate_unencrypted_keypair().unwrap();
    let pin = PinnedKey::from_base64(&kp.pk.to_base64()).unwrap();
    Key { sk: kp.sk, pin }
}

fn sign(k: &Key, data: &[u8]) -> Vec<u8> {
    minisign::sign(None, &k.sk, Cursor::new(data), None, None)
        .unwrap()
        .to_string()
        .into_bytes()
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

fn sha(data: &[u8]) -> String {
    super::super::sha256_hex(data)
}

struct Fake(HashMap<String, Vec<u8>>);

impl Fetch for Fake {
    fn get(&self, path: &str, _max: usize) -> Result<Vec<u8>, NetError> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| NetError::Io("404".into()))
    }
}

struct Fx {
    rel: Key,
    ts: Key,
}

impl Fx {
    fn new() -> Self {
        Self {
            rel: key(),
            ts: key(),
        }
    }
    fn anchors(&self) -> TrustAnchors {
        TrustAnchors {
            release: vec![self.rel.pin.clone()],
            timestamp: vec![self.ts.pin.clone()],
        }
    }
    fn feed(&self, version: &str, min: Option<&str>, expires: i64) -> Fake {
        let min = min
            .map(|m| format!(r#","min_supported":"{m}","security":true"#))
            .unwrap_or_default();
        let release = format!(
            r#"{{"schema":1,"channel":"stable","version":"{version}","released_at":"{}"{min},"artifact":{{"target":"windows-x86_64-nsis","url":"https://example.invalid/x.exe","sha256":"{}","size":10}}}}"#,
            rfc(NOW - 100),
            "0".repeat(64)
        )
        .into_bytes();
        let fresh = format!(
            r#"{{"schema":1,"channel":"stable","release_sha256":"{}","issued_at":"{}","expires_at":"{}"}}"#,
            sha(&release),
            rfc(NOW - 50),
            rfc(expires)
        )
        .into_bytes();
        let p = |n: &str| format!("{FEED_PREFIX}/stable/{n}");
        let mut m = HashMap::new();
        m.insert(p("release.json.minisig"), sign(&self.rel, &release));
        m.insert(p("freshness.json.minisig"), sign(&self.ts, &fresh));
        m.insert(p("release.json"), release);
        m.insert(p("freshness.json"), fresh);
        Fake(m)
    }
}

#[test]
fn pinned_keys_parse() {
    let a = pinned_anchors();
    assert_eq!(a.release.len(), 2);
    assert_eq!(a.timestamp.len(), 1);
}

#[test]
fn reports_available_up_to_date_and_below_min() {
    let fx = Fx::new();
    let exp = NOW + 3600;
    let f = fx.feed("0.2.0", None, exp);
    assert_eq!(
        check(&f, &fx.anchors(), "0.1.2", NOW),
        UpdateStatus::Available {
            version: "0.2.0".into(),
            security: false,
            below_min_supported: false
        }
    );
    assert_eq!(
        check(&f, &fx.anchors(), "0.2.0", NOW),
        UpdateStatus::UpToDate {
            verified_until: exp
        }
    );
    let f = fx.feed("0.3.0", Some("0.2.5"), exp);
    assert_eq!(
        check(&f, &fx.anchors(), "0.2.0", NOW),
        UpdateStatus::Available {
            version: "0.3.0".into(),
            security: true,
            below_min_supported: true
        }
    );
}

#[test]
fn expired_feed_is_stale_never_up_to_date() {
    let fx = Fx::new();
    let f = fx.feed("0.1.2", None, NOW - 1);
    assert_eq!(check(&f, &fx.anchors(), "0.1.2", NOW), UpdateStatus::Stale);
}

#[test]
fn rollback_and_wrong_keys_fail() {
    let fx = Fx::new();
    let f = fx.feed("0.1.0", None, NOW + 3600);
    assert!(matches!(
        check(&f, &fx.anchors(), "0.1.2", NOW),
        UpdateStatus::Failed {
            code: "UPDATE_ROLLBACK",
            ..
        }
    ));
    let other = Fx::new();
    assert!(matches!(
        check(&f, &other.anchors(), "0.1.0", NOW),
        UpdateStatus::Failed {
            code: "UPDATE_FEED_UNTRUSTED",
            ..
        }
    ));
}

#[test]
fn fetch_failures_and_air_gap_are_failures() {
    let fx = Fx::new();
    let empty = Fake(HashMap::new());
    assert!(matches!(
        check(&empty, &fx.anchors(), "0.1.2", NOW),
        UpdateStatus::Failed {
            code: "UPDATE_FETCH_FAILED",
            ..
        }
    ));
    let gate = NetGate::default();
    assert!(matches!(
        check(&GateFetch(&gate), &fx.anchors(), "0.1.2", NOW),
        UpdateStatus::Failed {
            code: "UPDATE_AIR_GAPPED",
            ..
        }
    ));
    assert_eq!(gate.sockets_opened(), 0);
}

#[test]
fn beta_installs_follow_beta_channel() {
    assert_eq!(channel_for("0.3.0-beta.1"), "beta");
    assert_eq!(channel_for("0.3.0"), "stable");
}

#[test]
fn mode_persists_and_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Notify, "default");
    UpdateMode::Off.save(d.path()).unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Off);
    UpdateMode::Notify.save(d.path()).unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Notify);
    std::fs::write(d.path().join(SETTINGS_FILE), b"garbage").unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Off);
}
