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
        self.feed_on("stable", version, min, expires)
    }
    fn feed_on(&self, channel: &str, version: &str, min: Option<&str>, expires: i64) -> Fake {
        self.feed_full(channel, version, min, expires, None)
    }
    fn feed_full(
        &self,
        channel: &str,
        version: &str,
        min: Option<&str>,
        expires: i64,
        vault_format: Option<u32>,
    ) -> Fake {
        let vf = vault_format
            .map(|f| format!(r#","vault_format":{f}"#))
            .unwrap_or_default();
        let min = min
            .map(|m| format!(r#","min_supported":"{m}","security":true"#))
            .unwrap_or_default();
        let release = format!(
            r#"{{"schema":1,"channel":"{channel}","version":"{version}","released_at":"{}"{min}{vf},"artifact":{{"target":"windows-x86_64-nsis","url":"https://example.invalid/x.exe","sha256":"{}","size":10}}}}"#,
            rfc(NOW - 100),
            "0".repeat(64)
        )
        .into_bytes();
        let fresh = format!(
            r#"{{"schema":1,"channel":"{channel}","release_sha256":"{}","issued_at":"{}","expires_at":"{}"}}"#,
            sha(&release),
            rfc(NOW - 50),
            rfc(expires)
        )
        .into_bytes();
        let p = |n: &str| format!("{FEED_PREFIX}/{channel}/{n}");
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
        check(&f, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Available {
            version: "0.2.0".into(),
            security: false,
            below_min_supported: false,
            changes_vault_format: false
        }
    );
    assert_eq!(
        check(&f, &fx.anchors(), "0.2.0", None, NOW),
        UpdateStatus::UpToDate {
            verified_until: exp
        }
    );
    let f = fx.feed("0.3.0", Some("0.2.5"), exp);
    assert_eq!(
        check(&f, &fx.anchors(), "0.2.0", None, NOW),
        UpdateStatus::Available {
            version: "0.3.0".into(),
            security: true,
            below_min_supported: true,
            changes_vault_format: false
        }
    );
}

#[test]
fn newer_vault_format_is_flagged_and_lower_or_equal_is_ignored() {
    use crate::vault::container::FORMAT_VERSION;
    let fx = Fx::new();
    let cur = u32::from(FORMAT_VERSION);
    let flag = |fmt: Option<u32>| {
        let f = fx.feed_full("stable", "0.2.0", None, NOW + 3600, fmt);
        match check(&f, &fx.anchors(), "0.1.2", None, NOW) {
            UpdateStatus::Available {
                changes_vault_format,
                ..
            } => changes_vault_format,
            other => panic!("{other:?}"),
        }
    };
    assert!(flag(Some(cur + 1)));
    assert!(!flag(Some(cur)));
    assert!(!flag(Some(cur - 1)), "a lower feed value is ignored");
    assert!(!flag(None));
}

#[test]
fn expired_feed_is_stale_never_up_to_date() {
    let fx = Fx::new();
    let f = fx.feed("0.1.2", None, NOW - 1);
    assert_eq!(
        check(&f, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Stale
    );
}

#[test]
fn rollback_and_wrong_keys_fail() {
    let fx = Fx::new();
    let f = fx.feed("0.1.0", None, NOW + 3600);
    assert!(matches!(
        check(&f, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Failed {
            code: "UPDATE_ROLLBACK",
            ..
        }
    ));
    let other = Fx::new();
    assert!(matches!(
        check(&f, &other.anchors(), "0.1.0", None, NOW),
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
        check(&empty, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Failed {
            code: "UPDATE_FETCH_FAILED",
            ..
        }
    ));
    let gate = NetGate::default();
    assert!(matches!(
        check(&GateFetch(&gate), &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Failed {
            code: "UPDATE_AIR_GAPPED",
            ..
        }
    ));
    assert_eq!(gate.sockets_opened(), 0);
}

/// Serves `freshness.json(.minisig)` from `old` for the first `mixed` requests and everything
/// else from `new`: a feed deploy landing between the requests of one check.
struct MidDeploy {
    old: Fake,
    new: Fake,
    mixed: usize,
    calls: std::cell::Cell<usize>,
}

impl Fetch for MidDeploy {
    fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, NetError> {
        let n = self.calls.get();
        self.calls.set(n + 1);
        if n < self.mixed && path.contains("freshness") {
            self.old.get(path, max)
        } else {
            self.new.get(path, max)
        }
    }
}

#[test]
fn deploy_between_requests_is_retried_once() {
    let fx = Fx::new();
    let exp = NOW + 3600;
    let f = MidDeploy {
        old: fx.feed("0.2.0", None, exp),
        new: fx.feed("0.3.0", None, exp),
        mixed: 4,
        calls: Default::default(),
    };
    assert_eq!(
        check(&f, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Available {
            version: "0.3.0".into(),
            security: false,
            below_min_supported: false,
            changes_vault_format: false
        }
    );
    assert_eq!(f.calls.get(), 8, "exactly one retry");
    // A pair that never matches is reported as a mismatch, not as a bad signature.
    let f = MidDeploy {
        old: fx.feed("0.2.0", None, exp),
        new: fx.feed("0.3.0", None, exp),
        mixed: usize::MAX,
        calls: Default::default(),
    };
    assert!(matches!(
        check(&f, &fx.anchors(), "0.1.2", None, NOW),
        UpdateStatus::Failed {
            code: "UPDATE_FEED_MISMATCH",
            ..
        }
    ));
}

/// End to end against the deployed stable feed: real gate, real TLS, real pinned keys
/// (run with `--ignored`; needs internet and a feed newer than 0.0.1).
#[cfg(feature = "network")]
#[test]
#[ignore]
fn live_feed_verifies_with_pinned_keys() {
    let gate = NetGate::default();
    gate.set_air_gapped(false);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let s = check(&GateFetch(&gate), &pinned_anchors(), "0.0.1", None, now);
    assert!(
        matches!(s, UpdateStatus::Available { .. }),
        "live feed did not verify: {s:?}"
    );
    // The same signed feed with no pinned keys is refused.
    let none = TrustAnchors {
        release: vec![],
        timestamp: vec![],
    };
    assert!(matches!(
        check(&GateFetch(&gate), &none, "0.0.1", None, now),
        UpdateStatus::Failed {
            code: "UPDATE_FEED_UNTRUSTED",
            ..
        }
    ));
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
    // The new mode round-trips, and an unknown name still means off.
    UpdateMode::DownloadThenAsk.save(d.path()).unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::DownloadThenAsk);
    assert_eq!(
        serde_json::to_string(&UpdateMode::DownloadThenAsk).unwrap(),
        "\"download_then_ask\""
    );
    std::fs::write(d.path().join(SETTINGS_FILE), br#"{"mode":"auto_install"}"#).unwrap();
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Off);
}

#[test]
fn failed_mode_save_leaves_the_saved_mode_untouched() {
    // The command saves before changing the mode in effect; a failed save must report an error
    // and leave the old file as it was (the UI then shows the mode really in effect, #195).
    let d = tempfile::tempdir().unwrap();
    UpdateMode::Off.save(d.path()).unwrap();
    // A directory where the temp file goes makes the write fail.
    std::fs::create_dir(d.path().join(format!("{SETTINGS_FILE}.tmp"))).unwrap();
    assert!(UpdateMode::DownloadThenAsk.save(d.path()).is_err());
    assert_eq!(UpdateMode::load(d.path()), UpdateMode::Off);
}

#[test]
fn beta_install_takes_the_higher_of_beta_and_stable() {
    let fx = Fx::new();
    let a = fx.anchors();
    let exp = NOW + 3600;
    let both = |beta: &str, stable: &str| {
        let mut m = fx.feed_on("beta", beta, None, exp).0;
        m.extend(fx.feed_on("stable", stable, None, exp).0);
        Fake(m)
    };
    let version = |f: &Fake, installed: &str| match check(f, &a, installed, None, NOW) {
        UpdateStatus::Available { version, .. } => version,
        other => panic!("{other:?}"),
    };
    // Stable newer than the last beta: offered to the beta install.
    assert_eq!(
        version(&both("0.3.0-beta.2", "0.3.0"), "0.3.0-beta.1"),
        "0.3.0"
    );
    // A newer beta than stable stays on beta.
    assert_eq!(
        version(&both("0.4.0-beta.1", "0.3.0"), "0.3.0-beta.1"),
        "0.4.0-beta.1"
    );
    // Stable older than the installed beta is a rollback on that feed only: beta still answers.
    let f = both("0.3.0-beta.2", "0.2.0");
    assert!(matches!(
        check(&f, &a, "0.3.0-beta.2", None, NOW),
        UpdateStatus::UpToDate { .. }
    ));
    // No beta feed at all: the stable release is still offered.
    let f = fx.feed_on("stable", "0.3.0", None, exp);
    assert_eq!(version(&f, "0.3.0-beta.1"), "0.3.0");
    // A stable install never reads the beta feed.
    let f = fx.feed_on("beta", "0.4.0-beta.1", None, exp);
    assert!(matches!(
        check(&f, &a, "0.3.0", None, NOW),
        UpdateStatus::Failed { .. }
    ));
}

#[test]
fn beta_install_is_never_up_to_date_while_the_stable_feed_is_unconfirmed() {
    let fx = Fx::new();
    let a = fx.anchors();
    let exp = NOW + 3600;
    let installed = "0.3.0-beta.2";
    let with_stable = |stable: Option<Fake>| {
        let mut m = fx.feed_on("beta", installed, None, exp).0;
        if let Some(s) = stable {
            m.extend(s.0);
        }
        Fake(m)
    };
    // Beta is current but the stable feed cannot be reached: not "up to date".
    let f = with_stable(None);
    assert!(matches!(
        check(&f, &a, installed, None, NOW),
        UpdateStatus::Failed { .. }
    ));
    // Beta is current but the stable feed is stale (a freeze): reported as stale.
    let f = with_stable(Some(fx.feed_on("stable", "0.3.0", None, NOW - 1)));
    assert!(matches!(
        check(&f, &a, installed, None, NOW),
        UpdateStatus::Stale
    ));
    // A stable release older than the beta is expected and still reads as up to date.
    let f = with_stable(Some(fx.feed_on("stable", "0.2.0", None, exp)));
    assert!(matches!(
        check(&f, &a, installed, None, NOW),
        UpdateStatus::UpToDate { .. }
    ));
    // A beta offer is never hidden by a stable failure.
    let mut m = fx.feed_on("beta", "0.4.0-beta.1", None, exp).0;
    m.extend(fx.feed_on("stable", "0.3.0", None, NOW - 1).0);
    match check(&Fake(m), &a, installed, None, NOW) {
        UpdateStatus::Available { version, .. } => assert_eq!(version, "0.4.0-beta.1"),
        other => panic!("{other:?}"),
    }
}
