use super::*;
use minisign::KeyPair;
use std::io::Cursor;

const NOW: i64 = 1_800_000_000; // 2027-01-15

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

fn release_json(version: &str, installer: &[u8]) -> Vec<u8> {
    release_json_with(
        version,
        "windows-x86_64-nsis",
        "https://example.invalid/x.exe",
        installer,
    )
}

fn release_json_with(version: &str, target: &str, url: &str, installer: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"schema":1,"channel":"stable","version":"{version}","released_at":"{}","artifact":{{"target":"{target}","url":"{url}","sha256":"{}","size":{}}}}}"#,
        rfc(NOW - 100),
        sha256_hex(installer),
        installer.len()
    )
    .into_bytes()
}

fn fresh_json(release: &[u8], expires: i64) -> Vec<u8> {
    fresh_json_issued(release, NOW - 50, expires)
}

fn fresh_json_issued(release: &[u8], issued: i64, expires: i64) -> Vec<u8> {
    format!(
        r#"{{"schema":1,"channel":"stable","release_sha256":"{}","issued_at":"{}","expires_at":"{}"}}"#,
        sha256_hex(release),
        rfc(issued),
        rfc(expires)
    )
    .into_bytes()
}

/// Sign and verify arbitrary manifest bytes with the fixture's pinned keys.
fn run_raw(
    fx: &Fx,
    rel: &[u8],
    fresh: &[u8],
    st: &LocalState<'_>,
) -> Result<VerifiedRelease, UpdateError> {
    verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: rel,
            release_sig: &sign(&fx.rel_key, rel),
            freshness: fresh,
            freshness_sig: &sign(&fx.ts_key, fresh),
        },
        st,
    )
}

struct Fx {
    rel_key: Key,
    next_key: Key,
    ts_key: Key,
}

impl Fx {
    fn new() -> Self {
        Self {
            rel_key: key(),
            next_key: key(),
            ts_key: key(),
        }
    }
    fn anchors(&self) -> TrustAnchors {
        TrustAnchors {
            release: vec![self.rel_key.pin.clone(), self.next_key.pin.clone()],
            timestamp: vec![self.ts_key.pin.clone()],
        }
    }
}

fn local<'a>(installed: &'a str, highest: Option<&'a str>) -> LocalState<'a> {
    LocalState {
        channel: "stable",
        target: THIS_TARGET,
        installed,
        highest_seen: highest,
        now_unix: NOW,
    }
}

fn run(
    fx: &Fx,
    signer: &Key,
    version: &str,
    expires: i64,
    st: &LocalState<'_>,
) -> Result<VerifiedRelease, UpdateError> {
    let rel = release_json(version, b"installer");
    let fresh = fresh_json(&rel, expires);
    let (rs, fs) = (sign(signer, &rel), sign(&fx.ts_key, &fresh));
    verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: &rel,
            release_sig: &rs,
            freshness: &fresh,
            freshness_sig: &fs,
        },
        st,
    )
}

#[test]
fn valid_feed_reports_update() {
    let fx = Fx::new();
    let v = run(&fx, &fx.rel_key, "0.2.0", NOW + 1000, &local("0.1.1", None)).unwrap();
    assert!(v.update_available);
    assert_eq!(v.release_key_index, 0);
    assert_eq!(v.release.version, "0.2.0");
}

#[test]
fn same_version_is_up_to_date() {
    let fx = Fx::new();
    let v = run(&fx, &fx.rel_key, "0.1.1", NOW + 1000, &local("0.1.1", None)).unwrap();
    assert!(!v.update_available);
}

#[test]
fn next_key_accepted_unpinned_rejected() {
    let fx = Fx::new();
    let st = local("0.1.1", None);
    let v = run(&fx, &fx.next_key, "0.2.0", NOW + 1000, &st).unwrap();
    assert_eq!(v.release_key_index, 1);
    let rogue = key();
    assert_eq!(
        run(&fx, &rogue, "0.2.0", NOW + 1000, &st),
        Err(UpdateError::BadSignature("release.json"))
    );
}

#[test]
fn timestamp_key_cannot_sign_release_and_vice_versa() {
    let fx = Fx::new();
    let st = local("0.1.1", None);
    assert_eq!(
        run(&fx, &fx.ts_key, "0.2.0", NOW + 1000, &st),
        Err(UpdateError::BadSignature("release.json"))
    );
    let rel = release_json("0.2.0", b"installer");
    let fresh = fresh_json(&rel, NOW + 1000);
    let r = verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: &rel,
            release_sig: &sign(&fx.rel_key, &rel),
            freshness: &fresh,
            freshness_sig: &sign(&fx.rel_key, &fresh),
        },
        &st,
    );
    assert_eq!(r, Err(UpdateError::BadSignature("freshness.json")));
}

#[test]
fn tampered_release_fails_signature() {
    let fx = Fx::new();
    let rel = release_json("0.2.0", b"installer");
    let fresh = fresh_json(&rel, NOW + 1000);
    let mut bad = rel.clone();
    bad[10] ^= 1;
    let r = verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: &bad,
            release_sig: &sign(&fx.rel_key, &rel),
            freshness: &fresh,
            freshness_sig: &sign(&fx.ts_key, &fresh),
        },
        &local("0.1.1", None),
    );
    assert_eq!(r, Err(UpdateError::BadSignature("release.json")));
}

#[test]
fn freshness_for_a_different_release_is_rejected() {
    let fx = Fx::new();
    let old = release_json("0.2.0", b"installer");
    let newer = release_json("0.3.0", b"installer");
    let fresh = fresh_json(&old, NOW + 1000);
    let r = verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: &newer,
            release_sig: &sign(&fx.rel_key, &newer),
            freshness: &fresh,
            freshness_sig: &sign(&fx.ts_key, &fresh),
        },
        &local("0.1.1", None),
    );
    assert_eq!(r, Err(UpdateError::FreshnessMismatch));
}

#[test]
fn expired_freshness_is_stale() {
    let fx = Fx::new();
    let r = run(&fx, &fx.rel_key, "0.2.0", NOW - 1, &local("0.1.1", None));
    assert_eq!(r, Err(UpdateError::Stale));
}

#[test]
fn rollback_below_installed_or_highest_seen_is_rejected() {
    let fx = Fx::new();
    let r = run(&fx, &fx.rel_key, "0.1.0", NOW + 1000, &local("0.1.1", None));
    assert!(matches!(r, Err(UpdateError::Rollback { .. })));
    // Validly signed and fresh, but older than a release we already verified.
    let r = run(
        &fx,
        &fx.rel_key,
        "0.2.0",
        NOW + 1000,
        &local("0.1.1", Some("0.3.0")),
    );
    assert!(matches!(r, Err(UpdateError::Rollback { .. })));
}

#[test]
fn channel_mismatch_rejected() {
    let fx = Fx::new();
    let mut st = local("0.1.1", None);
    st.channel = "beta";
    assert_eq!(
        run(&fx, &fx.rel_key, "0.2.0", NOW + 1000, &st),
        Err(UpdateError::ChannelMismatch)
    );
}

#[test]
fn garbage_inputs_fail_closed() {
    let fx = Fx::new();
    let r = verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: b"{}",
            release_sig: "not a signature",
            freshness: b"{}",
            freshness_sig: "",
        },
        &local("0.1.1", None),
    );
    assert_eq!(r, Err(UpdateError::BadSignature("release.json")));
    assert!(PinnedKey::from_base64("nope").is_err());
}

#[test]
fn oversized_manifest_rejected() {
    let fx = Fx::new();
    let big = vec![b' '; MAX_MANIFEST_BYTES + 1];
    let r = verify_feed(
        &fx.anchors(),
        &FeedFiles {
            release: &big,
            release_sig: "",
            freshness: b"",
            freshness_sig: "",
        },
        &local("0.1.1", None),
    );
    assert_eq!(r, Err(UpdateError::Malformed("manifest too large")));
}

#[test]
fn download_must_match_signed_size_and_hash() {
    let fx = Fx::new();
    let v = run(&fx, &fx.rel_key, "0.2.0", NOW + 1000, &local("0.1.1", None)).unwrap();
    assert!(verify_download(&v.release, b"installer").is_ok());
    assert_eq!(
        verify_download(&v.release, b"installeR"),
        Err(UpdateError::ArtifactMismatch)
    );
    assert_eq!(
        verify_download(&v.release, b"installer!"),
        Err(UpdateError::ArtifactMismatch)
    );
}

#[test]
fn freshness_window_is_bounded() {
    let fx = Fx::new();
    let st = local("0.1.1", None);
    let rel = release_json("0.2.0", b"installer");
    // Exactly the maximum window is fine.
    let ok = fresh_json_issued(&rel, NOW - 50, NOW - 50 + MAX_FRESHNESS_SECS);
    assert!(run_raw(&fx, &rel, &ok, &st).is_ok());
    // One second longer, or a far-future expiry, is refused.
    let long = fresh_json_issued(&rel, NOW - 50, NOW - 50 + MAX_FRESHNESS_SECS + 1);
    assert_eq!(
        run_raw(&fx, &rel, &long, &st),
        Err(UpdateError::Malformed("freshness window"))
    );
    let forever = fresh_json_issued(&rel, NOW - 50, NOW + 100 * 365 * 86_400);
    assert_eq!(
        run_raw(&fx, &rel, &forever, &st),
        Err(UpdateError::Malformed("freshness window"))
    );
    // Expiry not after issue is refused.
    let inverted = fresh_json_issued(&rel, NOW + 10, NOW + 10);
    assert_eq!(
        run_raw(&fx, &rel, &inverted, &st),
        Err(UpdateError::Malformed("freshness window"))
    );
}

#[test]
fn freshness_issued_in_the_future_is_refused() {
    let fx = Fx::new();
    let st = local("0.1.1", None);
    let rel = release_json("0.2.0", b"installer");
    // Within clock-skew tolerance: accepted.
    let skew = fresh_json_issued(&rel, NOW + MAX_CLOCK_SKEW_SECS, NOW + 86_400);
    assert!(run_raw(&fx, &rel, &skew, &st).is_ok());
    // Beyond it (minted to outlive the window): refused.
    let ahead = fresh_json_issued(&rel, NOW + MAX_CLOCK_SKEW_SECS + 1, NOW + 86_400);
    assert_eq!(
        run_raw(&fx, &rel, &ahead, &st),
        Err(UpdateError::Malformed("freshness issued in the future"))
    );
}

#[test]
fn artifact_url_must_be_https() {
    let fx = Fx::new();
    let st = local("0.1.1", None);
    for url in [
        "http://example.invalid/x.exe",
        "file:///C:/Windows/x.exe",
        "ftp://example.invalid/x.exe",
        "not a url",
    ] {
        let rel = release_json_with("0.2.0", THIS_TARGET, url, b"installer");
        let fresh = fresh_json(&rel, NOW + 1000);
        assert_eq!(
            run_raw(&fx, &rel, &fresh, &st),
            Err(UpdateError::Malformed("artifact url")),
            "{url}"
        );
    }
}

#[test]
fn artifact_for_another_target_is_refused() {
    let fx = Fx::new();
    let rel = release_json_with(
        "0.2.0",
        "linux-aarch64-deb",
        "https://example.invalid/x.deb",
        b"installer",
    );
    let fresh = fresh_json(&rel, NOW + 1000);
    assert_eq!(
        run_raw(&fx, &rel, &fresh, &local("0.1.1", None)),
        Err(UpdateError::TargetMismatch)
    );
}

#[test]
fn prerelease_refused_on_stable_only() {
    let fx = Fx::new();
    let rel = release_json("0.2.0-rc.1", b"installer");
    let fresh = fresh_json(&rel, NOW + 1000);
    assert_eq!(
        run_raw(&fx, &rel, &fresh, &local("0.1.1", None)),
        Err(UpdateError::ChannelMismatch)
    );
    // The planned beta channel may offer pre-releases.
    let beta_rel = String::from_utf8(rel)
        .unwrap()
        .replace("\"stable\"", "\"beta\"")
        .into_bytes();
    let beta_fresh = String::from_utf8(fresh_json(&beta_rel, NOW + 1000))
        .unwrap()
        .replace("\"stable\"", "\"beta\"")
        .into_bytes();
    let mut st = local("0.1.1", None);
    st.channel = "beta";
    assert!(
        run_raw(&fx, &beta_rel, &beta_fresh, &st)
            .unwrap()
            .update_available
    );
}

#[test]
fn build_metadata_does_not_count_as_newer() {
    let fx = Fx::new();
    let v = run(
        &fx,
        &fx.rel_key,
        "0.1.1+rebuild",
        NOW + 1000,
        &local("0.1.1", None),
    )
    .unwrap();
    assert!(!v.update_available);
    // Nor older: same precedence is not a rollback either way.
    let v = run(
        &fx,
        &fx.rel_key,
        "0.1.1",
        NOW + 1000,
        &local("0.1.1+rebuild", None),
    )
    .unwrap();
    assert!(!v.update_available);
}
