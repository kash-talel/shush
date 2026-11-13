//! RFC 6238 TOTP calculator (spec §8 `totp/mod.rs`, issue #24).
//!
//! Accepts either a bare Base32 secret (spaces, lowercase and `=` padding are
//! tolerated) or a full `otpauth://totp/...` URI, so algorithm, digit count and
//! period from the issuer are preserved.

use serde::Serialize;
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

/// Shortest accepted shared secret: 80 bits (common for Google-style issuers;
/// `totp-rs`' checked constructors would require 128 and reject these).
const MIN_SECRET_BYTES: usize = 10;

/// Why a TOTP secret could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// Not valid Base32 / not a parsable otpauth URI.
    #[error("not a valid TOTP secret or otpauth:// URI")]
    Invalid,
    /// Fewer than 80 bits of secret.
    #[error("TOTP secret is too short (needs at least 80 bits)")]
    TooShort,
    /// Digits outside 6..=8 (5 for Steam) or period outside 1..=300 s.
    #[error("unsupported TOTP parameters")]
    Unsupported,
    /// System clock is before 1970.
    #[error("system clock is invalid")]
    Clock,
}

/// A code ready for display. The code itself is short-lived by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TotpCode {
    /// The current code, e.g. `"492039"`.
    pub code: String,
    /// Step length in seconds.
    pub period: u64,
    /// Seconds until the code rotates.
    pub remaining: u64,
}

/// Parses a stored TOTP secret (Base32 or `otpauth://` URI).
pub fn parse(stored: &str) -> Result<TOTP, TotpError> {
    let stored = stored.trim();
    let lower = stored.to_ascii_lowercase();
    let totp = if lower.starts_with("otpauth://") {
        TOTP::from_url_unchecked(stored).map_err(|_| TotpError::Invalid)?
    } else if lower.starts_with("steam://") {
        // Steam Guard shared secret (Base32) in the `steam://` shorthand.
        let url = Zeroizing::new(format!("otpauth://steam/Steam?secret={}", &stored[8..]));
        TOTP::from_url_unchecked(url.as_str()).map_err(|_| TotpError::Invalid)?
    } else {
        let cleaned = Zeroizing::new(
            stored
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>(),
        );
        let bytes = Secret::Encoded(cleaned.to_string())
            .to_bytes()
            .map_err(|_| TotpError::Invalid)?;
        TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new())
    };
    validate(&totp)?;
    Ok(totp)
}

fn validate(t: &TOTP) -> Result<(), TotpError> {
    if t.secret.len() < MIN_SECRET_BYTES {
        return Err(TotpError::TooShort);
    }
    // Steam Guard codes are 5 characters from a custom alphabet.
    let digits_ok = if t.algorithm == Algorithm::Steam {
        t.digits == 5
    } else {
        (6..=8).contains(&t.digits)
    };
    if !digits_ok || !(1..=300).contains(&t.step) {
        return Err(TotpError::Unsupported);
    }
    Ok(())
}

/// Code for a given Unix time.
pub fn code_at(t: &TOTP, unix_secs: u64) -> TotpCode {
    TotpCode {
        code: t.generate(unix_secs),
        period: t.step,
        remaining: t.step - (unix_secs % t.step),
    }
}

/// Code for the current system time.
pub fn current_code(stored: &str) -> Result<TotpCode, TotpError> {
    let t = parse(stored)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TotpError::Clock)?
        .as_secs();
    Ok(code_at(&t, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, SHA-1, 8 digits; secret = ASCII "12345678901234567890".
    #[test]
    fn rfc6238_sha1_vectors() {
        let t = TOTP::new_unchecked(
            Algorithm::SHA1,
            8,
            1,
            30,
            b"12345678901234567890".to_vec(),
            None,
            String::new(),
        );
        for (time, code) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            assert_eq!(code_at(&t, time).code, code, "T={time}");
        }
    }

    #[test]
    fn base32_secret_is_normalised() {
        // Base32("12345678901234567890"), written the way sites display it.
        let t = parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(t.digits, 6);
        assert_eq!(code_at(&t, 59).code, "287082"); // last 6 digits of the RFC value
    }

    #[test]
    fn otpauth_uri_keeps_issuer_parameters() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8&period=60";
        let t = parse(uri).unwrap();
        assert_eq!(t.digits, 8);
        assert_eq!(t.step, 60);
        let c = code_at(&t, 119);
        assert_eq!(c.period, 60);
        assert_eq!(c.remaining, 1);
        assert_eq!(c.code.len(), 8);
    }

    #[test]
    fn sha256_and_sha512_algorithms_are_honoured() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let sha1 = parse(&format!("otpauth://totp/x?secret={secret}")).unwrap();
        let sha256 = parse(&format!(
            "otpauth://totp/x?secret={secret}&algorithm=SHA256"
        ))
        .unwrap();
        let sha512 = parse(&format!(
            "otpauth://totp/x?secret={secret}&algorithm=SHA512"
        ))
        .unwrap();
        assert_eq!(sha256.algorithm, Algorithm::SHA256);
        assert_eq!(sha512.algorithm, Algorithm::SHA512);
        let c = [&sha1, &sha256, &sha512].map(|t| code_at(t, 59).code);
        assert!(c[0] != c[1] && c[1] != c[2] && c[0] != c[2]);
    }

    #[test]
    fn steam_guard_uses_five_char_alphabet() {
        for stored in [
            "steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "otpauth://totp/Steam:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Steam",
        ] {
            let t = parse(stored).unwrap();
            assert_eq!(t.algorithm, Algorithm::Steam);
            let c = code_at(&t, 59);
            assert_eq!(c.code.len(), 5);
            assert_eq!(c.period, 30);
            assert!(c
                .code
                .chars()
                .all(|ch| "23456789BCDFGHJKMNPQRTVWXY".contains(ch)));
        }
    }

    #[test]
    fn accepts_80_bit_secrets_rejects_shorter() {
        assert!(parse("JBSWY3DPEHPK3PXPJBSW").is_ok()); // 100 bits
        assert!(parse("JBSWY3DPEHPK3PXP").is_ok()); // 80 bits
        assert_eq!(parse("JBSWY3DP").unwrap_err(), TotpError::TooShort);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse("not base32 at all!").unwrap_err(), TotpError::Invalid);
        assert!(parse("otpauth://totp/x?secret=").is_err());
    }

    #[test]
    fn remaining_counts_down_within_period() {
        let t = parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code_at(&t, 30).remaining, 30);
        assert_eq!(code_at(&t, 59).remaining, 1);
    }
}
