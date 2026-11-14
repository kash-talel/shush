//! Per-item hybrid logical clock for LAN sync merges (issue #137, spec §9.2).
//!
//! A clock value is `(physical_ms, counter, device_id)`, compared in that
//! order. It orders edits *between devices* without trusting either side's
//! wall clock: a peer claiming a time more than [`MAX_DRIFT_MS`] ahead of ours
//! is parked instead of merged ([`Hlc::is_plausible`]), and no clock value ever
//! decides which password is active (see `sync_merge`).

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Largest accepted lead of a received clock over local time (24 h).
pub const MAX_DRIFT_MS: u64 = 24 * 60 * 60 * 1000;

/// A hybrid logical clock value. Ordering is `(physical_ms, counter, device_id)`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Zeroize)]
#[cfg_attr(test, derive(Debug))]
pub struct Hlc {
    /// Milliseconds since the Unix epoch (never behind a value already issued).
    pub physical_ms: u64,
    /// Tie-breaker for values issued within the same millisecond.
    pub counter: u32,
    /// Id of the device that issued it (final deterministic tie-break).
    pub device_id: String,
}

/// Current Unix time in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Hlc {
    /// The next value strictly greater than `last` (and than every value this
    /// device issued), given local time `now_ms`.
    pub fn next(last: Option<&Hlc>, now_ms: u64, device_id: &str) -> Hlc {
        let (physical_ms, counter) = match last {
            Some(l) if l.physical_ms >= now_ms => (l.physical_ms, l.counter.saturating_add(1)),
            _ => (now_ms, 0),
        };
        Hlc {
            physical_ms,
            counter,
            device_id: device_id.to_string(),
        }
    }

    /// Whether this clock is no more than [`MAX_DRIFT_MS`] ahead of `now_ms`.
    pub fn is_plausible(&self, now_ms: u64) -> bool {
        self.physical_ms <= now_ms.saturating_add(MAX_DRIFT_MS)
    }
}

/// `a > b`, where a missing clock (legacy data) is older than any clock.
pub fn newer(a: Option<&Hlc>, b: Option<&Hlc>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_is_monotonic_even_if_the_wall_clock_goes_back() {
        let a = Hlc::next(None, 1000, "d");
        let b = Hlc::next(Some(&a), 1000, "d");
        let c = Hlc::next(Some(&b), 500, "d");
        assert!(a < b && b < c);
        assert_eq!((c.physical_ms, c.counter), (1000, 2));
        let d = Hlc::next(Some(&c), 2000, "d");
        assert_eq!((d.physical_ms, d.counter), (2000, 0));
    }

    #[test]
    fn device_id_breaks_ties_and_missing_is_oldest() {
        let a = Hlc::next(None, 1, "a");
        let b = Hlc::next(None, 1, "b");
        assert!(b > a);
        assert!(newer(Some(&a), None));
        assert!(!newer(None, Some(&a)));
        assert!(!newer(None, None));
    }

    #[test]
    fn drift_bound_is_24h() {
        let h = Hlc::next(None, 1_000 + MAX_DRIFT_MS, "d");
        assert!(h.is_plausible(1_000));
        let far = Hlc::next(None, 1_001 + MAX_DRIFT_MS, "d");
        assert!(!far.is_plausible(1_000));
    }
}
