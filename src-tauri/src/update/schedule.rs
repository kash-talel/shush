//! Timing of the background update check, kept free of threads and clocks so tests can drive it
//! with a fake `now` (#200).

use std::time::{Duration, Instant};

/// First check this long after the gate opens.
pub const FIRST_DELAY: Duration = Duration::from_secs(30);
/// Gap after a verified answer.
pub const OK_DELAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Gap after a failed (fetch / mismatch) check, so a boot while offline retries soon.
pub const RETRY_DELAY: Duration = Duration::from_secs(60 * 60);
/// Jitter is drawn from `0..JITTER_SECS`.
pub const JITTER_SECS: u64 = 2 * 60 * 60;

/// What the polling loop should do on this tick.
#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// Nothing to do yet.
    Wait,
    /// Run a check now.
    Check,
}

/// Re-arms when checks are not eligible (air-gapped, updates off), arms on first eligibility.
#[derive(Default)]
pub struct Schedule {
    due: Option<Instant>,
}

impl Schedule {
    /// One poll with the current time and whether a check is allowed right now.
    pub fn tick(&mut self, now: Instant, eligible: bool) -> Tick {
        if !eligible {
            self.due = None;
            return Tick::Wait;
        }
        match self.due {
            None => {
                self.due = Some(now + FIRST_DELAY);
                Tick::Wait
            }
            Some(t) if now >= t => Tick::Check,
            Some(_) => Tick::Wait,
        }
    }

    /// Records the outcome of a check that `tick` asked for and arms the next one.
    pub fn done(&mut self, now: Instant, settled: bool, jitter_secs: u64) {
        let base = if settled { OK_DELAY } else { RETRY_DELAY };
        self.due = Some(now + base + Duration::from_secs(jitter_secs.min(JITTER_SECS - 1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_check_about_30s_after_the_gate_opens() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        assert_eq!(s.tick(t0, true), Tick::Wait);
        assert_eq!(s.tick(t0 + Duration::from_secs(29), true), Tick::Wait);
        assert_eq!(s.tick(t0 + Duration::from_secs(30), true), Tick::Check);
    }

    #[test]
    fn next_check_is_24h_plus_bounded_jitter_after_success() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        s.tick(t0, true);
        s.done(t0, true, JITTER_SECS * 5);
        let day = Duration::from_secs(24 * 3600);
        assert_eq!(s.tick(t0 + day - Duration::from_secs(1), true), Tick::Wait);
        assert_eq!(
            s.tick(t0 + day + Duration::from_secs(JITTER_SECS), true),
            Tick::Check
        );
        s.done(t0, true, 0);
        assert_eq!(s.tick(t0 + day, true), Tick::Check);
    }

    #[test]
    fn failed_check_retries_in_about_an_hour_not_a_day() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        s.tick(t0, true);
        s.done(t0, false, 0);
        let h = Duration::from_secs(3600);
        assert_eq!(s.tick(t0 + h - Duration::from_secs(1), true), Tick::Wait);
        assert_eq!(s.tick(t0 + h, true), Tick::Check);
        s.done(t0, false, 5000);
        assert_eq!(s.tick(t0 + h - Duration::from_secs(1), true), Tick::Wait);
        assert_eq!(
            s.tick(t0 + h + Duration::from_secs(JITTER_SECS), true),
            Tick::Check
        );
    }

    #[test]
    fn going_ineligible_rearms_with_a_fresh_30s_delay() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        s.tick(t0, true);
        assert_eq!(s.tick(t0 + Duration::from_secs(100), false), Tick::Wait);
        let t1 = t0 + Duration::from_secs(200);
        assert_eq!(s.tick(t1, true), Tick::Wait);
        assert_eq!(s.tick(t1 + Duration::from_secs(29), true), Tick::Wait);
        assert_eq!(s.tick(t1 + Duration::from_secs(30), true), Tick::Check);
    }
}
