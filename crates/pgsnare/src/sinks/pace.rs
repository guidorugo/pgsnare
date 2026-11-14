// SPDX-License-Identifier: Apache-2.0

//! Time for the dispatcher: the rate limit of a sink, the pause before
//! another attempt, and log lines that do not come in floods.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// The pause before the first retry. Each further one is twice as long.
pub(super) const FIRST_BACKOFF: Duration = Duration::from_millis(250);

/// The longest pause between two attempts.
pub(super) const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The least time between two log lines about the same trouble.
pub(super) const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The rate limit of one sink.
///
/// A sink may deliver so many events per second. After a quiet time it
/// may deliver a second's worth at once, and then one event every so
/// often. An event that comes too early waits: [`Pace::wait`] says how
/// long. What cannot wait is in the queue of the sink, and what does not
/// fit there is dropped and counted.
pub(super) struct Pace {
    /// The time between two events at the limit.
    interval: Duration,
    /// How far ahead of the steady rate a burst may run.
    allowance: Duration,
    /// The moment the next event is due at the steady rate.
    due: Instant,
}

impl Pace {
    pub(super) fn new(max_per_second: u32, now: Instant) -> Self {
        let rate = max_per_second.max(1);
        let interval = Duration::from_secs(1) / rate;
        Self {
            interval,
            allowance: interval.saturating_mul(rate.saturating_sub(1)),
            due: now,
        }
    }

    /// Takes the place of one event and says how long it has to wait
    /// before it may be delivered.
    pub(super) fn wait(&mut self, now: Instant) -> Duration {
        let due = self.due.max(now);
        let earliest = due.checked_sub(self.allowance).unwrap_or(now);
        // At the last moment the clock can tell, the next one is due then.
        self.due = due.checked_add(self.interval).unwrap_or(due);
        earliest.saturating_duration_since(now)
    }
}

/// The pause before retry number `retry`, counting from 1.
///
/// It doubles with every retry up to [`MAX_BACKOFF`], and `jitter` shortens
/// it by up to half, so that sinks that failed together do not all come
/// back at the same moment.
pub(super) fn backoff(retry: u32, jitter: u64) -> Duration {
    let doublings = retry.saturating_sub(1).min(16);
    let full = FIRST_BACKOFF
        .saturating_mul(1u32 << doublings)
        .min(MAX_BACKOFF);
    let half = full / 2;
    let share = u32::try_from(jitter % 1024).unwrap_or(0);
    half + half.saturating_mul(share) / 1024
}

/// A number that is different every time, for the jitter of a pause. It
/// does not have to be unpredictable.
pub(super) fn jitter() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// Lets one log line through every [`LOG_INTERVAL`] and counts the ones it
/// held back, for one task.
pub(super) struct LogGate {
    next: Option<Instant>,
    held_back: u64,
}

impl LogGate {
    pub(super) const fn new() -> Self {
        Self {
            next: None,
            held_back: 0,
        }
    }

    /// Whether a line may be written now. If so, the answer is how many
    /// were held back since the last one.
    pub(super) fn pass(&mut self, now: Instant) -> Option<u64> {
        if self.next.is_some_and(|next| now < next) {
            self.held_back = self.held_back.saturating_add(1);
            return None;
        }
        // Past the last moment the clock can tell, every line may pass.
        self.next = now.checked_add(LOG_INTERVAL);
        Some(std::mem::take(&mut self.held_back))
    }
}

/// The same for a line that any thread may want to write, such as one from
/// the data path. It takes no lock.
pub(super) struct SharedLogGate {
    started: Instant,
    /// The moment the next line may be written, in milliseconds after
    /// `started`.
    next_millis: AtomicU64,
    held_back: AtomicU64,
}

impl SharedLogGate {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            started: now,
            next_millis: AtomicU64::new(0),
            held_back: AtomicU64::new(0),
        }
    }

    /// Whether a line may be written now. If so, the answer is how many
    /// were held back since the last one.
    pub(super) fn pass(&self, now: Instant) -> Option<u64> {
        let millis = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let elapsed = millis(now.saturating_duration_since(self.started));
        let next = self.next_millis.load(Ordering::Relaxed);
        let after = elapsed.saturating_add(millis(LOG_INTERVAL));
        if elapsed < next
            || self
                .next_millis
                .compare_exchange(next, after, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(self.held_back.swap(0, Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The last moment the clock can tell, give or take a nanosecond.
    fn end_of_the_clock() -> Instant {
        let mut last = Instant::now();
        let mut step = Duration::MAX;
        while !step.is_zero() {
            match last.checked_add(step) {
                Some(later) => last = later,
                None => step /= 2,
            }
        }
        last
    }

    #[tokio::test(start_paused = true)]
    async fn the_end_of_the_clock_is_no_reason_to_panic() {
        let end = end_of_the_clock();
        let mut pace = Pace::new(4, Instant::now());
        for _ in 0..8 {
            let _ = pace.wait(end);
        }
        let mut gate = LogGate::new();
        assert!(gate.pass(end).is_some());
        assert!(gate.pass(end).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_sink_may_deliver_a_seconds_worth_at_once_and_then_keeps_the_rate() {
        let start = Instant::now();
        let mut pace = Pace::new(4, start);
        // Four at once.
        for _ in 0..4 {
            assert_eq!(pace.wait(start), Duration::ZERO);
        }
        // Then one every quarter of a second.
        assert_eq!(pace.wait(start), Duration::from_millis(250));
        assert_eq!(pace.wait(start), Duration::from_millis(500));

        // After a quiet time the allowance is back, and no more than that.
        let later = start + Duration::from_secs(60);
        for _ in 0..4 {
            assert_eq!(pace.wait(later), Duration::ZERO);
        }
        assert_eq!(pace.wait(later), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn a_limit_of_one_per_second_lets_one_through_each_second() {
        let start = Instant::now();
        let mut pace = Pace::new(1, start);
        assert_eq!(pace.wait(start), Duration::ZERO);
        assert_eq!(pace.wait(start), Duration::from_secs(1));
        assert_eq!(pace.wait(start), Duration::from_secs(2));
        assert_eq!(
            pace.wait(start + Duration::from_millis(2500)),
            Duration::from_millis(500)
        );
        // Zero is not a rate. The configuration refuses it, and here it
        // counts as one.
        let mut pace = Pace::new(0, start);
        assert_eq!(pace.wait(start), Duration::ZERO);
        assert_eq!(pace.wait(start), Duration::from_secs(1));
    }

    #[test]
    fn the_pause_doubles_up_to_its_limit_and_jitter_takes_at_most_half() {
        // With the most jitter there is, nearly the full pause.
        let nearly = |full: Duration| full / 2 + (full / 2) * 1023 / 1024;
        assert_eq!(backoff(1, 1023), nearly(Duration::from_millis(250)));
        assert_eq!(backoff(2, 1023), nearly(Duration::from_millis(500)));
        assert_eq!(backoff(3, 1023), nearly(Duration::from_secs(1)));
        assert_eq!(backoff(8, 1023), nearly(MAX_BACKOFF));
        assert_eq!(backoff(1000, 1023), nearly(MAX_BACKOFF));
        assert_eq!(backoff(u32::MAX, u64::MAX), nearly(MAX_BACKOFF));
        // With none, half of it.
        assert_eq!(backoff(1, 0), Duration::from_millis(125));
        assert_eq!(backoff(1000, 1024), MAX_BACKOFF / 2);
        // The first retry is retry 1, and 0 is taken for it.
        assert_eq!(backoff(0, 0), backoff(1, 0));

        for retry in 0..40 {
            for jitter in [0, 1, 500, 1023, 1024, u64::MAX] {
                let pause = backoff(retry, jitter);
                assert!(pause >= FIRST_BACKOFF / 2, "{retry} {jitter}");
                assert!(pause <= MAX_BACKOFF, "{retry} {jitter}");
            }
        }
        assert_ne!(jitter(), jitter());
    }

    #[tokio::test(start_paused = true)]
    async fn a_gate_lets_one_line_through_at_a_time() {
        let start = Instant::now();
        let mut gate = LogGate::new();
        assert_eq!(gate.pass(start), Some(0));
        assert_eq!(gate.pass(start), None);
        assert_eq!(gate.pass(start + LOG_INTERVAL / 2), None);
        assert_eq!(gate.pass(start + LOG_INTERVAL), Some(2));
        assert_eq!(gate.pass(start + LOG_INTERVAL * 2), Some(0));

        let shared = SharedLogGate::new(start);
        assert_eq!(shared.pass(start), Some(0));
        assert_eq!(shared.pass(start), None);
        assert_eq!(shared.pass(start + LOG_INTERVAL / 2), None);
        assert_eq!(shared.pass(start + LOG_INTERVAL), Some(2));
        assert_eq!(shared.pass(start + LOG_INTERVAL), None);
        assert_eq!(shared.pass(start + LOG_INTERVAL * 3), Some(1));
    }
}
