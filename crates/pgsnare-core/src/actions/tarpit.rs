// SPDX-License-Identifier: Apache-2.0

//! `tarpit`: the session goes on, slowly.
//!
//! Once a hit asks for it, every batch of bytes the server sends the
//! client is held back for a delay drawn at random, evenly between the
//! shortest and the longest delay of the policy, so the delays follow no
//! period. With a rate cap, a batch is also held at least as long as the
//! cap allows for its size. The session logic asks for the delay with
//! [`Effect::Delay`]; the runtime owns the timer, and reads nothing more
//! from the server while the client is held, so no buffer grows.
//!
//! A tarpitted session keeps a real database connection busy, so it is
//! bounded twice, by limits the proxy checks before a session is held:
//!
//! - **In number.** [`TarpitPlaces`] counts the tarpitted sessions of the
//!   whole proxy. A session takes a place before it is held and keeps it
//!   until it ends; when every place is taken, the session is killed
//!   instead, so a client that opens many sessions and trips tokens is
//!   killed, not queued.
//! - **In time.** [`Effect::Tarpit`] tells the runtime the longest time
//!   the session may stay tarpitted. Past it, the runtime reports
//!   [`Report::TarpitOver`] and the session is killed.
//!
//! [`Effect::Delay`]: crate::session::Effect::Delay
//! [`Effect::Tarpit`]: crate::session::Effect::Tarpit
//! [`Report::TarpitOver`]: crate::session::Report::TarpitOver

use core::fmt;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::bait::Entropy;
use crate::policy::TarpitSettings;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The places for tarpitted sessions, shared by every session of the
/// proxy.
#[derive(Debug, Default)]
pub struct TarpitPlaces {
    held: AtomicU32,
}

impl TarpitPlaces {
    /// No place taken.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: AtomicU32::new(0),
        }
    }

    /// How many sessions are tarpitted now.
    #[must_use]
    pub fn held(&self) -> u32 {
        self.held.load(Ordering::Acquire)
    }

    /// Takes a place, if fewer than `max` are taken. The place is given
    /// back when the result is dropped.
    #[must_use]
    pub fn take(self: &Arc<Self>, max: u32) -> Option<TarpitPlace> {
        let mut held = self.held.load(Ordering::Acquire);
        while held < max {
            match self.held.compare_exchange_weak(
                held,
                held.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(TarpitPlace {
                        places: Arc::clone(self),
                    });
                }
                Err(now) => held = now,
            }
        }
        None
    }
}

/// One place taken in [`TarpitPlaces`].
pub struct TarpitPlace {
    places: Arc<TarpitPlaces>,
}

impl Drop for TarpitPlace {
    fn drop(&mut self) {
        // Every place was counted when it was taken, so this never goes
        // below zero.
        self.places.held.fetch_sub(1, Ordering::AcqRel);
    }
}

impl fmt::Debug for TarpitPlace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TarpitPlace")
    }
}

/// A tarpitted session: its place and the settings in force when it was
/// tarpitted.
#[derive(Debug)]
pub struct Tarpit {
    _place: TarpitPlace,
    settings: TarpitSettings,
}

impl Tarpit {
    /// Tarpits a session with `settings`, if a place is free.
    #[must_use]
    pub fn start(places: &Arc<TarpitPlaces>, settings: TarpitSettings) -> Option<Self> {
        places.take(settings.max_sessions).map(|place| Self {
            _place: place,
            settings,
        })
    }

    /// The longest time the session may stay tarpitted.
    #[must_use]
    pub const fn max_duration(&self) -> Duration {
        self.settings.max_duration
    }

    /// How long to hold back `bytes` bytes for the client.
    ///
    /// A delay between the shortest and the longest of the settings, drawn
    /// from `entropy`, and at least as long as the rate cap asks for. If
    /// `entropy` fails, the longest delay. Never longer than the session
    /// may stay tarpitted.
    pub fn delay(&self, bytes: usize, entropy: &mut dyn Entropy) -> Duration {
        let settings = &self.settings;
        let low = settings.delay_min.as_nanos();
        let high = settings.delay_max.as_nanos().max(low);
        let span = high.saturating_sub(low);
        let mut random = [0u8; 16];
        let jitter = if entropy.fill(&mut random).is_ok() {
            let drawn = u128::from_le_bytes(random);
            low.saturating_add(drawn.checked_rem(span.saturating_add(1)).unwrap_or(0))
        } else {
            high
        };
        let paced = settings.max_bytes_per_second.map_or(0, |rate| {
            let bytes = u128::try_from(bytes).unwrap_or(u128::MAX);
            bytes
                .saturating_mul(NANOS_PER_SECOND)
                .checked_div(u128::from(rate))
                .unwrap_or(u128::MAX)
        });
        let nanos = jitter.max(paced).min(settings.max_duration.as_nanos());
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bait::EntropyError;

    struct Counting(u64);

    impl Entropy for Counting {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for byte in dest.iter_mut() {
                // xorshift: no short period.
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0.to_le_bytes()[0];
            }
            Ok(())
        }
    }

    struct Broken;

    impl Entropy for Broken {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new())
        }
    }

    fn settings(min: u64, max: u64, rate: Option<u64>) -> TarpitSettings {
        TarpitSettings::new(
            Duration::from_millis(min),
            Duration::from_millis(max),
            Duration::from_secs(60),
            2,
            rate,
        )
    }

    #[test]
    fn no_more_sessions_are_tarpitted_than_the_settings_allow() {
        let places = Arc::new(TarpitPlaces::new());
        let first = Tarpit::start(&places, settings(1, 2, None));
        let second = Tarpit::start(&places, settings(1, 2, None));
        assert!(first.is_some() && second.is_some());
        assert!(Tarpit::start(&places, settings(1, 2, None)).is_none());
        assert_eq!(places.held(), 2);
        drop(first);
        assert_eq!(places.held(), 1);
        assert!(Tarpit::start(&places, settings(1, 2, None)).is_some());
        assert_eq!(places.held(), 1);
    }

    #[test]
    fn delays_fall_within_the_range_and_vary() {
        let places = Arc::new(TarpitPlaces::new());
        let tarpit = Tarpit::start(&places, settings(2_000, 30_000, None)).unwrap();
        let mut entropy = Counting(7);
        let delays: Vec<Duration> = (0..200).map(|_| tarpit.delay(10, &mut entropy)).collect();
        for delay in &delays {
            assert!(*delay >= Duration::from_secs(2) && *delay <= Duration::from_secs(30));
        }
        let distinct: std::collections::BTreeSet<_> = delays.iter().collect();
        assert!(distinct.len() > 150, "{} distinct delays", distinct.len());
    }

    #[test]
    fn a_rate_cap_holds_a_large_batch_longer() {
        let places = Arc::new(TarpitPlaces::new());
        let tarpit = Tarpit::start(&places, settings(1, 2, Some(1_000))).unwrap();
        let mut entropy = Counting(1);
        assert_eq!(tarpit.delay(5_000, &mut entropy), Duration::from_secs(5));
        assert!(tarpit.delay(1, &mut entropy) <= Duration::from_millis(2));
        // Never beyond the time the session may stay tarpitted.
        assert_eq!(
            tarpit.delay(usize::MAX, &mut entropy),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn a_failing_source_gives_the_longest_delay() {
        let places = Arc::new(TarpitPlaces::new());
        let tarpit = Tarpit::start(&places, settings(1, 2, None)).unwrap();
        assert_eq!(tarpit.delay(1, &mut Broken), Duration::from_millis(2));
    }
}
