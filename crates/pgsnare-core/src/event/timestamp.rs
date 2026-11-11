// SPDX-License-Identifier: Apache-2.0

//! The time of an event.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

const MICROS_PER_SECOND: u64 = 1_000_000;
const SECONDS_PER_DAY: u64 = 86_400;

/// 9999-12-31T23:59:59.999999Z, the last instant with a four-digit year.
const MAX_UNIX_MICROS: u64 = 253_402_300_799_999_999;

/// A point in time, in UTC, with microsecond resolution.
///
/// The session logic has no clock, so a timestamp is always handed in by
/// the runtime. In JSON it is an RFC 3339 string with six fractional digits,
/// such as `2026-11-11T17:06:31.123456Z`. The width is fixed, so timestamps
/// sort correctly as text.
///
/// The range is the Unix epoch to the end of the year 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

/// The text was not a timestamp in the form this crate writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseTimestampError;

impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a timestamp looks like 2026-11-11T17:06:31.123456Z")
    }
}

impl core::error::Error for ParseTimestampError {}

/// A calendar date and time of day.
struct Civil {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
    micros: u64,
}

impl Timestamp {
    /// 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self(0);

    /// The latest time that can be represented.
    pub const MAX: Self = Self(MAX_UNIX_MICROS);

    /// A timestamp from microseconds since the Unix epoch, or `None` past
    /// the year 9999.
    #[must_use]
    pub const fn from_unix_micros(micros: u64) -> Option<Self> {
        if micros <= MAX_UNIX_MICROS {
            Some(Self(micros))
        } else {
            None
        }
    }

    /// A timestamp from whole seconds since the Unix epoch plus nanoseconds,
    /// as a system clock reports them. Precision finer than a microsecond is
    /// dropped. `None` past the year 9999 or for a nanosecond count of a
    /// second or more.
    #[must_use]
    pub fn from_unix(seconds: u64, subsec_nanos: u32) -> Option<Self> {
        if subsec_nanos >= 1_000_000_000 {
            return None;
        }
        let micros = seconds
            .checked_mul(MICROS_PER_SECOND)?
            .checked_add(u64::from(subsec_nanos / 1_000))?;
        Self::from_unix_micros(micros)
    }

    /// Microseconds since the Unix epoch.
    #[must_use]
    pub const fn unix_micros(self) -> u64 {
        self.0
    }

    /// Splits the timestamp into calendar fields.
    ///
    /// The date part is the well-known "civil from days" calculation for the
    /// proleptic Gregorian calendar. Every intermediate value is far below
    /// `u64::MAX` for the supported range, and the checked operations make
    /// that a fact the compiler holds us to.
    fn civil(self) -> Option<Civil> {
        let seconds = self.0 / MICROS_PER_SECOND;
        let micros = self.0 % MICROS_PER_SECOND;
        let days = seconds / SECONDS_PER_DAY;
        let second_of_day = seconds % SECONDS_PER_DAY;

        // Days since 0000-03-01, split into 400-year eras.
        let shifted = days.checked_add(719_468)?;
        let era = shifted / 146_097;
        let day_of_era = shifted % 146_097;
        let year_of_era = day_of_era
            .checked_sub(day_of_era / 1_460)?
            .checked_add(day_of_era / 36_524)?
            .checked_sub(day_of_era / 146_096)?
            / 365;
        let day_of_year = day_of_era.checked_sub(
            year_of_era
                .checked_mul(365)?
                .checked_add(year_of_era / 4)?
                .checked_sub(year_of_era / 100)?,
        )?;
        // Months counted from March, so the leap day comes last.
        let shifted_month = day_of_year.checked_mul(5)?.checked_add(2)? / 153;
        let day = day_of_year
            .checked_sub(shifted_month.checked_mul(153)?.checked_add(2)? / 5)?
            .checked_add(1)?;
        let (month, year_carry) = if shifted_month < 10 {
            (shifted_month.checked_add(3)?, 0)
        } else {
            (shifted_month.checked_sub(9)?, 1)
        };
        let year = era
            .checked_mul(400)?
            .checked_add(year_of_era)?
            .checked_add(year_carry)?;

        Some(Civil {
            year,
            month,
            day,
            hour: second_of_day / 3_600,
            minute: second_of_day % 3_600 / 60,
            second: second_of_day % 60,
            micros,
        })
    }

    /// The inverse of [`Timestamp::civil`]. `None` for a date that does not
    /// exist or lies outside the supported range.
    fn from_civil(civil: &Civil) -> Option<Self> {
        let Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
            micros,
        } = *civil;

        let in_range = (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
            && hour < 24
            && minute < 60
            && second < 60
            && micros < MICROS_PER_SECOND;
        if !in_range {
            return None;
        }

        // Count years from March, so the leap day comes last.
        let (shifted_year, shifted_month) = if month <= 2 {
            (year.checked_sub(1)?, month.checked_add(9)?)
        } else {
            (year, month.checked_sub(3)?)
        };
        let era = shifted_year / 400;
        let year_of_era = shifted_year % 400;
        let day_of_year = shifted_month
            .checked_mul(153)?
            .checked_add(2)?
            .checked_div(5)?
            .checked_add(day)?
            .checked_sub(1)?;
        let day_of_era = year_of_era
            .checked_mul(365)?
            .checked_add(year_of_era / 4)?
            .checked_sub(year_of_era / 100)?
            .checked_add(day_of_year)?;
        let days = era
            .checked_mul(146_097)?
            .checked_add(day_of_era)?
            .checked_sub(719_468)?;

        let second_of_day = hour
            .checked_mul(3_600)?
            .checked_add(minute.checked_mul(60)?)?
            .checked_add(second)?;
        let total = days
            .checked_mul(SECONDS_PER_DAY)?
            .checked_add(second_of_day)?
            .checked_mul(MICROS_PER_SECOND)?
            .checked_add(micros)?;
        Self::from_unix_micros(total)
    }
}

const fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `civil` cannot fail for a value within the range every constructor
        // enforces. If it ever did, the formatter reports an error instead
        // of printing a wrong time.
        let civil = self.civil().ok_or(fmt::Error)?;
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            civil.year,
            civil.month,
            civil.day,
            civil.hour,
            civil.minute,
            civil.second,
            civil.micros
        )
    }
}

/// Reads exactly `digits` decimal digits from the front of `text`.
fn take_number(text: &mut &[u8], digits: usize) -> Option<u64> {
    let (head, tail) = text.split_at_checked(digits)?;
    let mut value: u64 = 0;
    for byte in head {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(byte.wrapping_sub(b'0')))?;
    }
    *text = tail;
    Some(value)
}

/// Reads one expected byte from the front of `text`.
fn take_byte(text: &mut &[u8], expected: u8) -> Option<()> {
    let (first, tail) = text.split_first()?;
    if *first != expected {
        return None;
    }
    *text = tail;
    Some(())
}

impl FromStr for Timestamp {
    type Err = ParseTimestampError;

    /// Parses the form this crate writes: `YYYY-MM-DDTHH:MM:SS.ffffffZ`,
    /// in UTC with a capital `T` and `Z`. The fraction may have one to nine
    /// digits or be left out; digits past the sixth are dropped.
    fn from_str(text: &str) -> Result<Self, ParseTimestampError> {
        fn parse(text: &str) -> Option<Timestamp> {
            let mut rest = text.as_bytes();
            let year = take_number(&mut rest, 4)?;
            take_byte(&mut rest, b'-')?;
            let month = take_number(&mut rest, 2)?;
            take_byte(&mut rest, b'-')?;
            let day = take_number(&mut rest, 2)?;
            take_byte(&mut rest, b'T')?;
            let hour = take_number(&mut rest, 2)?;
            take_byte(&mut rest, b':')?;
            let minute = take_number(&mut rest, 2)?;
            take_byte(&mut rest, b':')?;
            let second = take_number(&mut rest, 2)?;

            let mut micros = 0;
            if take_byte(&mut rest, b'.').is_some() {
                let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
                if !(1..=9).contains(&digits) {
                    return None;
                }
                let mut fraction = take_number(&mut rest, digits)?;
                // Scale to exactly six digits.
                for _ in digits..6 {
                    fraction = fraction.checked_mul(10)?;
                }
                for _ in 6..digits {
                    fraction /= 10;
                }
                micros = fraction;
            }
            take_byte(&mut rest, b'Z')?;
            if !rest.is_empty() {
                return None;
            }

            Timestamp::from_civil(&Civil {
                year,
                month,
                day,
                hour,
                minute,
                second,
                micros,
            })
        }

        parse(text).ok_or(ParseTimestampError)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct TimestampVisitor;

impl de::Visitor<'_> for TimestampVisitor {
    type Value = Timestamp;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an RFC 3339 timestamp in UTC, such as 2026-11-11T17:06:31.123456Z")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Timestamp, E> {
        text.parse()
            .map_err(|_| E::invalid_value(de::Unexpected::Other("other text"), &self))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(TimestampVisitor)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn at(micros: u64) -> Timestamp {
        Timestamp::from_unix_micros(micros).unwrap()
    }

    #[test]
    fn known_instants_are_written_correctly() {
        let cases = [
            (0, "1970-01-01T00:00:00.000000Z"),
            (1, "1970-01-01T00:00:00.000001Z"),
            (86_399_999_999, "1970-01-01T23:59:59.999999Z"),
            (86_400_000_000, "1970-01-02T00:00:00.000000Z"),
            // The last day of February in a common year and in leap years.
            (951_782_400_000_000, "2000-02-29T00:00:00.000000Z"),
            (951_868_800_000_000, "2000-03-01T00:00:00.000000Z"),
            (1_709_164_800_000_000, "2024-02-29T00:00:00.000000Z"),
            (1_740_787_199_000_000, "2025-02-28T23:59:59.000000Z"),
            (1_740_787_200_000_000, "2025-03-01T00:00:00.000000Z"),
            // 2100 is not a leap year.
            (4_107_542_400_000_000, "2100-03-01T00:00:00.000000Z"),
            (1_794_416_791_123_456, "2026-11-11T17:06:31.123456Z"),
            (2_147_483_647_000_000, "2038-01-19T03:14:07.000000Z"),
            (MAX_UNIX_MICROS, "9999-12-31T23:59:59.999999Z"),
        ];
        for (micros, text) in cases {
            assert_eq!(at(micros).to_string(), text);
            assert_eq!(text.parse::<Timestamp>(), Ok(at(micros)), "{text}");
        }
    }

    #[test]
    fn the_range_ends_with_the_year_9999() {
        assert_eq!(
            Timestamp::from_unix_micros(MAX_UNIX_MICROS),
            Some(Timestamp::MAX)
        );
        assert_eq!(Timestamp::from_unix_micros(MAX_UNIX_MICROS + 1), None);
        assert_eq!(Timestamp::from_unix_micros(u64::MAX), None);
        assert_eq!(Timestamp::UNIX_EPOCH.unix_micros(), 0);
    }

    #[test]
    fn a_system_clock_reading_is_converted() {
        assert_eq!(Timestamp::from_unix(0, 0), Some(Timestamp::UNIX_EPOCH));
        assert_eq!(Timestamp::from_unix(1, 999_999_999), Some(at(1_999_999)));
        assert_eq!(Timestamp::from_unix(1, 1_500), Some(at(1_000_001)));
        assert_eq!(Timestamp::from_unix(1, 1_000_000_000), None);
        assert_eq!(Timestamp::from_unix(u64::MAX, 0), None);
        assert_eq!(Timestamp::from_unix(253_402_300_800, 0), None);
    }

    #[test]
    fn fractions_of_other_lengths_are_read() {
        let second = at(1_794_416_791_000_000);
        assert_eq!("2026-11-11T17:06:31Z".parse(), Ok(second));
        assert_eq!(
            "2026-11-11T17:06:31.5Z".parse(),
            Ok(at(1_794_416_791_500_000))
        );
        assert_eq!(
            "2026-11-11T17:06:31.123Z".parse(),
            Ok(at(1_794_416_791_123_000))
        );
        assert_eq!(
            "2026-11-11T17:06:31.123456789Z".parse(),
            Ok(at(1_794_416_791_123_456))
        );
    }

    #[test]
    fn malformed_timestamps_are_rejected() {
        for text in [
            "",
            "2026-11-11",
            "2026-11-11T17:06:31",             // no zone
            "2026-11-11T17:06:31+00:00",       // an offset instead of Z
            "2026-11-11t17:06:31Z",            // lower case
            "2026-11-11 17:06:31Z",            // a space
            "2026-11-11T17:06:31.Z",           // an empty fraction
            "2026-11-11T17:06:31.1234567890Z", // ten fractional digits
            "2026-11-11T17:06:31.123456Z ",    // trailing text
            "2026-13-01T00:00:00Z",            // month 13
            "2026-00-10T00:00:00Z",            // month 0
            "2026-02-29T00:00:00Z",            // not a leap year
            "2100-02-29T00:00:00Z",            // not a leap year either
            "2026-04-31T00:00:00Z",            // April has 30 days
            "2026-11-00T00:00:00Z",            // day 0
            "2026-11-11T24:00:00Z",            // hour 24
            "2026-11-11T23:60:00Z",            // minute 60
            "2026-11-11T23:59:60Z",            // no leap seconds
            "1969-12-31T23:59:59Z",            // before the epoch
            "02026-11-11T17:06:31Z",           // five-digit year
            "2026-1-11T17:06:31Z",             // one-digit month
            "2026-11-11T17:06:3\u{661}Z",      // a digit that is not ASCII
        ] {
            assert_eq!(
                text.parse::<Timestamp>(),
                Err(ParseTimestampError),
                "{text:?}"
            );
        }
    }

    #[test]
    fn json_uses_the_text_form() {
        let timestamp = at(1_794_416_791_123_456);
        let json = serde_json::to_string(&timestamp).unwrap();
        assert_eq!(json, "\"2026-11-11T17:06:31.123456Z\"");
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), timestamp);
        assert!(serde_json::from_str::<Timestamp>("\"yesterday\"").is_err());
        assert!(serde_json::from_str::<Timestamp>("1794416791").is_err());
    }

    /// The same calendar arithmetic done the slow, obvious way.
    fn slow_date(mut days: u64) -> (u64, u64, u64) {
        let mut year = 1970;
        loop {
            let length = if is_leap_year(year) { 366 } else { 365 };
            if days < length {
                break;
            }
            days -= length;
            year += 1;
        }
        let mut month = 1;
        loop {
            let length = days_in_month(year, month);
            if days < length {
                break;
            }
            days -= length;
            month += 1;
        }
        (year, month, days + 1)
    }

    #[test]
    fn every_day_of_six_centuries_matches_the_slow_calculation() {
        // 1970 to 2570 covers every kind of century boundary.
        for day in 0..(601 * 366) {
            let civil = at(day * SECONDS_PER_DAY * MICROS_PER_SECOND)
                .civil()
                .unwrap();
            assert_eq!(
                (civil.year, civil.month, civil.day),
                slow_date(day),
                "day {day}"
            );
        }
    }

    proptest! {
        #[test]
        fn every_timestamp_round_trips_through_text(micros in 0..=MAX_UNIX_MICROS) {
            let timestamp = at(micros);
            let text = timestamp.to_string();
            prop_assert_eq!(text.len(), 27);
            prop_assert_eq!(text.parse::<Timestamp>(), Ok(timestamp));
        }

        #[test]
        fn text_order_is_time_order(a in 0..=MAX_UNIX_MICROS, b in 0..=MAX_UNIX_MICROS) {
            prop_assert_eq!(at(a).to_string().cmp(&at(b).to_string()), a.cmp(&b));
        }

        #[test]
        fn the_calendar_fields_match_the_slow_calculation(micros in 0..=MAX_UNIX_MICROS) {
            let civil = at(micros).civil().unwrap();
            let days = micros / MICROS_PER_SECOND / SECONDS_PER_DAY;
            prop_assert_eq!((civil.year, civil.month, civil.day), slow_date(days));
        }

        #[test]
        fn parsing_never_panics(text in "\\PC{0,40}") {
            let _ = text.parse::<Timestamp>();
        }
    }
}
