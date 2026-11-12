// SPDX-License-Identifier: Apache-2.0

//! Durations and sizes, which the configuration writes as text with a unit.

use std::fmt;
use std::time::Duration;

use serde::de;

/// The parse step of one kind of unit text.
type Parse<T> = fn(&str) -> Option<T>;

/// Reads text with a unit and never repeats what it could not read.
struct UnitVisitor<T> {
    expecting: &'static str,
    parse: Parse<T>,
}

impl<T> de::Visitor<'_> for UnitVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        (self.parse)(text)
            .ok_or_else(|| E::invalid_value(de::Unexpected::Other("other text"), &self.expecting))
    }
}

/// Splits `text` into its leading decimal number and the rest.
///
/// The number is plain digits: no sign, no fraction, no leading zero except
/// for zero itself, and it must fit in a `u64`.
fn split_number(text: &str) -> Option<(u64, &str)> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, rest) = text.split_at_checked(digits)?;
    if number.is_empty() || (number.len() > 1 && number.starts_with('0')) {
        return None;
    }
    Some((number.parse().ok()?, rest))
}

/// Parses a duration: a whole number and one of `ms`, `s`, `m`, `h`, `d`.
#[must_use]
pub fn parse_duration(text: &str) -> Option<Duration> {
    let (number, unit) = split_number(text)?;
    let milliseconds = match unit {
        "ms" => number,
        "s" => number.checked_mul(1_000)?,
        "m" => number.checked_mul(60_000)?,
        "h" => number.checked_mul(3_600_000)?,
        "d" => number.checked_mul(86_400_000)?,
        _ => return None,
    };
    Some(Duration::from_millis(milliseconds))
}

/// Parses a duration range: `2s-30s`, or a single duration for a fixed one.
#[must_use]
pub fn parse_duration_range(text: &str) -> Option<DurationRange> {
    let (min, max) = match text.split_once('-') {
        Some((min, max)) => (parse_duration(min)?, parse_duration(max)?),
        None => {
            let fixed = parse_duration(text)?;
            (fixed, fixed)
        }
    };
    (min <= max).then_some(DurationRange { min, max })
}

/// Parses a size: a whole number and one of `B`, `KiB`, `MiB`, `GiB`.
#[must_use]
pub fn parse_byte_size(text: &str) -> Option<u64> {
    let (number, unit) = split_number(text)?;
    match unit {
        "B" => Some(number),
        "KiB" => number.checked_mul(1 << 10),
        "MiB" => number.checked_mul(1 << 20),
        "GiB" => number.checked_mul(1 << 30),
        _ => None,
    }
}

/// A range of durations, from `min` to `max` inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DurationRange {
    /// The shortest duration.
    pub min: Duration,
    /// The longest duration.
    pub max: Duration,
}

const DURATION: &str = "a duration: a whole number and a unit, such as 500ms, 30s, 10m, 1h or 1d";
const DURATION_RANGE: &str = "a duration such as 5s, or a range of durations such as 2s-30s";
const BYTE_SIZE: &str = "a size: a whole number and a unit, such as 512B, 64KiB, 1MiB or 1GiB";

/// For `#[serde(deserialize_with = "units::duration")]`.
pub(super) fn duration<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    deserializer.deserialize_str(UnitVisitor {
        expecting: DURATION,
        parse: parse_duration,
    })
}

/// For `#[serde(deserialize_with = "units::duration_range")]`.
pub(super) fn duration_range<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<DurationRange, D::Error> {
    deserializer.deserialize_str(UnitVisitor {
        expecting: DURATION_RANGE,
        parse: parse_duration_range,
    })
}

/// For `#[serde(deserialize_with = "units::byte_size")]`.
pub(super) fn byte_size<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    deserializer.deserialize_str(UnitVisitor {
        expecting: BYTE_SIZE,
        parse: parse_byte_size,
    })
}

/// For `#[serde(deserialize_with = "units::optional_byte_size")]`.
pub(super) fn optional_byte_size<'de, D: de::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    struct Optional;

    impl<'de> de::Visitor<'de> for Optional {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(BYTE_SIZE)
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_some<D: de::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Option<u64>, D::Error> {
            byte_size(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(Optional)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_a_whole_number_and_a_unit() {
        let cases = [
            ("0s", Duration::ZERO),
            ("1ms", Duration::from_millis(1)),
            ("500ms", Duration::from_millis(500)),
            ("30s", Duration::from_secs(30)),
            ("10m", Duration::from_secs(600)),
            ("2h", Duration::from_secs(7_200)),
            ("1d", Duration::from_secs(86_400)),
            ("18446744073709551615ms", Duration::from_millis(u64::MAX)),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_duration(text), Some(expected), "{text}");
        }
    }

    #[test]
    fn malformed_durations_are_rejected() {
        for text in [
            "",
            "30",   // no unit
            "s",    // no number
            "30 s", // a space
            " 30s",
            "30s ",
            "30S", // units are case-sensitive
            "30sec",
            "1.5s", // no fractions
            "-5s",  // no sign
            "+5s",
            "05s",   // no leading zero
            "1h30m", // one number, one unit
            "30us",
            "1w",
            "18446744073709551616ms", // does not fit
            "18446744073709551615s",  // overflows when converted
            "\u{663}0s",              // a digit that is not ASCII
        ] {
            assert_eq!(parse_duration(text), None, "{text:?}");
        }
    }

    #[test]
    fn duration_ranges_are_one_or_two_durations() {
        let seconds = Duration::from_secs;
        assert_eq!(
            parse_duration_range("2s-30s"),
            Some(DurationRange {
                min: seconds(2),
                max: seconds(30)
            })
        );
        assert_eq!(
            parse_duration_range("500ms-2m"),
            Some(DurationRange {
                min: Duration::from_millis(500),
                max: seconds(120)
            })
        );
        assert_eq!(
            parse_duration_range("5s"),
            Some(DurationRange {
                min: seconds(5),
                max: seconds(5)
            })
        );
        assert_eq!(
            parse_duration_range("5s-5s"),
            Some(DurationRange {
                min: seconds(5),
                max: seconds(5)
            })
        );
        for text in [
            "",
            "-",
            "2s-",
            "-30s",
            "30s-2s",
            "2s-30s-60s",
            "2s - 30s",
            "2-30s",
            "2s..30s",
        ] {
            assert_eq!(parse_duration_range(text), None, "{text:?}");
        }
    }

    #[test]
    fn sizes_are_a_whole_number_and_a_binary_unit() {
        let cases = [
            ("0B", 0),
            ("512B", 512),
            ("1KiB", 1_024),
            ("64KiB", 65_536),
            ("1MiB", 1_048_576),
            ("1GiB", 1_073_741_824),
            ("17179869183GiB", 17_179_869_183 << 30),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_byte_size(text), Some(expected), "{text}");
        }
        for text in [
            "",
            "1",
            "MiB",
            "1 MiB",
            "1mib",
            "1MB", // decimal units are not accepted, to avoid guessing
            "1kB",
            "1K",
            "1.5MiB",
            "-1MiB",
            "01MiB",
            "1TiB",
            "17179869184GiB", // overflows
        ] {
            assert_eq!(parse_byte_size(text), None, "{text:?}");
        }
    }
}
