// SPDX-License-Identifier: Apache-2.0

//! Identifiers of sessions and events.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// The text of an identifier was not 32 lowercase hexadecimal digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseIdError;

impl fmt::Display for ParseIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an identifier is 32 lowercase hexadecimal digits")
    }
}

impl core::error::Error for ParseIdError {}

fn parse_hex(text: &str) -> Result<u128, ParseIdError> {
    let well_formed = text.len() == 32
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        return Err(ParseIdError);
    }
    u128::from_str_radix(text, 16).map_err(|_| ParseIdError)
}

struct HexVisitor;

impl de::Visitor<'_> for HexVisitor {
    type Value = u128;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("32 lowercase hexadecimal digits")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<u128, E> {
        // The text is not repeated in the error.
        parse_hex(text).map_err(|_| E::invalid_value(de::Unexpected::Other("other text"), &self))
    }
}

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u128);

        impl $name {
            /// Wraps a 128-bit value. The caller makes it unique, normally
            /// by drawing it from a secure random generator.
            #[must_use]
            pub const fn from_u128(value: u128) -> Self {
                Self(value)
            }

            /// The 128-bit value.
            #[must_use]
            pub const fn as_u128(self) -> u128 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:032x}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(text: &str) -> Result<Self, ParseIdError> {
                parse_hex(text).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(HexVisitor).map(Self)
            }
        }
    };
}

identifier! {
    /// Identifies one session: one client connection paired with one backend
    /// connection.
    ///
    /// The runtime assigns it when it accepts the connection. It is written
    /// as 32 lowercase hexadecimal digits.
    SessionId
}

identifier! {
    /// Identifies one event.
    ///
    /// It is assigned when the event is sealed, and is written as 32
    /// lowercase hexadecimal digits.
    EventId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_is_written_as_32_hex_digits() {
        assert_eq!(
            SessionId::from_u128(0).to_string(),
            "00000000000000000000000000000000"
        );
        assert_eq!(
            SessionId::from_u128(0xdead_beef).to_string(),
            "000000000000000000000000deadbeef"
        );
        assert_eq!(
            EventId::from_u128(u128::MAX).to_string(),
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn an_identifier_round_trips_through_text_and_json() {
        for value in [0, 1, 0xdead_beef, u128::MAX, 1 << 127] {
            let id = EventId::from_u128(value);
            assert_eq!(id.to_string().parse::<EventId>(), Ok(id));
            let json = serde_json::to_string(&id).unwrap();
            assert_eq!(serde_json::from_str::<EventId>(&json).unwrap(), id);
            assert_eq!(id.as_u128(), value);
        }
    }

    #[test]
    fn malformed_identifiers_are_rejected() {
        for text in [
            "",
            "0",
            "0000000000000000000000000000000",   // 31 digits
            "000000000000000000000000000000000", // 33 digits
            "0000000000000000000000000000000G",
            "0000000000000000000000000000000A", // upper case
            "+0000000000000000000000000000000", // a sign
            " 0000000000000000000000000000000",
        ] {
            assert_eq!(text.parse::<SessionId>(), Err(ParseIdError), "{text:?}");
        }
        assert!(serde_json::from_str::<SessionId>("\"xyz\"").is_err());
        assert!(serde_json::from_str::<SessionId>("7").is_err());
    }

    #[test]
    fn a_rejected_identifier_is_not_repeated_in_the_error() {
        let error = serde_json::from_str::<SessionId>("\"not-an-identifier\"").unwrap_err();
        assert!(!error.to_string().contains("not-an-identifier"), "{error}");
    }
}
