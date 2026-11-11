// SPDX-License-Identifier: Apache-2.0

//! Identifiers of tokens and rules.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// The longest identifier allowed, in bytes.
pub const MAX_ID_BYTES: usize = 64;

/// The text is not a valid token or rule identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTING)
    }
}

impl core::error::Error for InvalidId {}

const EXPECTING: &str = "an identifier of 1 to 64 characters: ASCII letters, digits, \
                         '.', '_' and '-', starting with a letter or a digit";

fn is_valid(text: &str) -> bool {
    let mut bytes = text.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    text.len() <= MAX_ID_BYTES
        && first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

struct IdVisitor;

impl de::Visitor<'_> for IdVisitor {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTING)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<String, E> {
        if is_valid(text) {
            Ok(text.to_owned())
        } else {
            // The text is not repeated: a honeytoken value written where an
            // identifier belongs must not end up in an error message.
            Err(E::invalid_value(de::Unexpected::Other("other text"), &self))
        }
    }
}

macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Checks the text and wraps it.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidId`] unless the text is 1 to 64 ASCII
            /// letters, digits, `.`, `_` or `-`, starting with a letter or
            /// a digit.
            pub fn new(text: &str) -> Result<Self, InvalidId> {
                if is_valid(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(InvalidId)
                }
            }

            /// The identifier as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(text: &str) -> Result<Self, InvalidId> {
                Self::new(text)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_str(IdVisitor).map(Self)
            }
        }
    };
}

identifier! {
    /// The identifier of a honeytoken.
    ///
    /// Events, logs and metrics name a token by this id and never by its
    /// value. The id comes from configuration, has a bounded length and a
    /// restricted alphabet, and is therefore safe to use as a metric label.
    TokenId
}

identifier! {
    /// The identifier of an SQL rule. It follows the same format as a
    /// [`TokenId`].
    RuleId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_identifiers_are_accepted() {
        for text in [
            "a",
            "7",
            "users-admin-backup",
            "catalog_enumeration",
            "Billing.Cards.v2",
            &"x".repeat(MAX_ID_BYTES),
        ] {
            let id = TokenId::new(text).unwrap();
            assert_eq!(id.as_str(), text);
            assert_eq!(id.to_string(), text);
            assert_eq!(text.parse::<RuleId>().unwrap().as_str(), text);
        }
    }

    #[test]
    fn malformed_identifiers_are_rejected() {
        for text in [
            "",
            "-leading-dash",
            ".leading-dot",
            "_leading_underscore",
            "has space",
            "has/slash",
            "has:colon",
            "caf\u{e9}",
            "new\nline",
            "nul\0byte",
            &"x".repeat(MAX_ID_BYTES + 1),
        ] {
            assert_eq!(TokenId::new(text), Err(InvalidId), "{text:?}");
            assert_eq!(RuleId::new(text), Err(InvalidId), "{text:?}");
        }
    }

    #[test]
    fn json_uses_the_plain_text() {
        let id = TokenId::new("users-admin-backup").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"users-admin-backup\"");
        assert_eq!(serde_json::from_str::<TokenId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<TokenId>("\"\"").is_err());
        assert!(serde_json::from_str::<TokenId>("12").is_err());
    }

    #[test]
    fn a_rejected_identifier_is_not_repeated_in_the_error() {
        let error = serde_json::from_str::<TokenId>("\"svc.backup.8f3k2q@mail.example\"")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("svc.backup"), "{error}");
        assert!(!error.contains("mail.example"), "{error}");
    }
}
