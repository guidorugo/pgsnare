// SPDX-License-Identifier: Apache-2.0

//! A generated value.

use core::fmt;

use super::error::BaitError;
use crate::detect::{MIN_VALUE_LEN, TokenValue};

/// A generated bait value. **Treat it as a secret.**
///
/// Once it is planted and configured, this is the value of a honeytoken,
/// and whoever learns it can avoid it. Like [`TokenValue`], this type
/// prints as `<redacted>` in `Debug`, has no `Display`, and gives its text
/// only through the deliberately named [`Bait::expose`].
///
/// # What holds for every value
///
/// - It is ASCII, so it matches in every client encoding.
/// - It is at least [`MIN_VALUE_LEN`] bytes long.
/// - It is made of letters, digits and the characters `. - _ @ : $ / + = ,`
///   and nothing else. The text formats that the
///   [`detect`](crate::detect#limits-of-substring-matching) module lists
///   escape or double other characters, such as quotes and backslashes,
///   and a value that contains one is missed where that happened. These
///   characters are left as they are.
///
/// A value is built by a generator of this module and by nothing else, and
/// it is checked against these rules when it is built.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bait(String);

impl Bait {
    /// Wraps the text a generator produced, after checking it against the
    /// rules every value follows.
    pub(super) fn new(text: String) -> Result<Self, BaitError> {
        if text.len() >= MIN_VALUE_LEN && text.bytes().all(is_plain) {
            Ok(Self(text))
        } else {
            Err(BaitError::Defect)
        }
    }

    /// The value itself.
    ///
    /// Use it to plant the value, to send it as bait, or to print it for
    /// the operator who asked for it. Never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Whether a byte may appear in a value.
const fn is_plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'-' | b'_' | b'@' | b':' | b'$' | b'/' | b'+' | b'=' | b','
        )
}

impl fmt::Debug for Bait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bait(<redacted>)")
    }
}

impl From<Bait> for TokenValue {
    fn from(bait: Bait) -> Self {
        Self::new(bait.0)
    }
}

impl From<&Bait> for TokenValue {
    fn from(bait: &Bait) -> Self {
        Self::new(bait.0.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_never_prints_its_text() {
        let bait = Bait::new("svc.backup.k7q2m5xd3pza".to_owned()).unwrap();
        assert_eq!(format!("{bait:?}"), "Bait(<redacted>)");
        assert_eq!(format!("{bait:#?}"), "Bait(<redacted>)");
        assert_eq!(bait.expose(), "svc.backup.k7q2m5xd3pza");
    }

    #[test]
    fn a_value_shorter_than_a_honeytoken_is_a_defect() {
        assert_eq!(Bait::new("elevenbytes".to_owned()), Err(BaitError::Defect));
        assert_eq!(Bait::new(String::new()), Err(BaitError::Defect));
        assert!(Bait::new("exactly12byt".to_owned()).is_ok());
    }

    #[test]
    fn only_characters_that_no_text_format_changes_are_allowed() {
        let allowed = "AZaz09.-_@:$/+=,";
        assert!(Bait::new(allowed.to_owned()).is_ok());
        for byte in 0..=u8::MAX {
            let text = String::from_utf8(vec![b'a'; 12])
                .map(|mut text| {
                    text.push(char::from(byte));
                    text
                })
                .unwrap();
            let expected = byte.is_ascii_alphanumeric() || allowed.as_bytes().contains(&byte);
            assert_eq!(Bait::new(text).is_ok(), expected, "byte {byte:#04x}");
        }
        // The characters the detect module warns about, by name.
        for bad in [
            '"', '\\', '\'', '<', '>', '&', '\t', '\n', '\0', ' ', '\u{e9}',
        ] {
            assert_eq!(
                Bait::new(format!("aaaaaaaaaaaa{bad}")),
                Err(BaitError::Defect),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_value_becomes_a_token_value_unchanged() {
        let bait = Bait::new("QK7M-2X5D-3PZA-F4T6".to_owned()).unwrap();
        assert_eq!(TokenValue::from(&bait).expose(), b"QK7M-2X5D-3PZA-F4T6");
        assert_eq!(TokenValue::from(bait).expose(), b"QK7M-2X5D-3PZA-F4T6");
    }
}
