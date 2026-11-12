// SPDX-License-Identifier: Apache-2.0

//! What the matcher is built from: token ids, secret token values and the
//! description of one token.

use std::fmt;
use std::sync::Arc;

/// What stands in for a token value wherever one would otherwise be printed.
const REDACTED: &str = "<redacted>";

/// The identifier of a honeytoken.
///
/// An id is not secret. Errors and matches use it to name a token, so that
/// the token's values never have to be shown.
///
/// Cloning is cheap: clones share one allocation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(Arc<str>);

impl TokenId {
    /// Creates an id from its text.
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TokenId").field(&self.as_str()).finish()
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for TokenId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for TokenId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for TokenId {
    fn from(id: String) -> Self {
        Self(Arc::from(id))
    }
}

/// One value of a honeytoken. **This is a secret.**
///
/// Whoever learns a value can avoid it, so a value must never reach a log, an
/// error message or an event. To make that hard to get wrong, the `Debug` and
/// `Display` output of this type is always `<redacted>`, and the only way to
/// read the bytes is the deliberately named [`TokenValue::expose`].
///
/// A `TokenValue` holds whatever it is given. The rules a value must follow
/// are checked by [`Matcher::build`](super::Matcher::build), which can name
/// the token a bad value belongs to.
///
/// ```
/// use pgsnare_core::detect::TokenValue;
///
/// let value = TokenValue::from("svc.backup.8f3k2q@mail.example");
/// assert_eq!(format!("{value}"), "<redacted>");
/// assert_eq!(format!("{value:?}"), "TokenValue(<redacted>)");
/// ```
#[derive(Clone)]
pub struct TokenValue(Box<[u8]>);

impl TokenValue {
    /// Wraps the bytes of a value.
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(value.into().into_boxed_slice())
    }

    /// The secret bytes.
    ///
    /// Use the result for matching only. Never format, log or store it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenValue({REDACTED})")
    }
}

impl fmt::Display for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl From<&str> for TokenValue {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for TokenValue {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for TokenValue {
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for TokenValue {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

/// One honeytoken as the matcher needs it: an id, one or more values, and
/// whether letter case is ignored when looking for them.
///
/// This is the whole input of [`Matcher::build`](super::Matcher::build). It
/// knows nothing about responses, scopes or configuration files; whatever
/// loads the configuration maps its own token type onto this one.
///
/// ```
/// use pgsnare_core::detect::TokenSpec;
///
/// let token = TokenSpec::new("users-admin-backup", ["svc.backup.8f3k2q@mail.example"])
///     .case_insensitive(true);
/// assert_eq!(token.id().as_str(), "users-admin-backup");
/// assert_eq!(token.values().len(), 1);
/// assert!(token.is_case_insensitive());
/// ```
#[derive(Debug, Clone)]
pub struct TokenSpec {
    id: TokenId,
    values: Vec<TokenValue>,
    case_insensitive: bool,
}

impl TokenSpec {
    /// Describes a token whose values are looked for exactly as written.
    pub fn new<I, V>(id: impl Into<TokenId>, values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<TokenValue>,
    {
        Self {
            id: id.into(),
            values: values.into_iter().map(Into::into).collect(),
            case_insensitive: false,
        }
    }

    /// Sets whether the values are also found when their ASCII letters appear
    /// in another case.
    #[must_use]
    pub fn case_insensitive(mut self, yes: bool) -> Self {
        self.case_insensitive = yes;
        self
    }

    /// The token's id.
    pub fn id(&self) -> &TokenId {
        &self.id
    }

    /// The token's values, in the order they were given.
    pub fn values(&self) -> &[TokenValue] {
        &self.values
    }

    /// Whether ASCII letter case is ignored when looking for the values.
    pub fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_id_keeps_its_text() {
        let id = TokenId::from("users-admin-backup");
        assert_eq!(id.as_str(), "users-admin-backup");
        assert_eq!(id.to_string(), "users-admin-backup");
        assert_eq!(format!("{id:?}"), r#"TokenId("users-admin-backup")"#);
        assert_eq!(id, TokenId::from(String::from("users-admin-backup")));
    }

    #[test]
    fn token_value_never_prints_its_bytes() {
        let value = TokenValue::from("svc.backup.8f3k2q@mail.example");
        assert_eq!(format!("{value}"), "<redacted>");
        assert_eq!(format!("{value:?}"), "TokenValue(<redacted>)");
        assert_eq!(format!("{value:#?}"), "TokenValue(<redacted>)");
        assert_eq!(value.expose(), b"svc.backup.8f3k2q@mail.example");
    }

    #[test]
    fn token_value_accepts_any_bytes() {
        let value = TokenValue::from(vec![0x00, 0xff, 0x80]);
        assert_eq!(value.expose(), [0x00, 0xff, 0x80]);
        assert_eq!(TokenValue::from(&b"abc"[..]).expose(), b"abc");
        assert_eq!(TokenValue::from(String::from("abc")).expose(), b"abc");
    }

    #[test]
    fn token_spec_debug_shows_the_id_and_hides_the_values() {
        let token = TokenSpec::new("users-admin-backup", ["svc.backup.8f3k2q@mail.example"]);
        let debug = format!("{token:?}");
        assert!(debug.contains("users-admin-backup"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("svc.backup"));
        assert!(!debug.contains("mail.example"));
    }

    #[test]
    fn token_spec_is_case_sensitive_unless_asked() {
        let token = TokenSpec::new("a", ["0123456789ab"]);
        assert!(!token.is_case_insensitive());
        assert!(token.clone().case_insensitive(true).is_case_insensitive());
        assert!(!token.case_insensitive(false).is_case_insensitive());
    }
}
