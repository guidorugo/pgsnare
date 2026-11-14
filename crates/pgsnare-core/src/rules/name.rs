// SPDX-License-Identifier: Apache-2.0

//! Names of relations and functions, as the configuration gives them.

use core::fmt;

/// The longest name PostgreSQL keeps, in bytes. It cuts a longer one while
/// it reads a statement, so a configured name is cut the same way.
pub const MAX_IDENTIFIER_BYTES: usize = 63;

/// Why a configured name was not accepted. The text is fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidName(&'static str);

impl InvalidName {
    /// What is wrong with the name.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for InvalidName {}

/// The name of a relation or a function, with or without a schema, in the
/// form PostgreSQL gives a name when it reads a statement.
///
/// It is written the way it would be in SQL: `users`, `public.users`,
/// `"Users"`, `"my schema"."my.table"`. A part without quotes is folded to
/// lower case, as PostgreSQL folds it; a part in double quotes is kept as
/// it is, with `""` for one quote. Each part is cut at
/// [`MAX_IDENTIFIER_BYTES`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct QualifiedName {
    schema: Option<Box<str>>,
    name: Box<str>,
}

impl QualifiedName {
    /// Reads a name as the configuration gives it.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with it: an empty part, a character that
    /// needs quotes, a quote that is not closed, or more than two parts.
    pub fn parse(text: &str) -> Result<Self, InvalidName> {
        let (first, rest) = part(text)?;
        let Some(rest) = rest else {
            return Ok(Self {
                schema: None,
                name: first,
            });
        };
        let (second, rest) = part(rest)?;
        if rest.is_some() {
            return Err(InvalidName(
                "must be a name or schema.name, without a database",
            ));
        }
        Ok(Self {
            schema: Some(first),
            name: second,
        })
    }

    /// The schema, when the name has one.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The name without its schema.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether a name found in a statement can be this one.
    ///
    /// The names must be equal. The schemas must be equal when both are
    /// given. When either side leaves the schema out it matches, because
    /// the search path of the session decides what it means and is not
    /// known here; that errs on the side of a match.
    #[must_use]
    pub fn matches(&self, schema: Option<&str>, name: &str) -> bool {
        *self.name == *name
            && match (self.schema.as_deref(), schema) {
                (Some(wanted), Some(found)) => wanted == found,
                _ => true,
            }
    }
}

/// Reads one part of a name from the start of `text`. Returns the part and
/// what follows the dot after it, if there is a dot.
fn part(text: &str) -> Result<(Box<str>, Option<&str>), InvalidName> {
    const NEEDS_QUOTES: InvalidName = InvalidName(
        "a name without double quotes holds letters, digits, _ and $, and starts with a letter or _",
    );
    let (name, rest) = if let Some(quoted) = text.strip_prefix('"') {
        let mut name = String::new();
        let mut chars = quoted.char_indices();
        let after = loop {
            match chars.next() {
                None => return Err(InvalidName("a double quote is not closed")),
                Some((at, '"')) => {
                    if quoted
                        .get(at.saturating_add(1)..)
                        .is_some_and(|tail| tail.starts_with('"'))
                    {
                        chars.next();
                        name.push('"');
                    } else {
                        break quoted.get(at.saturating_add(1)..).unwrap_or_default();
                    }
                }
                Some((_, '\0')) => return Err(InvalidName("must not hold a NUL")),
                Some((_, other)) => name.push(other),
            }
        };
        (name, after)
    } else {
        let end = text.find('.').unwrap_or(text.len());
        let (name, after) = text.split_at_checked(end).ok_or(NEEDS_QUOTES)?;
        let mut chars = name.chars();
        let starts_well = chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_' || !first.is_ascii());
        let goes_on_well =
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$' || !c.is_ascii());
        if !name.is_empty() && !(starts_well && goes_on_well) {
            return Err(NEEDS_QUOTES);
        }
        (name.to_ascii_lowercase(), after)
    };
    if name.is_empty() {
        return Err(InvalidName("a part of the name is empty"));
    }
    let rest = match rest.strip_prefix('.') {
        Some(rest) => Some(rest),
        None if rest.is_empty() => None,
        None => {
            return Err(InvalidName(
                "a quoted name is followed by something other than a dot",
            ));
        }
    };
    Ok((cut(&name).into(), rest))
}

/// The name cut at [`MAX_IDENTIFIER_BYTES`], on a character boundary, as
/// PostgreSQL cuts it.
fn cut(name: &str) -> &str {
    let mut end = name.len().min(MAX_IDENTIFIER_BYTES);
    while !name.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    name.get(..end).unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> (Option<String>, String) {
        let name = QualifiedName::parse(text).unwrap();
        (name.schema().map(str::to_owned), name.name().to_owned())
    }

    #[test]
    fn names_are_read_as_postgresql_reads_them() {
        assert_eq!(parsed("users"), (None, "users".into()));
        assert_eq!(parsed("Users"), (None, "users".into()));
        assert_eq!(parsed("PG_READ_FILE"), (None, "pg_read_file".into()));
        assert_eq!(
            parsed("public.Users"),
            (Some("public".into()), "users".into())
        );
        assert_eq!(parsed("\"Users\""), (None, "Users".into()));
        assert_eq!(
            parsed("\"my schema\".\"my.\"\"table\""),
            (Some("my schema".into()), "my.\"table".into())
        );
        assert_eq!(parsed("Public.\"T\""), (Some("public".into()), "T".into()));
        // Only ASCII letters are folded.
        assert_eq!(parsed("\u{c9}t\u{e9}"), (None, "\u{c9}t\u{e9}".into()));
        assert_eq!(parsed("_a$1"), (None, "_a$1".into()));
    }

    #[test]
    fn a_long_name_is_cut_like_postgresql_cuts_it() {
        let long = "a".repeat(70);
        assert_eq!(parsed(&long).1, "a".repeat(63));
        // 62 bytes and a two-byte character: the character does not fit.
        let edge = format!("{}\u{e9}", "a".repeat(62));
        assert_eq!(parsed(&edge).1, "a".repeat(62));
    }

    #[test]
    fn broken_names_are_refused() {
        for text in [
            "",
            ".",
            "a.",
            ".a",
            "a..b",
            "a.b.c",
            "\"\"",
            "\"a",
            "\"a\"b",
            "a b",
            "pg_sleep(1)",
            "1a",
            "$a",
            "a-b",
            "a;b",
            "\"a\0\"",
        ] {
            assert!(QualifiedName::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn a_missing_schema_matches_any() {
        let bare = QualifiedName::parse("users").unwrap();
        assert!(bare.matches(None, "users"));
        assert!(bare.matches(Some("public"), "users"));
        assert!(!bare.matches(None, "Users"));
        assert!(!bare.matches(None, "user"));

        let qualified = QualifiedName::parse("public.users").unwrap();
        assert!(qualified.matches(None, "users"));
        assert!(qualified.matches(Some("public"), "users"));
        assert!(!qualified.matches(Some("other"), "users"));
        assert!(!qualified.matches(Some("public"), "cards"));
    }
}
