// SPDX-License-Identifier: Apache-2.0

//! The errors of the detection module.
//!
//! None of these types has a field that could hold a token value. They name
//! tokens by id and values by position.

use std::error::Error;
use std::fmt;

use super::pattern::{MIN_VALUE_LEN, PatternForm};
use super::token::TokenId;

/// Points at one value of one token without revealing the value.
///
/// It is printed as, for example, `values[1] of token "users-admin-backup"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValueLocation {
    /// The id of the token the value belongs to.
    pub token: TokenId,
    /// The position of that token in the list given to
    /// [`Matcher::build`](super::Matcher::build), counted from zero.
    pub token_index: usize,
    /// The position of the value among the token's values, counted from
    /// zero.
    pub value_index: usize,
}

impl fmt::Display for ValueLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "values[{}] of ", self.value_index)?;
        write_token(f, &self.token, self.token_index)
    }
}

/// Names a token by its id, or by its position if the id is empty.
fn write_token(f: &mut fmt::Formatter<'_>, id: &TokenId, index: usize) -> fmt::Result {
    if id.as_str().is_empty() {
        write!(f, "tokens[{index}]")
    } else {
        // The id is quoted and escaped, so an unusual id cannot break up the
        // line it is printed on.
        write!(f, "token {:?}", id.as_str())
    }
}

/// One reason a token list was refused.
///
/// An error names the token by id and the value by position. It never
/// contains a value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// A token has an empty id, so nothing could name it in a report.
    EmptyId {
        /// The position of the token in the list, counted from zero.
        token_index: usize,
    },
    /// Two tokens have the same id, so a match could not tell them apart.
    DuplicateId {
        /// The id that is used twice.
        id: TokenId,
        /// The position of the later token, counted from zero.
        token_index: usize,
        /// The position of the first token with this id, counted from zero.
        first_index: usize,
    },
    /// A token has no values, so it could never be found.
    NoValues {
        /// The id of the token.
        token: TokenId,
        /// The position of the token in the list, counted from zero.
        token_index: usize,
    },
    /// A value contains a byte outside ASCII.
    NotAscii {
        /// Which value.
        location: ValueLocation,
    },
    /// A value is shorter than [`MIN_VALUE_LEN`] bytes.
    TooShort {
        /// Which value.
        location: ValueLocation,
    },
    /// A value is byte for byte the same as an earlier one.
    Duplicate {
        /// The later of the two values.
        location: ValueLocation,
        /// The earlier of the two values.
        earlier: ValueLocation,
    },
    /// Data that matches one value would also match another, because the
    /// first contains the second.
    ///
    /// The forms say which spelling of each value is involved. In the plain
    /// case both are [`PatternForm::Raw`]: one configured value contains the
    /// other.
    Contains {
        /// The value that contains the other.
        container: ValueLocation,
        /// The spelling of the container in which the other value appears:
        /// as configured, in hexadecimal, or in another letter case that its
        /// case-insensitive token accepts.
        container_form: PatternForm,
        /// The value that is contained.
        contained: ValueLocation,
        /// The form in which the contained value appears.
        contained_form: PatternForm,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId { token_index } => {
                write!(f, "tokens[{token_index}] has an empty id")
            }
            Self::DuplicateId {
                id,
                token_index,
                first_index,
            } => write!(
                f,
                "tokens[{first_index}] and tokens[{token_index}] have the same id {:?}",
                id.as_str()
            ),
            Self::NoValues { token, token_index } => {
                write_token(f, token, *token_index)?;
                f.write_str(" has no values")
            }
            Self::NotAscii { location } => write!(f, "{location} is not ASCII"),
            Self::TooShort { location } => {
                write!(f, "{location} is shorter than {MIN_VALUE_LEN} bytes")
            }
            Self::Duplicate { location, earlier } => {
                write!(f, "{location} is the same as {earlier}")
            }
            Self::Contains {
                container,
                container_form,
                contained,
                contained_form,
            } => {
                match container_form {
                    PatternForm::Hex => write!(f, "the hex form of {container}")?,
                    PatternForm::CaseInsensitive => {
                        write!(f, "{container}, in another letter case,")?;
                    }
                    PatternForm::Raw => write!(f, "{container}")?,
                }
                f.write_str(" contains ")?;
                match contained_form {
                    PatternForm::Hex => write!(f, "the hex form of {contained}"),
                    PatternForm::CaseInsensitive => {
                        write!(f, "{contained} in another letter case")
                    }
                    PatternForm::Raw => write!(f, "{contained}"),
                }
            }
        }
    }
}

impl Error for ValidationError {}

/// Every problem found in a token list, up to [`ValidationErrors::LIMIT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors {
    errors: Vec<ValidationError>,
    truncated: bool,
}

impl ValidationErrors {
    /// The largest number of problems that is listed. A broken list can
    /// contain a problem for every pair of values, so the report is capped.
    pub const LIMIT: usize = 64;

    pub(crate) fn new() -> Self {
        Self {
            errors: Vec::new(),
            truncated: false,
        }
    }

    /// Records a problem, or notes that one was left out once the list is
    /// full.
    pub(crate) fn push(&mut self, error: ValidationError) {
        if self.errors.len() < Self::LIMIT {
            self.errors.push(error);
        } else {
            self.truncated = true;
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// The problems, in the order they were found.
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Whether more problems exist than are listed.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the honeytoken list is not valid")?;
        for (position, error) in self.errors.iter().enumerate() {
            f.write_str(if position == 0 { ": " } else { "; " })?;
            write!(f, "{error}")?;
        }
        if self.truncated {
            f.write_str("; more problems were found and are not listed")?;
        }
        Ok(())
    }
}

impl Error for ValidationErrors {}

/// Why [`Matcher::build`](super::Matcher::build) could not build a matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The token list breaks at least one rule. Nothing was compiled.
    Invalid(ValidationErrors),
    /// The values are too many or too long to be compiled.
    TooLarge,
    /// The compiled patterns cannot be searched the way the matcher needs.
    /// This points at a defect, not at the token list.
    SearchUnavailable,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(errors) => write!(f, "{errors}"),
            Self::TooLarge => {
                f.write_str("the honeytoken values are too many or too long to compile")
            }
            Self::SearchUnavailable => {
                f.write_str("the compiled honeytoken patterns cannot be searched")
            }
        }
    }
}

impl Error for BuildError {}

impl From<ValidationErrors> for BuildError {
    fn from(errors: ValidationErrors) -> Self {
        Self::Invalid(errors)
    }
}

/// A scan could not be carried out.
///
/// A matcher that was built successfully is not expected to produce this
/// error for any input. It exists so that a defect surfaces as an inspection
/// error, which the caller can treat as a reason to fail closed, instead of
/// as a panic or as a silently missed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    kind: ScanErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanErrorKind {
    SearchFailed,
    UnknownPattern,
}

impl ScanError {
    /// The automaton refused to run the search.
    pub(crate) fn search_failed() -> Self {
        Self {
            kind: ScanErrorKind::SearchFailed,
        }
    }

    /// The automaton reported a pattern the matcher has no record of.
    pub(crate) fn unknown_pattern() -> Self {
        Self {
            kind: ScanErrorKind::UnknownPattern,
        }
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ScanErrorKind::SearchFailed => "the honeytoken search could not run",
            ScanErrorKind::UnknownPattern => {
                "the honeytoken search reported a pattern the matcher does not know"
            }
        })
    }
}

impl Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(token: &str, token_index: usize, value_index: usize) -> ValueLocation {
        ValueLocation {
            token: TokenId::from(token),
            token_index,
            value_index,
        }
    }

    #[test]
    fn locations_name_the_token_and_the_position() {
        assert_eq!(
            location("users-admin-backup", 3, 1).to_string(),
            r#"values[1] of token "users-admin-backup""#
        );
        // An empty id names nothing, so the position in the list is used.
        assert_eq!(location("", 3, 1).to_string(), "values[1] of tokens[3]");
    }

    #[test]
    fn ids_are_escaped_when_printed_in_an_error() {
        let error = ValidationError::NotAscii {
            location: location("two\nlines", 0, 0),
        };
        assert_eq!(
            error.to_string(),
            r#"values[0] of token "two\nlines" is not ASCII"#
        );
    }

    #[test]
    fn every_kind_of_problem_has_a_message() {
        let a = location("a", 0, 0);
        let b = location("b", 1, 2);
        let cases = [
            (
                ValidationError::EmptyId { token_index: 4 },
                "tokens[4] has an empty id",
            ),
            (
                ValidationError::DuplicateId {
                    id: TokenId::from("a"),
                    token_index: 5,
                    first_index: 0,
                },
                r#"tokens[0] and tokens[5] have the same id "a""#,
            ),
            (
                ValidationError::NoValues {
                    token: TokenId::from("a"),
                    token_index: 0,
                },
                r#"token "a" has no values"#,
            ),
            (
                ValidationError::NoValues {
                    token: TokenId::from(""),
                    token_index: 7,
                },
                "tokens[7] has no values",
            ),
            (
                ValidationError::NotAscii {
                    location: a.clone(),
                },
                r#"values[0] of token "a" is not ASCII"#,
            ),
            (
                ValidationError::TooShort {
                    location: a.clone(),
                },
                r#"values[0] of token "a" is shorter than 12 bytes"#,
            ),
            (
                ValidationError::Duplicate {
                    location: b.clone(),
                    earlier: a.clone(),
                },
                r#"values[2] of token "b" is the same as values[0] of token "a""#,
            ),
            (
                ValidationError::Contains {
                    container: a.clone(),
                    container_form: PatternForm::Raw,
                    contained: b.clone(),
                    contained_form: PatternForm::Raw,
                },
                r#"values[0] of token "a" contains values[2] of token "b""#,
            ),
            (
                ValidationError::Contains {
                    container: a.clone(),
                    container_form: PatternForm::Hex,
                    contained: b.clone(),
                    contained_form: PatternForm::CaseInsensitive,
                },
                r#"the hex form of values[0] of token "a" contains values[2] of token "b" in another letter case"#,
            ),
            (
                ValidationError::Contains {
                    container: a,
                    container_form: PatternForm::CaseInsensitive,
                    contained: b,
                    contained_form: PatternForm::Hex,
                },
                r#"values[0] of token "a", in another letter case, contains the hex form of values[2] of token "b""#,
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn the_list_of_problems_is_capped() {
        let mut errors = ValidationErrors::new();
        assert!(errors.is_empty());
        for token_index in 0..ValidationErrors::LIMIT {
            errors.push(ValidationError::EmptyId { token_index });
        }
        assert_eq!(errors.errors().len(), ValidationErrors::LIMIT);
        assert!(!errors.is_truncated());

        errors.push(ValidationError::EmptyId { token_index: 9999 });
        assert_eq!(errors.errors().len(), ValidationErrors::LIMIT);
        assert!(errors.is_truncated());
        assert!(
            errors
                .to_string()
                .ends_with("; more problems were found and are not listed")
        );
        assert!(!errors.to_string().contains("9999"));
    }

    #[test]
    fn the_list_of_problems_prints_on_one_line() {
        let mut errors = ValidationErrors::new();
        errors.push(ValidationError::EmptyId { token_index: 0 });
        errors.push(ValidationError::EmptyId { token_index: 1 });
        assert_eq!(
            errors.to_string(),
            "the honeytoken list is not valid: tokens[0] has an empty id; tokens[1] has an empty id"
        );
        assert_eq!(
            BuildError::from(errors.clone()).to_string(),
            errors.to_string()
        );
    }

    #[test]
    fn scan_and_build_errors_have_fixed_messages() {
        assert_eq!(
            ScanError::search_failed().to_string(),
            "the honeytoken search could not run"
        );
        assert_eq!(
            ScanError::unknown_pattern().to_string(),
            "the honeytoken search reported a pattern the matcher does not know"
        );
        assert_eq!(
            BuildError::TooLarge.to_string(),
            "the honeytoken values are too many or too long to compile"
        );
        assert_eq!(
            BuildError::SearchUnavailable.to_string(),
            "the compiled honeytoken patterns cannot be searched"
        );
    }
}
