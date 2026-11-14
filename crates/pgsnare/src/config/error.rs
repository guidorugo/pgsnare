// SPDX-License-Identifier: Apache-2.0

//! What can be wrong with a configuration, and how it is reported.
//!
//! One rule holds for every message this module produces: **it contains no
//! text from the document.** A message is built from fixed text, numbers,
//! and the names of fields of the schema. A honeytoken value therefore
//! cannot reach a log through an error, however the document is mangled.
//! File names are the one exception, and only the loader adds those.

use std::fmt;
use std::path::PathBuf;

/// One thing that is wrong with a configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Problem {
    /// The file the problem is in, when the configuration came from files.
    pub file: Option<PathBuf>,
    /// The line of the problem, counting from 1, when it is known.
    pub line: Option<u64>,
    /// The column of the problem, counting from 1, when it is known.
    pub column: Option<u64>,
    /// Where in the schema the problem is, such as
    /// `listeners[0].client_tls`, when it is known.
    pub path: Option<String>,
    /// What is wrong. It never contains text from the document.
    pub message: String,
}

impl Problem {
    pub(super) fn at_position(line: Option<u64>, column: Option<u64>, message: String) -> Self {
        Self {
            file: None,
            line,
            column,
            path: None,
            message,
        }
    }

    pub(super) fn at_path(path: &At, message: String) -> Self {
        Self {
            file: None,
            line: None,
            column: None,
            path: (!path.0.is_empty()).then(|| path.0.clone()),
            message,
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}: ", file.display())?;
        }
        match (self.line, self.column) {
            (Some(line), Some(column)) => write!(f, "line {line}, column {column}: ")?,
            (Some(line), None) => write!(f, "line {line}: ")?,
            _ => {}
        }
        if let Some(path) = &self.path {
            write!(f, "{path}: ")?;
        }
        f.write_str(&self.message)
    }
}

/// Why a configuration was rejected: one or more [`Problem`]s.
///
/// Displaying it prints one problem per line. The text is safe to log: see
/// the rule at the top of this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    problems: Vec<Problem>,
}

impl ConfigError {
    pub(super) fn one(problem: Problem) -> Self {
        Self {
            problems: vec![problem],
        }
    }

    /// Everything that is wrong. There is at least one problem.
    #[must_use]
    pub fn problems(&self) -> &[Problem] {
        &self.problems
    }

    /// Marks every problem that has no file yet as belonging to `file`.
    pub(super) fn in_file(mut self, file: &std::path::Path) -> Self {
        for problem in &mut self.problems {
            if problem.file.is_none() {
                problem.file = Some(file.to_path_buf());
            }
        }
        self
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, problem) in self.problems.iter().enumerate() {
            if index > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// A place in the schema, such as `listeners[0].client_tls`.
///
/// It is made of field names and positions only, never of text from the
/// document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct At(String);

impl At {
    /// The top of the document.
    pub(super) fn root() -> Self {
        Self(String::new())
    }

    /// The field `name` of this place.
    pub(super) fn field(&self, name: &'static str) -> Self {
        if self.0.is_empty() {
            Self(name.to_owned())
        } else {
            Self(format!("{}.{name}", self.0))
        }
    }

    /// The element `index` of this place, counting from 0.
    pub(super) fn index(&self, index: usize) -> Self {
        Self(format!("{}[{index}]", self.0))
    }
}

impl fmt::Display for At {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Collects the problems found while checking a configuration.
///
/// Every message is a `&'static str`, which is what keeps text from the
/// document out of them.
#[derive(Debug, Default)]
pub(super) struct Problems {
    list: Vec<Problem>,
    /// The file the problems found from now on belong to.
    file: Option<PathBuf>,
}

impl Problems {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// How many problems were recorded so far.
    pub(super) fn len(&self) -> usize {
        self.list.len()
    }

    /// Sets the file that later problems belong to.
    pub(super) fn set_file(&mut self, file: Option<PathBuf>) {
        self.file = file;
    }

    /// Records a problem at a place.
    pub(super) fn add(&mut self, at: &At, message: &'static str) {
        let mut problem = Problem::at_path(at, message.to_owned());
        problem.file.clone_from(&self.file);
        self.list.push(problem);
    }

    /// Records a problem at a place that involves a second place.
    pub(super) fn add_with(&mut self, at: &At, message: &'static str, other: &At) {
        let mut problem = Problem::at_path(at, format!("{message} (see {other})"));
        problem.file.clone_from(&self.file);
        self.list.push(problem);
    }

    /// Records a problem at a place that involves a second place, which may
    /// be in another file.
    pub(super) fn add_with_place(
        &mut self,
        at: &At,
        message: &'static str,
        other: &At,
        other_file: Option<&std::path::Path>,
    ) {
        let text = match other_file {
            Some(file) if self.file.as_deref() != Some(file) => {
                format!("{message} (see {other} in {})", file.display())
            }
            _ => format!("{message} (see {other})"),
        };
        let mut problem = Problem::at_path(at, text);
        problem.file.clone_from(&self.file);
        self.list.push(problem);
    }

    /// Records the outcome of a check that reports a fixed reason.
    pub(super) fn check(&mut self, at: &At, outcome: Result<(), &'static str>) {
        if let Err(message) = outcome {
            self.add(at, message);
        }
    }

    pub(super) fn into_result(self) -> Result<(), ConfigError> {
        if self.list.is_empty() {
            Ok(())
        } else {
            Err(ConfigError {
                problems: self.list,
            })
        }
    }
}

/// Fixed messages that a conversion inside the schema reports through serde.
///
/// serde hands a conversion error to the YAML library as free text. The
/// loader prints such text only if it is exactly one of these, which keeps
/// the rule at the top of this module true even for messages that pass
/// through code this crate does not control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reason {
    /// A webhook needs exactly one of `url`, `url_env` and `url_file`.
    OneUrlSource,
    /// A webhook needs exactly one of `hmac_secret_env` and
    /// `hmac_secret_file`.
    OneSecretSource,
}

impl Reason {
    pub(super) const ALL: [Self; 2] = [Self::OneUrlSource, Self::OneSecretSource];

    pub(super) const fn text(self) -> &'static str {
        match self {
            Self::OneUrlSource => "set exactly one of url, url_env and url_file",
            Self::OneSecretSource => {
                "set exactly one of hmac_secret_env and hmac_secret_file: \
                 a secret is named by an environment variable or a file, never written here"
            }
        }
    }

    /// The fixed message that is exactly `text`, if there is one.
    pub(super) fn recognise(text: &str) -> Option<&'static str> {
        Self::ALL
            .into_iter()
            .map(Self::text)
            .find(|known| *known == text)
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_prints_what_is_known_about_its_place() {
        let mut problem = Problem::at_position(Some(3), Some(7), "unknown field".to_owned());
        assert_eq!(problem.to_string(), "line 3, column 7: unknown field");

        problem.file = Some(PathBuf::from("/etc/pgsnare/pgsnare.yaml"));
        assert_eq!(
            problem.to_string(),
            "/etc/pgsnare/pgsnare.yaml: line 3, column 7: unknown field"
        );

        let at = At::root().field("listeners").index(0).field("client_tls");
        assert_eq!(at.to_string(), "listeners[0].client_tls");
        assert_eq!(
            Problem::at_path(&at, "cert and key are required".to_owned()).to_string(),
            "listeners[0].client_tls: cert and key are required"
        );
        assert_eq!(
            Problem::at_path(&At::root(), "no listeners".to_owned()).to_string(),
            "no listeners"
        );
        assert_eq!(
            Problem::at_position(None, None, "invalid YAML".to_owned()).to_string(),
            "invalid YAML"
        );
    }

    #[test]
    fn problems_are_collected_and_printed_one_per_line() {
        let mut problems = Problems::new();
        assert!(Problems::new().into_result().is_ok());

        let tokens = At::root().field("tokens");
        problems.add(&tokens.index(1), "values must not be empty");
        problems.add_with(
            &tokens.index(2).field("id"),
            "this id is already used",
            &tokens.index(0).field("id"),
        );
        problems.check(&tokens.index(3), Ok(()));
        problems.check(
            &tokens.index(4),
            Err("actions must list at least one action"),
        );
        problems.set_file(Some(PathBuf::from("/etc/pgsnare/tokens/a.yaml")));
        problems.add(&tokens.index(0), "values must not be empty");

        let error = problems.into_result().unwrap_err();
        assert_eq!(error.problems().len(), 4);
        assert_eq!(
            error.to_string(),
            "tokens[1]: values must not be empty\n\
             tokens[2].id: this id is already used (see tokens[0].id)\n\
             tokens[4]: actions must list at least one action\n\
             /etc/pgsnare/tokens/a.yaml: tokens[0]: values must not be empty"
        );

        let error = error.in_file(std::path::Path::new("/etc/pgsnare/pgsnare.yaml"));
        assert!(
            error
                .to_string()
                .starts_with("/etc/pgsnare/pgsnare.yaml: tokens[1]: ")
        );
        assert!(
            error
                .to_string()
                .ends_with("/etc/pgsnare/tokens/a.yaml: tokens[0]: values must not be empty")
        );
    }

    #[test]
    fn only_the_fixed_reasons_are_recognised() {
        for reason in Reason::ALL {
            assert_eq!(Reason::recognise(&reason.to_string()), Some(reason.text()));
        }
        assert_eq!(Reason::recognise(""), None);
        assert_eq!(Reason::recognise("set exactly one of url"), None);
        assert_eq!(
            Reason::recognise(&format!("{} ", Reason::OneUrlSource.text())),
            None
        );
    }
}
