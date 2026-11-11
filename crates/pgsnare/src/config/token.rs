// SPDX-License-Identifier: Apache-2.0

//! Honeytokens: the values to watch for, and what to do when one is seen.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use pgsnare_core::policy::{ActionSet, Escalation, Scope, TokenId, TokenPolicy};
use serde::{Deserialize, Deserializer, de};

use super::error::{At, ConfigError, Problems};
use super::yaml;

/// The shortest value a token may have, in bytes. A shorter value could
/// turn up in ordinary data by accident.
pub const MIN_VALUE_BYTES: usize = 12;

/// The longest value a token may have, in bytes.
pub const MAX_VALUE_BYTES: usize = 1024;

/// One value of a honeytoken.
///
/// The value is what pgsnare watches for, and it must not show up in logs,
/// events or metrics. This type has no `Display`, its `Debug` output hides
/// the value, and it cannot be serialised. The only way to the value is
/// [`TokenValue::expose`], which makes each use easy to find in review.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenValue(String);

impl TokenValue {
    /// The value itself. Use it to build the matcher, and for nothing that
    /// writes it anywhere.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The length of the value in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty. An empty value never passes validation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What is wrong with the value, if anything.
    fn check(&self) -> Result<(), &'static str> {
        if !self.0.is_ascii() {
            return Err("a value must be ASCII, so that it matches in every client encoding");
        }
        if self.0.len() < MIN_VALUE_BYTES {
            return Err("a value must be at least 12 bytes long");
        }
        if self.0.len() > MAX_VALUE_BYTES {
            return Err("a value must be at most 1024 bytes long");
        }
        Ok(())
    }
}

impl fmt::Debug for TokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenValue(<redacted>)")
    }
}

struct TokenValueVisitor;

impl de::Visitor<'_> for TokenValueVisitor {
    type Value = TokenValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a honeytoken value as quoted text")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<TokenValue, E> {
        Ok(TokenValue(text.to_owned()))
    }
}

impl<'de> Deserialize<'de> for TokenValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(TokenValueVisitor)
    }
}

/// Where a honeytoken was planted. This is a hint for the reader of an
/// event. Detection never depends on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TokenScope {
    /// The database the token was planted in.
    #[serde(default)]
    pub database: Option<String>,
    /// The table it was planted in.
    #[serde(default)]
    pub table: Option<String>,
    /// The column it was planted in.
    #[serde(default)]
    pub column: Option<String>,
}

/// The longest accepted text in a [`TokenScope`], in bytes.
const MAX_SCOPE_BYTES: usize = 256;

/// One honeytoken.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Token {
    /// The identifier that events, logs and metrics use for this token.
    pub id: TokenId,
    /// The values to watch for. Seeing any one of them is a hit.
    pub values: Vec<TokenValue>,
    /// Whether the values also match when ASCII letters differ in case.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Where the token was planted, for the reader of an event.
    #[serde(default)]
    pub scope: TokenScope,
    /// The response to a hit. The default is `[alert]`.
    #[serde(default = "default_actions")]
    pub actions: ActionSet,
    /// A stronger response after repeated hits in one session.
    #[serde(default)]
    pub escalate: Option<Escalation>,
    /// Where this token was defined.
    #[serde(skip)]
    pub origin: TokenOrigin,
}

const fn default_actions() -> ActionSet {
    ActionSet::ALERT
}

/// Where a token was defined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenOrigin {
    /// The file the token is in. `None` when the configuration did not come
    /// from a file.
    pub file: Option<PathBuf>,
    /// The position of the token in the `tokens` list of that file, counting
    /// from 0.
    pub index: usize,
}

impl Token {
    /// What the policy keeps about this token: everything but its values.
    #[must_use]
    pub fn policy(&self) -> TokenPolicy {
        let mut policy = TokenPolicy::new(self.id.clone());
        policy.scope = Scope::new(
            self.scope.database.clone(),
            self.scope.table.clone(),
            self.scope.column.clone(),
        );
        policy.actions = self.actions;
        policy.escalate = self.escalate;
        policy
    }

    fn at(&self) -> At {
        At::root().field("tokens").index(self.origin.index)
    }

    fn validate(&self, problems: &mut Problems) {
        let at = self.at();
        if self.values.is_empty() {
            problems.add(&at.field("values"), "at least one value is required");
        }
        for (index, value) in self.values.iter().enumerate() {
            problems.check(&at.field("values").index(index), value.check());
        }
        if self.actions.is_empty() {
            problems.add(&at.field("actions"), "at least one action is required");
        }
        if let Some(escalation) = self.escalate {
            problems.check(&at.field("escalate"), escalation.validate());
        }
        let scope = at.field("scope");
        for (name, text) in [
            ("database", &self.scope.database),
            ("table", &self.scope.table),
            ("column", &self.scope.column),
        ] {
            if let Some(text) = text {
                problems.check(&scope.field(name), check_scope_text(text));
            }
        }
    }
}

fn check_scope_text(text: &str) -> Result<(), &'static str> {
    if text.is_empty() || text.len() > MAX_SCOPE_BYTES {
        return Err("must be between 1 and 256 bytes long");
    }
    if text.chars().any(char::is_control) {
        return Err("must not contain control characters");
    }
    Ok(())
}

/// Numbers the tokens of one document and records where they came from.
pub(super) fn set_origins(tokens: &mut [Token], file: Option<&Path>) {
    for (index, token) in tokens.iter_mut().enumerate() {
        token.origin = TokenOrigin {
            file: file.map(Path::to_path_buf),
            index,
        };
    }
}

/// Checks every token, and what the tokens must agree on among themselves:
/// no id and no value is used twice.
///
/// The tokens may come from several files. Each problem is reported for the
/// file and the position the token was defined at.
pub(super) fn validate_all(tokens: &[Token], problems: &mut Problems) {
    let mut ids: HashMap<&TokenId, &Token> = HashMap::new();
    let mut values: HashMap<&str, (&Token, usize)> = HashMap::new();

    for token in tokens {
        problems.set_file(token.origin.file.clone());
        token.validate(problems);

        let at = token.at();
        match ids.get(&token.id) {
            Some(first) => problems.add_with_place(
                &at.field("id"),
                "this id is already used",
                &first.at().field("id"),
                first.origin.file.as_deref(),
            ),
            None => {
                ids.insert(&token.id, token);
            }
        }

        for (index, value) in token.values.iter().enumerate() {
            match values.get(value.expose()) {
                Some((first, first_index)) => problems.add_with_place(
                    &at.field("values").index(index),
                    "this value is already used",
                    &first.at().field("values").index(*first_index),
                    first.origin.file.as_deref(),
                ),
                None => {
                    values.insert(value.expose(), (token, index));
                }
            }
        }
    }
    problems.set_file(None);
}

/// A file that holds honeytokens and nothing else, so that it can be stored
/// and mounted as a secret.
///
/// ```yaml
/// tokens:
///   - id: users-admin-backup
///     values: ["svc.backup.8f3k2q@mail.example"]
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TokenFile {
    /// The tokens in the file.
    pub tokens: Vec<Token>,
}

impl TokenFile {
    /// Reads a token file and checks each token on its own.
    ///
    /// Whether an id or a value is used twice is checked later, across all
    /// files.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the document. The error never contains
    /// text from the document.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let mut file: Self = yaml::from_str(text).map_err(ConfigError::one)?;
        set_origins(&mut file.tokens, None);
        let mut problems = Problems::new();
        validate_all(&file.tokens, &mut problems);
        problems.into_result()?;
        Ok(file)
    }

    /// Reads a token file without checking the tokens.
    pub(super) fn parse(text: &str, file: &Path) -> Result<Self, ConfigError> {
        let mut parsed: Self =
            yaml::from_str(text).map_err(|problem| ConfigError::one(problem).in_file(file))?;
        set_origins(&mut parsed.tokens, Some(file));
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use pgsnare_core::policy::Action;

    use super::*;

    const VALUE: &str = "svc.backup.8f3k2q@mail.example";

    fn tokens(text: &str) -> Result<Vec<Token>, String> {
        TokenFile::from_yaml(text)
            .map(|file| file.tokens)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_minimal_token_alerts() {
        let tokens = tokens(&format!(
            "tokens:\n  - id: users-admin-backup\n    values: [\"{VALUE}\"]\n"
        ))
        .unwrap();
        let [token] = tokens.as_slice() else {
            panic!("expected one token");
        };
        assert_eq!(token.id.as_str(), "users-admin-backup");
        assert_eq!(token.values.len(), 1);
        assert_eq!(token.values[0].expose(), VALUE);
        assert_eq!(token.values[0].len(), VALUE.len());
        assert!(!token.values[0].is_empty());
        assert!(!token.case_insensitive);
        assert_eq!(token.scope, TokenScope::default());
        assert_eq!(token.actions, ActionSet::ALERT);
        assert_eq!(token.escalate, None);
        assert_eq!(
            token.origin,
            TokenOrigin {
                file: None,
                index: 0
            }
        );
    }

    #[test]
    fn every_field_can_be_set() {
        let tokens = tokens(
            "\
tokens:
  - id: first
    values: [\"first-value-0001\"]
  - id: cards.test
    values:
      - \"4000-0000-0000-0002\"
      - \"card-holder-J0HN-D03\"
    case_insensitive: true
    scope: { database: shop, table: public.cards, column: number }
    actions: [alert, tarpit]
    escalate: { after_hits: 2, to: [kill] }
",
        )
        .unwrap();
        let token = &tokens[1];
        assert_eq!(token.origin.index, 1);
        assert_eq!(token.values.len(), 2);
        assert!(token.case_insensitive);
        assert_eq!(token.scope.database.as_deref(), Some("shop"));
        assert_eq!(token.scope.table.as_deref(), Some("public.cards"));
        assert_eq!(token.scope.column.as_deref(), Some("number"));
        assert_eq!(
            token.actions,
            ActionSet::of(&[Action::Alert, Action::Tarpit])
        );
        assert_eq!(
            token.escalate,
            Some(Escalation::new(2, ActionSet::of(&[Action::Kill])))
        );

        let policy = token.policy();
        assert_eq!(policy.id.as_str(), "cards.test");
        assert_eq!(policy.scope.table.as_deref(), Some("public.cards"));
        assert_eq!(
            policy.actions_for_hit(1),
            ActionSet::of(&[Action::Alert, Action::Tarpit])
        );
        assert_eq!(policy.actions_for_hit(2), ActionSet::of(&[Action::Kill]));
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn a_value_must_be_ascii_and_at_least_twelve_bytes() {
        let with =
            |value: &str| tokens(&format!("tokens:\n  - id: t\n    values: [\"{value}\"]\n"));
        assert!(with("exactly12byt").is_ok());
        assert!(with(&"v".repeat(1024)).is_ok());
        assert_eq!(
            with("elevenbytes").unwrap_err(),
            "tokens[0].values[0]: a value must be at least 12 bytes long"
        );
        assert_eq!(
            with("").unwrap_err(),
            "tokens[0].values[0]: a value must be at least 12 bytes long"
        );
        assert_eq!(
            with(&"v".repeat(1025)).unwrap_err(),
            "tokens[0].values[0]: a value must be at most 1024 bytes long"
        );
        assert_eq!(
            with("caf\u{e9}-au-lait-backup-account").unwrap_err(),
            "tokens[0].values[0]: a value must be ASCII, so that it matches in every client encoding"
        );
        // Twelve characters, but more bytes, and still not ASCII.
        assert!(with(&"\u{e9}".repeat(12)).is_err());
    }

    #[test]
    fn a_token_needs_values_and_actions() {
        assert_eq!(
            tokens("tokens:\n  - id: t\n    values: []\n").unwrap_err(),
            "tokens[0].values: at least one value is required"
        );
        assert_eq!(
            tokens(&format!(
                "tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    actions: []\n"
            ))
            .unwrap_err(),
            "tokens[0].actions: at least one action is required"
        );
        assert_eq!(
            tokens(&format!(
                "tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    escalate: {{ after_hits: 0, to: [kill] }}\n"
            ))
            .unwrap_err(),
            "tokens[0].escalate: after_hits must be at least 1"
        );
        assert_eq!(
            tokens(&format!(
                "tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    scope: {{ table: \"\" }}\n"
            ))
            .unwrap_err(),
            "tokens[0].scope.table: must be between 1 and 256 bytes long"
        );
        let error = tokens("tokens:\n  - values: [\"0123456789ab\"]\n").unwrap_err();
        assert!(error.ends_with("missing field `id`"), "{error}");
        let error = tokens("tokens:\n  - id: t\n").unwrap_err();
        assert!(error.ends_with("missing field `values`"), "{error}");
    }

    #[test]
    fn an_id_or_a_value_used_twice_is_reported_with_both_places() {
        let error = tokens(&format!(
            "\
tokens:
  - id: one
    values: [\"{VALUE}\", \"another-value-0001\"]
  - id: two
    values: [\"another-value-0002\", \"{VALUE}\"]
  - id: one
    values: [\"another-value-0003\", \"another-value-0003\"]
"
        ))
        .unwrap_err();
        assert_eq!(
            error,
            "tokens[1].values[1]: this value is already used (see tokens[0].values[0])\n\
             tokens[2].id: this id is already used (see tokens[0].id)\n\
             tokens[2].values[1]: this value is already used (see tokens[2].values[0])"
        );
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let error = tokens(
            "\
tokens:
  - id: a
    values: [\"short\"]
  - id: b
    values: []
    actions: []
",
        )
        .unwrap_err();
        assert_eq!(error.lines().count(), 3, "{error}");
    }

    #[test]
    fn a_token_file_holds_tokens_and_nothing_else() {
        let error = tokens(&format!(
            "tokens:\n  - id: t\n    values: [\"{VALUE}\"]\nlisteners: []\n"
        ))
        .unwrap_err();
        assert!(
            error.contains("unknown field; the fields here are: `tokens`"),
            "{error}"
        );

        let error = tokens(&format!("tokens:\n  - id: t\n    value: \"{VALUE}\"\n")).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
        assert!(tokens("").is_err());
    }

    #[test]
    fn a_value_never_appears_in_debug_output_or_in_an_error() {
        let file =
            TokenFile::from_yaml(&format!("tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n"))
                .unwrap();
        let shown = format!("{file:?}");
        assert!(!shown.contains(VALUE), "{shown}");
        assert!(!shown.contains("svc.backup"), "{shown}");
        assert!(shown.contains("TokenValue(<redacted>)"), "{shown}");

        // The value in every place where it does not belong.
        let documents = [
            format!("tokens:\n  - id: t\n    values: {VALUE}\n"),
            format!("tokens:\n  - id: t\n    values: [[\"{VALUE}\"]]\n"),
            format!("tokens:\n  - id: t\n    values: [{{v: \"{VALUE}\"}}]\n"),
            format!("tokens:\n  - id: t\n    value: \"{VALUE}\"\n"),
            format!("tokens:\n  - id: \"{VALUE}\"\n    values: []\n"),
            format!("tokens:\n  - \"{VALUE}\"\n"),
            format!("tokens: \"{VALUE}\"\n"),
            format!("tokens:\n  \"{VALUE}\": 1\n"),
            format!("\"{VALUE}\"\n"),
            format!("- \"{VALUE}\"\n"),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    actions: [\"{VALUE}\"]\n"),
            format!(
                "tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    case_insensitive: \"{VALUE}\"\n"
            ),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    escalate: \"{VALUE}\"\n"),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    scope: \"{VALUE}\"\n"),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\", \"{VALUE}\"]\n"),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\n"),
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\"]\n    \"{VALUE}\": 1\n"),
        ];
        for document in documents {
            let error = tokens(&document).unwrap_err();
            assert!(!error.contains(VALUE), "{document:?} leaked into {error:?}");
            assert!(
                !error.contains("svc.backup"),
                "{document:?} leaked into {error:?}"
            );
            assert!(
                !error.contains("mail.example"),
                "{document:?} leaked into {error:?}"
            );
        }
    }

    #[test]
    fn a_value_that_looks_like_a_number_must_be_quoted() {
        let error = tokens("tokens:\n  - id: t\n    values: [123456789012]\n").unwrap_err();
        assert!(
            error.ends_with("this value must be quoted to be read as text"),
            "{error}"
        );
        assert!(tokens("tokens:\n  - id: t\n    values: [\"123456789012\"]\n").is_ok());
    }
}
