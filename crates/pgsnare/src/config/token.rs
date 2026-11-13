// SPDX-License-Identifier: Apache-2.0

//! Honeytokens: the values to watch for, and what to do when one is seen.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use pgsnare_core::detect::{BuildError, Matcher, PatternForm, TokenSpec, ValidationError};
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

    /// What the matcher needs of this token: its id, its values and whether
    /// letter case is ignored.
    #[must_use]
    pub fn spec(&self) -> TokenSpec {
        TokenSpec::new(self.id.as_str(), self.values.iter().map(TokenValue::expose))
            .case_insensitive(self.case_insensitive)
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
/// no id and no value is used twice, and no value contains another.
///
/// The tokens may come from several files. Each problem is reported for the
/// file and the position the token was defined at.
///
/// A list that passes is one the matcher compiles: the last step is to ask
/// the matcher itself, so that the loader can never accept a list that
/// detection would refuse.
pub(super) fn validate_all(tokens: &[Token], problems: &mut Problems) {
    let before = problems.len();
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
    let found_so_far = problems.len() > before;
    check_with_matcher(tokens, found_so_far, problems);
    problems.set_file(None);
}

/// What is wrong when data that matches one value would also set off
/// another, by the forms in which the two meet.
const fn contains_message(container: PatternForm, contained: PatternForm) -> &'static str {
    match (container, contained) {
        (PatternForm::Raw, PatternForm::Raw) => {
            "this value contains another value, so data that matches it would set off both"
        }
        (PatternForm::Raw, PatternForm::Hex) => {
            "this value contains the hex form of another value, so data that matches it would \
             set off both"
        }
        (PatternForm::Raw, PatternForm::CaseInsensitive) => {
            "this value contains another value in another letter case, and that value ignores \
             case, so data that matches this one would set off both"
        }
        (PatternForm::Hex, PatternForm::Raw) => {
            "the hex form of this value contains another value, so data that matches it would \
             set off both"
        }
        (PatternForm::Hex, PatternForm::Hex) => {
            "the hex form of this value contains the hex form of another value, so data that \
             matches it would set off both"
        }
        (PatternForm::Hex, PatternForm::CaseInsensitive) => {
            "the hex form of this value contains another value in another letter case, and \
             that value ignores case, so data that matches this one would set off both"
        }
        (PatternForm::CaseInsensitive, PatternForm::Hex) => {
            "this value ignores case, and in another letter case it contains the hex form of \
             another value, so data that matches it would set off both"
        }
        (PatternForm::CaseInsensitive, _) => {
            "this value ignores case, and in another letter case it contains another value, \
             so data that matches it would set off both"
        }
        _ => "data that matches this value would also set off another value",
    }
}

/// Asks the matcher whether it compiles the tokens, and reports what the
/// checks above do not cover: a value that contains another.
///
/// `found_so_far` says whether those checks reported anything. If they did
/// not and the matcher still refuses the list for a reason that has no
/// message here, the list is reported as a whole, so that a difference
/// between the two sets of rules can never let an invalid list through.
fn check_with_matcher(tokens: &[Token], found_so_far: bool, problems: &mut Problems) {
    let specs: Vec<TokenSpec> = tokens.iter().map(Token::spec).collect();
    let all = At::root().field("tokens");
    let errors = match Matcher::build(&specs) {
        Ok(_) => return,
        Err(BuildError::Invalid(errors)) => errors,
        Err(BuildError::TooLarge) => {
            problems.set_file(None);
            problems.add(&all, "the values are too many or too long to be compiled");
            return;
        }
        Err(_) => {
            problems.set_file(None);
            problems.add(&all, "the values cannot be compiled");
            return;
        }
    };

    let mut reported = false;
    for error in errors.errors() {
        let ValidationError::Contains {
            container,
            container_form,
            contained,
            contained_form,
        } = error
        else {
            // The other rules of the matcher are checked above, each with a
            // message of its own.
            continue;
        };
        let (Some(outer), Some(inner)) = (
            tokens.get(container.token_index),
            tokens.get(contained.token_index),
        ) else {
            continue;
        };
        problems.set_file(outer.origin.file.clone());
        problems.add_with_place(
            &outer.at().field("values").index(container.value_index),
            contains_message(*container_form, *contained_form),
            &inner.at().field("values").index(contained.value_index),
            inner.origin.file.as_deref(),
        );
        reported = true;
    }
    if errors.is_truncated() {
        problems.set_file(None);
        problems.add(&all, "more values clash with each other than are listed");
        reported = true;
    }
    if !reported && !found_so_far {
        problems.set_file(None);
        problems.add(&all, "the honeytokens are not valid together");
    }
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
    fn a_value_that_contains_another_is_reported_with_both_places() {
        let error = tokens(
            "\
tokens:
  - id: short
    values: [\"alpha-0001-zulu\"]
  - id: long
    values: [\"another-value-0001\", \"prefix-alpha-0001-zulu-suffix\"]
",
        )
        .unwrap_err();
        assert_eq!(
            error,
            "tokens[1].values[1]: this value contains another value, so data that matches it \
             would set off both (see tokens[0].values[0])"
        );
        // Within one token as well, and whichever comes first.
        let error = tokens(
            "tokens:\n  - id: t\n    values: [\"prefix-alpha-0001-zulu\", \"alpha-0001-zulu\"]\n",
        )
        .unwrap_err();
        assert_eq!(
            error,
            "tokens[0].values[0]: this value contains another value, so data that matches it \
             would set off both (see tokens[0].values[1])"
        );
    }

    #[test]
    fn the_hex_form_and_the_letter_case_count_as_they_do_for_the_matcher() {
        // `6162636465666768696a6b6c` is `abcdefghijkl` in hexadecimal, which
        // is how a bytea column prints it.
        let error = tokens(
            "\
tokens:
  - id: text
    values: [\"abcdefghijkl\"]
  - id: digits
    values: [\"id-6162636465666768696a6b6c-end\"]
",
        )
        .unwrap_err();
        assert_eq!(
            error,
            "tokens[1].values[0]: this value contains the hex form of another value, so data \
             that matches it would set off both (see tokens[0].values[0])"
        );

        // Two values that differ in letter case are two values, until one of
        // the tokens ignores case.
        let document = |ignore_case: bool| {
            format!(
                "\
tokens:
  - id: upper
    values: [\"ALPHA-0001-ZULU\"]
  - id: lower
    values: [\"alpha-0001-zulu\"]
    case_insensitive: {ignore_case}
"
            )
        };
        assert!(tokens(&document(false)).is_ok());
        assert_eq!(
            tokens(&document(true)).unwrap_err(),
            "tokens[1].values[0]: this value ignores case, and in another letter case it \
             contains another value, so data that matches it would set off both (see \
             tokens[0].values[0])"
        );
    }

    #[test]
    fn a_value_used_twice_is_reported_once() {
        // The matcher refuses a value that is used twice as well. The loader
        // has said so already, and does not say it again.
        let error = tokens(&format!(
            "tokens:\n  - id: t\n    values: [\"{VALUE}\", \"{VALUE}\"]\n"
        ))
        .unwrap_err();
        assert_eq!(
            error,
            "tokens[0].values[1]: this value is already used (see tokens[0].values[0])"
        );
    }

    #[test]
    fn every_form_of_a_clash_has_a_message_without_a_value() {
        let forms = [
            PatternForm::Raw,
            PatternForm::Hex,
            PatternForm::CaseInsensitive,
        ];
        let mut messages = std::collections::BTreeSet::new();
        for container in forms {
            for contained in forms {
                let message = contains_message(container, contained);
                assert!(message.contains("set off"), "{message}");
                messages.insert(message);
            }
        }
        // Each pair of forms the matcher reports has a message of its own.
        // Both values in another letter case is a pair it never reports.
        assert_eq!(messages.len(), 8);
    }

    #[test]
    fn a_token_gives_the_matcher_its_id_its_values_and_its_letter_case() {
        let tokens = tokens(&format!(
            "tokens:\n  - id: one\n    values: [\"{VALUE}\", \"another-value-0001\"]\n    case_insensitive: true\n  - id: two\n    values: [\"another-value-0002\"]\n"
        ))
        .unwrap();
        let spec = tokens[0].spec();
        assert_eq!(spec.id().as_str(), "one");
        assert_eq!(spec.values().len(), 2);
        assert_eq!(spec.values()[0].expose(), VALUE.as_bytes());
        assert!(spec.is_case_insensitive());
        assert!(!tokens[1].spec().is_case_insensitive());
        // The values stay out of its debug output.
        assert!(!format!("{spec:?}").contains("svc.backup"));
    }

    /// Values that clash all the time: few characters, in both letter
    /// cases and with the digits their hex forms are made of, and many of
    /// them built around the same two stems.
    fn clashing_value() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;

        const STEMS: [&str; 2] = ["aAbB16jJaAbB", "1616aAjJbBaA"];
        let stem = || proptest::sample::select(STEMS.as_slice());
        prop_oneof![
            // Unrelated to the others. Some are too short.
            3 => "[aAbB16jJ]{10,16}".prop_map(String::from),
            // A stem, or a value that contains one.
            3 => ("[aAbB16jJ]{0,2}", stem(), "[aAbB16jJ]{0,2}")
                .prop_map(|(head, stem, tail)| format!("{head}{stem}{tail}")),
            // The hex form of a stem, alone or inside a value.
            1 => (stem(), "[aAbB16jJ]{0,2}").prop_map(|(stem, tail)| {
                let hex: String = stem.bytes().map(|byte| format!("{byte:02x}")).collect();
                format!("{hex}{tail}")
            }),
            // A stem in another letter case.
            1 => stem().prop_map(str::to_uppercase),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(800))]

        /// The loader accepts a token list exactly when the matcher
        /// compiles it, whatever the values have to do with each other.
        #[test]
        fn the_loader_accepts_a_list_exactly_when_the_matcher_compiles_it(
            list in proptest::collection::vec(
                (proptest::collection::vec(clashing_value(), 1..=3), proptest::prelude::any::<bool>()),
                1..=4,
            ),
        ) {
            let mut document = String::from("tokens:\n");
            let mut specs = Vec::new();
            for (index, (values, ignore_case)) in list.iter().enumerate() {
                document.push_str(&format!("  - id: t{index}\n    case_insensitive: {ignore_case}\n    values:\n"));
                for value in values {
                    document.push_str(&format!("      - \"{value}\"\n"));
                }
                specs.push(
                    TokenSpec::new(format!("t{index}"), values.iter().map(String::as_str))
                        .case_insensitive(*ignore_case),
                );
            }
            let loaded = TokenFile::from_yaml(&document);
            let compiled = Matcher::build(&specs);
            proptest::prop_assert_eq!(loaded.is_ok(), compiled.is_ok(), "{:?}", loaded.err());
        }
    }

    #[test]
    fn the_values_of_that_property_do_clash() {
        // If they never did, the property above would only compare lists
        // that both sides accept or that are too short.
        use proptest::strategy::{Strategy, ValueTree};
        use proptest::test_runner::TestRunner;

        let mut runner = TestRunner::deterministic();
        let (mut refused_for_a_clash, mut accepted) = (0, 0);
        for _ in 0..300 {
            let values: Vec<String> = (0..4)
                .map(|_| clashing_value().new_tree(&mut runner).unwrap().current())
                .filter(|value| value.len() >= MIN_VALUE_BYTES)
                .collect();
            let spec = TokenSpec::new("t", values.iter().map(String::as_str));
            match Matcher::build(&[spec]) {
                Ok(_) => accepted += 1,
                Err(BuildError::Invalid(errors)) => {
                    let contains =
                        |error: &ValidationError| matches!(error, ValidationError::Contains { .. });
                    if errors.errors().iter().any(contains) {
                        refused_for_a_clash += 1;
                    }
                }
                Err(other) => panic!("{other:?}"),
            }
        }
        assert!(refused_for_a_clash >= 30, "{refused_for_a_clash}");
        assert!(accepted >= 30, "{accepted}");
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
