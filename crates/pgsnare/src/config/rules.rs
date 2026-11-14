// SPDX-License-Identifier: Apache-2.0

//! Optional SQL rules.
//!
//! The rules flag suspicious statements before any data is read. They need
//! the SQL parser, which is only built with the `rules` feature. A
//! configuration that asks for rules is rejected by a build without them,
//! so a protection that was configured is never silently missing.
//!
//! Every rule can be narrowed down with three optional lists: `listeners`
//! and `users` name where it is on, `exclude_users` names who it is off
//! for. A list that is left out means all.

use pgsnare_core::policy::ActionSet;
use serde::Deserialize;

use super::error::{At, Problems};
use super::units;

/// What happens to a statement that the parser cannot read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ParseFailurePolicy {
    /// Let the statement through.
    Allow,
    /// Let the statement through and raise an event. This is the default.
    #[default]
    Alert,
    /// End the session before the statement reaches the database.
    Block,
}

/// The SQL rules. A rule that is left out is off.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Rules {
    /// What happens to a statement that the parser cannot read. It is never
    /// silently ignored.
    #[serde(default)]
    pub on_parse_failure: ParseFailurePolicy,
    /// A statement larger than this is not parsed and is treated as one the
    /// parser cannot read.
    #[serde(
        default = "default_max_parse_bytes",
        deserialize_with = "units::byte_size"
    )]
    pub max_parse_bytes: u64,
    /// Flags a listing of the system catalogues by an application user.
    #[serde(default)]
    pub catalog_enumeration: Option<CatalogEnumerationRule>,
    /// Flags a read of a listed table with neither a filter nor a limit.
    #[serde(default)]
    pub unbounded_read: Option<UnboundedReadRule>,
    /// Flags a result from a listed table with more rows than a threshold.
    #[serde(default)]
    pub row_threshold: Option<RowThresholdRule>,
    /// Flags the use of listed functions, such as those that read files, run
    /// programs or stall the session.
    #[serde(default)]
    pub functions: Option<FunctionsRule>,
}

/// The default for [`Rules::max_parse_bytes`]: 64 KiB.
///
/// Reading a statement can take about 1,500 times its size in memory for
/// as long as it takes, on every parser thread at once. The default keeps
/// that below 100 MiB per thread.
pub const DEFAULT_MAX_PARSE_BYTES: u64 = 64 * 1024;

/// The largest accepted [`Rules::max_parse_bytes`]: 64 MiB.
pub const MAX_MAX_PARSE_BYTES: u64 = 64 * 1024 * 1024;

const fn default_max_parse_bytes() -> u64 {
    DEFAULT_MAX_PARSE_BYTES
}

const fn default_actions() -> ActionSet {
    ActionSet::ALERT
}

/// Flags a listing of the system catalogues by an application user.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CatalogEnumerationRule {
    /// The response. The default is `[alert]`.
    #[serde(default = "default_actions")]
    pub actions: ActionSet,
    /// The listeners the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// The database users the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub users: Option<Vec<String>>,
    /// Database users the rule does not apply to, such as the one that runs
    /// migrations.
    #[serde(default)]
    pub exclude_users: Vec<String>,
}

/// Flags a read of a listed table with neither a filter nor a limit.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UnboundedReadRule {
    /// The tables the rule watches, such as `public.users`.
    pub tables: Vec<String>,
    /// The response. The default is `[alert]`.
    #[serde(default = "default_actions")]
    pub actions: ActionSet,
    /// The listeners the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// The database users the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub users: Option<Vec<String>>,
    /// Database users the rule does not apply to, such as the one that runs
    /// migrations.
    #[serde(default)]
    pub exclude_users: Vec<String>,
}

/// Flags a result from a listed table with more rows than a threshold.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RowThresholdRule {
    /// The tables the rule watches, such as `public.users`.
    pub tables: Vec<String>,
    /// The rule fires when a result has more rows than this.
    pub max_rows: u64,
    /// The response. The default is `[alert]`.
    #[serde(default = "default_actions")]
    pub actions: ActionSet,
    /// The listeners the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// The database users the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub users: Option<Vec<String>>,
    /// Database users the rule does not apply to, such as the one that runs
    /// migrations.
    #[serde(default)]
    pub exclude_users: Vec<String>,
}

/// Flags the use of listed functions.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct FunctionsRule {
    /// The functions the rule watches, such as `pg_read_file`.
    pub names: Vec<String>,
    /// The response. The default is `[alert]`.
    #[serde(default = "default_actions")]
    pub actions: ActionSet,
    /// The listeners the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub listeners: Option<Vec<String>>,
    /// The database users the rule is on for. Left out, it is on for all.
    #[serde(default)]
    pub users: Option<Vec<String>>,
    /// Database users the rule does not apply to, such as the one that runs
    /// migrations.
    #[serde(default)]
    pub exclude_users: Vec<String>,
}

/// The longest accepted name of a user, a table or a function, in bytes.
const MAX_NAME_BYTES: usize = 256;

fn check_names(names: &[String], required: bool, at: &At, problems: &mut Problems) {
    if required && names.is_empty() {
        problems.add(at, "at least one name is required");
    }
    for (index, name) in names.iter().enumerate() {
        let here = at.index(index);
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            problems.add(&here, "must be between 1 and 256 bytes long");
        } else if name.chars().any(char::is_control) {
            problems.add(&here, "must not contain control characters");
        }
        if names.iter().take(index).any(|earlier| earlier == name) {
            problems.add(&here, "this name is listed more than once");
        }
    }
}

fn check_actions(actions: ActionSet, at: &At, problems: &mut Problems) {
    if actions.is_empty() {
        problems.add(&at.field("actions"), "at least one action is required");
    }
}

/// Checks the names of tables or functions: that there is one, and that
/// each can be read as PostgreSQL would read it.
fn check_sql_names(names: &[String], at: &At, problems: &mut Problems) {
    check_names(names, true, at, problems);
    #[cfg(feature = "rules")]
    for (index, name) in names.iter().enumerate() {
        // An empty or overlong name was reported above.
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            continue;
        }
        if let Err(invalid) = pgsnare_core::rules::QualifiedName::parse(name) {
            problems.add(&at.index(index), invalid.reason());
        }
    }
}

/// The three lists that say where one rule applies.
struct Where<'a> {
    listeners: Option<&'a [String]>,
    users: Option<&'a [String]>,
    exclude_users: &'a [String],
}

impl Where<'_> {
    fn validate(&self, known_listeners: &[&str], at: &At, problems: &mut Problems) {
        if let Some(listeners) = self.listeners {
            let here = at.field("listeners");
            // An empty list would turn the rule off without saying so.
            check_names(listeners, true, &here, problems);
            for (index, listener) in listeners.iter().enumerate() {
                // A name that matches no listener would do the same.
                if !known_listeners.contains(&listener.as_str()) {
                    problems.add(&here.index(index), "no listener has this name");
                }
            }
        }
        if let Some(users) = self.users {
            check_names(users, true, &at.field("users"), problems);
        }
        let here = at.field("exclude_users");
        check_names(self.exclude_users, false, &here, problems);
        for (index, user) in self.exclude_users.iter().enumerate() {
            if self.users.is_some_and(|users| users.contains(user)) {
                problems.add(&here.index(index), "this user is also listed in users");
            }
        }
    }

    #[cfg(feature = "rules")]
    fn scope(&self) -> pgsnare_core::rules::RuleScope {
        pgsnare_core::rules::RuleScope::new(self.listeners, self.users, self.exclude_users)
    }
}

macro_rules! applies_where {
    ($($rule:ident),*) => {
        $(impl $rule {
            fn applies_where(&self) -> Where<'_> {
                Where {
                    listeners: self.listeners.as_deref(),
                    users: self.users.as_deref(),
                    exclude_users: &self.exclude_users,
                }
            }
        })*
    };
}

applies_where!(
    CatalogEnumerationRule,
    UnboundedReadRule,
    RowThresholdRule,
    FunctionsRule
);

impl Rules {
    /// Checks the section. `listeners` are the names of the configured
    /// listeners, which a rule may refer to.
    pub(super) fn validate(&self, listeners: &[&str], at: &At, problems: &mut Problems) {
        if !cfg!(feature = "rules") {
            problems.add(
                at,
                "this build of pgsnare has no SQL rules; remove the section or use a build with the rules feature",
            );
        }
        if self.max_parse_bytes == 0 || self.max_parse_bytes > MAX_MAX_PARSE_BYTES {
            problems.add(&at.field("max_parse_bytes"), "must be between 1B and 64MiB");
        }
        if let Some(rule) = &self.catalog_enumeration {
            let here = at.field("catalog_enumeration");
            check_actions(rule.actions, &here, problems);
            rule.applies_where().validate(listeners, &here, problems);
        }
        if let Some(rule) = &self.unbounded_read {
            let here = at.field("unbounded_read");
            check_actions(rule.actions, &here, problems);
            check_sql_names(&rule.tables, &here.field("tables"), problems);
            rule.applies_where().validate(listeners, &here, problems);
        }
        if let Some(rule) = &self.row_threshold {
            let here = at.field("row_threshold");
            check_actions(rule.actions, &here, problems);
            check_sql_names(&rule.tables, &here.field("tables"), problems);
            if rule.max_rows == 0 {
                problems.add(&here.field("max_rows"), "must be at least 1");
            }
            rule.applies_where().validate(listeners, &here, problems);
        }
        if let Some(rule) = &self.functions {
            let here = at.field("functions");
            check_actions(rule.actions, &here, problems);
            check_sql_names(&rule.names, &here.field("names"), problems);
            rule.applies_where().validate(listeners, &here, problems);
        }
    }

    /// Compiles the section into the rule set of a policy snapshot.
    ///
    /// # Errors
    ///
    /// A checked configuration always gives a rule set. The error is passed
    /// on all the same, so that a mistake in this crate cannot turn into a
    /// panic.
    #[cfg(feature = "rules")]
    pub fn rule_set(
        &self,
    ) -> Result<pgsnare_core::rules::RuleSet, pgsnare_core::rules::RuleSetError> {
        use pgsnare_core::rules::{OnParseFailure, RuleSet};

        let mut builder = RuleSet::builder()
            .on_parse_failure(match self.on_parse_failure {
                ParseFailurePolicy::Allow => OnParseFailure::Allow,
                ParseFailurePolicy::Alert => OnParseFailure::Alert,
                ParseFailurePolicy::Block => OnParseFailure::Block,
            })
            .max_parse_bytes(usize::try_from(self.max_parse_bytes).unwrap_or(usize::MAX))?;
        if let Some(rule) = &self.catalog_enumeration {
            builder = builder.catalog_enumeration(rule.actions, rule.applies_where().scope())?;
        }
        if let Some(rule) = &self.unbounded_read {
            builder =
                builder.unbounded_read(&rule.tables, rule.actions, rule.applies_where().scope())?;
        }
        if let Some(rule) = &self.row_threshold {
            builder = builder.row_threshold(
                &rule.tables,
                rule.max_rows,
                rule.actions,
                rule.applies_where().scope(),
            )?;
        }
        if let Some(rule) = &self.functions {
            builder = builder.functions(&rule.names, rule.actions, rule.applies_where().scope())?;
        }
        Ok(builder.build())
    }
}

#[cfg(test)]
mod tests {
    use pgsnare_core::policy::Action;

    use super::super::yaml;
    use super::*;

    fn problems(text: &str) -> Vec<String> {
        let rules: Rules = yaml::from_str(text).unwrap();
        let mut problems = Problems::new();
        rules.validate(
            &["main", "reports"],
            &At::root().field("rules"),
            &mut problems,
        );
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error
                .problems()
                .iter()
                .map(ToString::to_string)
                // What a build without the feature adds is tested on its own.
                .filter(|problem| !problem.contains("this build of pgsnare has no SQL rules"))
                .collect(),
        }
    }

    #[test]
    fn an_empty_section_turns_no_rule_on() {
        let rules: Rules = yaml::from_str("{}\n").unwrap();
        assert_eq!(rules.on_parse_failure, ParseFailurePolicy::Alert);
        assert_eq!(rules.max_parse_bytes, 64 * 1024);
        assert_eq!(rules.catalog_enumeration, None);
        assert_eq!(rules.unbounded_read, None);
        assert_eq!(rules.row_threshold, None);
        assert_eq!(rules.functions, None);
        assert!(problems("{}\n").is_empty());
    }

    #[test]
    fn every_rule_can_be_configured() {
        let text = "\
on_parse_failure: block
max_parse_bytes: 64KiB
catalog_enumeration: { actions: [alert], exclude_users: [migrator] }
unbounded_read: { tables: [public.users] }
row_threshold: { tables: [public.users, public.cards], max_rows: 1000, actions: [alert, tarpit] }
functions: { names: [pg_read_file, lo_export, pg_sleep], actions: [kill] }
";
        let rules: Rules = yaml::from_str(text).unwrap();
        assert_eq!(rules.on_parse_failure, ParseFailurePolicy::Block);
        assert_eq!(rules.max_parse_bytes, 65_536);
        assert_eq!(
            rules.catalog_enumeration.as_ref().unwrap().exclude_users,
            ["migrator"]
        );
        assert_eq!(
            rules.unbounded_read.as_ref().unwrap().actions,
            ActionSet::ALERT
        );
        let threshold = rules.row_threshold.as_ref().unwrap();
        assert_eq!(threshold.max_rows, 1000);
        assert_eq!(threshold.tables, ["public.users", "public.cards"]);
        assert_eq!(
            threshold.actions,
            ActionSet::of(&[Action::Alert, Action::Tarpit])
        );
        assert_eq!(rules.functions.as_ref().unwrap().names.len(), 3);
        assert!(problems(text).is_empty());
    }

    #[test]
    fn the_parse_failure_policies_have_their_names() {
        for (text, policy) in [
            ("allow", ParseFailurePolicy::Allow),
            ("alert", ParseFailurePolicy::Alert),
            ("block", ParseFailurePolicy::Block),
        ] {
            let rules: Rules = yaml::from_str(&format!("on_parse_failure: {text}\n")).unwrap();
            assert_eq!(rules.on_parse_failure, policy);
        }
        assert!(yaml::from_str::<Rules>("on_parse_failure: ignore\n").is_err());
    }

    #[test]
    fn invalid_rules_are_rejected() {
        assert_eq!(
            problems("max_parse_bytes: 0B\n"),
            ["rules.max_parse_bytes: must be between 1B and 64MiB"]
        );
        assert_eq!(
            problems("max_parse_bytes: 65MiB\n"),
            ["rules.max_parse_bytes: must be between 1B and 64MiB"]
        );
        assert_eq!(
            problems("unbounded_read: { tables: [] }\n"),
            ["rules.unbounded_read.tables: at least one name is required"]
        );
        assert_eq!(
            problems("row_threshold: { tables: [public.users], max_rows: 0, actions: [] }\n"),
            [
                "rules.row_threshold.actions: at least one action is required",
                "rules.row_threshold.max_rows: must be at least 1",
            ]
        );
        assert_eq!(
            problems("functions: { names: [pg_sleep, \"\", pg_sleep] }\n"),
            [
                "rules.functions.names[1]: must be between 1 and 256 bytes long",
                "rules.functions.names[2]: this name is listed more than once",
            ]
        );
        assert!(problems("catalog_enumeration: {}\n").is_empty());

        assert!(yaml::from_str::<Rules>("row_threshold: { tables: [t] }\n").is_err());
        assert!(yaml::from_str::<Rules>("unbounded_read: {}\n").is_err());
        assert!(yaml::from_str::<Rules>("unknown_rule: {}\n").is_err());
        assert!(yaml::from_str::<Rules>("catalog_enumeration: { tables: [a] }\n").is_err());
        assert!(yaml::from_str::<Rules>("functions: { names: [f], databases: [a] }\n").is_err());
    }

    #[test]
    fn every_rule_can_be_narrowed_down() {
        let text = "\
catalog_enumeration: { listeners: [main], users: [app], exclude_users: [migrator] }
unbounded_read: { tables: [public.users], listeners: [main, reports] }
row_threshold: { tables: [public.users], max_rows: 10, users: [app, report] }
functions: { names: [pg_sleep], exclude_users: [dba] }
";
        let rules: Rules = yaml::from_str(text).unwrap();
        assert!(problems(text).is_empty(), "{:?}", problems(text));
        let catalog = rules.catalog_enumeration.as_ref().unwrap();
        assert_eq!(catalog.listeners.as_deref(), Some(&["main".to_owned()][..]));
        assert_eq!(catalog.users.as_deref(), Some(&["app".to_owned()][..]));
        assert_eq!(catalog.exclude_users, ["migrator"]);
        let unbounded = rules.unbounded_read.as_ref().unwrap();
        assert_eq!(unbounded.listeners.as_ref().unwrap().len(), 2);
        assert_eq!(
            (unbounded.users.as_ref(), unbounded.exclude_users.len()),
            (None, 0)
        );
        assert_eq!(
            rules
                .row_threshold
                .as_ref()
                .unwrap()
                .users
                .as_ref()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(rules.functions.as_ref().unwrap().exclude_users, ["dba"]);
    }

    #[test]
    fn a_list_that_would_turn_a_rule_off_unnoticed_is_rejected() {
        assert_eq!(
            problems("functions: { names: [f], listeners: [] }\n"),
            ["rules.functions.listeners: at least one name is required"]
        );
        assert_eq!(
            problems("functions: { names: [f], listeners: [main, mian] }\n"),
            ["rules.functions.listeners[1]: no listener has this name"]
        );
        assert_eq!(
            problems("catalog_enumeration: { users: [] }\n"),
            ["rules.catalog_enumeration.users: at least one name is required"]
        );
        assert_eq!(
            problems("unbounded_read: { tables: [t], users: [app, dba], exclude_users: [dba] }\n"),
            ["rules.unbounded_read.exclude_users[0]: this user is also listed in users"]
        );
        assert_eq!(
            problems("row_threshold: { tables: [t], max_rows: 1, users: [a, a] }\n"),
            ["rules.row_threshold.users[1]: this name is listed more than once"]
        );
    }

    #[cfg(feature = "rules")]
    #[test]
    fn names_that_postgresql_would_not_read_are_rejected() {
        assert_eq!(
            problems("functions: { names: [\"pg_sleep(1)\"] }\n").len(),
            1
        );
        assert_eq!(
            problems("unbounded_read: { tables: [db.public.users] }\n"),
            ["rules.unbounded_read.tables[0]: must be a name or schema.name, without a database"]
        );
        assert!(
            problems("unbounded_read: { tables: ['\"My Table\"', Public.Users] }\n").is_empty()
        );
    }

    #[cfg(feature = "rules")]
    #[test]
    fn the_section_compiles_into_a_rule_set() {
        use pgsnare_core::rules::{Limits, OnParseFailure, RuleSet};

        let none: Rules = yaml::from_str("{}\n").unwrap();
        assert_eq!(none.rule_set().unwrap(), RuleSet::builder().build());
        // The default of the configuration is the default of the parser.
        assert_eq!(none.rule_set().unwrap().limits(), Limits::default());

        let text = "\
on_parse_failure: block
max_parse_bytes: 4KiB
functions: { names: [PG_SLEEP], actions: [kill], listeners: [main], exclude_users: [dba] }
";
        let rules: Rules = yaml::from_str(text).unwrap();
        let set = rules.rule_set().unwrap();
        assert_eq!(set.on_parse_failure(), OnParseFailure::Block);
        assert_eq!(set.limits().max_bytes, 4096);
        let subject = |listener, user| pgsnare_core::rules::Subject { listener, user };
        assert!(set.applies_to(&subject("main", Some("app"))));
        assert!(!set.applies_to(&subject("main", Some("dba"))));
        assert!(!set.applies_to(&subject("reports", Some("app"))));
    }

    #[test]
    fn a_build_without_the_feature_rejects_the_section() {
        let rules: Rules = yaml::from_str("{}\n").unwrap();
        let mut problems = Problems::new();
        rules.validate(&["main"], &At::root().field("rules"), &mut problems);
        let result = problems.into_result();
        if cfg!(feature = "rules") {
            assert!(result.is_ok());
        } else {
            let error = result.unwrap_err().to_string();
            assert!(
                error.starts_with("rules: this build of pgsnare has no SQL rules"),
                "{error}"
            );
        }
    }
}
