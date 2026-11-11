// SPDX-License-Identifier: Apache-2.0

//! Optional SQL rules.
//!
//! The rules flag suspicious statements before any data is read. They need
//! the SQL parser, which is only built with the `rules` feature. A
//! configuration that asks for rules is rejected by a build without them,
//! so a protection that was configured is never silently missing.

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

/// The default for [`Rules::max_parse_bytes`]: 1 MiB.
pub const DEFAULT_MAX_PARSE_BYTES: u64 = 1024 * 1024;

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

impl Rules {
    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
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
            check_names(
                &rule.exclude_users,
                false,
                &here.field("exclude_users"),
                problems,
            );
        }
        if let Some(rule) = &self.unbounded_read {
            let here = at.field("unbounded_read");
            check_actions(rule.actions, &here, problems);
            check_names(&rule.tables, true, &here.field("tables"), problems);
        }
        if let Some(rule) = &self.row_threshold {
            let here = at.field("row_threshold");
            check_actions(rule.actions, &here, problems);
            check_names(&rule.tables, true, &here.field("tables"), problems);
            if rule.max_rows == 0 {
                problems.add(&here.field("max_rows"), "must be at least 1");
            }
        }
        if let Some(rule) = &self.functions {
            let here = at.field("functions");
            check_actions(rule.actions, &here, problems);
            check_names(&rule.names, true, &here.field("names"), problems);
        }
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
        rules.validate(&At::root().field("rules"), &mut problems);
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
        assert_eq!(rules.max_parse_bytes, 1024 * 1024);
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
        assert!(yaml::from_str::<Rules>("catalog_enumeration: { users: [a] }\n").is_err());
    }

    #[test]
    fn a_build_without_the_feature_rejects_the_section() {
        let rules: Rules = yaml::from_str("{}\n").unwrap();
        let mut problems = Problems::new();
        rules.validate(&At::root().field("rules"), &mut problems);
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
