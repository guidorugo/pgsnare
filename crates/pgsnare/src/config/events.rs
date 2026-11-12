// SPDX-License-Identifier: Apache-2.0

//! Events: what they show, how they are labelled and where they go.

use std::collections::BTreeMap;
use std::time::Duration;

use pgsnare_core::policy::QueryRedaction;
use serde::Deserialize;

use super::error::{At, Problems};
use super::names::{EnvVarName, LabelName};
use super::sinks::{DEFAULT_QUEUE_SIZE, MAX_QUEUE_SIZE, Sink};
use super::units;

/// How events are produced and delivered.
///
/// The section is required, because it must name at least one sink: a
/// proxy that detects and tells nobody is of no use.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Events {
    /// How much of a statement an event shows: `full`, `fingerprint` (the
    /// default) or `none`. Bind parameters are never shown.
    #[serde(default)]
    pub query_redaction: QueryRedaction,
    /// Repeated hits of one token in one session within this time are
    /// reported as a single event with a count. `0s` turns that off.
    #[serde(default = "default_dedup_window", deserialize_with = "units::duration")]
    pub dedup_window: Duration,
    /// The length of the queue between the data path and the dispatcher, in
    /// events. When it is full, events are dropped and counted. Database
    /// traffic never waits for it.
    #[serde(default = "default_queue_size")]
    pub queue_size: u32,
    /// Labels added to every event, to tell instances apart.
    #[serde(default)]
    pub labels: BTreeMap<LabelName, String>,
    /// Environment variables whose values are added to every event as
    /// labels, each under the name of its variable. In Kubernetes these are
    /// typically the pod name and namespace.
    #[serde(default)]
    pub labels_from_env: Vec<EnvVarName>,
    /// Where events are delivered. At least one sink is required.
    pub sinks: Vec<Sink>,
}

/// The default for [`Events::dedup_window`].
pub const DEFAULT_DEDUP_WINDOW: Duration = Duration::from_secs(60);

/// The longest accepted [`Events::dedup_window`]: one day.
pub const MAX_DEDUP_WINDOW: Duration = Duration::from_secs(86_400);

/// The most labels an event may carry.
pub const MAX_LABELS: usize = 32;

/// The longest accepted label value, in bytes.
pub const MAX_LABEL_VALUE_BYTES: usize = 256;

const fn default_dedup_window() -> Duration {
    DEFAULT_DEDUP_WINDOW
}

const fn default_queue_size() -> u32 {
    DEFAULT_QUEUE_SIZE
}

impl Events {
    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        if self.dedup_window > MAX_DEDUP_WINDOW {
            problems.add(&at.field("dedup_window"), "must be at most 1d");
        }
        if self.queue_size == 0 || self.queue_size > MAX_QUEUE_SIZE {
            problems.add(&at.field("queue_size"), "must be between 1 and 1000000");
        }

        let labels = at.field("labels");
        for value in self.labels.values() {
            if value.is_empty() || value.len() > MAX_LABEL_VALUE_BYTES {
                problems.add(
                    &labels,
                    "a label value must be between 1 and 256 bytes long",
                );
            } else if value.chars().any(char::is_control) {
                problems.add(&labels, "a label value must not contain control characters");
            }
        }

        let from_env = at.field("labels_from_env");
        for (index, variable) in self.labels_from_env.iter().enumerate() {
            let here = from_env.index(index);
            match LabelName::from_env_var(variable) {
                None => problems.add(
                    &here,
                    "the variable name is too long for a label name: at most 64 characters",
                ),
                Some(label) if self.labels.contains_key(&label) => {
                    problems.add(&here, "a label with this name is already set in labels");
                }
                Some(_) => {}
            }
            if self
                .labels_from_env
                .iter()
                .take(index)
                .any(|earlier| earlier == variable)
            {
                problems.add(&here, "this variable is listed more than once");
            }
        }
        if self.labels.len().saturating_add(self.labels_from_env.len()) > MAX_LABELS {
            problems.add(
                at,
                "at most 32 labels are allowed, counting labels and labels_from_env",
            );
        }

        let sinks = at.field("sinks");
        if self.sinks.is_empty() {
            problems.add(&sinks, "at least one sink is required");
        }
        for (index, sink) in self.sinks.iter().enumerate() {
            sink.validate(&sinks.index(index), problems);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    fn events(text: &str) -> Events {
        yaml::from_str(text).unwrap()
    }

    fn problems(text: &str) -> Vec<String> {
        let mut problems = Problems::new();
        events(text).validate(&At::root().field("events"), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn a_minimal_section_names_one_sink() {
        let events = events("sinks: [{ type: stdout }]\n");
        assert_eq!(events.query_redaction, QueryRedaction::Fingerprint);
        assert_eq!(events.dedup_window, Duration::from_secs(60));
        assert_eq!(events.queue_size, 1_024);
        assert!(events.labels.is_empty());
        assert!(events.labels_from_env.is_empty());
        assert_eq!(events.sinks.len(), 1);
        assert!(problems("sinks: [{ type: stdout }]\n").is_empty());
    }

    #[test]
    fn every_setting_can_be_set() {
        let text = "\
query_redaction: none
dedup_window: 5m
queue_size: 4096
labels: { env: production, region: eu-west }
labels_from_env: [POD_NAME, POD_NAMESPACE]
sinks:
  - { type: webhook, url: \"https://alerts.example.com/hooks/pgsnare\", hmac_secret_env: PGSNARE_WEBHOOK_SECRET }
  - { type: stdout }
";
        let events = events(text);
        assert_eq!(events.query_redaction, QueryRedaction::None);
        assert_eq!(events.dedup_window, Duration::from_secs(300));
        assert_eq!(events.queue_size, 4_096);
        let labels: Vec<(&str, &str)> = events
            .labels
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(labels, [("env", "production"), ("region", "eu-west")]);
        let variables: Vec<&str> = events
            .labels_from_env
            .iter()
            .map(EnvVarName::as_str)
            .collect();
        assert_eq!(variables, ["POD_NAME", "POD_NAMESPACE"]);
        assert_eq!(events.sinks.len(), 2);
        assert!(problems(text).is_empty());

        for mode in ["full", "fingerprint", "none"] {
            assert!(
                problems(&format!(
                    "query_redaction: {mode}\nsinks: [{{ type: stdout }}]\n"
                ))
                .is_empty()
            );
        }
    }

    #[test]
    fn at_least_one_sink_is_required() {
        assert_eq!(
            problems("sinks: []\n"),
            ["events.sinks: at least one sink is required"]
        );
        let error = yaml::from_str::<Events>("query_redaction: full\n")
            .unwrap_err()
            .to_string();
        assert!(error.ends_with("missing field `sinks`"), "{error}");
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let with = |extra: &str| problems(&format!("sinks: [{{ type: stdout }}]\n{extra}"));
        assert_eq!(
            with("dedup_window: 2d\n"),
            ["events.dedup_window: must be at most 1d"]
        );
        assert!(with("dedup_window: 0s\n").is_empty());
        assert_eq!(
            with("queue_size: 0\n"),
            ["events.queue_size: must be between 1 and 1000000"]
        );
        assert_eq!(
            with("labels: { env: \"\" }\n"),
            ["events.labels: a label value must be between 1 and 256 bytes long"]
        );
        assert_eq!(
            with("labels: { env: \"two\\nlines\" }\n"),
            ["events.labels: a label value must not contain control characters"]
        );
        assert_eq!(
            with("labels: { POD_NAME: fixed }\nlabels_from_env: [POD_NAME]\n"),
            ["events.labels_from_env[0]: a label with this name is already set in labels"]
        );
        assert_eq!(
            with("labels_from_env: [POD_NAME, POD_NAMESPACE, POD_NAME]\n"),
            ["events.labels_from_env[2]: this variable is listed more than once"]
        );
        assert_eq!(
            with(&format!("labels_from_env: [{}]\n", "V".repeat(65))),
            [
                "events.labels_from_env[0]: the variable name is too long for a label name: at most 64 characters"
            ]
        );
        let many: Vec<String> = (0..33).map(|n| format!("L{n}")).collect();
        assert_eq!(
            with(&format!("labels_from_env: [{}]\n", many.join(", "))),
            ["events: at most 32 labels are allowed, counting labels and labels_from_env"]
        );

        for text in [
            "sinks: [{ type: stdout }]\nquery_redaction: partial\n",
            "sinks: [{ type: stdout }]\ndedup_window: 60\n",
            "sinks: [{ type: stdout }]\nlabels: { \"bad name\": x }\n",
            "sinks: [{ type: stdout }]\nlabels: [a, b]\n",
            "sinks: [{ type: stdout }]\nlabels_from_env: [\"POD-NAME\"]\n",
            "sinks: [{ type: stdout }]\nlabels: { env: 5 }\n",
            "sinks: [{ type: stdout }]\nredaction: full\n",
            "sinks: { type: stdout }\n",
        ] {
            assert!(yaml::from_str::<Events>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn problems_in_a_sink_are_reported_at_the_sink() {
        assert_eq!(
            problems("sinks:\n  - { type: stdout }\n  - { type: stdout, queue_size: 0 }\n"),
            ["events.sinks[1].queue_size: must be between 1 and 1000000"]
        );
    }
}
