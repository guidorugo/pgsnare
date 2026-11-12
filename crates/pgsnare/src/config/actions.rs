// SPDX-License-Identifier: Apache-2.0

//! The settings of the responses.

use std::time::Duration;

use pgsnare_core::policy::{
    ActionSettings, FakeDataSettings, KillSettings, SqlState, TarpitSettings,
};
use serde::Deserialize;

use super::error::{At, Problems};
use super::units::{self, DurationRange};

/// The settings of every response. Which response a token gets is set on
/// the token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Actions {
    /// The error a killed session receives.
    pub kill: Kill,
    /// How a tarpitted session is slowed down, and where that stops.
    pub tarpit: Tarpit,
    /// How many rows `fake_data` adds.
    pub fake_data: FakeData,
}

/// The error a killed session receives.
///
/// The defaults are what PostgreSQL itself reports when an administrator
/// ends a session, so the client cannot tell the difference.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Kill {
    /// The SQLSTATE code of the error. It must be quoted when it consists
    /// of digits only.
    pub sqlstate: SqlState,
    /// The message of the error, in printable ASCII.
    pub message: String,
}

impl Default for Kill {
    fn default() -> Self {
        let defaults = KillSettings::default();
        Self {
            sqlstate: defaults.sqlstate,
            message: defaults.message,
        }
    }
}

/// How a tarpitted session is slowed down, and where that stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Tarpit {
    /// The delay before each flush to the client: a range such as `2s-30s`
    /// to draw from at random, or a single duration.
    #[serde(deserialize_with = "units::duration_range")]
    pub delay: DurationRange,
    /// How long a session may stay tarpitted before it is killed.
    #[serde(deserialize_with = "units::duration")]
    pub max_duration: Duration,
    /// How many sessions may be tarpitted at once. A further session that
    /// should be tarpitted is killed instead.
    pub max_sessions: u32,
    /// An optional cap on the data sent to the client per second, such as
    /// `1KiB`.
    #[serde(deserialize_with = "units::optional_byte_size")]
    pub max_bytes_per_second: Option<u64>,
}

impl Default for Tarpit {
    fn default() -> Self {
        let defaults = TarpitSettings::default();
        Self {
            delay: DurationRange {
                min: defaults.delay_min,
                max: defaults.delay_max,
            },
            max_duration: defaults.max_duration,
            max_sessions: defaults.max_sessions,
            max_bytes_per_second: defaults.max_bytes_per_second,
        }
    }
}

/// How many generated rows the `fake_data` response adds to a result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct FakeData {
    /// The number of rows added.
    pub rows: u32,
}

impl Default for FakeData {
    fn default() -> Self {
        Self {
            rows: FakeDataSettings::default().rows,
        }
    }
}

impl Actions {
    /// These settings as the policy holds them.
    #[must_use]
    pub fn policy(&self) -> ActionSettings {
        ActionSettings::new(
            KillSettings::new(self.kill.sqlstate, self.kill.message.clone()),
            TarpitSettings::new(
                self.tarpit.delay.min,
                self.tarpit.delay.max,
                self.tarpit.max_duration,
                self.tarpit.max_sessions,
                self.tarpit.max_bytes_per_second,
            ),
            FakeDataSettings::new(self.fake_data.rows),
        )
    }

    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        let policy = self.policy();
        problems.check(&at.field("kill"), policy.kill.validate());
        problems.check(&at.field("tarpit"), policy.tarpit.validate());
        problems.check(&at.field("fake_data"), policy.fake_data.validate());
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    fn problems(text: &str) -> Vec<String> {
        let actions: Actions = yaml::from_str(text).unwrap();
        let mut problems = Problems::new();
        actions.validate(&At::root().field("actions"), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn the_defaults_are_the_policy_defaults() {
        let actions: Actions = yaml::from_str("{}\n").unwrap();
        assert_eq!(actions, Actions::default());
        assert_eq!(actions.policy(), ActionSettings::default());
        assert_eq!(actions.kill.sqlstate.as_str(), "57P01");
        assert_eq!(actions.tarpit.delay.min, Duration::from_secs(2));
        assert_eq!(actions.tarpit.delay.max, Duration::from_secs(30));
        assert_eq!(actions.tarpit.max_duration, Duration::from_secs(600));
        assert_eq!(actions.tarpit.max_sessions, 50);
        assert_eq!(actions.tarpit.max_bytes_per_second, None);
        assert_eq!(actions.fake_data.rows, 500);
        assert!(problems("{}\n").is_empty());
    }

    #[test]
    fn every_setting_can_be_set() {
        let actions: Actions = yaml::from_str(
            "\
kill: { sqlstate: \"57014\", message: canceling statement due to user request }
tarpit: { delay: 500ms-5s, max_duration: 2m, max_sessions: 10, max_bytes_per_second: 1KiB }
fake_data: { rows: 25 }
",
        )
        .unwrap();
        let policy = actions.policy();
        assert_eq!(policy.kill.sqlstate.as_str(), "57014");
        assert_eq!(
            policy.kill.message,
            "canceling statement due to user request"
        );
        assert_eq!(policy.tarpit.delay_min, Duration::from_millis(500));
        assert_eq!(policy.tarpit.delay_max, Duration::from_secs(5));
        assert_eq!(policy.tarpit.max_duration, Duration::from_secs(120));
        assert_eq!(policy.tarpit.max_sessions, 10);
        assert_eq!(policy.tarpit.max_bytes_per_second, Some(1024));
        assert_eq!(policy.fake_data.rows, 25);

        let fixed: Actions = yaml::from_str("tarpit: { delay: 3s }\n").unwrap();
        assert_eq!(fixed.tarpit.delay.min, fixed.tarpit.delay.max);
        // A setting that is left out keeps its default.
        assert_eq!(fixed.tarpit.max_sessions, 50);
        assert_eq!(fixed.kill, Kill::default());
    }

    #[test]
    fn invalid_settings_are_rejected() {
        assert_eq!(
            problems("tarpit: { delay: 20m }\n"),
            ["actions.tarpit: the longest delay must not exceed max_duration"]
        );
        assert_eq!(
            problems("tarpit: { max_sessions: 0 }\n"),
            ["actions.tarpit: max_sessions must be at least 1"]
        );
        assert_eq!(
            problems("tarpit: { max_bytes_per_second: 0B }\n"),
            ["actions.tarpit: max_bytes_per_second must be greater than zero"]
        );
        assert_eq!(
            problems("fake_data: { rows: 0 }\n"),
            ["actions.fake_data: rows must be between 1 and 100000"]
        );
        assert_eq!(
            problems("kill: { message: \"\" }\n"),
            ["actions.kill: message must not be empty"]
        );
        assert_eq!(
            problems("kill: { message: \"two\\nlines\" }\n"),
            ["actions.kill: message must be printable ASCII"]
        );

        // An unquoted code that is all digits would be read as a number.
        assert!(yaml::from_str::<Actions>("kill: { sqlstate: 57014 }\n").is_err());
        assert!(yaml::from_str::<Actions>("kill: { sqlstate: 57p01 }\n").is_err());
        assert!(yaml::from_str::<Actions>("tarpit: { delay: 30s-2s }\n").is_err());
        assert!(yaml::from_str::<Actions>("tarpit: { delay: 2-30 }\n").is_err());
        assert!(yaml::from_str::<Actions>("tarpit: { max_bytes_per_second: 1024 }\n").is_err());
        assert!(yaml::from_str::<Actions>("drop: {}\n").is_err());
        assert!(yaml::from_str::<Actions>("kill: { code: \"57P01\" }\n").is_err());
    }
}
