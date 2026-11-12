// SPDX-License-Identifier: Apache-2.0

//! Inspection settings.

use pgsnare_core::policy::{self, OnError};
use serde::Deserialize;

use super::error::{At, Problems};
use super::units;

/// How traffic is inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[non_exhaustive]
pub struct Inspection {
    /// What happens to a session when inspecting it fails. The default,
    /// `fail_closed`, ends the session. `fail_open` lets it continue without
    /// inspection and must be chosen explicitly.
    pub on_error: OnError,
    /// A message up to this size is scanned whole before any byte of it is
    /// forwarded. A larger one is scanned as a stream.
    #[serde(deserialize_with = "units::byte_size")]
    pub max_buffered_frame: u64,
}

impl Default for Inspection {
    fn default() -> Self {
        let defaults = policy::Inspection::default();
        Self {
            on_error: defaults.on_error,
            max_buffered_frame: u64::try_from(defaults.max_buffered_frame).unwrap_or(u64::MAX),
        }
    }
}

impl Inspection {
    /// These settings as the policy holds them.
    #[must_use]
    pub fn policy(&self) -> policy::Inspection {
        // A size that does not fit the platform is far above the limit and
        // is rejected by validation.
        let max_buffered_frame = usize::try_from(self.max_buffered_frame).unwrap_or(usize::MAX);
        policy::Inspection::new(self.on_error, max_buffered_frame)
    }

    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        if self.policy().validate().is_err() {
            problems.add(
                &at.field("max_buffered_frame"),
                "must be between 1KiB and 1GiB",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    fn problems(inspection: &Inspection) -> Vec<String> {
        let mut problems = Problems::new();
        inspection.validate(&At::root().field("inspection"), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn the_defaults_fail_closed_and_buffer_one_mebibyte() {
        let inspection = Inspection::default();
        assert_eq!(inspection.on_error, OnError::FailClosed);
        assert_eq!(inspection.max_buffered_frame, 1024 * 1024);
        assert!(problems(&inspection).is_empty());
        assert_eq!(inspection.policy(), policy::Inspection::default());

        let empty: Inspection = yaml::from_str("{}\n").unwrap();
        assert_eq!(empty, inspection);
    }

    #[test]
    fn both_settings_can_be_set() {
        let inspection: Inspection =
            yaml::from_str("on_error: fail_open\nmax_buffered_frame: 64KiB\n").unwrap();
        assert_eq!(inspection.on_error, OnError::FailOpen);
        assert_eq!(inspection.max_buffered_frame, 65_536);
        assert_eq!(inspection.policy().max_buffered_frame, 65_536);
        assert!(problems(&inspection).is_empty());
    }

    #[test]
    fn invalid_settings_are_rejected() {
        assert!(yaml::from_str::<Inspection>("on_error: open\n").is_err());
        assert!(yaml::from_str::<Inspection>("on_error: fail-open\n").is_err());
        assert!(yaml::from_str::<Inspection>("max_buffered_frame: 1048576\n").is_err());
        assert!(yaml::from_str::<Inspection>("max_buffered_frame: 1MB\n").is_err());
        assert!(yaml::from_str::<Inspection>("max_frame: 1MiB\n").is_err());

        for size in ["0B", "1023B", "2GiB", "17179869183GiB"] {
            let inspection: Inspection =
                yaml::from_str(&format!("max_buffered_frame: {size}\n")).unwrap();
            assert_eq!(
                problems(&inspection),
                ["inspection.max_buffered_frame: must be between 1KiB and 1GiB"],
                "{size}"
            );
        }
        for size in ["1KiB", "1GiB"] {
            let inspection: Inspection =
                yaml::from_str(&format!("max_buffered_frame: {size}\n")).unwrap();
            assert!(problems(&inspection).is_empty(), "{size}");
        }
    }
}
