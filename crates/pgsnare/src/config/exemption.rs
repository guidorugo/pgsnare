// SPDX-License-Identifier: Apache-2.0

//! Exemptions: who may read honeytokens without triggering anything.

use pgsnare_core::policy::{self, IpCidr};
use serde::Deserialize;

use super::error::{At, Problems};

/// A database user, a range of client addresses, or both, whose hits are
/// counted and trigger nothing.
///
/// Use it for a backup, a replica or an ETL job that reads whole tables
/// through pgsnare. When both are given, both must match.
///
/// An exemption by address is only as trustworthy as the address pgsnare
/// sees. Behind a load balancer that hides client addresses, exempt by user
/// instead.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Exemption {
    /// The database user that is exempt.
    #[serde(default)]
    pub db_user: Option<String>,
    /// The client addresses that are exempt, such as `192.0.2.5/32`.
    #[serde(default)]
    pub client_cidr: Option<IpCidr>,
}

/// The longest accepted user name, in bytes.
const MAX_USER_BYTES: usize = 256;

impl Exemption {
    /// This exemption as the policy holds it.
    #[must_use]
    pub fn policy(&self) -> policy::Exemption {
        policy::Exemption::new(self.db_user.clone(), self.client_cidr)
    }

    pub(super) fn validate(&self, at: &At, problems: &mut Problems) {
        problems.check(at, self.policy().validate());
        if let Some(user) = &self.db_user
            && (user.len() > MAX_USER_BYTES || user.chars().any(char::is_control))
        {
            problems.add(
                &at.field("db_user"),
                "must be at most 256 bytes long and must not contain control characters",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::yaml;
    use super::*;

    fn problems(text: &str) -> Vec<String> {
        let exemption: Exemption = yaml::from_str(text).unwrap();
        let mut problems = Problems::new();
        exemption.validate(&At::root().field("exemptions").index(0), &mut problems);
        match problems.into_result() {
            Ok(()) => Vec::new(),
            Err(error) => error.problems().iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn an_exemption_names_a_user_a_range_or_both() {
        assert!(problems("db_user: backup\n").is_empty());
        assert!(problems("client_cidr: 192.0.2.5/32\n").is_empty());
        assert!(problems("{ db_user: backup, client_cidr: 192.0.2.5/32 }\n").is_empty());
        assert!(problems("client_cidr: 2001:db8::/32\n").is_empty());

        let exemption: Exemption =
            yaml::from_str("{ db_user: backup, client_cidr: 192.0.2.5/32 }\n").unwrap();
        let policy = exemption.policy();
        assert!(policy.covers(Some("backup"), "192.0.2.5".parse().unwrap()));
        assert!(!policy.covers(Some("backup"), "192.0.2.6".parse().unwrap()));
    }

    #[test]
    fn invalid_exemptions_are_rejected() {
        assert_eq!(
            problems("{}\n"),
            ["exemptions[0]: an exemption needs db_user, client_cidr or both"]
        );
        assert_eq!(
            problems("db_user: \"\"\n"),
            ["exemptions[0]: db_user must not be empty"]
        );
        assert_eq!(
            problems(&format!("db_user: {}\n", "u".repeat(257))),
            [
                "exemptions[0].db_user: must be at most 256 bytes long and must not contain control characters"
            ]
        );
        // A range needs a prefix length, and no bits after the prefix.
        assert!(yaml::from_str::<Exemption>("client_cidr: 192.0.2.5\n").is_err());
        assert!(yaml::from_str::<Exemption>("client_cidr: 192.0.2.5/24\n").is_err());
        assert!(yaml::from_str::<Exemption>("client_ip: 192.0.2.5/32\n").is_err());
    }
}
