// SPDX-License-Identifier: Apache-2.0

//! What the policy says about one token, and who is exempt.

use core::net::IpAddr;

use super::{ActionSet, Escalation, IpCidr, TokenId};

/// Where a honeytoken was planted. This is a hint for the reader of an
/// event. Detection never depends on it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Scope {
    /// The database the token was planted in.
    pub database: Option<String>,
    /// The table it was planted in.
    pub table: Option<String>,
    /// The column it was planted in.
    pub column: Option<String>,
}

impl Scope {
    /// A scope from its parts.
    #[must_use]
    pub const fn new(
        database: Option<String>,
        table: Option<String>,
        column: Option<String>,
    ) -> Self {
        Self {
            database,
            table,
            column,
        }
    }
}

/// What the policy says about one honeytoken.
///
/// The values of the token are not here. They are compiled into the matcher,
/// and everything else refers to the token by its id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TokenPolicy {
    /// The identifier events use for this token.
    pub id: TokenId,
    /// Where the token was planted, for the reader of an event.
    pub scope: Scope,
    /// The response to a hit.
    pub actions: ActionSet,
    /// A stronger response after repeated hits in one session.
    pub escalate: Option<Escalation>,
}

impl TokenPolicy {
    /// A token that answers a hit with `alert`.
    #[must_use]
    pub fn new(id: TokenId) -> Self {
        Self {
            id,
            scope: Scope::default(),
            actions: ActionSet::ALERT,
            escalate: None,
        }
    }

    /// The response to the `hit`-th hit of this token in one session,
    /// counting from 1.
    #[must_use]
    pub fn actions_for_hit(&self, hit: u64) -> ActionSet {
        match self.escalate {
            Some(escalation) if hit >= u64::from(escalation.after_hits) => escalation.to,
            _ => self.actions,
        }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: no action, or an invalid escalation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.actions.is_empty() {
            return Err("actions must list at least one action");
        }
        if let Some(escalation) = self.escalate {
            escalation.validate()?;
        }
        Ok(())
    }
}

/// A database user, an address range, or both, whose hits are counted and
/// trigger nothing.
///
/// Without exemptions, a backup, a replica or an ETL job that reads whole
/// tables through pgsnare would fire every time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Exemption {
    /// The database user that is exempt. `None` means any user.
    pub db_user: Option<String>,
    /// The client addresses that are exempt. `None` means any address.
    pub client_cidr: Option<IpCidr>,
}

impl Exemption {
    /// An exemption from its parts. At least one must be given: see
    /// [`Exemption::validate`].
    #[must_use]
    pub const fn new(db_user: Option<String>, client_cidr: Option<IpCidr>) -> Self {
        Self {
            db_user,
            client_cidr,
        }
    }

    /// Whether a session is covered. When both a user and a range are given,
    /// both must match.
    ///
    /// `db_user` is the user the database has accepted, or `None` while the
    /// login is still in progress. A name the client merely claims is not
    /// enough: anyone can claim to be the backup user.
    ///
    /// An exemption with neither a user nor a range covers nobody.
    #[must_use]
    pub fn covers(&self, db_user: Option<&str>, client_ip: IpAddr) -> bool {
        if self.db_user.is_none() && self.client_cidr.is_none() {
            return false;
        }
        let user_matches = match &self.db_user {
            Some(exempt) => db_user == Some(exempt.as_str()),
            None => true,
        };
        let address_matches = match &self.client_cidr {
            Some(range) => range.contains(client_ip),
            None => true,
        };
        user_matches && address_matches
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: neither a user nor a range, or an empty user
    /// name.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.db_user.is_none() && self.client_cidr.is_none() {
            return Err("an exemption needs db_user, client_cidr or both");
        }
        if self.db_user.as_deref() == Some("") {
            return Err("db_user must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Action;
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_new_token_alerts() {
        let token = TokenPolicy::new(TokenId::new("users-admin-backup").unwrap());
        assert_eq!(token.actions, ActionSet::ALERT);
        assert_eq!(token.escalate, None);
        assert_eq!(token.scope, Scope::default());
        assert_eq!(token.validate(), Ok(()));
        assert_eq!(token.actions_for_hit(1), ActionSet::ALERT);
        assert_eq!(token.actions_for_hit(u64::MAX), ActionSet::ALERT);
    }

    #[test]
    fn escalation_applies_from_the_configured_hit_on() {
        let kill = ActionSet::of(&[Action::Kill]);
        let mut token = TokenPolicy::new(TokenId::new("t").unwrap());
        token.escalate = Some(Escalation::new(3, kill));
        assert_eq!(token.validate(), Ok(()));
        assert_eq!(token.actions_for_hit(1), ActionSet::ALERT);
        assert_eq!(token.actions_for_hit(2), ActionSet::ALERT);
        assert_eq!(token.actions_for_hit(3), kill);
        assert_eq!(token.actions_for_hit(4), kill);
        assert_eq!(token.actions_for_hit(u64::MAX), kill);
    }

    #[test]
    fn a_token_needs_an_action_and_a_valid_escalation() {
        let mut token = TokenPolicy::new(TokenId::new("t").unwrap());
        token.actions = ActionSet::EMPTY;
        assert!(token.validate().is_err());

        token.actions = ActionSet::ALERT;
        token.escalate = Some(Escalation::new(0, ActionSet::ALERT));
        assert!(token.validate().is_err());
    }

    #[test]
    fn an_exemption_by_user_ignores_the_address() {
        let exemption = Exemption::new(Some("backup".to_owned()), None);
        assert_eq!(exemption.validate(), Ok(()));
        assert!(exemption.covers(Some("backup"), ip("192.0.2.5")));
        assert!(exemption.covers(Some("backup"), ip("2001:db8::1")));
        assert!(!exemption.covers(Some("Backup"), ip("192.0.2.5")));
        assert!(!exemption.covers(Some("backup2"), ip("192.0.2.5")));
        assert!(!exemption.covers(None, ip("192.0.2.5")));
    }

    #[test]
    fn an_exemption_by_address_ignores_the_user() {
        let exemption = Exemption::new(None, Some("192.0.2.0/24".parse().unwrap()));
        assert_eq!(exemption.validate(), Ok(()));
        assert!(exemption.covers(Some("anyone"), ip("192.0.2.5")));
        assert!(exemption.covers(None, ip("192.0.2.5")));
        assert!(!exemption.covers(Some("anyone"), ip("198.51.100.5")));
    }

    #[test]
    fn an_exemption_by_user_and_address_needs_both() {
        let exemption = Exemption::new(
            Some("backup".to_owned()),
            Some("192.0.2.5/32".parse().unwrap()),
        );
        assert_eq!(exemption.validate(), Ok(()));
        assert!(exemption.covers(Some("backup"), ip("192.0.2.5")));
        assert!(!exemption.covers(Some("backup"), ip("192.0.2.6")));
        assert!(!exemption.covers(Some("app"), ip("192.0.2.5")));
        assert!(!exemption.covers(None, ip("192.0.2.5")));
    }

    #[test]
    fn an_empty_exemption_is_invalid_and_covers_nobody() {
        let empty = Exemption::new(None, None);
        assert!(empty.validate().is_err());
        assert!(!empty.covers(Some("backup"), ip("192.0.2.5")));
        assert!(!empty.covers(None, ip("192.0.2.5")));

        assert!(
            Exemption::new(Some(String::new()), None)
                .validate()
                .is_err()
        );
    }
}
