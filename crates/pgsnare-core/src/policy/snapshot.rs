// SPDX-License-Identifier: Apache-2.0

//! The policy snapshot and where sessions get it from.

use core::fmt;
use core::net::IpAddr;
use std::sync::Arc;

use crate::detect::Matcher;
#[cfg(feature = "rules")]
use crate::rules::RuleSet;

use super::{ActionSettings, Exemption, Inspection, QueryRedaction, TokenId, TokenPolicy};

/// Everything the session logic needs to decide what a message means and
/// what to do about it, frozen at one point in time.
///
/// A snapshot never changes. A reload builds a new one away from the data
/// path and swaps it in, and a session picks up the new one at its next
/// message. Two sessions, or two messages of one session, may therefore see
/// different snapshots, but nothing ever sees a half-updated one.
///
/// The snapshot also holds the compiled [`Matcher`] of its tokens, so that
/// the tokens a session looks for and the responses to them always come
/// from the same configuration. Two snapshots cannot be compared: a
/// compiled matcher has no equality.
///
/// Build one with [`PolicySnapshot::builder`].
#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    generation: u64,
    inspection: Inspection,
    /// Sorted by id, so a token is found by binary search.
    tokens: Vec<TokenPolicy>,
    exemptions: Vec<Exemption>,
    actions: ActionSettings,
    query_redaction: QueryRedaction,
    /// Shared, so that cloning a snapshot never copies compiled patterns.
    matcher: Arc<Matcher>,
    /// The SQL rules, when the configuration has any. They are part of the
    /// snapshot so that a reload swaps them with everything else.
    #[cfg(feature = "rules")]
    rules: Option<Arc<RuleSet>>,
}

impl PolicySnapshot {
    /// Starts a snapshot with the default settings, no tokens and no
    /// exemptions.
    #[must_use]
    pub fn builder() -> PolicySnapshotBuilder {
        PolicySnapshotBuilder::default()
    }

    /// A number that tells snapshots apart. The source of snapshots raises
    /// it with every reload, so logs, metrics and tests can tell which
    /// policy was in force.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The limits of inspection.
    #[must_use]
    pub const fn inspection(&self) -> &Inspection {
        &self.inspection
    }

    /// Every token, ordered by id.
    #[must_use]
    pub fn tokens(&self) -> &[TokenPolicy] {
        &self.tokens
    }

    /// The token with this id, if the snapshot has one.
    #[must_use]
    pub fn token(&self, id: &TokenId) -> Option<&TokenPolicy> {
        let index = self
            .tokens
            .binary_search_by(|token| token.id.cmp(id))
            .ok()?;
        self.tokens.get(index)
    }

    /// Every exemption.
    #[must_use]
    pub fn exemptions(&self) -> &[Exemption] {
        &self.exemptions
    }

    /// Whether hits in a session are counted and trigger nothing else.
    ///
    /// `db_user` is the user the database has accepted, or `None` while the
    /// login is still in progress: see [`Exemption::covers`].
    #[must_use]
    pub fn is_exempt(&self, db_user: Option<&str>, client_ip: IpAddr) -> bool {
        self.exemptions
            .iter()
            .any(|exemption| exemption.covers(db_user, client_ip))
    }

    /// The settings of every response.
    #[must_use]
    pub const fn actions(&self) -> &ActionSettings {
        &self.actions
    }

    /// How much of a statement an event shows.
    #[must_use]
    pub const fn query_redaction(&self) -> QueryRedaction {
        self.query_redaction
    }

    /// The matcher that finds the values of the tokens in traffic. It finds
    /// nothing when the snapshot has no tokens.
    #[must_use]
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// The SQL rules, or `None` when the configuration has no `rules`
    /// section. Shared, so that a statement waiting for its analysis can
    /// keep the rules it is judged by without keeping the whole snapshot.
    #[cfg(feature = "rules")]
    #[must_use]
    pub const fn rules(&self) -> Option<&Arc<RuleSet>> {
        self.rules.as_ref()
    }
}

/// Why a snapshot could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// Two tokens have the same id.
    DuplicateToken(TokenId),
    /// A token is invalid.
    Token {
        /// The token.
        id: TokenId,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An exemption is invalid.
    Exemption {
        /// Its position in the list, counting from 0.
        index: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A setting is invalid.
    Setting {
        /// The group of settings, such as `tarpit`.
        section: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The matcher does not fit the tokens.
    Matcher {
        /// What is wrong with it.
        reason: &'static str,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateToken(id) => write!(f, "token id `{id}` is used more than once"),
            Self::Token { id, reason } => write!(f, "token `{id}`: {reason}"),
            Self::Exemption { index, reason } => write!(f, "exemption {index}: {reason}"),
            Self::Setting { section, reason } => write!(f, "{section}: {reason}"),
            Self::Matcher { reason } => write!(f, "matcher: {reason}"),
        }
    }
}

impl core::error::Error for PolicyError {}

/// Collects the parts of a [`PolicySnapshot`].
#[derive(Clone, Debug, Default)]
pub struct PolicySnapshotBuilder {
    generation: u64,
    inspection: Inspection,
    tokens: Vec<TokenPolicy>,
    exemptions: Vec<Exemption>,
    actions: ActionSettings,
    query_redaction: QueryRedaction,
    matcher: Option<Matcher>,
    #[cfg(feature = "rules")]
    rules: Option<RuleSet>,
}

impl PolicySnapshotBuilder {
    /// Sets the generation number.
    #[must_use]
    pub const fn generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Sets the limits of inspection.
    #[must_use]
    pub const fn inspection(mut self, inspection: Inspection) -> Self {
        self.inspection = inspection;
        self
    }

    /// Adds a token.
    #[must_use]
    pub fn token(mut self, token: TokenPolicy) -> Self {
        self.tokens.push(token);
        self
    }

    /// Adds several tokens.
    #[must_use]
    pub fn tokens(mut self, tokens: impl IntoIterator<Item = TokenPolicy>) -> Self {
        self.tokens.extend(tokens);
        self
    }

    /// Adds an exemption.
    #[must_use]
    pub fn exemption(mut self, exemption: Exemption) -> Self {
        self.exemptions.push(exemption);
        self
    }

    /// Adds several exemptions.
    #[must_use]
    pub fn exemptions(mut self, exemptions: impl IntoIterator<Item = Exemption>) -> Self {
        self.exemptions.extend(exemptions);
        self
    }

    /// Sets the settings of every response.
    #[must_use]
    pub fn actions(mut self, actions: ActionSettings) -> Self {
        self.actions = actions;
        self
    }

    /// Sets how much of a statement an event shows.
    #[must_use]
    pub const fn query_redaction(mut self, query_redaction: QueryRedaction) -> Self {
        self.query_redaction = query_redaction;
        self
    }

    /// Sets the matcher compiled from the values of the tokens. A snapshot
    /// with tokens needs one, built from exactly those tokens: without it
    /// the tokens would be named and never found.
    #[must_use]
    pub fn matcher(mut self, matcher: Matcher) -> Self {
        self.matcher = Some(matcher);
        self
    }

    /// Sets the SQL rules. Without this call the snapshot has none.
    #[cfg(feature = "rules")]
    #[must_use]
    pub fn rules(mut self, rules: RuleSet) -> Self {
        self.rules = Some(rules);
        self
    }

    /// Checks everything and freezes it.
    ///
    /// # Errors
    ///
    /// Returns the first problem found: a token id used twice, an invalid
    /// token, exemption or setting, or a matcher that was not built from as
    /// many tokens as the snapshot has.
    pub fn build(self) -> Result<PolicySnapshot, PolicyError> {
        let Self {
            generation,
            inspection,
            mut tokens,
            exemptions,
            actions,
            query_redaction,
            matcher,
            #[cfg(feature = "rules")]
            rules,
        } = self;

        let setting = |section, result: Result<(), &'static str>| {
            result.map_err(|reason| PolicyError::Setting { section, reason })
        };
        setting("inspection", inspection.validate())?;
        setting("kill", actions.kill.validate())?;
        setting("tarpit", actions.tarpit.validate())?;
        setting("fake_data", actions.fake_data.validate())?;

        for token in &tokens {
            token.validate().map_err(|reason| PolicyError::Token {
                id: token.id.clone(),
                reason,
            })?;
        }
        tokens.sort_by(|a, b| a.id.cmp(&b.id));
        for pair in tokens.windows(2) {
            if let [a, b] = pair
                && a.id == b.id
            {
                return Err(PolicyError::DuplicateToken(a.id.clone()));
            }
        }

        for (index, exemption) in exemptions.iter().enumerate() {
            exemption
                .validate()
                .map_err(|reason| PolicyError::Exemption { index, reason })?;
        }

        let matcher = match matcher {
            Some(matcher) => matcher,
            None => Matcher::build(&[]).map_err(|_| PolicyError::Matcher {
                reason: "an empty matcher could not be built",
            })?,
        };
        // A matcher for other tokens than these would leave a token
        // undetected, or report one the policy has no response for.
        if matcher.token_count() != tokens.len() {
            return Err(PolicyError::Matcher {
                reason: "it was not built from the tokens of the policy",
            });
        }

        Ok(PolicySnapshot {
            generation,
            inspection,
            tokens,
            exemptions,
            actions,
            query_redaction,
            matcher: Arc::new(matcher),
            #[cfg(feature = "rules")]
            rules: rules.map(Arc::new),
        })
    }
}

/// Where the session logic gets the current policy.
///
/// The runtime implements this on top of a pointer that a reload swaps
/// atomically. Tests and tools use [`FixedPolicy`].
///
/// A caller takes one snapshot per message and uses it for the whole
/// message, so that a reload never changes the rules halfway through one.
pub trait PolicySource: Send + Sync {
    /// The snapshot in force right now. This is called for every message,
    /// so it must be cheap and must never block.
    fn snapshot(&self) -> Arc<PolicySnapshot>;
}

/// A [`PolicySource`] that always returns the same snapshot.
#[derive(Clone, Debug)]
pub struct FixedPolicy(Arc<PolicySnapshot>);

impl FixedPolicy {
    /// A source that always returns `snapshot`.
    #[must_use]
    pub fn new(snapshot: PolicySnapshot) -> Self {
        Self(Arc::new(snapshot))
    }
}

impl PolicySource for FixedPolicy {
    fn snapshot(&self) -> Arc<PolicySnapshot> {
        Arc::clone(&self.0)
    }
}

impl<T: PolicySource + ?Sized> PolicySource for Arc<T> {
    fn snapshot(&self) -> Arc<PolicySnapshot> {
        (**self).snapshot()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::super::{
        Action, ActionSet, Escalation, FakeDataSettings, KillSettings, OnError, TarpitSettings,
    };
    use super::*;
    use crate::detect::TokenSpec;

    fn token(id: &str) -> TokenPolicy {
        TokenPolicy::new(TokenId::new(id).unwrap())
    }

    fn id(text: &str) -> TokenId {
        TokenId::new(text).unwrap()
    }

    /// A matcher for tokens with these ids, each with a value of its own.
    fn matcher(ids: &[&str]) -> Matcher {
        let specs: Vec<TokenSpec> = ids
            .iter()
            .map(|id| TokenSpec::new(*id, [format!("value-of-{id}@mail.example")]))
            .collect();
        Matcher::build(&specs).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_empty_snapshot_has_the_safe_defaults() {
        let snapshot = PolicySnapshot::builder().build().unwrap();
        assert_eq!(snapshot.generation(), 0);
        assert_eq!(snapshot.inspection().on_error, OnError::FailClosed);
        assert_eq!(snapshot.inspection().max_buffered_frame, 1024 * 1024);
        assert!(snapshot.tokens().is_empty());
        assert!(snapshot.exemptions().is_empty());
        assert_eq!(snapshot.query_redaction(), QueryRedaction::Fingerprint);
        assert_eq!(snapshot.actions(), &ActionSettings::default());
        assert!(!snapshot.is_exempt(Some("backup"), ip("192.0.2.5")));
        assert_eq!(snapshot.token(&id("nope")), None);
        assert!(snapshot.matcher().is_empty());
    }

    #[test]
    fn the_matcher_of_a_snapshot_finds_the_values_of_its_tokens() {
        let snapshot = PolicySnapshot::builder()
            .token(token("alpha"))
            .matcher(matcher(&["alpha"]))
            .build()
            .unwrap();
        let found: Vec<_> = snapshot
            .matcher()
            .scan(b"1\tvalue-of-alpha@mail.example\n")
            .map(|found| found.unwrap().token_id().as_str().to_owned())
            .collect();
        assert_eq!(found, ["alpha"]);
        // A copy shares the compiled patterns.
        assert_eq!(snapshot.clone().matcher().token_count(), 1);
    }

    #[test]
    fn tokens_without_their_matcher_are_refused() {
        let wrong = PolicyError::Matcher {
            reason: "it was not built from the tokens of the policy",
        };
        // No matcher at all: the tokens would be named and never found.
        let missing = PolicySnapshot::builder().token(token("alpha")).build();
        assert_eq!(missing.unwrap_err(), wrong);
        // A matcher for fewer tokens, and one for more.
        let fewer = PolicySnapshot::builder()
            .tokens([token("alpha"), token("beta")])
            .matcher(matcher(&["alpha"]))
            .build();
        assert_eq!(fewer.unwrap_err(), wrong);
        let more = PolicySnapshot::builder()
            .matcher(matcher(&["alpha"]))
            .build();
        assert_eq!(more.unwrap_err(), wrong);
        assert_eq!(
            wrong.to_string(),
            "matcher: it was not built from the tokens of the policy"
        );
    }

    #[test]
    fn everything_set_on_the_builder_is_in_the_snapshot() {
        let mut escalating = token("users-admin-backup");
        escalating.actions = ActionSet::of(&[Action::Alert, Action::Tarpit]);
        escalating.escalate = Some(Escalation::new(3, ActionSet::of(&[Action::Kill])));

        let actions = ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::new(
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(60),
                5,
                Some(1024),
            ),
            FakeDataSettings::new(10),
        );

        let snapshot = PolicySnapshot::builder()
            .generation(7)
            .inspection(Inspection::new(OnError::FailOpen, 4096))
            .token(escalating.clone())
            .tokens([token("zebra"), token("alpha")])
            .matcher(matcher(&["users-admin-backup", "zebra", "alpha"]))
            .exemption(Exemption::new(Some("backup".to_owned()), None))
            .exemptions([Exemption::new(None, Some("192.0.2.0/24".parse().unwrap()))])
            .actions(actions.clone())
            .query_redaction(QueryRedaction::None)
            .build()
            .unwrap();

        assert_eq!(snapshot.generation(), 7);
        assert_eq!(
            snapshot.inspection(),
            &Inspection::new(OnError::FailOpen, 4096)
        );
        assert_eq!(snapshot.actions(), &actions);
        assert_eq!(snapshot.query_redaction(), QueryRedaction::None);
        assert_eq!(snapshot.exemptions().len(), 2);

        let ids: Vec<&str> = snapshot.tokens().iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["alpha", "users-admin-backup", "zebra"]);
        assert_eq!(snapshot.token(&id("users-admin-backup")), Some(&escalating));
        assert_eq!(snapshot.token(&id("alpha")), Some(&token("alpha")));
        assert_eq!(snapshot.token(&id("zebra")), Some(&token("zebra")));
        assert_eq!(snapshot.token(&id("missing")), None);

        assert!(snapshot.is_exempt(Some("backup"), ip("203.0.113.1")));
        assert!(snapshot.is_exempt(Some("app"), ip("192.0.2.9")));
        assert!(snapshot.is_exempt(None, ip("192.0.2.9")));
        assert!(!snapshot.is_exempt(Some("app"), ip("203.0.113.1")));
        assert!(!snapshot.is_exempt(None, ip("203.0.113.1")));
    }

    #[test]
    fn a_token_id_used_twice_is_rejected() {
        let error = PolicySnapshot::builder()
            .tokens([token("b"), token("a"), token("b")])
            .build()
            .unwrap_err();
        assert_eq!(error, PolicyError::DuplicateToken(id("b")));
        assert_eq!(error.to_string(), "token id `b` is used more than once");
    }

    #[test]
    fn invalid_parts_are_rejected_with_their_place() {
        let mut no_actions = token("quiet");
        no_actions.actions = ActionSet::EMPTY;
        let error = PolicySnapshot::builder()
            .token(no_actions)
            .build()
            .unwrap_err();
        assert!(matches!(&error, PolicyError::Token { id, .. } if id.as_str() == "quiet"));
        assert!(error.to_string().starts_with("token `quiet`: "));

        let error = PolicySnapshot::builder()
            .exemption(Exemption::new(Some("backup".to_owned()), None))
            .exemption(Exemption::new(None, None))
            .build()
            .unwrap_err();
        assert!(matches!(error, PolicyError::Exemption { index: 1, .. }));
        assert!(error.to_string().starts_with("exemption 1: "));

        let error = PolicySnapshot::builder()
            .inspection(Inspection::new(OnError::FailClosed, 1))
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            PolicyError::Setting {
                section: "inspection",
                ..
            }
        ));

        let mut actions = ActionSettings::default();
        actions.tarpit.max_sessions = 0;
        let error = PolicySnapshot::builder()
            .actions(actions)
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            PolicyError::Setting {
                section: "tarpit",
                ..
            }
        ));

        let mut actions = ActionSettings::default();
        actions.fake_data.rows = 0;
        let error = PolicySnapshot::builder()
            .actions(actions)
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            PolicyError::Setting {
                section: "fake_data",
                ..
            }
        ));

        let mut actions = ActionSettings::default();
        actions.kill.message = String::new();
        let error = PolicySnapshot::builder()
            .actions(actions)
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            PolicyError::Setting {
                section: "kill",
                ..
            }
        ));
    }

    #[test]
    fn a_fixed_source_always_returns_the_same_snapshot() {
        let source = FixedPolicy::new(PolicySnapshot::builder().generation(3).build().unwrap());
        let first = source.snapshot();
        let second = source.snapshot();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.generation(), 3);

        // A source can be shared, and used through a trait object.
        let shared: Arc<dyn PolicySource> = Arc::new(source);
        assert_eq!(shared.snapshot().generation(), 3);
        let handle = std::thread::spawn({
            let shared = Arc::clone(&shared);
            move || shared.snapshot().generation()
        });
        assert_eq!(handle.join().unwrap(), 3);
    }

    #[test]
    fn a_snapshot_can_be_shared_between_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PolicySnapshot>();
        assert_send_sync::<FixedPolicy>();
    }
}
