// SPDX-License-Identifier: Apache-2.0

//! Responses to a hit.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeSeq};

/// One response to a hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    /// Emit an event and let the session continue.
    Alert,
    /// Withhold the matching message, send the client a fatal error, cancel
    /// the running statement and close both connections.
    Kill,
    /// Slow the session down.
    Tarpit,
    /// Add generated rows to the result.
    FakeData,
}

impl Action {
    /// Every action, in the order they are listed and serialised.
    pub const ALL: [Self; 4] = [Self::Alert, Self::Kill, Self::Tarpit, Self::FakeData];

    /// The name used in configuration and in events.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Kill => "kill",
            Self::Tarpit => "tarpit",
            Self::FakeData => "fake_data",
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Alert => 1,
            Self::Kill => 2,
            Self::Tarpit => 4,
            Self::FakeData => 8,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of responses, without order and without duplicates.
///
/// In configuration and in events it is a list, such as `[alert, kill]`.
/// Writing an action twice in such a list is an error.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ActionSet(u8);

impl ActionSet {
    /// The set with no action.
    pub const EMPTY: Self = Self(0);

    /// The default response: `alert` alone.
    pub const ALERT: Self = Self(Action::Alert.bit());

    /// A set with the given actions.
    #[must_use]
    pub fn of(actions: &[Action]) -> Self {
        let mut set = Self::EMPTY;
        for action in actions {
            set.insert(*action);
        }
        set
    }

    /// Adds an action. Returns `false` if it was already in the set.
    pub const fn insert(&mut self, action: Action) -> bool {
        let fresh = self.0 & action.bit() == 0;
        self.0 |= action.bit();
        fresh
    }

    /// Whether the action is in the set.
    #[must_use]
    pub const fn contains(self, action: Action) -> bool {
        self.0 & action.bit() != 0
    }

    /// Whether the set has no action.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of actions in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// The set with every action of both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The actions in the set, in the order of [`Action::ALL`].
    pub fn iter(self) -> impl Iterator<Item = Action> {
        Action::ALL
            .into_iter()
            .filter(move |action| self.contains(*action))
    }
}

impl fmt::Debug for ActionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl FromIterator<Action> for ActionSet {
    fn from_iter<I: IntoIterator<Item = Action>>(actions: I) -> Self {
        let mut set = Self::EMPTY;
        for action in actions {
            set.insert(action);
        }
        set
    }
}

impl Serialize for ActionSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut list = serializer.serialize_seq(Some(self.len()))?;
        for action in self.iter() {
            list.serialize_element(&action)?;
        }
        list.end()
    }
}

struct ActionSetVisitor;

impl<'de> de::Visitor<'de> for ActionSetVisitor {
    type Value = ActionSet;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of actions, each of alert, kill, tarpit or fake_data at most once")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut list: A) -> Result<ActionSet, A::Error> {
        let mut set = ActionSet::EMPTY;
        while let Some(action) = list.next_element::<Action>()? {
            if !set.insert(action) {
                return Err(de::Error::invalid_value(
                    de::Unexpected::Other("an action listed twice"),
                    &self,
                ));
            }
        }
        Ok(set)
    }
}

impl<'de> Deserialize<'de> for ActionSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(ActionSetVisitor)
    }
}

/// A stronger response after repeated hits in one session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Escalation {
    /// From this many hits of the token in one session on, `to` applies.
    pub after_hits: u32,
    /// The response that replaces the token's normal one.
    pub to: ActionSet,
}

impl Escalation {
    /// An escalation to `to` from the `after_hits`-th hit on.
    #[must_use]
    pub const fn new(after_hits: u32, to: ActionSet) -> Self {
        Self { after_hits, to }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: a count of zero, or an empty response.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.after_hits == 0 {
            return Err("after_hits must be at least 1");
        }
        if self.to.is_empty() {
            return Err("to must list at least one action");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_match_their_json_form() {
        for action in Action::ALL {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(json, format!("\"{}\"", action.name()));
            assert_eq!(serde_json::from_str::<Action>(&json).unwrap(), action);
            assert_eq!(action.to_string(), action.name());
        }
        assert!(serde_json::from_str::<Action>("\"block\"").is_err());
    }

    #[test]
    fn a_set_has_no_order_and_no_duplicates() {
        let mut set = ActionSet::EMPTY;
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        assert!(set.insert(Action::Kill));
        assert!(set.insert(Action::Alert));
        assert!(!set.insert(Action::Kill));
        assert_eq!(set.len(), 2);
        assert!(set.contains(Action::Alert));
        assert!(set.contains(Action::Kill));
        assert!(!set.contains(Action::Tarpit));

        assert_eq!(set, ActionSet::of(&[Action::Alert, Action::Kill]));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [Action::Alert, Action::Kill]
        );
        assert_eq!(format!("{set:?}"), "{Alert, Kill}");

        let all: ActionSet = Action::ALL.into_iter().collect();
        assert_eq!(all.len(), Action::ALL.len());
        assert_eq!(set.union(ActionSet::of(&[Action::FakeData])).len(), 3);
        assert_eq!(ActionSet::default(), ActionSet::EMPTY);
        assert_eq!(ActionSet::ALERT, ActionSet::of(&[Action::Alert]));
    }

    #[test]
    fn a_set_is_a_json_list_in_a_fixed_order() {
        let set = ActionSet::of(&[Action::FakeData, Action::Alert]);
        let json = serde_json::to_string(&set).unwrap();
        assert_eq!(json, "[\"alert\",\"fake_data\"]");
        assert_eq!(serde_json::from_str::<ActionSet>(&json).unwrap(), set);
        assert_eq!(
            serde_json::from_str::<ActionSet>("[\"kill\",\"alert\"]").unwrap(),
            ActionSet::of(&[Action::Alert, Action::Kill])
        );
        assert_eq!(serde_json::to_string(&ActionSet::EMPTY).unwrap(), "[]");
        assert_eq!(
            serde_json::from_str::<ActionSet>("[]").unwrap(),
            ActionSet::EMPTY
        );
    }

    #[test]
    fn a_list_with_a_repeated_or_unknown_action_is_rejected() {
        assert!(serde_json::from_str::<ActionSet>("[\"alert\",\"alert\"]").is_err());
        assert!(serde_json::from_str::<ActionSet>("[\"alert\",\"drop\"]").is_err());
        assert!(serde_json::from_str::<ActionSet>("\"alert\"").is_err());
    }

    #[test]
    fn an_escalation_needs_a_count_and_a_response() {
        let kill = ActionSet::of(&[Action::Kill]);
        assert_eq!(Escalation::new(3, kill).validate(), Ok(()));
        assert!(Escalation::new(0, kill).validate().is_err());
        assert!(Escalation::new(3, ActionSet::EMPTY).validate().is_err());

        let parsed: Escalation =
            serde_json::from_str("{\"after_hits\":3,\"to\":[\"kill\"]}").unwrap();
        assert_eq!(parsed, Escalation::new(3, kill));
        assert!(serde_json::from_str::<Escalation>("{\"after_hits\":3}").is_err());
        assert!(
            serde_json::from_str::<Escalation>("{\"after_hits\":3,\"to\":[],\"extra\":1}").is_err()
        );
    }
}
