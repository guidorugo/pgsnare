// SPDX-License-Identifier: Apache-2.0

//! The rules of one policy, and which of them a statement sets off.

use core::fmt;

use crate::policy::{ActionSet, RuleId};

use super::analysis::{Analysis, Relation, RelationUse};
use super::name::QualifiedName;
use super::precheck::{DEFAULT_MAX_PARSE_BYTES, Limits};

/// The id of the rule that flags a listing of the system catalogues.
pub const CATALOG_ENUMERATION: &str = "catalog_enumeration";
/// The id of the rule that flags a read with neither a filter nor a limit.
pub const UNBOUNDED_READ: &str = "unbounded_read";
/// The id of the rule that flags a result with too many rows.
pub const ROW_THRESHOLD: &str = "row_threshold";
/// The id of the rule that flags the use of listed functions.
pub const FUNCTIONS: &str = "functions";

/// What happens to a statement that has no analysis.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OnParseFailure {
    /// Let the statement through.
    Allow,
    /// Let the statement through and raise an event.
    #[default]
    Alert,
    /// End the session before the statement reaches the database.
    Block,
}

/// Who a statement comes from, as far as the rules care.
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    /// The name of the listener the client connected to.
    pub listener: &'a str,
    /// The database user of the session, once the database accepted it.
    pub user: Option<&'a str>,
}

/// Where one rule applies. A list that is left out means all.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RuleScope {
    listeners: Option<Vec<Box<str>>>,
    users: Option<Vec<Box<str>>>,
    exclude_users: Vec<Box<str>>,
}

impl RuleScope {
    /// A scope from its lists: the listeners the rule is on for, the
    /// database users it is on for, and the users it is off for. An
    /// excluded user is excluded even when also listed.
    #[must_use]
    pub fn new(
        listeners: Option<&[String]>,
        users: Option<&[String]>,
        exclude_users: &[String],
    ) -> Self {
        let boxed = |names: &[String]| names.iter().map(|name| Box::from(name.as_str())).collect();
        Self {
            listeners: listeners.map(boxed),
            users: users.map(boxed),
            exclude_users: boxed(exclude_users),
        }
    }

    /// Whether the rule applies to statements from `subject`.
    ///
    /// A session whose user is not known is nobody's exception: it is not
    /// excluded, and a list of users does not leave it out.
    #[must_use]
    pub fn applies(&self, subject: &Subject<'_>) -> bool {
        let listed = |names: &[Box<str>], name: &str| names.iter().any(|known| **known == *name);
        if let Some(listeners) = &self.listeners
            && !listed(listeners, subject.listener)
        {
            return false;
        }
        match subject.user {
            None => true,
            Some(user) => {
                !listed(&self.exclude_users, user)
                    && self.users.as_ref().is_none_or(|users| listed(users, user))
            }
        }
    }
}

/// Why a rule set could not be built. The texts are fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSetError {
    /// The rule, or the setting, that is wrong.
    pub rule: &'static str,
    /// What is wrong with it.
    pub reason: &'static str,
}

impl fmt::Display for RuleSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.rule, self.reason)
    }
}

impl core::error::Error for RuleSetError {}

/// One rule that is on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule<T> {
    id: RuleId,
    actions: ActionSet,
    scope: RuleScope,
    what: T,
}

impl<T> Rule<T> {
    fn new(
        rule: &'static str,
        actions: ActionSet,
        scope: RuleScope,
        what: T,
    ) -> Result<Self, RuleSetError> {
        if actions.is_empty() {
            return Err(RuleSetError {
                rule,
                reason: "at least one action is required",
            });
        }
        let id = RuleId::new(rule).map_err(|_| RuleSetError {
            rule,
            reason: "the id of the rule is not valid",
        })?;
        Ok(Self {
            id,
            actions,
            scope,
            what,
        })
    }

    fn hit(&self) -> (RuleId, ActionSet) {
        (self.id.clone(), self.actions)
    }
}

fn names(rule: &'static str, names: &[String]) -> Result<Vec<QualifiedName>, RuleSetError> {
    if names.is_empty() {
        return Err(RuleSetError {
            rule,
            reason: "at least one name is required",
        });
    }
    names
        .iter()
        .map(|name| {
            QualifiedName::parse(name).map_err(|invalid| RuleSetError {
                rule,
                reason: invalid.reason(),
            })
        })
        .collect()
}

/// The row threshold that a statement arms, see [`RuleSet::row_threshold`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowThreshold {
    /// The rule that fires.
    pub rule: RuleId,
    /// It fires when a result has more rows than this.
    pub max_rows: u64,
    /// The response.
    pub actions: ActionSet,
}

/// The SQL rules of one policy, compiled once from the configuration.
///
/// It is part of the policy snapshot and never changes. The names in it
/// are in the form the parser gives names, so judging a statement is a
/// comparison of short strings and nothing more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    on_parse_failure: OnParseFailure,
    max_parse_bytes: usize,
    catalog_enumeration: Option<Rule<()>>,
    unbounded_read: Option<Rule<Vec<QualifiedName>>>,
    row_threshold: Option<Rule<(Vec<QualifiedName>, u64)>>,
    functions: Option<Rule<Vec<QualifiedName>>>,
}

impl RuleSet {
    /// Starts a rule set with no rule on.
    #[must_use]
    pub const fn builder() -> RuleSetBuilder {
        RuleSetBuilder(Self {
            on_parse_failure: OnParseFailure::Alert,
            max_parse_bytes: DEFAULT_MAX_PARSE_BYTES,
            catalog_enumeration: None,
            unbounded_read: None,
            row_threshold: None,
            functions: None,
        })
    }

    /// What happens to a statement that has no analysis.
    #[must_use]
    pub const fn on_parse_failure(&self) -> OnParseFailure {
        self.on_parse_failure
    }

    /// The limits an analysis for this rule set runs under.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        Limits::with_max_bytes(self.max_parse_bytes)
    }

    /// Whether any rule applies to statements from `subject`. When none
    /// does, there is nothing to analyse a statement for.
    #[must_use]
    pub fn applies_to(&self, subject: &Subject<'_>) -> bool {
        [
            self.catalog_enumeration.as_ref().map(|rule| &rule.scope),
            self.unbounded_read.as_ref().map(|rule| &rule.scope),
            self.row_threshold.as_ref().map(|rule| &rule.scope),
            self.functions.as_ref().map(|rule| &rule.scope),
        ]
        .into_iter()
        .flatten()
        .any(|scope| scope.applies(subject))
    }

    /// Whether the rule about functions applies to statements from
    /// `subject`. A call that does not name its function cannot be judged
    /// by it.
    #[must_use]
    pub fn watches_functions(&self, subject: &Subject<'_>) -> bool {
        self.functions
            .as_ref()
            .is_some_and(|rule| rule.scope.applies(subject))
    }

    /// The rules a statement sets off before it runs, each with its
    /// response. At most one entry per rule, however many statements the
    /// text holds and however often one of them breaks the rule.
    ///
    /// This is a pure function: the same analysis, rule set and subject
    /// give the same answer. An incomplete analysis is judged on what it
    /// holds; whether that is enough is for the caller to decide.
    ///
    /// The row threshold is not here, because it depends on the result:
    /// see [`RuleSet::row_threshold`].
    #[must_use]
    pub fn evaluate(&self, analysis: &Analysis, subject: &Subject<'_>) -> Vec<(RuleId, ActionSet)> {
        let mut hits = Vec::new();
        if let Some(rule) = &self.catalog_enumeration
            && rule.scope.applies(subject)
            && analysis.relations().iter().any(reads_a_catalogue)
        {
            hits.push(rule.hit());
        }
        if let Some(rule) = &self.unbounded_read
            && rule.scope.applies(subject)
            && analysis.relations().iter().any(|relation| {
                relation.usage().contains(RelationUse::UNBOUNDED_READ)
                    && listed(&rule.what, relation)
            })
        {
            hits.push(rule.hit());
        }
        if let Some(rule) = &self.functions
            && rule.scope.applies(subject)
            && analysis.functions().iter().any(|function| {
                rule.what
                    .iter()
                    .any(|name| name.matches(function.schema(), function.name()))
            })
        {
            hits.push(rule.hit());
        }
        hits
    }

    /// The row threshold a statement arms: set when the rule applies to
    /// `subject` and the statement reads a listed table.
    #[must_use]
    pub fn row_threshold(
        &self,
        analysis: &Analysis,
        subject: &Subject<'_>,
    ) -> Option<RowThreshold> {
        let rule = self.row_threshold.as_ref()?;
        let (tables, max_rows) = &rule.what;
        let armed = rule.scope.applies(subject)
            && analysis.relations().iter().any(|relation| {
                relation.usage().contains(RelationUse::READ) && listed(tables, relation)
            });
        armed.then(|| RowThreshold {
            rule: rule.id.clone(),
            max_rows: *max_rows,
            actions: rule.actions,
        })
    }
}

fn listed(tables: &[QualifiedName], relation: &Relation) -> bool {
    tables
        .iter()
        .any(|table| table.matches(relation.schema(), relation.name()))
}

/// Whether a relation is read and belongs to the system catalogues: one in
/// `pg_catalog` or `information_schema`, or one without a schema whose name
/// starts with `pg_`. PostgreSQL looks in `pg_catalog` first, and every
/// relation there has such a name.
fn reads_a_catalogue(relation: &Relation) -> bool {
    relation.usage().contains(RelationUse::READ)
        && match relation.schema() {
            Some(schema) => schema == "pg_catalog" || schema == "information_schema",
            None => relation.name().starts_with("pg_"),
        }
}

/// Collects the rules of a [`RuleSet`]. A rule that is not set is off.
#[derive(Clone, Debug)]
pub struct RuleSetBuilder(RuleSet);

impl RuleSetBuilder {
    /// Sets what happens to a statement that has no analysis.
    #[must_use]
    pub const fn on_parse_failure(mut self, policy: OnParseFailure) -> Self {
        self.0.on_parse_failure = policy;
        self
    }

    /// Sets the size above which a statement is not parsed.
    ///
    /// # Errors
    ///
    /// Zero is refused: it would leave every statement without an
    /// analysis.
    pub fn max_parse_bytes(mut self, bytes: usize) -> Result<Self, RuleSetError> {
        if bytes == 0 {
            return Err(RuleSetError {
                rule: "max_parse_bytes",
                reason: "must be at least 1",
            });
        }
        self.0.max_parse_bytes = bytes;
        Ok(self)
    }

    /// Turns on the rule that flags a read of the system catalogues.
    ///
    /// # Errors
    ///
    /// Returns an error when `actions` is empty.
    pub fn catalog_enumeration(
        mut self,
        actions: ActionSet,
        scope: RuleScope,
    ) -> Result<Self, RuleSetError> {
        self.0.catalog_enumeration = Some(Rule::new(CATALOG_ENUMERATION, actions, scope, ())?);
        Ok(self)
    }

    /// Turns on the rule that flags a read of one of `tables` with neither
    /// a filter nor a limit.
    ///
    /// # Errors
    ///
    /// Returns an error when `actions` or `tables` is empty or a name is
    /// not valid, see [`QualifiedName::parse`].
    pub fn unbounded_read(
        mut self,
        tables: &[String],
        actions: ActionSet,
        scope: RuleScope,
    ) -> Result<Self, RuleSetError> {
        let tables = names(UNBOUNDED_READ, tables)?;
        self.0.unbounded_read = Some(Rule::new(UNBOUNDED_READ, actions, scope, tables)?);
        Ok(self)
    }

    /// Turns on the rule that flags a result of more than `max_rows` rows
    /// from one of `tables`.
    ///
    /// # Errors
    ///
    /// Returns an error when `actions` or `tables` is empty, a name is not
    /// valid, or `max_rows` is zero.
    pub fn row_threshold(
        mut self,
        tables: &[String],
        max_rows: u64,
        actions: ActionSet,
        scope: RuleScope,
    ) -> Result<Self, RuleSetError> {
        if max_rows == 0 {
            return Err(RuleSetError {
                rule: ROW_THRESHOLD,
                reason: "max_rows must be at least 1",
            });
        }
        let tables = names(ROW_THRESHOLD, tables)?;
        self.0.row_threshold = Some(Rule::new(
            ROW_THRESHOLD,
            actions,
            scope,
            (tables, max_rows),
        )?);
        Ok(self)
    }

    /// Turns on the rule that flags the use of one of the functions in
    /// `names`.
    ///
    /// # Errors
    ///
    /// Returns an error when `actions` or `names` is empty or a name is
    /// not valid.
    pub fn functions(
        mut self,
        function_names: &[String],
        actions: ActionSet,
        scope: RuleScope,
    ) -> Result<Self, RuleSetError> {
        let function_names = names(FUNCTIONS, function_names)?;
        self.0.functions = Some(Rule::new(FUNCTIONS, actions, scope, function_names)?);
        Ok(self)
    }

    /// Freezes the rule set.
    #[must_use]
    pub fn build(self) -> RuleSet {
        self.0
    }
}
