// SPDX-License-Identifier: Apache-2.0

//! What the rules know about one statement.

use core::fmt;
use core::mem::size_of;

/// The most relations an analysis names. A statement with more is
/// incomplete.
pub const MAX_RELATIONS: usize = 256;

/// The most functions an analysis names. A statement with more is
/// incomplete.
pub const MAX_FUNCTIONS: usize = 256;

/// The most kinds of statement an analysis names.
pub const MAX_KINDS: usize = 64;

/// The longest name an analysis keeps. PostgreSQL cuts a name at 63 bytes
/// while it reads the statement, so a longer one means something is wrong
/// and the analysis is incomplete.
const MAX_NAME_BYTES: usize = 255;

/// How a statement uses a relation. One relation can be used in several
/// ways, by one statement or by several in the same text.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RelationUse(u8);

impl RelationUse {
    /// Named, and not in a place that reads or writes rows: `TRUNCATE`,
    /// `ALTER TABLE`, `GRANT` and the like.
    pub const NAMED: Self = Self(0);
    /// Rows are read from it.
    pub const READ: Self = Self(1);
    /// Rows are read from it and nothing narrows them down: no `WHERE` and
    /// no `LIMIT` on the way from the relation to the result.
    pub const UNBOUNDED_READ: Self = Self(1 | 2);
    /// Rows are written to it or removed from it.
    pub const WRITTEN: Self = Self(4);

    /// Whether every use in `other` is in this one too.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both uses together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Debug for RelationUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelationUse({:#05b})", self.0)
    }
}

/// What a statement text contains, beyond relations and functions.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct StatementFlags(u8);

impl StatementFlags {
    /// Nothing of note.
    pub const NONE: Self = Self(0);
    /// `COPY ... TO`: rows leave the database.
    pub const COPY_TO: Self = Self(1);
    /// `COPY ... FROM`: rows enter it.
    pub const COPY_FROM: Self = Self(2);
    /// `COPY` to or from a program the server runs.
    pub const COPY_PROGRAM: Self = Self(4);
    /// `COPY` to or from a file on the server.
    pub const COPY_FILE: Self = Self(8);
    /// A statement that carries code as a string, which the parser does not
    /// read: `DO`, and `CREATE FUNCTION` or `CREATE PROCEDURE`.
    pub const OPAQUE_BODY: Self = Self(16);
    /// A statement that runs one that was stored earlier: `EXECUTE`,
    /// `FETCH`, `MOVE`. What runs is not in this text.
    pub const RUNS_STORED: Self = Self(32);

    /// Whether every flag in `other` is set here too.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets of flags together.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Debug for StatementFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatementFlags({:#08b})", self.0)
    }
}

/// A relation a statement names: a table, a view, or anything else that
/// stands where a table can.
///
/// The names are as PostgreSQL reads them: an unquoted name in lower case,
/// a quoted one as written, escapes resolved.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Relation {
    schema: Option<Box<str>>,
    name: Box<str>,
    usage: RelationUse,
}

impl Relation {
    /// The schema, when the statement gives one.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The name of the relation.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Every way the statement uses the relation.
    #[must_use]
    pub const fn usage(&self) -> RelationUse {
        self.usage
    }
}

/// A function a statement names: one it calls, or one it refers to by name,
/// as `CREATE TRIGGER ... EXECUTE FUNCTION` and `GRANT ... ON FUNCTION` do.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Function {
    schema: Option<Box<str>>,
    name: Box<str>,
}

impl Function {
    /// The schema, when the statement gives one.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The name of the function.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// What the rules know about one statement text, which may hold several
/// statements. Everything in it is bounded.
///
/// The names in it come from the statement, so they are attacker input:
/// they are compared with the names of the configuration and go nowhere
/// else. That is why `Debug` prints counts only.
#[derive(Clone, PartialEq, Eq)]
pub struct Analysis {
    statements: u32,
    kinds: Vec<&'static str>,
    relations: Vec<Relation>,
    functions: Vec<Function>,
    flags: StatementFlags,
    complete: bool,
    /// Whether the normalised text and the fingerprint were asked for.
    normalise_tried: bool,
    normalised: Option<Box<str>>,
    fingerprint: Option<u64>,
}

impl Analysis {
    pub(super) const fn new() -> Self {
        Self {
            statements: 0,
            kinds: Vec::new(),
            relations: Vec::new(),
            functions: Vec::new(),
            flags: StatementFlags::NONE,
            complete: true,
            normalise_tried: false,
            normalised: None,
            fingerprint: None,
        }
    }

    /// How many statements the text holds. An empty text, or one with only
    /// comments, holds none.
    #[must_use]
    pub const fn statement_count(&self) -> u32 {
        self.statements
    }

    /// The kinds of the statements, each once, by the name of the parser's
    /// node: `SelectStmt`, `CopyStmt` and so on.
    #[must_use]
    pub fn kinds(&self) -> &[&'static str] {
        &self.kinds
    }

    /// The relations the statements name, each once.
    #[must_use]
    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }

    /// The functions the statements name, each once.
    #[must_use]
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// The flags of all statements together.
    #[must_use]
    pub const fn flags(&self) -> StatementFlags {
        self.flags
    }

    /// Whether everything the statements name is in the lists. When a list
    /// was full, or a name was not usable, this is false and a rule could
    /// miss something: the caller treats the statement as one that could
    /// not be read.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// The statement with every constant replaced by a placeholder, when it
    /// was asked for and is short enough to keep.
    #[must_use]
    pub fn normalised(&self) -> Option<&str> {
        self.normalised.as_deref()
    }

    /// The parser's fingerprint, the same for statements that differ only
    /// in their constants. Present when it was asked for.
    #[must_use]
    pub const fn fingerprint(&self) -> Option<u64> {
        self.fingerprint
    }

    /// Whether this analysis holds everything `limits` asks for, so that it
    /// can stand in for a new one.
    #[must_use]
    pub const fn covers(&self, limits: &super::Limits) -> bool {
        self.normalise_tried || !limits.normalise
    }

    /// About how much memory the analysis takes, in bytes.
    #[must_use]
    pub fn weight(&self) -> usize {
        let name = |text: &str| text.len();
        let optional = |text: &Option<Box<str>>| text.as_deref().map_or(0, str::len);
        let mut bytes = size_of::<Self>();
        bytes = bytes.saturating_add(self.kinds.capacity().saturating_mul(size_of::<&str>()));
        bytes = bytes.saturating_add(
            self.relations
                .capacity()
                .saturating_mul(size_of::<Relation>()),
        );
        bytes = bytes.saturating_add(
            self.functions
                .capacity()
                .saturating_mul(size_of::<Function>()),
        );
        for relation in &self.relations {
            bytes = bytes
                .saturating_add(name(&relation.name))
                .saturating_add(optional(&relation.schema));
        }
        for function in &self.functions {
            bytes = bytes
                .saturating_add(name(&function.name))
                .saturating_add(optional(&function.schema));
        }
        bytes.saturating_add(optional(&self.normalised))
    }

    pub(super) const fn add_flags(&mut self, flags: StatementFlags) {
        self.flags = self.flags.union(flags);
    }

    pub(super) fn add_statement(&mut self, kind: &'static str) {
        self.statements = self.statements.saturating_add(1);
        if self.kinds.contains(&kind) {
            return;
        }
        if self.kinds.len() >= MAX_KINDS {
            self.complete = false;
        } else {
            self.kinds.push(kind);
        }
    }

    /// Notes a relation and returns its place in the list, or `None` when
    /// it could not be kept.
    pub(super) fn add_relation(&mut self, schema: &str, name: &str) -> Option<usize> {
        let Some((schema, name)) = usable(schema, name) else {
            self.complete = false;
            return None;
        };
        if let Some(found) = self
            .relations
            .iter()
            .position(|known| known.schema.as_deref() == schema && &*known.name == name)
        {
            return Some(found);
        }
        if self.relations.len() >= MAX_RELATIONS {
            self.complete = false;
            return None;
        }
        self.relations.push(Relation {
            schema: schema.map(Box::from),
            name: Box::from(name),
            usage: RelationUse::NAMED,
        });
        self.relations.len().checked_sub(1)
    }

    pub(super) fn use_relation(&mut self, index: usize, usage: RelationUse) {
        if let Some(relation) = self.relations.get_mut(index) {
            relation.usage = relation.usage.union(usage);
        }
    }

    pub(super) fn add_function(&mut self, schema: &str, name: &str) {
        let Some((schema, name)) = usable(schema, name) else {
            self.complete = false;
            return;
        };
        if self
            .functions
            .iter()
            .any(|known| known.schema.as_deref() == schema && &*known.name == name)
        {
            return;
        }
        if self.functions.len() >= MAX_FUNCTIONS {
            self.complete = false;
            return;
        }
        self.functions.push(Function {
            schema: schema.map(Box::from),
            name: Box::from(name),
        });
    }

    pub(super) fn set_normalised(
        &mut self,
        normalised: Option<Box<str>>,
        fingerprint: Option<u64>,
    ) {
        self.normalise_tried = true;
        self.normalised = normalised;
        self.fingerprint = fingerprint;
    }

    pub(super) fn shrink(&mut self) {
        self.kinds.shrink_to_fit();
        self.relations.shrink_to_fit();
        self.functions.shrink_to_fit();
    }
}

impl Default for Analysis {
    fn default() -> Self {
        Self::new()
    }
}

/// A name and its schema in the form they are kept in, or `None` when the
/// name is empty or either is too long.
fn usable<'a>(schema: &'a str, name: &'a str) -> Option<(Option<&'a str>, &'a str)> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || schema.len() > MAX_NAME_BYTES {
        return None;
    }
    Some(((!schema.is_empty()).then_some(schema), name))
}

impl fmt::Debug for Analysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Analysis")
            .field("statements", &self.statements)
            .field("kinds", &self.kinds.len())
            .field("relations", &self.relations.len())
            .field("functions", &self.functions.len())
            .field("flags", &self.flags)
            .field("complete", &self.complete)
            .field("normalised", &self.normalised.is_some())
            .field("fingerprint", &self.fingerprint.is_some())
            .finish()
    }
}

impl fmt::Debug for Relation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relation")
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function").finish_non_exhaustive()
    }
}
