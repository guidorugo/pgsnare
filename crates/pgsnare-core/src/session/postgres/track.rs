// SPDX-License-Identifier: Apache-2.0

//! Which statement a message belongs to.
//!
//! A [`Tracker`] follows the messages of one session and tells, for each,
//! the statement behind it, so that an event can name the statement that
//! produced a hit. Detection does not depend on it: a hit is raised
//! whether or not its statement is known.
//!
//! # How it follows a session
//!
//! Every message of the client that the server answers is put in a queue:
//! `Query`, `Parse`, `Bind`, `Describe`, `Execute`, `Close`, `Sync` and
//! `FunctionCall`. The server answers in the order it was asked, so the
//! entry at the front of the queue is the one a message of the server
//! belongs to, however many messages the client has sent ahead.
//!
//! A prepared statement and a portal exist from the moment the server
//! confirms them, with `ParseComplete` and `BindComplete`, and not from
//! the moment the client asks: a `Parse` the server refuses leaves the
//! statement that had the name before. Portals end with the transaction,
//! which `ReadyForQuery` reports, and a `Query` ends the unnamed statement
//! and the unnamed portal.
//!
//! After an error in the extended protocol the server skips every message
//! up to the next `Sync`. The tracker drops the same entries, and drops
//! what the client sends until its `Sync` when that is still to come.
//!
//! # A message of the client
//!
//! A `Query` and a `Parse` carry their statement. A `Bind`, a `Describe`,
//! an `Execute` and a `Close` name one: the tracker looks first at what
//! the client has asked for since the last `Sync`, then at what the server
//! has confirmed. When the name was redefined before that `Sync`, and the
//! server has not answered yet, the statement is unknown, because it
//! depends on whether the earlier messages succeed. `CopyData` belongs to
//! the statement that runs when the server has announced the COPY.
//! `CopyDone` and `CopyFail` end the COPY, and the session shows them when
//! it is over: they are reported without a statement.
//!
//! # Losing the place
//!
//! The tracker gives up its place when the queue is full, when a message
//! is malformed or of a type it does not know, when a name is longer than
//! `MAX_NAME_BYTES` (the server tells such names apart by their
//! beginning only), when a message that names a statement arrives in
//! chunks, and when the server sends a message the entry at the front
//! cannot have caused. It then forgets everything it holds and reports
//! every statement as unknown, until the server has sent one
//! `ReadyForQuery` for each `Query`, `Sync` and `FunctionCall` that was
//! outstanding or has been sent since. When the server ignores one of
//! those, which it does between an error and a `Sync`, the count stays too
//! high and the statements stay unknown: the tracker errs to that side.
//!
//! # What it cannot see
//!
//! The tracker reads the protocol and no SQL. A statement that is
//! prepared, deallocated or discarded by an SQL command, and a cursor that
//! is declared or closed by one, are not followed. A name that was first
//! defined by a `Parse` and then redefined by SQL commands is reported
//! with the text of the `Parse`.
//!
//! # Bounds
//!
//! At most `MAX_PENDING` entries in the queue, `MAX_STATEMENTS`
//! prepared statements, `MAX_PORTALS` portals and `MAX_TEXT_BYTES` of
//! statement text for a session, each text counted once. A text that does
//! not fit is not kept, and its statement is reported as unknown. A
//! statement or portal past its bound is not recorded.

use core::fmt;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use pgsnare_proto::frontend::{self, Target};
use pgsnare_proto::{Frame, backend};

use crate::event::{Query, StatementDigest};
use crate::policy::QueryRedaction;
#[cfg(feature = "rules")]
use crate::rules::{Analysis, ParseFailure};

use super::scan::single_select;

/// The most messages of a client that can wait for their answer.
pub(super) const MAX_PENDING: usize = 256;
/// The most prepared statements a tracker records.
pub(super) const MAX_STATEMENTS: usize = 256;
/// The most portals a tracker records.
pub(super) const MAX_PORTALS: usize = 64;
/// The most bytes of statement text a tracker holds.
pub(super) const MAX_TEXT_BYTES: usize = 256 * 1024;
/// The longest name of a statement or a portal a tracker follows.
pub(super) const MAX_NAME_BYTES: usize = 63;

/// A statement text the tracker holds. Its length is taken off the count
/// when the last holder lets go.
///
/// What is worked out from the text is kept beside it, so that a message
/// that belongs to the statement costs what the message is long, however
/// long the statement is. A new text is a new `Kept`.
pub(super) struct Kept {
    bytes: Box<[u8]>,
    used: Arc<AtomicUsize>,
    /// Whether the text is one statement that reads rows.
    single_select: OnceLock<bool>,
    /// What an event shows of the text under `full`.
    full: OnceLock<Query>,
    /// What an event shows of the text under `fingerprint`.
    fingerprint: OnceLock<Query>,
    /// What the parser made of the text, or why it made nothing. Empty
    /// until the answer is there, and for a text nobody asked about.
    #[cfg(feature = "rules")]
    analysis: OnceLock<Result<Arc<Analysis>, ParseFailure>>,
}

#[cfg(test)]
thread_local! {
    /// How often a held text was searched for [`single_select`].
    pub(super) static SINGLE_SELECT_SCANS: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
    /// How often a [`Query`] was made from a held text.
    pub(super) static QUERIES_MADE: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl Kept {
    fn new(text: &[u8], used: Arc<AtomicUsize>) -> Self {
        Self {
            bytes: text.into(),
            used,
            single_select: OnceLock::new(),
            full: OnceLock::new(),
            fingerprint: OnceLock::new(),
            #[cfg(feature = "rules")]
            analysis: OnceLock::new(),
        }
    }

    /// A text that no tracker counts: for a statement that is held for
    /// its analysis and that the tracker had no room for.
    #[cfg(feature = "rules")]
    pub(super) fn uncounted(text: &[u8]) -> Arc<Self> {
        Arc::new(Self::new(text, Arc::new(AtomicUsize::new(text.len()))))
    }

    /// Keeps the answer of the parser with the text. The first answer
    /// stays.
    #[cfg(feature = "rules")]
    pub(super) fn analysed(&self, outcome: Result<Arc<Analysis>, ParseFailure>) {
        let _ = self.analysis.set(outcome);
    }

    /// The answer of the parser, once there is one.
    #[cfg(all(test, feature = "rules"))]
    pub(super) fn analysis(&self) -> Option<&Result<Arc<Analysis>, ParseFailure>> {
        self.analysis.get()
    }

    fn scan_single_select(&self) -> bool {
        #[cfg(test)]
        SINGLE_SELECT_SCANS.with(|count| count.set(count.get().saturating_add(1)));
        single_select(&self.bytes)
    }

    fn make_query(&self, redaction: QueryRedaction, digest: &dyn StatementDigest) -> Query {
        #[cfg(test)]
        QUERIES_MADE.with(|count| count.set(count.get().saturating_add(1)));
        Query::from_statement(&self.bytes, redaction, digest)
    }
}

#[cfg(feature = "rules")]
impl AsRef<[u8]> for Kept {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes.len(), Ordering::Relaxed);
    }
}

/// A statement text, or `None` when it is unknown.
type Text = Option<Arc<Kept>>;

/// The statement a message belongs to.
pub(super) enum Statement<'a> {
    /// Not known.
    Unknown,
    /// The message carries it.
    Own {
        /// The text, in the message.
        bytes: &'a [u8],
        /// The same text as the tracker holds it from now on, when it had
        /// room for it.
        #[cfg(feature = "rules")]
        kept: Text,
    },
    /// The tracker holds it.
    Kept(Arc<Kept>),
}

impl Statement<'_> {
    /// Whether the statement is one that reads rows and reports them as
    /// `SELECT n`. Worked out once for a text the tracker holds.
    pub(super) fn single_select(&self) -> bool {
        match self {
            Self::Unknown => false,
            Self::Own { bytes, .. } => single_select(bytes),
            Self::Kept(kept) => *kept.single_select.get_or_init(|| kept.scan_single_select()),
        }
    }

    /// What an event shows of the statement under `redaction`. Worked out
    /// once for each mode for a text the tracker holds, so a reload that
    /// changes the mode is followed.
    pub(super) fn query(&self, redaction: QueryRedaction, digest: &dyn StatementDigest) -> Query {
        match self {
            Self::Unknown => Query::unknown(redaction),
            Self::Own { bytes, .. } => Query::from_statement(bytes, redaction, digest),
            Self::Kept(kept) => {
                let made = match redaction {
                    QueryRedaction::Full => &kept.full,
                    QueryRedaction::Fingerprint => &kept.fingerprint,
                    QueryRedaction::None => return Query::withheld(),
                };
                made.get_or_init(|| kept.make_query(redaction, digest))
                    .clone()
            }
        }
    }

    /// What the parser made of the statement, or why it made nothing.
    /// `None` when nobody asked, when the answer is not there yet, and
    /// when the tracker does not hold the text.
    ///
    /// The answer was worked out once, when the statement arrived: a
    /// message that names the statement costs nothing for it.
    ///
    /// Nothing but the tests reads it yet: the rules that judge a statement
    /// when it runs are still to come.
    #[cfg(all(test, feature = "rules"))]
    pub(super) fn analysis(&self) -> Option<&Result<Arc<Analysis>, ParseFailure>> {
        match self {
            Self::Unknown => None,
            Self::Own { kept, .. } => kept.as_ref().and_then(|kept| kept.analysis()),
            Self::Kept(kept) => kept.analysis(),
        }
    }
}

fn held(text: Text) -> Statement<'static> {
    text.map_or(Statement::Unknown, Statement::Kept)
}

type Name = Box<[u8]>;

/// A message of the client that the server has still to answer.
enum Pending {
    Query(Text),
    Parse {
        name: Name,
        text: Text,
    },
    Bind {
        portal: Name,
        statement: Name,
        /// The statement the client meant when it sent the message.
        text: Text,
    },
    Describe {
        target: Target,
        name: Name,
    },
    Execute {
        portal: Name,
    },
    Close {
        target: Target,
        name: Name,
    },
    Sync,
    FunctionCall,
}

impl Pending {
    /// Whether the server ends its answer with `ReadyForQuery`.
    const fn ends_with_ready(&self) -> bool {
        matches!(self, Self::Query(_) | Self::Sync | Self::FunctionCall)
    }
}

const fn ends_with_ready(tag: u8) -> bool {
    matches!(
        tag,
        frontend::tag::QUERY | frontend::tag::SYNC | frontend::tag::FUNCTION_CALL
    )
}

/// What a message of the server does to the entry it answers.
enum Step {
    Stay,
    Done,
    Skip,
}

/// The tracker cannot go on from this message.
struct Unexpected;

fn name(bytes: &[u8]) -> Result<Name, Unexpected> {
    if bytes.len() > MAX_NAME_BYTES {
        return Err(Unexpected);
    }
    Ok(bytes.into())
}

/// Follows the statements of one session.
#[derive(Default)]
pub(super) struct Tracker {
    pending: VecDeque<Pending>,
    statements: BTreeMap<Name, Text>,
    portals: BTreeMap<Name, Text>,
    /// The bytes of statement text held.
    used: Arc<AtomicUsize>,
    /// The server skips what the client sends until a `Sync` that has not
    /// been sent yet.
    skipping: bool,
    /// When the place is lost: how many `ReadyForQuery` the server has
    /// still to send before it can be found again.
    lost: Option<u64>,
}

impl fmt::Debug for Tracker {
    /// Prints counts and nothing that was read.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tracker")
            .field("pending", &self.pending.len())
            .field("statements", &self.statements.len())
            .field("portals", &self.portals.len())
            .field("text_bytes", &self.text_bytes())
            .field("lost", &self.lost.is_some())
            .finish()
    }
}

impl Tracker {
    /// The bytes of statement text held.
    pub(super) fn text_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    /// How much the tracker holds: entries, statements, portals and bytes
    /// of text.
    #[cfg(test)]
    pub(super) fn held(&self) -> [usize; 4] {
        [
            self.pending.len(),
            self.statements.len(),
            self.portals.len(),
            self.text_bytes(),
        ]
    }

    /// Whether the tracker has lost its place.
    pub(super) const fn is_lost(&self) -> bool {
        self.lost.is_some()
    }

    /// A whole message of the client. Returns the statement it belongs
    /// to.
    pub(super) fn client<'a>(&mut self, frame: Frame<'a>, in_copy: bool) -> Statement<'a> {
        let read = if self.is_lost() {
            Err(Unexpected)
        } else {
            self.read(frame, in_copy)
        };
        self.queue(frame.tag(), read)
    }

    /// The header of a message of the client that arrives in chunks.
    /// Returns the statement it belongs to.
    pub(super) fn client_chunked(&mut self, tag: u8, in_copy: bool) -> Statement<'static> {
        let read = match tag {
            _ if self.is_lost() => Err(Unexpected),
            // The text is too large to hold.
            frontend::tag::QUERY => Ok((Some(Pending::Query(None)), Statement::Unknown)),
            frontend::tag::FUNCTION_CALL => Ok((Some(Pending::FunctionCall), Statement::Unknown)),
            frontend::tag::COPY_DATA | frontend::tag::COPY_FAIL => Ok((None, self.copy(in_copy))),
            _ => Err(Unexpected),
        };
        self.queue(tag, read)
    }

    /// A message of the server. `body` is `None` for one that arrives in
    /// chunks. Returns the statement the message belongs to.
    pub(super) fn server(&mut self, tag: u8, body: Option<&[u8]>) -> Statement<'static> {
        use backend::tag;

        if let Some(owed) = self.lost {
            if tag == tag::READY_FOR_QUERY {
                let owed = owed.saturating_sub(1);
                self.lost = (owed > 0).then_some(owed);
            }
            return Statement::Unknown;
        }

        let step = match (tag, self.pending.front()) {
            // The server sends these whenever it likes.
            (
                tag::PARAMETER_STATUS
                | tag::NOTICE_RESPONSE
                | tag::NOTIFICATION_RESPONSE
                | tag::BACKEND_KEY_DATA
                | tag::NEGOTIATE_PROTOCOL_VERSION,
                _,
            )
            | (
                tag::PARAMETER_DESCRIPTION,
                Some(Pending::Describe {
                    target: Target::Statement,
                    ..
                }),
            )
            | (
                tag::ROW_DESCRIPTION | tag::COMMAND_COMPLETE | tag::EMPTY_QUERY_RESPONSE,
                Some(Pending::Query(_)),
            )
            | (
                tag::DATA_ROW
                | tag::COPY_IN_RESPONSE
                | tag::COPY_OUT_RESPONSE
                | tag::COPY_BOTH_RESPONSE
                | tag::COPY_DATA
                | tag::COPY_DONE,
                Some(Pending::Query(_) | Pending::Execute { .. }),
            )
            | (tag::FUNCTION_CALL_RESPONSE, Some(Pending::FunctionCall))
            // An error outside the extended protocol: `ReadyForQuery`
            // follows.
            | (
                tag::ERROR_RESPONSE,
                None | Some(Pending::Query(_) | Pending::Sync | Pending::FunctionCall),
            ) => Step::Stay,
            (tag::PARSE_COMPLETE, Some(Pending::Parse { .. }))
            | (tag::BIND_COMPLETE, Some(Pending::Bind { .. }))
            | (tag::CLOSE_COMPLETE, Some(Pending::Close { .. }))
            | (tag::ROW_DESCRIPTION | tag::NO_DATA, Some(Pending::Describe { .. }))
            | (
                tag::COMMAND_COMPLETE | tag::EMPTY_QUERY_RESPONSE | tag::PORTAL_SUSPENDED,
                Some(Pending::Execute { .. }),
            )
            | (
                tag::READY_FOR_QUERY,
                None | Some(Pending::Query(_) | Pending::Sync | Pending::FunctionCall),
            ) => Step::Done,
            (tag::ERROR_RESPONSE, Some(_)) => Step::Skip,
            _ => {
                self.lose();
                return Statement::Unknown;
            }
        };

        let statement = self.current();
        match step {
            Step::Stay => {}
            Step::Done => {
                if let Some(entry) = self.pending.pop_front() {
                    self.settle(entry);
                }
            }
            Step::Skip => {
                while self
                    .pending
                    .front()
                    .is_some_and(|entry| !matches!(entry, Pending::Sync))
                {
                    self.pending.pop_front();
                }
                self.skipping = self.pending.is_empty();
            }
        }
        // Portals end with their transaction, and an error ends them too.
        // Only a transaction that goes on keeps them.
        if tag == tag::READY_FOR_QUERY && body.and_then(<[u8]>::first) != Some(&b'T') {
            self.portals.clear();
        }
        held(statement)
    }

    /// Reads a message of the client: the entry it leaves in the queue,
    /// if any, and the statement it belongs to.
    fn read<'a>(
        &self,
        frame: Frame<'a>,
        in_copy: bool,
    ) -> Result<(Option<Pending>, Statement<'a>), Unexpected> {
        use frontend::tag;

        let read = match frame.tag() {
            tag::QUERY => {
                let sql = frontend::Query::from_frame(frame)
                    .map_err(|_| Unexpected)?
                    .sql();
                let text = self.keep(sql);
                let own = Statement::Own {
                    bytes: sql,
                    #[cfg(feature = "rules")]
                    kept: text.clone(),
                };
                (Some(Pending::Query(text)), own)
            }
            tag::PARSE => {
                let parse = frontend::Parse::from_frame(frame).map_err(|_| Unexpected)?;
                let text = self.keep(parse.sql());
                let own = Statement::Own {
                    bytes: parse.sql(),
                    #[cfg(feature = "rules")]
                    kept: text.clone(),
                };
                let entry = Pending::Parse {
                    name: name(parse.statement())?,
                    text,
                };
                (Some(entry), own)
            }
            tag::BIND => {
                let bind = frontend::Bind::from_frame(frame).map_err(|_| Unexpected)?;
                let text = self.intended(Target::Statement, bind.statement());
                let entry = Pending::Bind {
                    portal: name(bind.portal())?,
                    statement: name(bind.statement())?,
                    text: text.clone(),
                };
                (Some(entry), held(text))
            }
            tag::DESCRIBE => {
                let describe = frontend::Describe::from_frame(frame).map_err(|_| Unexpected)?;
                let entry = Pending::Describe {
                    target: describe.target(),
                    name: name(describe.name())?,
                };
                let text = self.intended(describe.target(), describe.name());
                (Some(entry), held(text))
            }
            tag::EXECUTE => {
                let execute = frontend::Execute::from_frame(frame).map_err(|_| Unexpected)?;
                let entry = Pending::Execute {
                    portal: name(execute.portal())?,
                };
                let text = self.intended(Target::Portal, execute.portal());
                (Some(entry), held(text))
            }
            tag::CLOSE => {
                let close = frontend::Close::from_frame(frame).map_err(|_| Unexpected)?;
                let entry = Pending::Close {
                    target: close.target(),
                    name: name(close.name())?,
                };
                let text = self.intended(close.target(), close.name());
                (Some(entry), held(text))
            }
            tag::SYNC => (Some(Pending::Sync), Statement::Unknown),
            tag::FUNCTION_CALL => (Some(Pending::FunctionCall), Statement::Unknown),
            tag::FLUSH | tag::TERMINATE => (None, Statement::Unknown),
            tag::COPY_DATA | tag::COPY_DONE | tag::COPY_FAIL => (None, self.copy(in_copy)),
            _ => return Err(Unexpected),
        };
        Ok(read)
    }

    /// Puts what was read of a message of the client in the queue, or
    /// gives up the place.
    fn queue<'a>(
        &mut self,
        tag: u8,
        read: Result<(Option<Pending>, Statement<'a>), Unexpected>,
    ) -> Statement<'a> {
        if !self.is_lost() {
            match read {
                Ok((None, statement)) => return statement,
                // The server does not look at it.
                Ok((Some(_), statement)) if self.skipping && tag != frontend::tag::SYNC => {
                    return statement;
                }
                Ok((Some(entry), statement)) if self.pending.len() < MAX_PENDING => {
                    self.skipping = false;
                    self.pending.push_back(entry);
                    return statement;
                }
                Ok(_) | Err(Unexpected) => self.lose(),
            }
        }
        if let Some(owed) = self.lost.as_mut()
            && ends_with_ready(tag)
        {
            *owed = owed.saturating_add(1);
        }
        Statement::Unknown
    }

    /// Forgets everything, until the server has answered all that is
    /// outstanding.
    fn lose(&mut self) {
        let owed = self
            .pending
            .iter()
            .filter(|entry| entry.ends_with_ready())
            .count();
        self.pending.clear();
        self.statements.clear();
        self.portals.clear();
        self.skipping = false;
        self.lost = Some(u64::try_from(owed).unwrap_or(u64::MAX));
    }

    /// Keeps a statement text, if it fits.
    fn keep(&self, text: &[u8]) -> Text {
        if text.len() > MAX_TEXT_BYTES.saturating_sub(self.text_bytes()) {
            return None;
        }
        self.used.fetch_add(text.len(), Ordering::Relaxed);
        Some(Arc::new(Kept::new(text, Arc::clone(&self.used))))
    }

    /// The statement that runs a COPY the server has announced.
    fn copy(&self, in_copy: bool) -> Statement<'static> {
        if in_copy {
            held(self.current())
        } else {
            Statement::Unknown
        }
    }

    /// The statement behind the entry the server is answering.
    fn current(&self) -> Text {
        match self.pending.front() {
            Some(Pending::Query(text) | Pending::Parse { text, .. }) => text.clone(),
            Some(Pending::Bind { statement, .. }) => self.confirmed(Target::Statement, statement),
            Some(Pending::Describe { target, name } | Pending::Close { target, name }) => {
                self.confirmed(*target, name)
            }
            Some(Pending::Execute { portal }) => self.confirmed(Target::Portal, portal),
            Some(Pending::Sync | Pending::FunctionCall) | None => None,
        }
    }

    /// The text of a statement or portal the server has confirmed.
    fn confirmed(&self, target: Target, name: &[u8]) -> Text {
        let map = match target {
            Target::Statement => &self.statements,
            Target::Portal => &self.portals,
        };
        map.get(name).cloned().flatten()
    }

    /// The text of the statement or portal a message of the client names,
    /// as the client can mean it at this point.
    fn intended(&self, target: Target, wanted: &[u8]) -> Text {
        // Whether the entries looked at were sent before the last `Sync`,
        // `Query` or `FunctionCall`. Whether those took effect is open
        // until the server has answered.
        let mut earlier = false;
        for entry in self.pending.iter().rev() {
            let found = match (entry, target) {
                (Pending::Parse { name, text }, Target::Statement) if **name == *wanted => {
                    Some(text.clone())
                }
                (Pending::Bind { portal, text, .. }, Target::Portal) if **portal == *wanted => {
                    Some(text.clone())
                }
                (
                    Pending::Close {
                        target: closed,
                        name,
                    },
                    _,
                ) if *closed == target && **name == *wanted => Some(None),
                // A `Query` ends the unnamed statement and portal.
                (Pending::Query(_), _) if wanted.is_empty() => Some(None),
                _ => None,
            };
            if let Some(text) = found {
                return if earlier { None } else { text };
            }
            earlier = earlier || entry.ends_with_ready();
        }
        self.confirmed(target, wanted)
    }

    /// Applies an entry the server has answered.
    fn settle(&mut self, entry: Pending) {
        match entry {
            Pending::Parse { name, text } => {
                self.statements.remove(&name);
                if text.is_some() && self.statements.len() < MAX_STATEMENTS {
                    self.statements.insert(name, text);
                }
            }
            Pending::Bind {
                portal, statement, ..
            } => {
                let text = self.confirmed(Target::Statement, &statement);
                self.portals.remove(&portal);
                if text.is_some() && self.portals.len() < MAX_PORTALS {
                    self.portals.insert(portal, text);
                }
            }
            Pending::Close {
                target: Target::Statement,
                name,
            } => {
                self.statements.remove(&name);
            }
            Pending::Close {
                target: Target::Portal,
                name,
            } => {
                self.portals.remove(&name);
            }
            Pending::Query(_) => {
                let unnamed: &[u8] = &[];
                self.statements.remove(unnamed);
                self.portals.remove(unnamed);
            }
            Pending::Describe { .. }
            | Pending::Execute { .. }
            | Pending::Sync
            | Pending::FunctionCall => {}
        }
    }
}
