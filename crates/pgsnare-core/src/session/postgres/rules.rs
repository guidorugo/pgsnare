// SPDX-License-Identifier: Apache-2.0

//! Where the SQL rules attach to a session.
//!
//! The rules judge a statement by what the PostgreSQL parser makes of it,
//! and the parser never runs here: it runs on threads of its own, which
//! the runtime owns. A [`Hook`] is the part of a [`Scanner`] that asks for
//! the analysis of a statement and decides what becomes of the statement
//! when there is none.
//!
//! # Which statements
//!
//! The text of every `Query` and every `Parse` of the client, when the
//! policy in force has rules and one of them applies to the session: to
//! its listener and to the user the database accepted. Without rules, and
//! in a session no rule applies to, nothing is asked and nothing is held.
//!
//! A `Bind`, a `Describe` and an `Execute` carry no statement. They name
//! one whose `Parse` was analysed when it arrived, and the answer is kept
//! with the text the tracker holds, so they cost nothing more.
//!
//! # A statement that sets off a rule
//!
//! When the analysis is there, the rules the statement was held under
//! judge it, once, before any of it is passed on: the catalogue rule, the
//! rule about unbounded reads and the rule about functions. A text with
//! several statements is judged as a whole, and each rule is raised at
//! most once for it.
//!
//! A rule hit takes the path of a honeytoken hit, [`Ledger::rule_hit`]:
//! an exempt session is counted and nothing else, the session is flagged,
//! and the response is carried out by the same code.
//!
//! - `alert`: a `rule_hit` event, and the statement goes on.
//! - `kill`: the event, and the session ends with the error of the policy
//!   before any byte of the statement is passed on. What the client sent
//!   earlier is cancelled as for a honeytoken.
//! - `tarpit`: the event, the statement goes on, and the session is slowed
//!   down from then on. When no place is free the session is killed.
//! - `fake_data`: there is no result yet that rows could be added to, so
//!   it is carried out as `alert`, and the event says `alert`.
//!
//! # The row threshold
//!
//! The fourth rule judges a result, not a statement: it fires when a
//! result has more rows than `max_rows`, once for that result, through the
//! same [`Ledger::rule_hit`]. Each `DataRow` the server sends counts, and so
//! does each `CopyData` of a `COPY ... TO STDOUT`, which the server sends
//! one per row; a row that arrives in parts counts as well. Counting a row
//! costs the same whatever the statement: the threshold is worked out
//! once, when the analysis arrives, and kept with the text.
//!
//! - The statement arms the threshold when its analysis names a listed
//!   table, whatever it does with it, or when it runs what an earlier
//!   statement stored (`EXECUTE`, `FETCH`), whose tables it cannot show.
//! - A statement without an analysis, of any reason, and a statement the
//!   tracker does not know, may read any table: their results are held to
//!   the threshold whenever the rule applies to the session.
//! - A statement can store a query under a name of its own: a view, a
//!   table made from a query, a rule, a function. Once the session has
//!   passed on such a statement that names a listed table, or a statement
//!   that carries code, or any statement without an analysis, every later
//!   result of the session is held to the threshold, whatever it names.
//!   What was stored before the session, or by another one, is not known
//!   here: a view over a listed table must be listed itself.
//! - A result is everything a `Query` returns, over all statements of its
//!   text, or everything a portal returns, over all `Execute`s of it. Where
//!   the tracker does not know the result, rows are counted together until
//!   the transaction ends.
//!
//! The responses are those of the other rules, with one difference: there
//! is a result, so `fake_data` follows the same conditions as for a
//! honeytoken, and is carried out as `alert` where it cannot be.
//!
//! A statement is judged where its text arrives. An `Execute` of a
//! prepared statement or a portal raises nothing again, and a statement
//! prepared before a reload is not judged by the rules loaded since. The
//! SQL statements `EXECUTE` and `FETCH` run what an earlier `PREPARE` or
//! `DECLARE` stored: that one was judged when it arrived, and they are not
//! tied back to it.
//!
//! # Holding a statement
//!
//! The message is searched for honeytokens first, exactly as without
//! rules: a hit is raised before anything is asked of the parser, and
//! whether the parser ever answers makes no difference to it. Then the
//! hook asks for the analysis with [`Effect::Analyse`] and answers
//! [`Verdict::Hold`]: the session keeps the message, and every message of
//! the client behind it, until the runtime has answered. Nothing of the
//! statement reaches the database before that.
//!
//! The text is the bytes the database will parse, which end at the first
//! NUL. It is shared with the tracker and not copied for the parser.
//!
//! # A statement without an analysis
//!
//! Every way of having no analysis ends in the same place, the
//! `on_parse_failure` setting of the rule set the statement was held
//! under:
//!
//! | Reason | Decided |
//! |---|---|
//! | The message is malformed | at once |
//! | The statement is longer than `max_parse_bytes` | at once |
//! | The message arrives in parts, too large to hold | at its header |
//! | The session's `client_encoding` is not `UTF8`, `standard_conforming_strings` is not `on`, or either is not known | at once |
//! | The parser refused the statement, or it nests too deep | when the runtime answers |
//! | The analysis is incomplete: a list in it was full | when the runtime answers |
//! | The parser threads were busy, did not answer in time, or one panicked | when the runtime answers |
//! | The statement carries code as a string: `DO`, `CREATE FUNCTION`, `CREATE PROCEDURE` | when the runtime answers |
//! | A `FunctionCall` message, in a session the rule about functions applies to | at once |
//! | A `Bind` of a named statement that SQL may have changed since its `Parse` | at once |
//!
//! - `allow`: the statement goes on.
//! - `alert`: the statement goes on, and a `parse_failure` event is raised.
//! - `block`: the event is raised and the session ends, with the error of
//!   `kill`, before any byte of the statement is passed on. A statement
//!   that arrives in parts is still searched for honeytokens to its last
//!   part, with none of it passed on, and the session ends then.
//!
//! Each is counted, with [`Effect::ParseFailed`], whatever the setting.
//!
//! A session the policy exempts is counted and nothing else, as for a
//! honeytoken: no event, and it is not ended.
//!
//! # What the parser does not read
//!
//! The body of a `DO` block or of a function is a string to the parser,
//! and what it runs, dynamic SQL included, is not in the analysis. Such a
//! statement is judged by what the parser does read of it, and is then a
//! statement without an analysis as well.
//!
//! A `FunctionCall` message names its function by the number the database
//! gave it, which no rule can compare with a name. Where the rule about
//! functions applies, the message is a statement without an analysis.
//!
//! # A statement prepared with SQL
//!
//! A statement prepared with a `Parse` and one prepared with the SQL
//! `PREPARE` share one set of names. The tracker follows the protocol
//! only, so after `DEALLOCATE s; PREPARE s AS ...` it still holds, for
//! `s`, the text of the `Parse`, and the analysis of that text.
//!
//! So the hook notes which names SQL may have changed, and from when, see
//! [`Changed`]:
//!
//! - An analysis that shows `PREPARE s` or `DEALLOCATE s` changes `s`.
//!   `DEALLOCATE ALL` and `DISCARD ALL` change every name; `DISCARD
//!   PLANS`, `TEMP` and `SEQUENCES` change none.
//! - A statement without an analysis, of any reason, may hold a `PREPARE`
//!   that is not seen: it changes every name. So do a `FunctionCall`
//!   where the rule about functions applies, and a `Query` passed on while
//!   no rule applies.
//! - A `Query` counts when it is passed on. A statement stored with
//!   `Parse` counts then, and again at each `Execute` that runs it. Once
//!   the session has stored one that may change names, an `Execute` of a
//!   statement the tracker does not know changes every name.
//!
//! A `Bind` of a changed name is a statement without an analysis, of the
//! reason `renamed`, until a `Parse` of the name sent after the change has
//! gone through: the server refuses a `Parse` of a name that exists, so
//! the name then holds the text of that `Parse`. The tracker gives that
//! text once the server has confirmed the `Parse`, and before that to a
//! `Bind` sent behind it before the next `Sync`, which the server skips if
//! the `Parse` fails. So a pooler that resets a connection with `DISCARD
//! ALL` raises nothing for the next client, which prepares its own
//! statements. A name whose text the tracker holds without an analysis
//! raises nothing more: nothing was judged by that text. A `Bind` that
//! arrives in parts or cannot be read shows no name, and counts as one of
//! a changed name once any name has changed. From the first `renamed`
//! `Bind` that goes on, every result of the session is held to the row
//! threshold, and every `Execute` may change a setting. The unnamed
//! statement goes on as before: SQL cannot make it.
//!
//! What is noted is bounded: one mark for every name, and at most
//! `MAX_CHANGED_NAMES` marks of single names, past which every name counts
//! as changed. A `PREPARE` that stored code runs, a function or a trigger,
//! is not seen.
//!
//! The statement that prepares was judged when it arrived, with the
//! statement it prepares, whatever else its analysis shows.
//!
//! # What the database reads
//!
//! The parser reads UTF-8, and reads strings as the database does with
//! `standard_conforming_strings` on. The hook follows what the server
//! reports of both settings. Until the server has reported both, they are
//! taken as unknown, and no statement is analysed.
//!
//! The server reports a change with its answer, and a client need not
//! wait for the answer before it sends its next statement. So a statement
//! is only analysed when the settings are known for the moment the
//! database reads it, see [`Reading`]:
//!
//! - After a statement that may change a setting has been passed on,
//!   nothing is analysed until the server has answered it. Such a
//!   statement is one whose analysis says so
//!   ([`Analysis::may_change_settings`]), one that has no analysis, a
//!   `FunctionCall`, and an `Execute` of a statement that is one of these
//!   or is not known.
//! - A change made inside a transaction is undone when the transaction
//!   fails, and any statement can fail. From such a statement until the
//!   server reports that no transaction is open, a statement is only
//!   analysed when the server has answered everything sent before it.
//!
//! A statement that is not analysed for this reason is a statement
//! without an analysis. A function or procedure of the database that
//! changes one of the two settings when it is called is not seen: its
//! code is not in the statement.
//!
//! # Events
//!
//! Under `query_redaction: fingerprint`, an event about a statement that
//! has an analysis shows the parser's form of it: the text with every
//! constant replaced by a placeholder (`normalized`), and the parser's
//! fingerprint, 16 hexadecimal digits that are the same for statements
//! that differ only in their constants. Both are made by the parser
//! threads with the analysis, once, and never on this thread. The digest
//! of the whole text, 64 hexadecimal digits, takes their place when the
//! statement has no analysis, when the form is longer than an event shows,
//! when one of the statements of the text is of a kind whose constants
//! the parser does not replace everywhere, when the form still holds a
//! comment or a string, and when it holds a honeytoken of the policy in
//! force.
//!
//! A `parse_failure` event names the message and shows the statement as
//! the redaction mode of the policy allows, like any other event. It never
//! holds the parser's own message, which quotes the statement.
//!
//! [`Scanner`]: super::Scanner

use std::collections::BTreeMap;
use std::sync::Arc;

use pgsnare_proto::{Frame, backend, frontend};

use crate::actions;
use crate::event::{EventKind, Query};
use crate::policy::QueryRedaction;
use crate::policy::{Action, ActionSet};
use crate::rules::{
    Analysis, OnParseFailure, ParseFailure, RowThreshold, RuleSet, StatementFlags, Subject,
};
use crate::session::{Direction, Effect, Output, StatementText};

use super::scan::{Ledger, Place, Raised, exempts};
use super::track::{Kept, MAX_NAME_BYTES, Statement};
use super::{Context, InspectionError, Verdict};

/// The statement whose analysis the session waits for.
struct Waiting {
    id: u64,
    /// The rules in force when the statement was held. They judge it,
    /// whatever has been loaded since.
    rules: Arc<RuleSet>,
    /// The text, and the place the answer is kept in.
    text: Arc<Kept>,
    /// The name of the message that carries the statement.
    name: Option<&'static str>,
    /// Whether the database runs the statement when it gets the message:
    /// a `Query`. A `Parse` only stores it.
    runs: bool,
    /// The serial of the last text the tracker had read when the
    /// statement was held: no text has been read since.
    serial: u64,
}

/// The most names of prepared statements a session remembers as changed
/// by SQL. Past it, every name counts as changed.
pub(super) const MAX_CHANGED_NAMES: usize = 256;

/// The name the server keeps a prepared statement under: it tells names
/// apart by their first 63 bytes.
fn server_name(name: &[u8]) -> &[u8] {
    name.get(..MAX_NAME_BYTES).unwrap_or(name)
}

/// Whether running a statement of this outcome may make, remove or
/// replace prepared statements: it prepares or deallocates with SQL, or
/// has no analysis.
fn changes_names(outcome: Option<&Result<Arc<Analysis>, ParseFailure>>) -> bool {
    !matches!(
        outcome,
        Some(Ok(analysis)) if !analysis.flags().intersects(
            StatementFlags::PREPARES
                .union(StatementFlags::DEALLOCATES_ALL)
                .union(StatementFlags::OPAQUE_BODY)
        )
    )
}

/// The prepared statements that SQL may have made, removed or replaced
/// since the tracker read the text it holds for them.
///
/// A change is marked with the serial of the last text the tracker had
/// read when the statement that makes it was let through, see
/// [`Kept::serial`]. A text with a larger serial is that of a `Parse` sent
/// after the change. The server refuses a `Parse` of a name that exists,
/// so that text stands for the name: the tracker holds it once the server
/// has confirmed the `Parse`, and before that only for messages sent
/// since the last `Sync`, which the server skips if the `Parse` fails.
#[derive(Default)]
struct Changed {
    /// Every name was changed at this mark.
    all: Option<u64>,
    /// Names changed later than `all`, each with its mark.
    names: BTreeMap<Box<[u8]>, u64>,
}

impl Changed {
    /// Whether no name was ever changed.
    fn is_empty(&self) -> bool {
        self.all.is_none() && self.names.is_empty()
    }

    /// Every name may have changed.
    fn everything(&mut self, serial: u64) {
        self.all = Some(serial);
        self.names.clear();
    }

    /// The name may have changed. Past [`MAX_CHANGED_NAMES`] names, every
    /// name counts as changed.
    fn name(&mut self, name: &[u8], serial: u64) {
        let name = server_name(name);
        if self.names.len() >= MAX_CHANGED_NAMES && !self.names.contains_key(name) {
            self.everything(serial);
        } else {
            self.names.insert(name.into(), serial);
        }
    }

    /// A statement of this outcome runs: what it may change.
    fn ran(&mut self, outcome: Option<&Result<Arc<Analysis>, ParseFailure>>, serial: u64) {
        match outcome {
            Some(Ok(analysis)) if !analysis.flags().contains(StatementFlags::OPAQUE_BODY) => {
                if analysis.flags().contains(StatementFlags::DEALLOCATES_ALL) {
                    self.everything(serial);
                }
                for name in analysis.statement_names() {
                    self.name(name.as_bytes(), serial);
                }
            }
            // Without an analysis, it may prepare anything.
            _ => self.everything(serial),
        }
    }

    /// Whether a `Bind` of the name can be judged by `statement`, which
    /// the tracker holds for it: the name was not changed since the
    /// tracker read the text, or the text has no analysis, so that nothing
    /// was judged by it and it is a statement without an analysis already.
    fn stands_for(&self, name: &[u8], statement: &Statement<'_>) -> bool {
        let named = self.names.get(server_name(name)).copied();
        let Some(mark) = named.max(self.all) else {
            return true;
        };
        matches!(statement, Statement::Kept(kept)
            if kept.serial() > mark || !matches!(kept.analysis(), Some(Ok(_))))
    }
}

/// What is known of the two settings that decide how the database reads
/// the text of a statement, for the moment it reads the next one.
///
/// The server reports a setting when it changes, before the
/// `ReadyForQuery` that ends the answer to what changed it. So the reports
/// are the truth once the server has answered everything that may have
/// changed a setting, and they stay the truth for as long as nothing
/// passed on since can change one.
///
/// The messages of the client that the server answers with a
/// `ReadyForQuery` are counted, and so are those answers. A message that
/// the server does not answer after all only makes the count of what is
/// outstanding too high, which keeps statements from being analysed and
/// never allows an analysis.
///
/// One such message is common: a `Sync` sent while the server reads the
/// data of a `COPY ... FROM STDIN`, which the server ignores. Client
/// libraries send one behind every `Execute`. It is taken out of the count
/// again when the server reports that the copy ended well, see
/// [`CopyIn`]. Any other message the server leaves unanswered stays in
/// the count: from then on, a statement that may change a setting leaves
/// the session without analyses.
#[derive(Debug, Default)]
struct Reading {
    /// Whether the server reported `client_encoding` as `UTF8`. `None`
    /// until it has reported one.
    utf8: Option<bool>,
    /// Whether the server reported `standard_conforming_strings` as `on`.
    /// `None` until it has reported one.
    conforming: Option<bool>,
    /// The messages passed on that the server answers with a
    /// `ReadyForQuery`: `Query`, `Sync`, `FunctionCall`.
    sent: u64,
    /// The `ReadyForQuery` of the server that answer them. Never more
    /// than `sent`: the one that ends the login answers none.
    answered: u64,
    /// The count `answered` has to reach before the server has answered
    /// every statement that may have changed a setting.
    changed_until: u64,
    /// A statement that may have changed a setting was passed on, and
    /// the server has not yet answered it and reported that no
    /// transaction is open. Until then the change may not be reported
    /// yet, or may be undone by a statement that fails.
    provisional: bool,
    /// A `Parse`, `Bind`, `Execute` or the like was passed on since the
    /// last message the server answers with a `ReadyForQuery`.
    unsynced: bool,
    /// How many `Query` and `Execute` messages were passed on since the
    /// server was last known to have answered everything.
    runs: u8,
    /// What was passed on since the last `Query` or `Execute`.
    copy: CopyIn,
    /// A copy the server announced and the client ended, whose statement
    /// is no longer the last: where its `Sync` messages began and how
    /// many they were.
    ended: Option<(u64, u64)>,
}

/// The messages passed on since the last `Query` or `Execute`, as far as
/// they matter if that statement is a `COPY ... FROM STDIN`.
///
/// While the server reads the data of such a copy it ignores `Sync`, and
/// answers none of them. Whether it did so is only certain afterwards:
/// when it reports the copy as complete, it has read everything from the
/// statement to the first `CopyDone` as part of the copy. Had the copy
/// failed, at any point, it would have reported an error instead, and
/// some of those `Sync` messages may have been answered.
#[derive(Debug, Default)]
struct CopyIn {
    /// The count of [`Reading::sent`] when the statement was passed on.
    base: u64,
    /// The `Sync` messages counted since, before the client ended the
    /// copy.
    syncs: u64,
    /// The client sent `CopyDone` or `CopyFail`.
    closed: bool,
    /// The client sent, before it ended the copy, a message that makes
    /// the server leave a copy with an error.
    spoiled: bool,
    /// The server announced a copy, and the statement is the only one
    /// that can have begun it.
    announced: bool,
}

impl Reading {
    /// Whether the database reads the next message of the client as the
    /// parser does. Asked before the message is counted.
    ///
    /// While a change may be open, that is so only when the server has
    /// answered everything: then nothing is on its way that could make a
    /// change, or fail and undo one.
    const fn known(&self) -> bool {
        matches!(self.utf8, Some(true))
            && matches!(self.conforming, Some(true))
            && (!self.provisional || (self.answered >= self.sent && !self.unsynced))
    }

    /// A message of the client is passed on.
    fn passed(&mut self, tag: u8) {
        // The server has answered everything sent before this message.
        if self.answered >= self.sent && !self.unsynced {
            self.runs = 0;
        }
        match tag {
            frontend::tag::QUERY | frontend::tag::SYNC | frontend::tag::FUNCTION_CALL => {
                self.sent = self.sent.saturating_add(1);
                self.unsynced = false;
            }
            // The server does nothing that could fail or change a setting.
            frontend::tag::FLUSH
            | frontend::tag::TERMINATE
            | frontend::tag::COPY_DATA
            | frontend::tag::COPY_DONE
            | frontend::tag::COPY_FAIL => {}
            _ => self.unsynced = true,
        }
        match tag {
            frontend::tag::QUERY | frontend::tag::EXECUTE => {
                // A copy that is complete on the side of the client keeps
                // its place until the server has said how it ended.
                if self.copy.announced && self.copy.closed && !self.copy.spoiled {
                    self.ended = Some((self.copy.base, self.copy.syncs));
                }
                self.copy = CopyIn {
                    base: self.sent,
                    ..CopyIn::default()
                };
                self.runs = self.runs.saturating_add(1);
            }
            frontend::tag::SYNC => {
                if !self.copy.closed && !self.copy.spoiled {
                    self.copy.syncs = self.copy.syncs.saturating_add(1);
                }
            }
            frontend::tag::FLUSH | frontend::tag::TERMINATE | frontend::tag::COPY_DATA => {}
            frontend::tag::COPY_DONE | frontend::tag::COPY_FAIL => self.copy.closed = true,
            _ => {
                if !self.copy.closed {
                    self.copy.spoiled = true;
                }
            }
        }
    }

    /// The server announces that it reads the data of a copy. Only one
    /// statement may be in question: with more than one on its way, the
    /// copy can belong to an earlier one than the last.
    const fn copy_announced(&mut self) {
        if self.runs == 1 {
            self.copy.announced = true;
        }
    }

    /// The server reports a statement as complete. After the announcement
    /// of a copy, it is the copy.
    fn completed(&mut self) {
        let ended = self.ended.take().or_else(|| {
            let copy = &mut self.copy;
            let ended =
                (copy.announced && copy.closed && !copy.spoiled).then_some((copy.base, copy.syncs));
            copy.announced = false;
            copy.syncs = 0;
            ended
        });
        let Some((base, syncs)) = ended else { return };
        // The server read these `Sync` messages as part of the copy and
        // answers none of them: they leave the count, and what was counted
        // after them moves up.
        let last = base.saturating_add(syncs);
        self.sent = self.sent.saturating_sub(syncs).max(self.answered);
        if self.changed_until > last {
            self.changed_until = self.changed_until.saturating_sub(syncs);
        } else if self.changed_until > base {
            self.changed_until = base.saturating_add(1);
        }
    }

    /// The message passed on last runs something that may change a
    /// setting. The server has answered it with the `ReadyForQuery` of
    /// the message itself, or with that of the `Sync` still to come.
    const fn may_have_changed(&mut self) {
        self.changed_until = if self.unsynced {
            self.sent.saturating_add(1)
        } else {
            self.sent
        };
        self.provisional = true;
    }

    /// A `ReadyForQuery` of the server, with the state of the transaction
    /// it reports, when that could be read.
    const fn ready(&mut self, transaction: Option<u8>) {
        // A copy that had ended well would have been reported before this.
        self.ended = None;
        self.copy.announced = false;
        if self.answered < self.sent {
            self.answered = self.answered.saturating_add(1);
        }
        // Outside a transaction nothing is left that could be undone.
        if matches!(transaction, Some(b'I')) && self.answered >= self.changed_until {
            self.provisional = false;
        }
    }

    /// A report of a setting could not be read: neither is known until
    /// the server reports it again.
    const fn lost(&mut self) {
        self.utf8 = Some(false);
        self.conforming = Some(false);
    }
}

/// The rows of one result, as the row threshold counts them.
#[derive(Debug, Default)]
pub(super) struct Rows {
    /// `None` until the first row; then the threshold the result is held
    /// to, if any. It does not change for the rest of the result.
    armed: Option<Option<RowThreshold>>,
    count: u64,
    fired: bool,
}

impl Rows {
    /// Counts one row of the result. `arm` gives the threshold, and is
    /// called at the first row only. Returns the threshold and the count
    /// when the result passes it, once.
    fn count(
        &mut self,
        arm: impl FnOnce() -> Option<RowThreshold>,
    ) -> Option<(&RowThreshold, u64)> {
        let threshold = self.armed.get_or_insert_with(arm).as_ref()?;
        self.count = self.count.saturating_add(1);
        if self.fired || self.count <= threshold.max_rows {
            return None;
        }
        self.fired = true;
        Some((threshold, self.count))
    }
}

/// What a scanner keeps for the SQL rules.
#[derive(Default)]
pub(super) struct Hook {
    /// The `id` of the next request.
    next_id: u64,
    waiting: Option<Waiting>,
    /// How the database reads a statement, as far as it is known.
    reading: Reading,
    /// The rows of results the tracker does not know, until the
    /// transaction ends.
    blind: Rows,
    /// The session passed on a statement that may have stored a query or
    /// code that reaches a table of the row threshold. From then on every
    /// result is held to the threshold, whatever its statement names.
    wide: bool,
    /// The prepared statements whose text the tracker holds may not be
    /// what the database runs under their names: a `Bind` of one has no
    /// analysis.
    changed: Changed,
    /// A `Parse` of the session stored a statement that may change names
    /// when it runs. An `Execute` of a statement the tracker does not know
    /// may run it.
    stores_changes: bool,
    /// A `Bind` of a changed name was passed on. A portal may run a
    /// statement no analysis shows, so every `Execute` from then on may
    /// change a setting.
    bound_renamed: bool,
}

/// Who the statements of a session come from.
fn subject<'a>(context: &'a Context<'a>) -> Subject<'a> {
    Subject {
        // A session whose listener is not known is in no list of them.
        listener: context.origin.listener.as_deref().unwrap_or_default(),
        // Until the database has accepted the login, the user is only what
        // the client claims.
        user: if context.authenticated {
            context.db_user
        } else {
            None
        },
    }
}

/// The rules of the policy in force, when one of them applies to the
/// session.
fn rules_for<'a>(context: &'a Context<'a>) -> Option<&'a Arc<RuleSet>> {
    context
        .policy
        .rules()
        .filter(|rules| rules.applies_to(&subject(context)))
}

/// The kinds of statement whose every constant the parser replaces when
/// it makes its form of a text. Of other kinds, such as `COMMENT`, `CREATE
/// VIEW` or `PREPARE`, it leaves the constants in place, and a number would
/// get through the check of [`parsed_query`].
const NORMALISED_KINDS: [&str; 9] = [
    "SelectStmt",
    "InsertStmt",
    "UpdateStmt",
    "DeleteStmt",
    "MergeStmt",
    "VariableSetStmt",
    "TransactionStmt",
    "CallStmt",
    "DeclareCursorStmt",
];

/// Whether the parser's form of a text may still hold something of the
/// text that is not a name or a keyword: a comment, which the parser keeps
/// as written, or a string or dollar-quoted string it did not replace.
fn may_hold_a_constant(normalised: &str) -> bool {
    let bytes = normalised.as_bytes();
    normalised.contains('\'')
        || normalised.contains("--")
        || normalised.contains("/*")
        // A placeholder is `$` and digits; anything else after `$` is a
        // dollar quote.
        || bytes.iter().enumerate().any(|(at, byte)| {
            *byte == b'$'
                && !bytes
                    .get(at.saturating_add(1))
                    .is_some_and(u8::is_ascii_digit)
        })
}

/// What an event shows of a statement under `fingerprint` in the parser's
/// form, made from its analysis: `None` when the form is not there or may
/// hold a constant, and the digest of the text must be shown instead.
///
/// The check against the honeytokens is not here, because the tokens can
/// change with a reload: the tracker makes it each time.
pub(super) fn parsed_query(analysis: &Analysis) -> Option<Query> {
    let normalised = analysis.normalised()?;
    let fingerprint = analysis.fingerprint()?;
    if !analysis
        .kinds()
        .iter()
        .all(|kind| NORMALISED_KINDS.contains(kind))
        || may_hold_a_constant(normalised)
    {
        return None;
    }
    Some(Query::fingerprint(
        format!("{fingerprint:016x}"),
        Some(normalised.to_owned()),
    ))
}

/// The row threshold a result of `statement` is held to.
fn armed(statement: &Statement<'_>, wide: bool, context: &Context<'_>) -> Option<RowThreshold> {
    if !wide
        && let Statement::Kept(kept) = statement
        && let Some(armed) = kept.threshold()
    {
        return armed.clone();
    }
    context
        .policy
        .rules()?
        .blind_row_threshold(&subject(context))
}

/// Counts a statement that has no analysis, raises the event the policy
/// asks for, and returns what is done about it. `kill` among it means the
/// session must end before the statement is passed on: the caller does
/// that.
fn raise(
    reason: ParseFailure,
    rules: &RuleSet,
    place: &Place<'_>,
    ledger: &Ledger,
    out: &mut Output,
) -> ActionSet {
    let actions = if exempts(place.context) {
        ActionSet::EMPTY
    } else {
        match rules.on_parse_failure() {
            OnParseFailure::Allow => ActionSet::EMPTY,
            OnParseFailure::Alert => ActionSet::ALERT,
            OnParseFailure::Block => ActionSet::of(&[Action::Alert, Action::Kill]),
        }
    };
    out.effects.push(Effect::ParseFailed { reason, actions });
    if !actions.is_empty() {
        let mut body = ledger.body(EventKind::ParseFailure, place);
        body.action_taken = actions;
        out.effects.push(Effect::Emit(Box::new(body)));
    }
    actions
}

/// Whether what an `Execute` runs may change a setting: anything but a
/// statement the tracker holds with an analysis that says it does not.
fn runs_unread(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::Kept(kept) => !matches!(
            kept.analysis(),
            Some(Ok(analysis)) if !analysis.may_change_settings()
        ),
        _ => true,
    }
}

/// Ends a session whose statement must not reach the database. Nothing of
/// the statement was passed on, so there is nothing to cancel.
pub(super) fn block(context: &Context<'_>, client_can_be_told: bool, out: &mut Output) -> Verdict {
    actions::kill(
        &context.policy.actions().kill,
        client_can_be_told,
        None,
        out,
    );
    Verdict::End
}

impl Hook {
    /// A whole message of the server: follows the settings that decide how
    /// the database reads a statement.
    pub(super) fn server(&mut self, frame: Frame<'_>) {
        if frame.tag() == backend::tag::READY_FOR_QUERY {
            let transaction = frame.body().first().copied();
            self.reading.ready(transaction);
            // Portals end with the transaction, and so does what is counted
            // for results that are not known.
            if transaction != Some(b'T') {
                self.blind = Rows::default();
            }
            return;
        }
        match frame.tag() {
            backend::tag::COPY_IN_RESPONSE => self.reading.copy_announced(),
            backend::tag::COMMAND_COMPLETE => self.reading.completed(),
            _ => {}
        }
        if frame.tag() != backend::tag::PARAMETER_STATUS {
            return;
        }
        let Ok(status) = backend::ParameterStatus::from_frame(frame) else {
            self.reading.lost();
            return;
        };
        match status.name() {
            b"client_encoding" => {
                self.reading.utf8 = Some(status.value().eq_ignore_ascii_case(b"UTF8"));
            }
            b"standard_conforming_strings" => {
                self.reading.conforming = Some(status.value() == b"on");
            }
            _ => {}
        }
    }

    /// The header of a message of the server that arrives in parts.
    pub(super) fn server_chunked(&mut self, tag: u8) {
        match tag {
            backend::tag::PARAMETER_STATUS => self.reading.lost(),
            // The state of the transaction is in a part not seen here.
            backend::tag::READY_FOR_QUERY => self.reading.ready(None),
            backend::tag::COPY_IN_RESPONSE => self.reading.copy_announced(),
            backend::tag::COMMAND_COMPLETE => self.reading.completed(),
            _ => {}
        }
    }

    /// A whole message of the client that the scanner is about to pass on,
    /// after it has been searched. `serial` is that of the last text the
    /// tracker has read. Returns what becomes of the message.
    pub(super) fn client(
        &mut self,
        frame: Frame<'_>,
        place: &Place<'_>,
        ledger: &Ledger,
        client_can_be_told: bool,
        serial: u64,
        out: &mut Output,
    ) -> Verdict {
        let tag = frame.tag();
        // What is known of the settings for the moment the database reads
        // this message, which is before it does what the message asks.
        let readable = self.reading.known();
        self.reading.passed(tag);
        let sql = match tag {
            frontend::tag::QUERY => frontend::Query::from_frame(frame)
                .ok()
                .map(|query| query.sql()),
            frontend::tag::PARSE => frontend::Parse::from_frame(frame)
                .ok()
                .map(|parse| parse.sql()),
            frontend::tag::FUNCTION_CALL => {
                // The function it calls by number may be the one that
                // changes a setting.
                self.reading.may_have_changed();
                return self.function_call(place, ledger, client_can_be_told, serial, out);
            }
            frontend::tag::EXECUTE => {
                if self.bound_renamed || runs_unread(place.statement) {
                    self.reading.may_have_changed();
                }
                // A statement stored with `Parse` runs here, and what it
                // changes counts from now.
                match place.statement {
                    Statement::Kept(kept) => self.changed.ran(kept.analysis(), serial),
                    _ if self.stores_changes => self.changed.everything(serial),
                    _ => {}
                }
                return Verdict::Forward;
            }
            frontend::tag::BIND => return self.bind(frame, place, ledger, client_can_be_told, out),
            _ => return Verdict::Forward,
        };
        // A `Query` runs its statement now. A `Parse` stores it, and the
        // `Execute` that runs it is looked at when it comes.
        let runs = tag == frontend::tag::QUERY;
        let context = place.context;
        let Some(rules) = rules_for(context) else {
            // Nobody reads the statement, so it may be one that changes a
            // setting or a name. Rules loaded later must not take it for
            // granted.
            self.unread(runs, serial);
            return Verdict::Forward;
        };
        // The parser's form of the statement is what an event shows under
        // `fingerprint`, so it is made with the analysis, once.
        let limits = rules
            .limits()
            .normalised(context.policy.query_redaction() == QueryRedaction::Fingerprint);

        let held = match sql {
            None => Err(ParseFailure::Unreadable),
            Some(_) if !readable => Err(ParseFailure::Encoding),
            Some(sql) if sql.len() > limits.max_bytes => Err(ParseFailure::TooLarge),
            // The session shows no message of the client while it holds
            // one. Should it, the second statement is not analysed.
            Some(_) if self.waiting.is_some() => Err(ParseFailure::Busy),
            Some(sql) => Ok(sql),
        };
        let sql = match held {
            Ok(sql) => sql,
            Err(reason) => {
                self.unread(runs, serial);
                let actions = raise(reason, rules, place, ledger, out);
                return if actions.contains(Action::Kill) {
                    block(context, client_can_be_told, out)
                } else {
                    self.wide = true;
                    Verdict::Forward
                };
            }
        };

        // The text the tracker keeps for the statement, so that the answer
        // stays with it, or a copy when the tracker had no room.
        let text = match place.statement {
            Statement::Own {
                kept: Some(kept), ..
            } => Arc::clone(kept),
            _ => Kept::uncounted(sql),
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let shared: Arc<dyn AsRef<[u8]> + Send + Sync> = text.clone();
        out.effects.push(Effect::Analyse {
            id,
            text: StatementText::new(shared),
            limits,
        });
        self.waiting = Some(Waiting {
            id,
            rules: Arc::clone(rules),
            text,
            name: place.name,
            runs,
            serial,
        });
        Verdict::Hold
    }

    /// A `Query` or `Parse` goes on without an analysis. Run, it may
    /// change a setting, and make, remove or replace any prepared
    /// statement.
    fn unread(&mut self, runs: bool, serial: u64) {
        if runs {
            self.reading.may_have_changed();
            self.changed.everything(serial);
        } else {
            self.stores_changes = true;
        }
    }

    /// The rules that cannot judge a `FunctionCall` of the session,
    /// because the message names its function by a number: set when the
    /// rule about functions applies to the session.
    fn blind_to_calls<'a>(context: &'a Context<'a>) -> Option<&'a Arc<RuleSet>> {
        rules_for(context).filter(|rules| rules.watches_functions(&subject(context)))
    }

    /// A whole `FunctionCall` of the client.
    fn function_call(
        &mut self,
        place: &Place<'_>,
        ledger: &Ledger,
        client_can_be_told: bool,
        serial: u64,
        out: &mut Output,
    ) -> Verdict {
        let context = place.context;
        let Some(rules) = Self::blind_to_calls(context) else {
            return Verdict::Forward;
        };
        // A statement without an analysis.
        self.changed.everything(serial);
        let actions = raise(ParseFailure::FunctionCall, rules, place, ledger, out);
        if actions.contains(Action::Kill) {
            block(context, client_can_be_told, out)
        } else {
            self.wide = true;
            Verdict::Forward
        }
    }

    /// A whole `Bind` of the client. A `Bind` of a name that SQL may have
    /// changed since the tracker read the text it holds for it has no
    /// analysis, see [`Changed`]. The unnamed statement is not affected:
    /// SQL cannot make it.
    fn bind(
        &mut self,
        frame: Frame<'_>,
        place: &Place<'_>,
        ledger: &Ledger,
        client_can_be_told: bool,
        out: &mut Output,
    ) -> Verdict {
        if self.changed.is_empty() {
            return Verdict::Forward;
        }
        // A `Bind` that cannot be read is taken for one of a changed name.
        if frontend::Bind::from_frame(frame).is_ok_and(|bind| {
            bind.statement().is_empty()
                || self.changed.stands_for(bind.statement(), place.statement)
        }) {
            return Verdict::Forward;
        }
        self.bound_renamed = true;
        let context = place.context;
        let Some(rules) = rules_for(context) else {
            return Verdict::Forward;
        };
        // The text the tracker holds for the name may not be the one that
        // runs, so the event does not show it.
        let unknown = Place {
            statement: &Statement::Unknown,
            ..*place
        };
        let actions = raise(ParseFailure::Renamed, rules, &unknown, ledger, out);
        if actions.contains(Action::Kill) {
            block(context, client_can_be_told, out)
        } else {
            self.wide = true;
            Verdict::Forward
        }
    }

    /// The header of a `Query`, `Parse` or `FunctionCall` of the client
    /// that arrives in parts: it cannot be held, so it has no analysis. So
    /// has a `Bind` once SQL may have changed a name, see [`Hook::bind`].
    /// `serial` is that of the last text the tracker has read. Returns
    /// whether the session must end before the message is passed on.
    pub(super) fn client_chunked(
        &mut self,
        tag: u8,
        place: &Place<'_>,
        ledger: &Ledger,
        serial: u64,
        out: &mut Output,
    ) -> bool {
        self.reading.passed(tag);
        // Nothing reads what arrives in parts: whatever it runs may change
        // a setting.
        if matches!(
            tag,
            frontend::tag::QUERY | frontend::tag::FUNCTION_CALL | frontend::tag::EXECUTE
        ) {
            self.reading.may_have_changed();
        }
        let (reason, rules) = match tag {
            frontend::tag::QUERY | frontend::tag::PARSE => {
                if tag == frontend::tag::QUERY {
                    self.changed.everything(serial);
                } else {
                    self.stores_changes = true;
                }
                (ParseFailure::Streamed, rules_for(place.context))
            }
            frontend::tag::FUNCTION_CALL => {
                let rules = Self::blind_to_calls(place.context);
                if rules.is_some() {
                    self.changed.everything(serial);
                }
                (ParseFailure::FunctionCall, rules)
            }
            // The name is in a part not seen here: it counts as a changed
            // one.
            frontend::tag::BIND if !self.changed.is_empty() => {
                self.bound_renamed = true;
                (ParseFailure::Renamed, rules_for(place.context))
            }
            _ => return false,
        };
        let Some(rules) = rules else {
            return false;
        };
        let blocked = raise(reason, rules, place, ledger, out).contains(Action::Kill);
        self.wide |= !blocked;
        blocked
    }

    /// The answer of the runtime to the request `id`. Returns what becomes
    /// of the held message, or `None` when no statement waits for this
    /// answer.
    ///
    /// With an analysis, this is where the rules judge the statement.
    pub(super) fn answer(
        &mut self,
        id: u64,
        outcome: Result<Arc<Analysis>, ParseFailure>,
        ledger: &mut Ledger,
        context: &Context<'_>,
        client_can_be_told: bool,
        out: &mut Output,
    ) -> Result<Option<Verdict>, InspectionError> {
        let Some(waiting) = self.waiting.take_if(|waiting| waiting.id == id) else {
            return Ok(None);
        };
        // An analysis with a full list does not tell everything the
        // statement touches: it is no analysis.
        let outcome = outcome.and_then(|analysis| {
            if analysis.is_complete() {
                Ok(analysis)
            } else {
                Err(ParseFailure::Incomplete)
            }
        });
        // What the statement may change of the names counts from now: a
        // `Query` runs it, and a stored one is taken to run at once too.
        // It counts again when an `Execute` runs it.
        self.changed.ran(Some(&outcome), waiting.serial);
        if !waiting.runs && changes_names(Some(&outcome)) {
            self.stores_changes = true;
        }
        waiting.text.analysed(outcome.clone());
        if let Ok(analysis) = &outcome {
            waiting
                .text
                .armed(waiting.rules.row_threshold(analysis, &subject(context)));
        }
        // No other message of the client was passed on since this one, so
        // it is still the last.
        let unread = !matches!(&outcome, Ok(analysis) if !analysis.may_change_settings());
        if waiting.runs && unread {
            self.reading.may_have_changed();
        }
        // What the statement stores, a later one reads under another name.
        if !matches!(&outcome, Ok(analysis) if !waiting.rules.stores_a_listed_read(analysis)) {
            self.wide = true;
        }

        let statement = Statement::Kept(Arc::clone(&waiting.text));
        let place = Place {
            direction: Direction::FromClient,
            name: waiting.name,
            in_session: true,
            statement: &statement,
            // No result of the statement exists yet.
            rows: false,
            context,
        };
        let analysis = match outcome {
            Ok(analysis) => analysis,
            Err(reason) => {
                let actions = raise(reason, &waiting.rules, &place, ledger, out);
                return Ok(Some(if actions.contains(Action::Kill) {
                    block(context, client_can_be_told, out)
                } else {
                    Verdict::Forward
                }));
            }
        };

        // Every rule the statement sets off is raised before the session
        // acts on any of them, as for the tokens of one message.
        let mut kill = false;
        for (rule_id, decided) in waiting.rules.evaluate(&analysis, &subject(context)) {
            let actions = ledger.rule_hit(rule_id, decided, None, &place, out);
            kill |= actions.contains(Action::Kill);
        }
        // Code the parser did not read: for that part there is no analysis.
        if analysis.flags().contains(StatementFlags::OPAQUE_BODY) {
            let actions = raise(
                ParseFailure::OpaqueBody,
                &waiting.rules,
                &place,
                ledger,
                out,
            );
            if actions.contains(Action::Kill) && !kill {
                return Ok(Some(block(context, client_can_be_told, out)));
            }
        }
        Raised::by_rules(kill)
            .respond(client_can_be_told, context, out)
            .map(Some)
    }

    /// A row of a result, at `place`: a `DataRow` or a `CopyData` of the
    /// server. `rows` is the count of the result as the tracker knows it.
    /// Returns the responses to carry out when the row passes the row
    /// threshold of the result.
    pub(super) fn row(
        &mut self,
        rows: Option<&mut Rows>,
        place: &Place<'_>,
        ledger: &mut Ledger,
        out: &mut Output,
    ) -> ActionSet {
        let wide = self.wide;
        let counted = rows.unwrap_or(&mut self.blind);
        let Some((threshold, count)) =
            counted.count(|| armed(place.statement, wide, place.context))
        else {
            return ActionSet::EMPTY;
        };
        // The rows sent before this one.
        let sent = count.saturating_sub(1);
        ledger.rule_hit(
            threshold.rule.clone(),
            threshold.actions,
            Some(sent),
            place,
            out,
        )
    }

    /// Whether a statement waits for its analysis.
    pub(super) const fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }
}
