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
//! | The session's `client_encoding` is not `UTF8`, or `standard_conforming_strings` is off | at once |
//! | The parser refused the statement, or it nests too deep | when the runtime answers |
//! | The analysis is incomplete: a list in it was full | when the runtime answers |
//! | The parser threads were busy, did not answer in time, or one panicked | when the runtime answers |
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
//! # What the database reads
//!
//! The parser reads UTF-8, and reads strings as the database does with
//! `standard_conforming_strings` on. The hook follows what the server
//! reports of both settings. Until the server has reported
//! `client_encoding`, it is taken as unknown, and no statement is
//! analysed.
//!
//! A change of either setting is known here only when the server reports
//! it. A client that changes one and sends its next statement without
//! waiting for the answer has that statement read under the old setting.
//!
//! # Events
//!
//! A `parse_failure` event names the message and shows the statement as
//! the redaction mode of the policy allows, like any other event. It never
//! holds the parser's own message, which quotes the statement.
//!
//! [`Scanner`]: super::Scanner

use std::sync::Arc;

use pgsnare_proto::{Frame, backend, frontend};

use crate::actions;
use crate::event::EventKind;
use crate::policy::{Action, ActionSet};
use crate::rules::{Analysis, OnParseFailure, ParseFailure, RuleSet, Subject};
use crate::session::{Direction, Effect, Output, StatementText};

use super::scan::{Ledger, Place, exempts};
use super::track::{Kept, Statement};
use super::{Context, Verdict};

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
}

/// What a scanner keeps for the SQL rules.
#[derive(Default)]
pub(super) struct Hook {
    /// The `id` of the next request.
    next_id: u64,
    waiting: Option<Waiting>,
    /// Whether the server reported `client_encoding` as `UTF8`. `None`
    /// until it has reported one.
    utf8: Option<bool>,
    /// Whether the server reported `standard_conforming_strings` as
    /// anything but `on`.
    lenient_strings: bool,
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
        if frame.tag() != backend::tag::PARAMETER_STATUS {
            return;
        }
        let Ok(status) = backend::ParameterStatus::from_frame(frame) else {
            self.settings_lost();
            return;
        };
        match status.name() {
            b"client_encoding" => {
                self.utf8 = Some(status.value().eq_ignore_ascii_case(b"UTF8"));
            }
            b"standard_conforming_strings" => {
                self.lenient_strings = status.value() != b"on";
            }
            _ => {}
        }
    }

    /// The header of a message of the server that arrives in parts.
    pub(super) fn server_chunked(&mut self, tag: u8) {
        if tag == backend::tag::PARAMETER_STATUS {
            self.settings_lost();
        }
    }

    /// A report of a setting could not be read: the encoding is unknown
    /// until the server reports it again.
    const fn settings_lost(&mut self) {
        self.utf8 = Some(false);
    }

    /// A whole message of the client that the scanner is about to pass on,
    /// after it has been searched. Returns what becomes of it.
    pub(super) fn client(
        &mut self,
        frame: Frame<'_>,
        place: &Place<'_>,
        ledger: &Ledger,
        client_can_be_told: bool,
        out: &mut Output,
    ) -> Verdict {
        let sql = match frame.tag() {
            frontend::tag::QUERY => frontend::Query::from_frame(frame)
                .ok()
                .map(|query| query.sql()),
            frontend::tag::PARSE => frontend::Parse::from_frame(frame)
                .ok()
                .map(|parse| parse.sql()),
            _ => return Verdict::Forward,
        };
        let context = place.context;
        let Some(rules) = rules_for(context) else {
            return Verdict::Forward;
        };
        let limits = rules.limits();

        let held = match sql {
            None => Err(ParseFailure::Unreadable),
            Some(_) if self.utf8 != Some(true) || self.lenient_strings => {
                Err(ParseFailure::Encoding)
            }
            Some(sql) if sql.len() > limits.max_bytes => Err(ParseFailure::TooLarge),
            // The session shows no message of the client while it holds
            // one. Should it, the second statement is not analysed.
            Some(_) if self.waiting.is_some() => Err(ParseFailure::Busy),
            Some(sql) => Ok(sql),
        };
        let sql = match held {
            Ok(sql) => sql,
            Err(reason) => {
                let actions = raise(reason, rules, place, ledger, out);
                return if actions.contains(Action::Kill) {
                    block(context, client_can_be_told, out)
                } else {
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
        });
        Verdict::Hold
    }

    /// The header of a `Query` or `Parse` of the client that arrives in
    /// parts: it cannot be held, so it has no analysis. Returns whether
    /// the session must end before the message is passed on.
    pub(super) fn client_chunked(
        tag: u8,
        place: &Place<'_>,
        ledger: &Ledger,
        out: &mut Output,
    ) -> bool {
        if !matches!(tag, frontend::tag::QUERY | frontend::tag::PARSE) {
            return false;
        }
        let Some(rules) = rules_for(place.context) else {
            return false;
        };
        raise(ParseFailure::Streamed, rules, place, ledger, out).contains(Action::Kill)
    }

    /// The answer of the runtime to the request `id`. Returns what becomes
    /// of the held message, or `None` when no statement waits for this
    /// answer.
    pub(super) fn answer(
        &mut self,
        id: u64,
        outcome: Result<Arc<Analysis>, ParseFailure>,
        ledger: &Ledger,
        context: &Context<'_>,
        client_can_be_told: bool,
        out: &mut Output,
    ) -> Option<Verdict> {
        let waiting = self.waiting.take_if(|waiting| waiting.id == id)?;
        // An analysis with a full list does not tell everything the
        // statement touches: it is no analysis.
        let outcome = outcome.and_then(|analysis| {
            if analysis.is_complete() {
                Ok(analysis)
            } else {
                Err(ParseFailure::Incomplete)
            }
        });
        waiting.text.analysed(outcome.clone());
        let reason = match outcome {
            Ok(_) => return Some(Verdict::Forward),
            Err(reason) => reason,
        };

        let statement = Statement::Kept(Arc::clone(&waiting.text));
        let place = Place {
            direction: Direction::FromClient,
            name: waiting.name,
            in_session: true,
            statement: &statement,
            rows: false,
            context,
        };
        let actions = raise(reason, &waiting.rules, &place, ledger, out);
        Some(if actions.contains(Action::Kill) {
            block(context, client_can_be_told, out)
        } else {
            Verdict::Forward
        })
    }

    /// Whether a statement waits for its analysis.
    pub(super) const fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }
}
