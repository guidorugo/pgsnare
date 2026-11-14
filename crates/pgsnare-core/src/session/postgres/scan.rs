// SPDX-License-Identifier: Apache-2.0

//! The inspector that looks for honeytokens.
//!
//! A [`Scanner`] searches everything a session shows it for the values of
//! the tokens of the policy, with the [`Matcher`] of the snapshot that is
//! in force for the message.
//!
//! # What is searched
//!
//! The whole body of every message, in both directions, whatever its type.
//! There is no list of the messages that can carry a value: a list is how a
//! message gets forgotten. The startup message is searched as the packet
//! that arrived, so every parameter the client sent is covered.
//!
//! # Values in more than one piece
//!
//! - **TCP reads.** The session puts a message together before it shows
//!   it, so the way the bytes arrived makes no difference.
//! - **A message too large to hold** arrives in chunks. One
//!   [`StreamScanner`] follows it from its header to its last chunk.
//! - **COPY.** The rows of a COPY are cut into `CopyData` messages wherever
//!   the sender likes. One [`StreamScanner`] for each direction reads the
//!   bodies of all `CopyData` messages as one stream, until the COPY in
//!   that direction ends. A client can send `CopyData` before the server
//!   has announced the COPY: those messages belong to the same stream, so
//!   a value cannot hide across the announcement.
//!
//! Nothing else is joined. A value split across two messages of another
//! kind is not a value any receiver would see.
//!
//! # Which policy applies
//!
//! A message is searched with the matcher of the snapshot in force when it
//! arrives. A message that arrives in chunks keeps the matcher it started
//! with until its last chunk, and a COPY keeps the matcher of its first
//! `CopyData` until it ends: the bytes carried from one piece to the next
//! mean nothing to another matcher. `CopyData` outside an announced COPY
//! moves to a new snapshot at once, at the price of the bytes carried.
//!
//! # A hit
//!
//! One hit is raised for each token in each message, or in each chunk of a
//! message that arrives in chunks, however often the token occurs there.
//! A hit is two effects: [`Effect::TokenHit`], which the runtime counts,
//! and [`Effect::Emit`] with a `token_hit` event. The event names the
//! token by its id, the direction and the message. It never holds the
//! bytes that matched, nor any other part of the message.
//!
//! The policy decides the response from the token and from how often the
//! session has hit it. Two responses are carried out so far:
//!
//! - `alert`: the hit is reported, and the message is passed on.
//! - `kill`: the message is held back, and the session ends with
//!   [`actions::kill`] once every hit of the message has been raised.
//!   The client is told with the error of the policy when it is at the
//!   end of a message, that is unless a message from the server is being
//!   passed on in chunks. A hit in a later chunk of such a message closes
//!   both connections without an error.
//!
//! A decision for responses none of which is built yet is carried out as
//! `alert`. The event and [`Effect::TokenHit`] say what was carried out.
//!
//! # The statement of an event
//!
//! A tracker (the `track` module) tells which statement a message belongs
//! to. An event shows of it what
//! [`Query::from_statement`](crate::event::Query::from_statement) gives under the
//! redaction mode of the snapshot in force, and never the text as such.
//! When the tracker does not know the statement, the event says that the
//! statement is unknown. The hit is raised all the same.
//!
//! # Exempt sessions
//!
//! A hit in a session the policy exempts is counted, with
//! [`Effect::TokenHit`] marked as exempt, and does nothing else: no event,
//! no response, and the session is not flagged.
//!
//! An exemption for a database user holds once the database has accepted
//! the login as that user, and not before: until then the name is what
//! the client claims. At startup only an exemption for an address range
//! alone can apply. The user is the one of the login for the whole
//! session. `SET ROLE` and `SET SESSION AUTHORIZATION` neither give an
//! exemption nor take one away. No other field a client sends, such as the
//! application name, has any part in it. The address is the one the proxy
//! saw.
//!
//! # Escalation
//!
//! The scanner counts the hits of each token for the life of the session
//! and asks the policy for the response to that hit. Nothing a client
//! sends lowers a count. Hits in an exempt session are not counted. The
//! table holds `MAX_COUNTED_TOKENS` tokens. A token that does not fit is
//! answered as if it had been hit without end, with its escalated
//! response.
//!
//! # A flagged session
//!
//! A session is flagged from its first hit that is not exempt, for the
//! rest of its life. Each later hit says so in its event, and each later
//! statement of the client raises a `session_activity` event, before the
//! statement is searched. Their number is not bounded here: the queue of
//! the dispatcher is the bound.
//!
//! # The SQL rules
//!
//! With the `rules` feature, a statement of the client that has been
//! searched is held until it has been judged by the rules of the policy,
//! see the `rules` module beside this one. A statement that sets off a
//! rule is a hit like that of a honeytoken, and takes the same path: it
//! is counted with `Effect::RuleHit`, also in an exempt session, where
//! that is all; it is reported with a `rule_hit` event that names the
//! rule and no token; it flags the session; and its response is carried
//! out by the code that carries out the response to a honeytoken. The
//! rules have no part in whether a honeytoken is found.
//!
//! # Statements
//!
//! Each `Query`, each `Execute` and each `FunctionCall` of a client is
//! counted as a statement, with [`Effect::QuerySeen`], when the session
//! sees it.
//!
//! # Bounds
//!
//! A scanner keeps, for each direction, at most two stream scanners, each
//! with fewer bytes than the longest pattern is long. A search takes time
//! in proportion to the bytes searched. The hits of one search are at most
//! one for each token of the policy. The tracker has its own bounds, and
//! the table of hit counts is bounded as said above.

use core::fmt;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pgsnare_proto::startup::StartupMessage;
use pgsnare_proto::{Chunk, Frame, FrameHeader, backend, frontend};

use crate::actions::{self, FakeRows, Tarpit, TarpitPlaces};
use crate::bait::Entropy;
use crate::detect::{Match, Matcher, ScanError, StreamScanner};
use crate::event::{EventBody, EventKind, StatementDigest};
#[cfg(feature = "rules")]
use crate::policy::RuleId;
use crate::policy::{Action, ActionSet, PolicySnapshot, TokenId};
#[cfg(feature = "rules")]
use crate::rules::{Analysis, ParseFailure};
use crate::session::{Direction, Effect, Output};

use super::names::{STARTUP_MESSAGE, message_name};
#[cfg(feature = "rules")]
use super::rules::{self, Hook};
use super::track::{Statement, Tracker};
use super::{Context, InspectionError, Inspector, Verdict};

/// A stream scanner and the generation of the snapshot whose matcher it
/// was made from.
struct Stream {
    scanner: StreamScanner,
    generation: u64,
}

impl Stream {
    fn new(policy: &PolicySnapshot) -> Self {
        Self {
            scanner: policy.matcher().stream(),
            generation: policy.generation(),
        }
    }
}

/// A message that arrives in chunks.
struct Chunked {
    name: Option<&'static str>,
    stream: Stream,
    /// The statement the message belongs to.
    statement: Statement<'static>,
    /// For a `CopyData`: which COPY of its direction the scanner belongs
    /// to, so that it is handed back only if that COPY is still running.
    copy: Option<u64>,
    /// Whether the message is a statement that must not reach the
    /// database: none of it is passed on, and the session ends with its
    /// last part.
    #[cfg(feature = "rules")]
    blocked: bool,
}

/// What a scanner keeps for one direction.
#[derive(Default)]
struct Half {
    /// The scanner of the `CopyData` messages. `None` when no `CopyData`
    /// has been seen since the last COPY ended, and while a `CopyData`
    /// that arrives in chunks has it.
    copy: Option<Stream>,
    /// Whether the server has announced a COPY that has not ended.
    announced: bool,
    /// Whether the announced COPY has begun to carry data. From then on
    /// it keeps its matcher.
    pinned: bool,
    /// Counts the COPYs that have ended.
    copies_ended: u64,
    /// The message that is arriving in chunks, if any.
    chunked: Option<Chunked>,
}

impl Half {
    /// Takes the scanner the next `CopyData` continues, or a new one.
    fn take_copy(&mut self, policy: &PolicySnapshot) -> Stream {
        let pinned = self.pinned;
        self.pinned = self.announced;
        match self.copy.take() {
            Some(stream) if pinned || stream.generation == policy.generation() => stream,
            _ => Stream::new(policy),
        }
    }
}

/// The most tokens whose hits a scanner counts one by one.
pub(super) const MAX_COUNTED_TOKENS: usize = 1024;

/// The responses every scanner can carry out.
const ALWAYS_BUILT: [Action; 2] = [Action::Alert, Action::Kill];

/// The responses that are carried out, of those the policy decided: the
/// ones in `built`, or `alert` when none of them is. `kill` ends the
/// session, so with it nothing is slowed down or added.
fn carried_out(decided: ActionSet, built: ActionSet) -> ActionSet {
    let kill = decided.contains(Action::Kill);
    let mut actions = ActionSet::EMPTY;
    for action in decided.iter() {
        let ended = kill && matches!(action, Action::Tarpit | Action::FakeData);
        if built.contains(action) && !ended {
            actions.insert(action);
        }
    }
    if actions.is_empty() {
        ActionSet::ALERT
    } else {
        actions
    }
}

/// `actions` without `action`, or `alert` when nothing is left.
fn without(actions: ActionSet, action: Action) -> ActionSet {
    let mut rest = ActionSet::EMPTY;
    for kept in actions.iter().filter(|kept| *kept != action) {
        rest.insert(kept);
    }
    if rest.is_empty() {
        ActionSet::ALERT
    } else {
        rest
    }
}

/// Whether `text` is one statement that reads rows and reports them as
/// `SELECT n`: a `SELECT`, `TABLE` or `VALUES`, with no `;` but at its
/// end. Anything else, a leading comment included, is not.
pub(super) fn single_select(text: &[u8]) -> bool {
    let trimmed = text.trim_ascii();
    let body = trimmed.strip_suffix(b";").unwrap_or(trimmed);
    if body.contains(&b';') {
        return false;
    }
    let word: Vec<u8> = body
        .iter()
        .take_while(|byte| byte.is_ascii_alphabetic())
        .map(u8::to_ascii_lowercase)
        .collect();
    matches!(word.as_slice(), b"select" | b"table" | b"values")
}

/// Whether a token of `policy` may answer with `fake_data`.
fn wants_rows(policy: &PolicySnapshot) -> bool {
    policy.tokens().iter().any(|token| {
        token.actions.contains(Action::FakeData)
            || token
                .escalate
                .is_some_and(|escalation| escalation.to.contains(Action::FakeData))
    })
}

/// What a scanner needs for the responses that go beyond `alert` and
/// `kill`: a source of randomness for each session, and the places for
/// tarpitted sessions of the whole proxy.
#[derive(Clone)]
pub struct Responses {
    entropy: Arc<dyn Fn() -> Box<dyn Entropy + Send> + Send + Sync>,
    tarpits: Arc<TarpitPlaces>,
}

impl Responses {
    /// Responses whose sessions each draw from a source `entropy` makes,
    /// and share `tarpits`.
    #[must_use]
    pub fn new(
        entropy: impl Fn() -> Box<dyn Entropy + Send> + Send + Sync + 'static,
        tarpits: Arc<TarpitPlaces>,
    ) -> Self {
        Self {
            entropy: Arc::new(entropy),
            tarpits,
        }
    }
}

impl fmt::Debug for Responses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Responses")
            .field("tarpitted", &self.tarpits.held())
            .finish_non_exhaustive()
    }
}

/// The state of the responses of one session.
struct Responder {
    entropy: Box<dyn Entropy + Send>,
    tarpits: Arc<TarpitPlaces>,
    /// Set once the session is tarpitted.
    tarpit: Option<Tarpit>,
    /// The result the server is sending, while rows can be made up for it.
    rows: Option<FakeRows>,
    /// Whether the next `RowDescription` describes a prepared statement,
    /// whose formats are not those of its results.
    describing_statement: bool,
    /// Whether the client has asked for a result in parts: a result may
    /// then end without `CommandComplete`. Once set, it stays.
    limited: bool,
}

impl Responder {
    fn built() -> ActionSet {
        ActionSet::of(&[
            Action::Alert,
            Action::Kill,
            Action::Tarpit,
            Action::FakeData,
        ])
    }

    /// Follows the results of the session, before `frame` is searched, and
    /// tells whether a hit in it can add rows.
    fn before(
        &mut self,
        frame: Frame<'_>,
        statement: &Statement<'_>,
        context: &Context<'_>,
    ) -> bool {
        let tag = frame.tag();
        match (from_wire(frame.direction()), tag) {
            (Direction::FromClient, frontend::tag::EXECUTE) => {
                let body = frame.body();
                let all_rows = body
                    .iter()
                    .position(|byte| *byte == 0)
                    .and_then(|end| body.get(end.checked_add(1)?..))
                    .is_some_and(|rest| rest == [0, 0, 0, 0]);
                self.limited |= !all_rows;
                false
            }
            (Direction::FromServer, backend::tag::PARAMETER_DESCRIPTION) => {
                self.describing_statement = true;
                false
            }
            (Direction::FromServer, backend::tag::ROW_DESCRIPTION) => {
                let statement = core::mem::take(&mut self.describing_statement);
                self.rows = (!statement && wants_rows(context.policy))
                    .then(|| FakeRows::describe(frame))
                    .flatten();
                false
            }
            (Direction::FromServer, backend::tag::NO_DATA) => {
                self.describing_statement = false;
                self.rows = None;
                false
            }
            (Direction::FromServer, backend::tag::DATA_ROW) => {
                self.rows.is_some() && !self.limited && statement.single_select()
            }
            _ => false,
        }
    }

    /// Follows the results of the session once `frame` has been searched.
    /// Returns whether made-up rows took the place of `frame`.
    fn after(
        &mut self,
        frame: Frame<'_>,
        raised: &Raised,
        context: &Context<'_>,
        out: &mut Output,
    ) -> bool {
        if from_wire(frame.direction()) != Direction::FromServer {
            return false;
        }
        match frame.tag() {
            backend::tag::DATA_ROW => {
                if let Some(rows) = self.rows.as_mut() {
                    if raised.fake {
                        rows.choose();
                    }
                    rows.observe(frame, !raised.matched);
                }
                false
            }
            backend::tag::COMMAND_COMPLETE => self.rows.take().is_some_and(|rows| {
                rows.is_chosen()
                    && !raised.kill
                    && raised.error.is_none()
                    && rows
                        .finish(
                            context.policy.actions().fake_data.rows,
                            frame,
                            context.policy.matcher(),
                            &mut *self.entropy,
                            &mut out.to_client,
                        )
                        .is_some()
            }),
            backend::tag::READY_FOR_QUERY
            | backend::tag::ERROR_RESPONSE
            | backend::tag::PORTAL_SUSPENDED
            | backend::tag::EMPTY_QUERY_RESPONSE => {
                self.rows = None;
                false
            }
            _ => false,
        }
    }

    /// Tarpits the session, unless it is already. Returns `false` when no
    /// place is free.
    fn tarpit(&mut self, context: &Context<'_>, out: &mut Output) -> bool {
        if self.tarpit.is_some() {
            return true;
        }
        let settings = context.policy.actions().tarpit;
        let Some(tarpit) = Tarpit::start(&self.tarpits, settings) else {
            return false;
        };
        out.effects.push(Effect::Tarpit {
            max_duration: tarpit.max_duration(),
        });
        self.tarpit = Some(tarpit);
        true
    }
}

/// What the hits of one search, or the rules a statement set off, ask of
/// the session.
pub(super) struct Raised {
    /// Whether a hit is answered with `kill`.
    pub(super) kill: bool,
    /// Whether a hit asks for made-up rows.
    fake: bool,
    /// Whether anything was found, exempt or not.
    matched: bool,
    /// A match that could not be reported.
    error: Option<InspectionError>,
}

impl Raised {
    /// Nothing was found.
    const fn nothing() -> Self {
        Self {
            kill: false,
            fake: false,
            matched: false,
            error: None,
        }
    }

    /// What a session does about a statement that set off rules, of which
    /// one is answered with `kill` or none is.
    #[cfg(feature = "rules")]
    pub(super) const fn by_rules(kill: bool) -> Self {
        Self {
            kill,
            ..Self::nothing()
        }
    }

    /// Ends the session if a hit asked for it, and otherwise passes the
    /// message on, or fails if a match could not be reported.
    pub(super) fn respond(
        self,
        client_can_be_told: bool,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        if self.kill {
            actions::kill(
                &context.policy.actions().kill,
                client_can_be_told,
                context.cancel_request,
                out,
            );
            return Ok(Verdict::End);
        }
        self.error.map_or(Ok(Verdict::Forward), Err)
    }
}

/// Where the bytes that are searched come from.
pub(super) struct Place<'a> {
    pub(super) direction: Direction,
    pub(super) name: Option<&'static str>,
    /// Whether a statement can be behind the message. Not so at startup.
    pub(super) in_session: bool,
    /// That statement, as far as the tracker knows it.
    pub(super) statement: &'a Statement<'a>,
    /// Whether made-up rows can be added to the result the message is in.
    pub(super) rows: bool,
    pub(super) context: &'a Context<'a>,
}

/// Whether the policy exempts the session, so that what is found in it is
/// counted and triggers nothing else.
pub(super) fn exempts(context: &Context<'_>) -> bool {
    // Until the database has accepted the login, the user is what the
    // client claims, and a claim exempts nobody.
    let user = if context.authenticated {
        context.db_user
    } else {
        None
    };
    context.policy.is_exempt(user, context.origin.client_ip)
}

/// What a scanner remembers of the hits of its session, and what it needs
/// to report one.
pub(super) struct Ledger {
    digest: Arc<dyn StatementDigest>,
    /// `None` when only `alert` and `kill` are built.
    responder: Option<Responder>,
    /// How often the session has hit each token.
    hits: BTreeMap<TokenId, u64>,
    /// Whether the session has had a hit that was not exempt.
    flagged: bool,
}

impl Ledger {
    /// Counts a hit and tells which hit of its token it is, from 1.
    fn count(&mut self, token_id: &TokenId) -> u64 {
        if let Some(count) = self.hits.get_mut(token_id) {
            *count = count.saturating_add(1);
            return *count;
        }
        if self.hits.len() >= MAX_COUNTED_TOKENS {
            // No room to count it: the strongest answer the policy has
            // for the token.
            return u64::MAX;
        }
        self.hits.insert(token_id.clone(), 1);
        1
    }

    /// An event about the message at `place`.
    pub(super) fn body(&self, kind: EventKind, place: &Place<'_>) -> EventBody {
        let context = place.context;
        let redaction = context.policy.query_redaction();
        let mut body = EventBody::new(kind, context.origin);
        body.direction = Some(place.direction);
        body.message_type = place.name.map(Cow::Borrowed);
        body.db_user = context.db_user.map(str::to_owned);
        body.database = context.database.map(str::to_owned);
        body.application_name = context.application_name.map(str::to_owned);
        body.query = place
            .in_session
            .then(|| place.statement.query(redaction, &*self.digest));
        body.session_flagged = self.flagged;
        body
    }

    /// Reports a statement of a session that is flagged.
    fn activity(&self, place: &Place<'_>, out: &mut Output) {
        if self.flagged {
            let body = self.body(EventKind::SessionActivity, place);
            out.effects.push(Effect::Emit(Box::new(body)));
        }
    }

    /// Raises a hit for each token among `matches`, once.
    ///
    /// A match that cannot be reported does not hide the others, and a
    /// `kill` does not either: every hit is raised before the session
    /// acts on any of them.
    fn raise(
        &mut self,
        matches: impl Iterator<Item = Result<Match, ScanError>>,
        place: &Place<'_>,
        out: &mut Output,
    ) -> Raised {
        let mut seen = BTreeSet::new();
        let mut raised = Raised::nothing();
        for found in matches {
            raised.matched = true;
            let Ok(found) = found else {
                raised.error = Some(InspectionError::new("a message could not be searched"));
                continue;
            };
            if !seen.insert(found.token_index()) {
                continue;
            }
            // The matcher and the policy name a token alike. They are
            // built from the same configuration.
            let Ok(token_id) = TokenId::new(found.token_id().as_str()) else {
                raised.error = Some(InspectionError::new(
                    "a token was found that the policy cannot name",
                ));
                continue;
            };
            let actions = self.hit(token_id, place, out);
            raised.kill |= actions.contains(Action::Kill);
            raised.fake |= actions.contains(Action::FakeData);
        }
        raised
    }

    /// Raises one hit and returns the responses to carry out.
    fn hit(&mut self, token_id: TokenId, place: &Place<'_>, out: &mut Output) -> ActionSet {
        let context = place.context;
        let policy = context.policy;

        if exempts(context) {
            out.effects.push(Effect::TokenHit {
                token_id,
                exempt: true,
                decided: ActionSet::EMPTY,
                actions: ActionSet::EMPTY,
            });
            return ActionSet::EMPTY;
        }

        let number = self.count(&token_id);
        let decided = policy
            .token(&token_id)
            .map_or(ActionSet::ALERT, |token| token.actions_for_hit(number));
        let actions = self.carry_out(decided, place, out);

        let mut body = self.body(EventKind::TokenHit, place);
        body.token_id = Some(token_id.clone());
        body.action_taken = actions;
        self.flagged = true;

        out.effects.push(Effect::TokenHit {
            token_id,
            exempt: false,
            decided,
            actions,
        });
        out.effects.push(Effect::Emit(Box::new(body)));
        actions
    }

    /// The responses to one hit that are carried out, of those the policy
    /// `decided`, and the start of those that begin here: the tarpit.
    ///
    /// This is the one place that turns a decision into responses, for a
    /// honeytoken and for a rule alike.
    fn carry_out(&mut self, decided: ActionSet, place: &Place<'_>, out: &mut Output) -> ActionSet {
        let built = match self.responder {
            Some(_) => Responder::built(),
            None => ActionSet::of(&ALWAYS_BUILT),
        };
        let mut actions = carried_out(decided, built);
        if actions.contains(Action::Tarpit)
            && !self
                .responder
                .as_mut()
                .is_some_and(|responder| responder.tarpit(place.context, out))
        {
            // Every place is taken: the session is killed, not queued.
            let mut killed = ActionSet::of(&[Action::Kill]);
            if actions.contains(Action::Alert) {
                killed.insert(Action::Alert);
            }
            actions = killed;
        }
        if actions.contains(Action::FakeData) && !place.rows {
            // No result here that rows can be added to: `alert` instead.
            actions = without(actions, Action::FakeData);
        }
        actions
    }

    /// Raises the hit of a rule that the statement at `place` set off, and
    /// returns the responses to carry out. `decided` is the response the
    /// rule asks for.
    ///
    /// A rule hit is a hit like that of a honeytoken: an exempt session is
    /// counted and nothing else, the responses are those of
    /// [`Ledger::carry_out`], and the session is flagged from then on. The
    /// event names the rule and no token.
    #[cfg(feature = "rules")]
    pub(super) fn rule_hit(
        &mut self,
        rule_id: RuleId,
        decided: ActionSet,
        place: &Place<'_>,
        out: &mut Output,
    ) -> ActionSet {
        if exempts(place.context) {
            out.effects.push(Effect::RuleHit {
                rule_id,
                exempt: true,
                decided: ActionSet::EMPTY,
                actions: ActionSet::EMPTY,
            });
            return ActionSet::EMPTY;
        }

        let actions = self.carry_out(decided, place, out);

        let mut body = self.body(EventKind::RuleHit, place);
        body.rule_id = Some(rule_id.clone());
        body.action_taken = actions;
        self.flagged = true;

        out.effects.push(Effect::RuleHit {
            rule_id,
            exempt: false,
            decided,
            actions,
        });
        out.effects.push(Effect::Emit(Box::new(body)));
        actions
    }
}

/// The inspector that looks for the honeytokens of the policy in
/// everything a session relays.
///
/// It searches the whole body of every message in both directions, and
/// the startup message, with the matcher of the snapshot in force. A
/// message that arrives in chunks is followed to its end, and the
/// `CopyData` messages of each direction are read as one stream until the
/// COPY ends, so a value split across them is found.
///
/// A hit is counted with [`Effect::TokenHit`] and reported with
/// [`Effect::Emit`], once for each token in a message, unless the policy
/// exempts the session: then it is only counted. The event names the
/// statement the message belongs to, as far as the redaction mode of the
/// policy shows it. The message is passed on, unless a hit is answered
/// with `kill`: then the session ends.
///
/// Each `Query`, `Execute` and `FunctionCall` of the client is counted
/// with [`Effect::QuerySeen`], and reported with a `session_activity`
/// event once the session has had a hit.
pub struct Scanner {
    from_client: Half,
    from_server: Half,
    tracker: Tracker,
    ledger: Ledger,
    #[cfg(feature = "rules")]
    rules: Hook,
}

impl Scanner {
    /// A scanner for one session. `digest` is the hash function behind
    /// the fingerprint of a statement.
    #[must_use]
    pub fn new(digest: Arc<dyn StatementDigest>) -> Self {
        Self::build(digest, None)
    }

    /// A scanner that also carries out `tarpit`, with `responses`.
    #[must_use]
    pub fn with_responses(digest: Arc<dyn StatementDigest>, responses: &Responses) -> Self {
        let responder = Responder {
            entropy: (responses.entropy)(),
            tarpits: Arc::clone(&responses.tarpits),
            tarpit: None,
            rows: None,
            describing_statement: false,
            limited: false,
        };
        Self::build(digest, Some(responder))
    }

    fn build(digest: Arc<dyn StatementDigest>, responder: Option<Responder>) -> Self {
        Self {
            from_client: Half::default(),
            from_server: Half::default(),
            tracker: Tracker::default(),
            ledger: Ledger {
                digest,
                responder,
                hits: BTreeMap::new(),
                flagged: false,
            },
            #[cfg(feature = "rules")]
            rules: Hook::default(),
        }
    }
}

impl fmt::Debug for Scanner {
    /// Prints where the scanner is and nothing it has read.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("client_copy", &self.from_client.announced)
            .field("server_copy", &self.from_server.announced)
            .field("client_chunked", &self.from_client.chunked.is_some())
            .field("server_chunked", &self.from_server.chunked.is_some())
            .field("flagged", &self.ledger.flagged)
            .field("tokens_hit", &self.ledger.hits.len())
            .field(
                "tarpitted",
                &self
                    .ledger
                    .responder
                    .as_ref()
                    .is_some_and(|responder| responder.tarpit.is_some()),
            )
            .field("tracker", &self.tracker)
            .field("awaits_analysis", &self.awaits_analysis())
            .finish()
    }
}

impl Scanner {
    /// Whether a statement of the session waits for its analysis.
    const fn awaits_analysis(&self) -> bool {
        #[cfg(feature = "rules")]
        {
            self.rules.is_waiting()
        }
        #[cfg(not(feature = "rules"))]
        {
            false
        }
    }
}

const fn half_of<'a>(
    from_client: &'a mut Half,
    from_server: &'a mut Half,
    direction: Direction,
) -> &'a mut Half {
    match direction {
        Direction::FromClient => from_client,
        Direction::FromServer => from_server,
    }
}

const fn from_wire(direction: pgsnare_proto::Direction) -> Direction {
    match direction {
        pgsnare_proto::Direction::FromClient => Direction::FromClient,
        pgsnare_proto::Direction::FromServer => Direction::FromServer,
    }
}

const fn is_copy_data(direction: Direction, tag: u8) -> bool {
    match direction {
        Direction::FromClient => tag == frontend::tag::COPY_DATA,
        Direction::FromServer => tag == backend::tag::COPY_DATA,
    }
}

/// Whether a message is one of the client that runs a statement.
fn is_statement(direction: Direction, tag: u8) -> bool {
    direction == Direction::FromClient
        && matches!(
            tag,
            frontend::tag::QUERY | frontend::tag::EXECUTE | frontend::tag::FUNCTION_CALL
        )
}

impl Inspector for Scanner {
    fn startup(
        &mut self,
        message: &StartupMessage<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let place = Place {
            direction: Direction::FromClient,
            name: Some(STARTUP_MESSAGE),
            in_session: false,
            statement: &Statement::Unknown,
            rows: false,
            context,
        };
        let matches = context.policy.matcher().scan(message.as_bytes());
        self.ledger
            .raise(matches, &place, out)
            .respond(true, context, out)
    }

    fn frame(
        &mut self,
        frame: Frame<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let direction = from_wire(frame.direction());
        let tag = frame.tag();
        #[cfg(feature = "rules")]
        if direction == Direction::FromServer {
            self.rules.server(frame);
        }
        let statement = match direction {
            Direction::FromClient => self.tracker.client(frame, context.in_copy),
            Direction::FromServer => self.tracker.server(tag, Some(frame.body())),
        };
        let rows = self
            .ledger
            .responder
            .as_mut()
            .is_some_and(|responder| responder.before(frame, &statement, context));
        let place = Place {
            direction,
            name: message_name(direction, tag),
            in_session: true,
            statement: &statement,
            rows,
            context,
        };
        if is_statement(direction, tag) {
            out.effects.push(Effect::QuerySeen);
            self.ledger.activity(&place, out);
        }
        let raised = if is_copy_data(direction, tag) {
            let half = half_of(&mut self.from_client, &mut self.from_server, direction);
            let mut stream = half.take_copy(context.policy);
            let raised = self
                .ledger
                .raise(stream.scanner.feed(frame.body()), &place, out);
            half.copy = Some(stream);
            raised
        } else {
            let matcher: &Matcher = context.policy.matcher();
            self.ledger.raise(matcher.scan(frame.body()), &place, out)
        };
        let replaced = self
            .ledger
            .responder
            .as_mut()
            .is_some_and(|responder| responder.after(frame, &raised, context, out));
        // A whole message from the server is never inside another one.
        let client_can_be_told = self.from_server.chunked.is_none();
        let verdict = raised.respond(client_can_be_told, context, out)?;
        // The message has been searched. Only now, and only if it would be
        // passed on, do the rules ask about its statement.
        #[cfg(feature = "rules")]
        let verdict = if verdict == Verdict::Forward && direction == Direction::FromClient {
            self.rules
                .client(frame, &place, &self.ledger, client_can_be_told, out)
        } else {
            verdict
        };
        // The made-up rows end with a `CommandComplete` of their own.
        Ok(match verdict {
            Verdict::Forward if replaced => Verdict::Withhold,
            other => other,
        })
    }

    fn stream_start(
        &mut self,
        direction: Direction,
        header: FrameHeader,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let tag = header.tag();
        let name = message_name(direction, tag);
        let statement = match direction {
            Direction::FromClient => self.tracker.client_chunked(tag, context.in_copy),
            Direction::FromServer => self.tracker.server(tag, None),
        };
        let place = Place {
            direction,
            name,
            in_session: true,
            statement: &statement,
            rows: false,
            context,
        };
        if is_statement(direction, tag) {
            out.effects.push(Effect::QuerySeen);
            self.ledger.activity(&place, out);
        }
        // A statement that arrives in parts cannot be held for the rules.
        #[cfg(feature = "rules")]
        let blocked = match direction {
            Direction::FromClient => Hook::client_chunked(tag, &place, &self.ledger, out),
            Direction::FromServer => {
                self.rules.server_chunked(tag);
                false
            }
        };
        let half = half_of(&mut self.from_client, &mut self.from_server, direction);
        let (stream, copy) = if is_copy_data(direction, tag) {
            (half.take_copy(context.policy), Some(half.copies_ended))
        } else {
            (Stream::new(context.policy), None)
        };
        half.chunked = Some(Chunked {
            name,
            stream,
            statement,
            copy,
            #[cfg(feature = "rules")]
            blocked,
        });
        // What is blocked is still searched, part by part, and none of it
        // is passed on.
        #[cfg(feature = "rules")]
        if blocked {
            return Ok(Verdict::Withhold);
        }
        Ok(Verdict::Forward)
    }

    fn stream_chunk(
        &mut self,
        direction: Direction,
        chunk: Chunk<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let half = half_of(&mut self.from_client, &mut self.from_server, direction);
        let Some(chunked) = half.chunked.as_mut() else {
            return Err(InspectionError::new(
                "a part of a message arrived without its beginning",
            ));
        };
        let place = Place {
            direction,
            name: chunked.name,
            in_session: true,
            statement: &chunked.statement,
            rows: false,
            context,
        };
        #[cfg(feature = "rules")]
        let blocked = chunked.blocked;
        let matches = chunked.stream.scanner.feed(chunk.data());
        let raised = self.ledger.raise(matches, &place, out);
        if chunk.is_last()
            && let Some(chunked) = half.chunked.take()
            && chunked.copy == Some(half.copies_ended)
        {
            // The COPY this message belongs to goes on.
            half.copy = Some(chunked.stream);
        }
        // The client has had the first part of a message from the server
        // that this chunk belongs to, or is in the middle of another one.
        let client_can_be_told =
            direction == Direction::FromClient && self.from_server.chunked.is_none();
        // A statement that must not reach the database: the session ends
        // with its last part, or as soon as a part cannot be dealt with,
        // and never goes on without it.
        #[cfg(feature = "rules")]
        if blocked && !raised.kill {
            return Ok(if chunk.is_last() || raised.error.is_some() {
                rules::block(context, client_can_be_told, out)
            } else {
                Verdict::Withhold
            });
        }
        raised.respond(client_can_be_told, context, out)
    }

    fn after_read(&mut self, direction: Direction, to_client: usize, out: &mut Output) {
        let Some(responder) = self.ledger.responder.as_mut() else {
            return;
        };
        if direction == Direction::FromServer
            && to_client > 0
            && let Some(tarpit) = &responder.tarpit
        {
            let delay = tarpit.delay(to_client, &mut *responder.entropy);
            out.effects.push(Effect::Delay(delay));
        }
    }

    fn copy_started(&mut self, direction: Direction) {
        let half = half_of(&mut self.from_client, &mut self.from_server, direction);
        half.announced = true;
        half.pinned = false;
    }

    fn copy_ended(&mut self, direction: Direction) {
        let half = half_of(&mut self.from_client, &mut self.from_server, direction);
        half.announced = false;
        half.pinned = false;
        half.copy = None;
        half.copies_ended = half.copies_ended.wrapping_add(1);
    }

    #[cfg(feature = "rules")]
    fn analysed(
        &mut self,
        id: u64,
        outcome: Result<Arc<Analysis>, ParseFailure>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Option<Verdict>, InspectionError> {
        // A whole message from the server is never inside another one.
        let client_can_be_told = self.from_server.chunked.is_none();
        self.rules.answer(
            id,
            outcome,
            &mut self.ledger,
            context,
            client_can_be_told,
            out,
        )
    }
}
