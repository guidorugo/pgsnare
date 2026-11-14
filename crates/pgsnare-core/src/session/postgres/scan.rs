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
//! session has hit it. The one response that is carried out so far is
//! `alert`, and the message is passed on.
//!
//! # The statement of an event
//!
//! A tracker (the `track` module) tells which statement a message belongs
//! to. An event shows of it what [`Query::from_statement`] gives under the
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

use crate::detect::{Match, Matcher, ScanError, StreamScanner};
use crate::event::{EventBody, EventKind, Query, StatementDigest};
use crate::policy::{ActionSet, PolicySnapshot, TokenId};
use crate::session::{Direction, Effect, Output};

use super::names::{STARTUP_MESSAGE, message_name};
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

/// The responses that are carried out, of those the policy decided.
///
/// Only `alert` is built: whatever was decided, the hit is reported and
/// the message is passed on.
const fn carried_out(_decided: ActionSet) -> ActionSet {
    ActionSet::ALERT
}

/// Where the bytes that are searched come from.
struct Place<'a> {
    direction: Direction,
    name: Option<&'static str>,
    /// Whether a statement can be behind the message. Not so at startup.
    in_session: bool,
    /// The text of that statement, when the tracker knows it.
    statement: Option<&'a [u8]>,
    context: &'a Context<'a>,
}

/// What a scanner remembers of the hits of its session, and what it needs
/// to report one.
struct Ledger {
    digest: Arc<dyn StatementDigest>,
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
    fn body(&self, kind: EventKind, place: &Place<'_>) -> EventBody {
        let context = place.context;
        let redaction = context.policy.query_redaction();
        let mut body = EventBody::new(kind, context.origin);
        body.direction = Some(place.direction);
        body.message_type = place.name.map(Cow::Borrowed);
        body.db_user = context.db_user.map(str::to_owned);
        body.database = context.database.map(str::to_owned);
        body.application_name = context.application_name.map(str::to_owned);
        body.query = place.in_session.then(|| match place.statement {
            Some(text) => Query::from_statement(text, redaction, &*self.digest),
            None => Query::unknown(redaction),
        });
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
    /// A match that cannot be reported does not hide the others: the error
    /// is returned after every hit has been raised.
    fn raise(
        &mut self,
        matches: impl Iterator<Item = Result<Match, ScanError>>,
        place: &Place<'_>,
        out: &mut Output,
    ) -> Result<(), InspectionError> {
        let mut seen = BTreeSet::new();
        let mut result = Ok(());
        for found in matches {
            let Ok(found) = found else {
                result = Err(InspectionError::new("a message could not be searched"));
                continue;
            };
            if !seen.insert(found.token_index()) {
                continue;
            }
            // The matcher and the policy name a token alike. They are
            // built from the same configuration.
            let Ok(token_id) = TokenId::new(found.token_id().as_str()) else {
                result = Err(InspectionError::new(
                    "a token was found that the policy cannot name",
                ));
                continue;
            };
            self.hit(token_id, place, out);
        }
        result
    }

    fn hit(&mut self, token_id: TokenId, place: &Place<'_>, out: &mut Output) {
        let context = place.context;
        let policy = context.policy;

        // Until the database has accepted the login, the user is what the
        // client claims, and a claim exempts nobody.
        let user = if context.authenticated {
            context.db_user
        } else {
            None
        };
        if policy.is_exempt(user, context.origin.client_ip) {
            out.effects.push(Effect::TokenHit {
                token_id,
                exempt: true,
                decided: ActionSet::EMPTY,
                actions: ActionSet::EMPTY,
            });
            return;
        }

        let number = self.count(&token_id);
        let decided = policy
            .token(&token_id)
            .map_or(ActionSet::ALERT, |token| token.actions_for_hit(number));
        let actions = carried_out(decided);

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
/// policy shows it. The message is passed on.
///
/// Each `Query`, `Execute` and `FunctionCall` of the client is counted
/// with [`Effect::QuerySeen`], and reported with a `session_activity`
/// event once the session has had a hit.
pub struct Scanner {
    from_client: Half,
    from_server: Half,
    tracker: Tracker,
    ledger: Ledger,
}

impl Scanner {
    /// A scanner for one session. `digest` is the hash function behind
    /// the fingerprint of a statement.
    #[must_use]
    pub fn new(digest: Arc<dyn StatementDigest>) -> Self {
        Self {
            from_client: Half::default(),
            from_server: Half::default(),
            tracker: Tracker::default(),
            ledger: Ledger {
                digest,
                hits: BTreeMap::new(),
                flagged: false,
            },
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
            .field("tracker", &self.tracker)
            .finish()
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
            statement: None,
            context,
        };
        let matches = context.policy.matcher().scan(message.as_bytes());
        self.ledger.raise(matches, &place, out)?;
        Ok(Verdict::Forward)
    }

    fn frame(
        &mut self,
        frame: Frame<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let direction = from_wire(frame.direction());
        let tag = frame.tag();
        let statement = match direction {
            Direction::FromClient => self.tracker.client(frame, context.in_copy),
            Direction::FromServer => self.tracker.server(tag, Some(frame.body())),
        };
        let place = Place {
            direction,
            name: message_name(direction, tag),
            in_session: true,
            statement: statement.bytes(),
            context,
        };
        if is_statement(direction, tag) {
            out.effects.push(Effect::QuerySeen);
            self.ledger.activity(&place, out);
        }
        if is_copy_data(direction, tag) {
            let half = half_of(&mut self.from_client, &mut self.from_server, direction);
            let mut stream = half.take_copy(context.policy);
            let result = self
                .ledger
                .raise(stream.scanner.feed(frame.body()), &place, out);
            half.copy = Some(stream);
            result?;
        } else {
            let matcher: &Matcher = context.policy.matcher();
            self.ledger.raise(matcher.scan(frame.body()), &place, out)?;
        }
        Ok(Verdict::Forward)
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
        if is_statement(direction, tag) {
            out.effects.push(Effect::QuerySeen);
            let place = Place {
                direction,
                name,
                in_session: true,
                statement: statement.bytes(),
                context,
            };
            self.ledger.activity(&place, out);
        }
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
        });
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
            statement: chunked.statement.bytes(),
            context,
        };
        let matches = chunked.stream.scanner.feed(chunk.data());
        let result = self.ledger.raise(matches, &place, out);
        if chunk.is_last()
            && let Some(chunked) = half.chunked.take()
            && chunked.copy == Some(half.copies_ended)
        {
            // The COPY this message belongs to goes on.
            half.copy = Some(chunked.stream);
        }
        result?;
        Ok(Verdict::Forward)
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
}
