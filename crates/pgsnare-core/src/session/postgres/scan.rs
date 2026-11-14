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
//! The response to a hit is `alert`, and the message is passed on.
//!
//! # Statements
//!
//! Each `Query` and each `Execute` of a client is counted as a statement,
//! with [`Effect::QuerySeen`], when the session sees it.
//!
//! # Bounds
//!
//! A scanner keeps, for each direction, at most two stream scanners, each
//! with fewer bytes than the longest pattern is long. A search takes time
//! in proportion to the bytes searched. The hits of one search are at most
//! one for each token of the policy.

use core::fmt;
use std::borrow::Cow;
use std::collections::BTreeSet;

use pgsnare_proto::startup::StartupMessage;
use pgsnare_proto::{Chunk, Frame, FrameHeader, backend, frontend};

use crate::detect::{Match, Matcher, ScanError, StreamScanner};
use crate::event::{EventBody, EventKind, Query};
use crate::policy::{ActionSet, PolicySnapshot, TokenId};
use crate::session::{Direction, Effect, Output};

use super::names::{STARTUP_MESSAGE, message_name};
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
/// [`Effect::Emit`], once for each token in a message. The message is
/// passed on. Each `Query` and `Execute` of the client is counted with
/// [`Effect::QuerySeen`].
#[derive(Default)]
pub struct Scanner {
    from_client: Half,
    from_server: Half,
}

impl Scanner {
    /// A scanner for one session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn half_mut(&mut self, direction: Direction) -> &mut Half {
        match direction {
            Direction::FromClient => &mut self.from_client,
            Direction::FromServer => &mut self.from_server,
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
            .finish()
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

/// Counts a message of the client that runs a statement.
fn count_statement(direction: Direction, tag: u8, out: &mut Output) {
    if direction == Direction::FromClient
        && matches!(tag, frontend::tag::QUERY | frontend::tag::EXECUTE)
    {
        out.effects.push(Effect::QuerySeen);
    }
}

/// Where the bytes that are searched come from.
struct Place<'a> {
    direction: Direction,
    name: Option<&'static str>,
    /// Whether a statement can be behind the message. Not so at startup.
    in_session: bool,
    context: &'a Context<'a>,
}

/// Raises a hit for each token among `matches`, once.
///
/// A match that cannot be reported does not hide the others: the error is
/// returned after every hit has been raised.
fn raise(
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
        // The matcher and the policy name a token alike. They are built
        // from the same configuration.
        let Ok(token_id) = TokenId::new(found.token_id().as_str()) else {
            result = Err(InspectionError::new(
                "a token was found that the policy cannot name",
            ));
            continue;
        };
        hit(token_id, place, out);
    }
    result
}

fn hit(token_id: TokenId, place: &Place<'_>, out: &mut Output) {
    let context = place.context;
    // Every response but `alert` is still to come.
    let actions = ActionSet::ALERT;

    let mut body = EventBody::new(EventKind::TokenHit, context.origin);
    body.token_id = Some(token_id.clone());
    body.action_taken = actions;
    body.direction = Some(place.direction);
    body.message_type = place.name.map(Cow::Borrowed);
    body.db_user = context.db_user.map(str::to_owned);
    body.database = context.database.map(str::to_owned);
    body.application_name = context.application_name.map(str::to_owned);
    // Which statement a message belongs to is not followed yet.
    body.query = place
        .in_session
        .then(|| Query::unknown(context.policy.query_redaction()));

    out.effects.push(Effect::TokenHit {
        token_id,
        exempt: false,
        actions,
    });
    out.effects.push(Effect::Emit(Box::new(body)));
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
            context,
        };
        let matches = context.policy.matcher().scan(message.as_bytes());
        raise(matches, &place, out)?;
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
        count_statement(direction, tag, out);
        let place = Place {
            direction,
            name: message_name(direction, tag),
            in_session: true,
            context,
        };
        if is_copy_data(direction, tag) {
            let half = self.half_mut(direction);
            let mut stream = half.take_copy(context.policy);
            let result = raise(stream.scanner.feed(frame.body()), &place, out);
            half.copy = Some(stream);
            result?;
        } else {
            let matcher: &Matcher = context.policy.matcher();
            raise(matcher.scan(frame.body()), &place, out)?;
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
        count_statement(direction, tag, out);
        let half = self.half_mut(direction);
        let (stream, copy) = if is_copy_data(direction, tag) {
            (half.take_copy(context.policy), Some(half.copies_ended))
        } else {
            (Stream::new(context.policy), None)
        };
        half.chunked = Some(Chunked {
            name: message_name(direction, tag),
            stream,
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
        let half = self.half_mut(direction);
        let Some(chunked) = half.chunked.as_mut() else {
            return Err(InspectionError::new(
                "a part of a message arrived without its beginning",
            ));
        };
        let place = Place {
            direction,
            name: chunked.name,
            in_session: true,
            context,
        };
        let result = raise(chunked.stream.scanner.feed(chunk.data()), &place, out);
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
        let half = self.half_mut(direction);
        half.announced = true;
        half.pinned = false;
    }

    fn copy_ended(&mut self, direction: Direction) {
        let half = self.half_mut(direction);
        half.announced = false;
        half.pinned = false;
        half.copy = None;
        half.copies_ended = half.copies_ended.wrapping_add(1);
    }
}
