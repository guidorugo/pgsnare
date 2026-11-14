// SPDX-License-Identifier: Apache-2.0

//! The place where detection attaches to a session.
//!
//! A session shows everything it is about to pass on to its [`Inspector`]
//! and does what the inspector decides. There is one method for each kind
//! of thing a session passes on, and each is called for both directions:
//!
//! | What | Method | When |
//! |---|---|---|
//! | The startup message | [`Inspector::startup`] | Before the database is contacted |
//! | A whole message | [`Inspector::frame`] | When it is complete, and before any byte of it is passed on |
//! | A message too large to hold | [`Inspector::stream_start`], then [`Inspector::stream_chunk`] | As its parts arrive |
//!
//! The messages of the login are not shown: a session passes them to the
//! login strategy and to nobody else.
//!
//! # COPY
//!
//! A value can be split across the `CopyData` messages of one COPY, so a
//! scanner has to follow a COPY from its start to its end.
//! [`Inspector::copy_started`] and [`Inspector::copy_ended`] mark both, for
//! each direction separately, as the server announces them.
//!
//! The marks describe what the server has said and not what the client has
//! already sent. A client that does not wait for the server can send
//! `CopyData` before the COPY is announced, and its last messages can
//! arrive after the server has ended a COPY with an error. Such messages
//! are shown like any other, with [`Context::in_copy`] false.
//!
//! # The session keeps its own state
//!
//! A session updates what it knows from a message before it shows the
//! message, so withholding a message never makes the session lose its
//! place in the protocol.

use core::fmt;

use pgsnare_proto::startup::StartupMessage;
use pgsnare_proto::{Chunk, Frame, FrameHeader};

use crate::policy::PolicySnapshot;
use crate::session::{Direction, Output, SessionOrigin};

/// What a session knows about the message it shows to an [`Inspector`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Context<'a> {
    /// The policy in force for this message.
    pub policy: &'a PolicySnapshot,
    /// Where the session comes from.
    pub origin: &'a SessionOrigin,
    /// The database user the client asked for, once the startup message
    /// has been read.
    pub db_user: Option<&'a str>,
    /// Whether the database has accepted the login. Until then
    /// [`Context::db_user`] is only what the client claims to be.
    pub authenticated: bool,
    /// The database the client asked for.
    pub database: Option<&'a str>,
    /// The application name the client reported, if any.
    pub application_name: Option<&'a str>,
    /// Whether the server has announced a COPY in the direction of the
    /// message that has not ended yet.
    pub in_copy: bool,
    /// The request that cancels the query this session is running, built
    /// from the key the server issued. `None` until the server has sent
    /// the key.
    pub cancel_request: Option<&'a [u8]>,
}

/// What a session does with something it showed to an [`Inspector`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    /// Pass it on unchanged.
    Forward,
    /// Hold it back. The session goes on.
    ///
    /// To send something else in its place, the inspector appends that to
    /// the [`Output`] it was given.
    ///
    /// Holding back a chunk of a message whose earlier parts have been
    /// passed on leaves the receiver with half a message. An inspector
    /// that does so must end the session: see [`Verdict::End`].
    Withhold,
    /// Hold it back, and everything after it in both directions: the
    /// session is over.
    ///
    /// The inspector appends to the [`Output`] what each side should still
    /// receive and the effects that close the connections. The session
    /// produces nothing more.
    End,
}

/// An inspector could not do its work.
///
/// The session then applies the failure policy: it ends, or it goes on as
/// a tunnel without inspection. The reason is a fixed text. It cannot
/// carry anything taken from the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionError {
    reason: &'static str,
}

impl InspectionError {
    /// An error with a fixed reason.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self { reason }
    }

    /// The reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inspection failed: {}", self.reason)
    }
}

impl core::error::Error for InspectionError {}

/// Looks at what one session is about to pass on and decides whether it
/// goes through.
///
/// An inspector belongs to one session and is called in the order the
/// bytes arrived. It does no I/O.
pub trait Inspector: Send {
    /// Called with the startup message of the client, before the session
    /// asks for the connection to the database.
    ///
    /// A session cannot go on without its startup message, so
    /// [`Verdict::Withhold`] ends it like [`Verdict::End`].
    ///
    /// # Errors
    ///
    /// Returns an error when the message could not be inspected. The login
    /// has not happened yet, so the session ends whatever the policy says.
    fn startup(
        &mut self,
        message: &StartupMessage<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        let _ = (message, context, out);
        Ok(Verdict::Forward)
    }

    /// Called with a whole message, from either side, before any byte of
    /// it is passed on. [`Frame::direction`] tells which side sent it.
    ///
    /// # Errors
    ///
    /// Returns an error when the message could not be inspected.
    fn frame(
        &mut self,
        frame: Frame<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError>;

    /// Called with the header of a message that is too large to hold. Its
    /// body follows through [`Inspector::stream_chunk`].
    ///
    /// When the header is held back, the session passes on none of the
    /// body either, whatever is decided for the chunks.
    ///
    /// # Errors
    ///
    /// Returns an error when the message could not be inspected.
    fn stream_start(
        &mut self,
        direction: Direction,
        header: FrameHeader,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError>;

    /// Called with the next part of the body of a message that is too
    /// large to hold. [`Chunk::is_last`] tells when the message is
    /// complete.
    ///
    /// # Errors
    ///
    /// Returns an error when the chunk could not be inspected.
    fn stream_chunk(
        &mut self,
        direction: Direction,
        chunk: Chunk<'_>,
        context: &Context<'_>,
        out: &mut Output,
    ) -> Result<Verdict, InspectionError>;

    /// Called when the server has announced a COPY in which `direction`
    /// carries the data.
    fn copy_started(&mut self, direction: Direction) {
        let _ = direction;
    }

    /// Called when the COPY in `direction` has ended, whichever side ended
    /// it and however.
    fn copy_ended(&mut self, direction: Direction) {
        let _ = direction;
    }
}

/// The inspector of a session that is only relayed: everything goes
/// through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PassThrough;

impl Inspector for PassThrough {
    fn frame(
        &mut self,
        _frame: Frame<'_>,
        _context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        Ok(Verdict::Forward)
    }

    fn stream_start(
        &mut self,
        _direction: Direction,
        _header: FrameHeader,
        _context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        Ok(Verdict::Forward)
    }

    fn stream_chunk(
        &mut self,
        _direction: Direction,
        _chunk: Chunk<'_>,
        _context: &Context<'_>,
        _out: &mut Output,
    ) -> Result<Verdict, InspectionError> {
        Ok(Verdict::Forward)
    }
}

/// Makes the inspector of each new session.
///
/// Every function or closure that takes the origin of a session and returns
/// an inspector is a factory.
pub trait InspectorFactory: Send + Sync + 'static {
    /// The inspector for a session that has just been accepted.
    fn inspector(&self, origin: &SessionOrigin) -> Box<dyn Inspector>;
}

impl<F> InspectorFactory for F
where
    F: Fn(&SessionOrigin) -> Box<dyn Inspector> + Send + Sync + 'static,
{
    fn inspector(&self, origin: &SessionOrigin) -> Box<dyn Inspector> {
        self(origin)
    }
}
