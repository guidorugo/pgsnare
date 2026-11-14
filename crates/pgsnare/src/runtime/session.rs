// SPDX-License-Identifier: Apache-2.0

//! Driving one session: the sockets, the timers and the effects.
//!
//! The session logic decides and this module acts. It reads from both
//! connections, hands what it read to the session logic, writes what the
//! session logic queued, and carries out its effects.
//!
//! # One task, two directions
//!
//! A session is one task. Its two directions are independent all the same:
//! each is read only while there is room for what reading it produces, and
//! each is written whenever its connection takes bytes. A client that
//! stops reading therefore slows down the database and nothing else, and
//! the other way round, exactly as without a proxy in between.
//!
//! # Bounded memory
//!
//! - A direction is not read while more than [`HIGH_WATER`] bytes wait to
//!   be written to the other side. What waits is therefore bounded by that,
//!   plus one read, plus one message that the session logic held until it
//!   was complete.
//! - The buffers a session reads into are small while it is idle, grow
//!   when a read fills them, and shrink again when the session has been
//!   quiet for [`IDLE_AFTER`].
//!
//! # Nothing waits for ever
//!
//! - Until the database has accepted the login, the whole session has to
//!   finish within the login timeout of its listener.
//! - Once one connection is being closed, the session has [`LINGER`] to
//!   send what is still queued. A peer that does not read cannot hold it
//!   open.
//!
//! # What the proxy adds
//!
//! Once the database has accepted the login, the session measures how long
//! bytes stay in the proxy: from the moment it read something from one
//! connection to the moment everything that came of it has been written to
//! the other. That time goes into the histogram of added latency of the
//! [`Status`]. It includes what the session logic takes and the wait for a
//! peer that is slow to read. It leaves out what is held back on purpose:
//! bytes for a client that the session logic told the runtime to delay.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::extension::{ProtocolSession, SessionError};
use pgsnare_core::policy::PolicySource;
use pgsnare_core::session::{Direction, Effect, Leg, Output, Report, SessionOrigin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, sleep_until};

use crate::builder::Proxy;
use crate::tls::{self, ClientLeg};

use super::backend::{Connected, Connector};
use super::events::{Events, new_session_id};
use super::status::Status;
use super::stream::{BackendStream, ClientStream, Rewind};

/// A direction is not read while this many bytes wait to be written to the
/// other side.
pub(crate) const HIGH_WATER: usize = 256 * 1024;

/// The size of a read buffer of a session that is quiet.
const SMALL_READ: usize = 1024;

/// The size of a read buffer of a session that is busy.
const LARGE_READ: usize = 64 * 1024;

/// How long a session must be quiet before it gives back its buffers.
pub(crate) const IDLE_AFTER: Duration = Duration::from_secs(2);

/// How long a session that is closing has to send what is still queued.
pub(crate) const LINGER: Duration = Duration::from_secs(5);

/// How long forwarding a cancel request may take.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes that have been written are removed from the front of a queue once
/// there are this many of them.
const COMPACT_AFTER: usize = 64 * 1024;

/// How the proxy is doing, as its sessions and listeners need to know it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Stage {
    /// Accepting clients.
    Running,
    /// Asked to stop: no new clients, open sessions may finish.
    Draining,
    /// Out of time: open sessions are closed.
    Stopping,
}

/// Everything the sessions of one listener share.
pub(crate) struct ListenerContext {
    pub(crate) name: String,
    pub(crate) proxy: Proxy,
    pub(crate) policy: Arc<dyn PolicySource>,
    pub(crate) client_tls: ClientLeg,
    pub(crate) connector: Connector,
    pub(crate) alpn: Option<&'static [u8]>,
    pub(crate) login_timeout: Duration,
    pub(crate) status: Arc<Status>,
    pub(crate) events: Arc<Events>,
}

/// A buffer to read into, small while quiet and large while busy. What it
/// holds at any moment is part of what the runtime reports about itself.
struct ReadBuffer {
    bytes: Vec<u8>,
    status: Arc<Status>,
}

impl ReadBuffer {
    fn new(status: &Arc<Status>) -> Self {
        status.read_buffer_resized(0, SMALL_READ);
        Self {
            bytes: vec![0; SMALL_READ],
            status: Arc::clone(status),
        }
    }

    fn resize(&mut self, size: usize) {
        self.status.read_buffer_resized(self.bytes.len(), size);
        self.bytes = vec![0; size];
    }

    /// After a read of `count` bytes: a read that filled the buffer is
    /// followed by a larger one.
    fn after_read(&mut self, count: usize) {
        if count >= self.bytes.len() && self.bytes.len() < LARGE_READ {
            self.resize(LARGE_READ);
        }
    }

    fn shrink(&mut self) {
        if self.bytes.len() > SMALL_READ {
            self.resize(SMALL_READ);
        }
    }
}

impl Drop for ReadBuffer {
    fn drop(&mut self) {
        self.status.read_buffer_resized(self.bytes.len(), 0);
    }
}

async fn read_some<R: AsyncRead + Unpin>(
    reader: Option<&mut R>,
    buffer: &mut [u8],
) -> io::Result<usize> {
    match reader {
        Some(reader) => reader.read(buffer).await,
        None => std::future::pending().await,
    }
}

async fn write_some<W: AsyncWrite + Unpin>(
    writer: Option<&mut W>,
    bytes: &[u8],
) -> io::Result<usize> {
    match writer {
        Some(writer) => writer.write(bytes).await,
        None => std::future::pending().await,
    }
}

async fn flush_some<W: AsyncWrite + Unpin>(writer: Option<&mut W>) -> io::Result<()> {
    match writer {
        Some(writer) => writer.flush().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_some(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Why something a session waited for did not happen.
enum Cut {
    /// The time allowed for the login ran out.
    Deadline,
    /// The proxy is stopping.
    Stopping,
}

/// Waits for `work`, but no longer than until `deadline` and not beyond
/// the moment the proxy stops.
async fn bounded<T>(
    deadline: Option<Instant>,
    stage: &mut watch::Receiver<Stage>,
    work: impl Future<Output = T>,
) -> Result<T, Cut> {
    tokio::pin!(work);
    loop {
        tokio::select! {
            done = &mut work => return Ok(done),
            () = sleep_until_some(deadline) => return Err(Cut::Deadline),
            changed = stage.changed() => {
                if changed.is_err() || *stage.borrow() == Stage::Stopping {
                    return Err(Cut::Stopping);
                }
            }
        }
    }
}

type Halves<S> = (ReadHalf<S>, WriteHalf<S>);

/// One session and everything the runtime holds for it.
struct Driver {
    context: Arc<ListenerContext>,
    peer: SocketAddr,
    session: Box<dyn ProtocolSession>,
    stage: watch::Receiver<Stage>,
    /// What the session logic queued. `client_sent` and `backend_sent`
    /// count how much of each queue has been written already.
    out: Output,
    client_sent: usize,
    backend_sent: usize,

    client: Option<Halves<ClientStream>>,
    backend: Option<Halves<BackendStream>>,
    client_is_tls: bool,
    backend_is_tls: bool,
    /// Whether bytes were written that the connection may still hold.
    client_unflushed: bool,
    backend_unflushed: bool,
    /// Whether the connection is closed once its queue has been written.
    client_closing: bool,
    backend_closing: bool,

    client_buffer: ReadBuffer,
    backend_buffer: ReadBuffer,

    logged_in: bool,
    login_deadline: Instant,
    /// Nothing is written to the client before this moment.
    hold_client_until: Option<Instant>,
    /// When the oldest bytes were read whose outcome has not been written
    /// to the client in full, and the same for the database.
    to_client_since: Option<Instant>,
    to_backend_since: Option<Instant>,
    /// The session ends at this moment at the latest.
    linger_until: Option<Instant>,
    /// Set when the session is to end at once.
    over: bool,
    told_to_stop: bool,
}

/// Runs one session from the accepted connection to its end.
pub(crate) async fn run(
    context: Arc<ListenerContext>,
    stream: TcpStream,
    peer: SocketAddr,
    stage: watch::Receiver<Stage>,
) {
    let origin = SessionOrigin::new(new_session_id(), peer.ip(), peer.port(), false)
        .with_client_tls_policy(context.client_tls.policy());
    let session = context.proxy.start_session(origin);
    let login_deadline = Instant::now() + context.login_timeout;
    let (client_buffer, backend_buffer) = (
        ReadBuffer::new(&context.status),
        ReadBuffer::new(&context.status),
    );
    let mut driver = Driver {
        context,
        peer,
        session,
        stage,
        out: Output::new(),
        client_sent: 0,
        backend_sent: 0,
        client: Some(tokio::io::split(ClientStream::Plain(stream))),
        backend: None,
        client_is_tls: false,
        backend_is_tls: false,
        client_unflushed: false,
        backend_unflushed: false,
        client_closing: false,
        backend_closing: false,
        client_buffer,
        backend_buffer,
        logged_in: false,
        login_deadline,
        hold_client_until: None,
        to_client_since: None,
        to_backend_since: None,
        linger_until: None,
        over: false,
        told_to_stop: false,
    };
    driver.drive().await;
}

impl Driver {
    async fn drive(&mut self) {
        let idle = sleep(IDLE_AFTER);
        tokio::pin!(idle);
        // Whether anything happened since the idle timer was last set, and
        // whether the buffers have been given back since.
        let mut active = false;
        let mut shrunk = false;

        // The proxy may have been told to stop before this task first ran.
        if *self.stage.borrow() == Stage::Stopping {
            self.stop().await;
        }

        loop {
            self.finish_closing().await;
            if self.over || (self.client.is_none() && self.backend.is_none()) {
                break;
            }

            let to_client = self.out.to_client.len().saturating_sub(self.client_sent);
            let to_backend = self.out.to_server.len().saturating_sub(self.backend_sent);
            let now = Instant::now();
            let client_held = self.hold_client_until.is_some_and(|until| until > now);
            if client_held {
                // Held back on purpose: not time the proxy adds.
                self.to_client_since = None;
            }
            let login_deadline = (!self.logged_in).then_some(self.login_deadline);

            let (client_reader, client_writer) = match &mut self.client {
                Some((reader, writer)) => (Some(reader), Some(writer)),
                None => (None, None),
            };
            let (backend_reader, backend_writer) = match &mut self.backend {
                Some((reader, writer)) => (Some(reader), Some(writer)),
                None => (None, None),
            };
            // A connection that is being closed is no longer read.
            let client_reader = client_reader.filter(|_| !self.client_closing);
            let backend_reader = backend_reader.filter(|_| !self.backend_closing);
            // Reading produces bytes for the other side, so a direction is
            // read only while the other side keeps up.
            let read_client = client_reader.is_some() && to_backend < HIGH_WATER;
            let read_backend = backend_reader.is_some() && to_client < HIGH_WATER;
            let (flush_client, flush_backend) = (
                to_client == 0 && self.client_unflushed,
                to_backend == 0 && self.backend_unflushed,
            );
            // One writer serves either the write or the flush of a
            // connection, whichever is due.
            let (client_write, client_flush) = if to_client > 0 {
                (client_writer, None)
            } else {
                (None, client_writer)
            };
            let (backend_write, backend_flush) = if to_backend > 0 {
                (backend_writer, None)
            } else {
                (None, backend_writer)
            };
            let client_queue = self
                .out
                .to_client
                .get(self.client_sent..)
                .unwrap_or_default();
            let backend_queue = self
                .out
                .to_server
                .get(self.backend_sent..)
                .unwrap_or_default();

            tokio::select! {
                changed = self.stage.changed() => {
                    if changed.is_err() || *self.stage.borrow() == Stage::Stopping {
                        self.stop().await;
                    }
                }
                () = sleep_until_some(login_deadline) => {
                    self.context.status.login_timed_out();
                    tracing::info!(
                        listener = %self.context.name,
                        client = %self.peer,
                        "a client did not log in within the time allowed"
                    );
                    self.over = true;
                }
                () = sleep_until_some(self.linger_until) => {
                    self.over = true;
                }
                () = sleep_until_some(self.hold_client_until), if client_held => {
                    self.hold_client_until = None;
                }
                () = &mut idle, if !shrunk => {
                    if active {
                        active = false;
                        idle.as_mut().reset(Instant::now() + IDLE_AFTER);
                    } else {
                        self.release_buffers();
                        shrunk = true;
                    }
                }
                written = write_some(client_write, client_queue), if to_client > 0 && !client_held => {
                    active = true;
                    match written {
                        Ok(count) if count > 0 => {
                            self.client_sent = self.client_sent.saturating_add(count);
                            self.client_unflushed = self.client_is_tls;
                            self.compact();
                            self.note_written(Leg::Client);
                        }
                        _ => self.drop_client(),
                    }
                }
                written = write_some(backend_write, backend_queue), if to_backend > 0 => {
                    active = true;
                    match written {
                        Ok(count) if count > 0 => {
                            self.backend_sent = self.backend_sent.saturating_add(count);
                            self.backend_unflushed = self.backend_is_tls;
                            self.compact();
                            self.note_written(Leg::Backend);
                        }
                        _ => self.drop_backend(),
                    }
                }
                flushed = flush_some(client_flush), if flush_client => {
                    match flushed {
                        Ok(()) => {
                            self.client_unflushed = false;
                            self.note_written(Leg::Client);
                        }
                        Err(_) => self.drop_client(),
                    }
                }
                flushed = flush_some(backend_flush), if flush_backend => {
                    match flushed {
                        Ok(()) => {
                            self.backend_unflushed = false;
                            self.note_written(Leg::Backend);
                        }
                        Err(_) => self.drop_backend(),
                    }
                }
                read = read_some(client_reader, &mut self.client_buffer.bytes), if read_client => {
                    active = true;
                    match read {
                        Ok(count) if count > 0 => {
                            let read_at = Instant::now();
                            self.context.status.read_from_client(count);
                            self.step(Direction::FromClient, count).await;
                            self.client_buffer.after_read(count);
                            self.note_read(Direction::FromClient, read_at);
                        }
                        // The client has gone, cleanly or not.
                        _ => self.drop_client(),
                    }
                }
                read = read_some(backend_reader, &mut self.backend_buffer.bytes), if read_backend => {
                    active = true;
                    match read {
                        Ok(count) if count > 0 => {
                            let read_at = Instant::now();
                            self.context.status.read_from_server(count);
                            self.step(Direction::FromServer, count).await;
                            self.backend_buffer.after_read(count);
                            self.note_read(Direction::FromServer, read_at);
                        }
                        _ => self.drop_backend(),
                    }
                }
            }

            if active && shrunk {
                shrunk = false;
                idle.as_mut().reset(Instant::now() + IDLE_AFTER);
            }
        }
    }

    /// Hands the session logic what was just read from one side and
    /// carries out what it asks for.
    async fn step(&mut self, from: Direction, count: usize) {
        let policy = self.context.policy.snapshot();
        let buffer = match from {
            Direction::FromClient => &self.client_buffer,
            Direction::FromServer => &self.backend_buffer,
        };
        let input = buffer.bytes.get(..count).unwrap_or_default();
        let result = self.session.on_bytes(from, input, &policy, &mut self.out);
        self.after(result).await;
    }

    /// Starts the clock for what a read left to be written to the other
    /// connection, unless a clock for that connection is running already:
    /// what is measured is the wait of the oldest bytes.
    fn note_read(&mut self, from: Direction, read_at: Instant) {
        // The login waits for the database, which is not time the proxy
        // adds.
        if !self.logged_in {
            return;
        }
        match from {
            Direction::FromClient => {
                if self.to_backend_since.is_none() && self.out.to_server.len() > self.backend_sent {
                    self.to_backend_since = Some(read_at);
                }
            }
            Direction::FromServer => {
                if self.to_client_since.is_none()
                    && self.hold_client_until.is_none()
                    && self.out.to_client.len() > self.client_sent
                {
                    self.to_client_since = Some(read_at);
                }
            }
        }
    }

    /// Stops the clock of a connection once everything queued for it has
    /// been written, and notes how long that took.
    fn note_written(&mut self, leg: Leg) {
        let (since, queued, sent, unflushed) = match leg {
            Leg::Client => (
                &mut self.to_client_since,
                self.out.to_client.len(),
                self.client_sent,
                self.client_unflushed,
            ),
            Leg::Backend => (
                &mut self.to_backend_since,
                self.out.to_server.len(),
                self.backend_sent,
                self.backend_unflushed,
            ),
        };
        if sent >= queued
            && !unflushed
            && let Some(read_at) = since.take()
        {
            self.context.status.latency_added(read_at.elapsed());
        }
    }

    fn report(&mut self, report: Report) {
        let policy = self.context.policy.snapshot();
        let result = self.session.on_report(report, &policy, &mut self.out);
        self.settle(result);
    }

    /// What follows every call into the session logic.
    async fn after(&mut self, result: Result<(), SessionError>) {
        self.settle(result);
        self.carry_out().await;
    }

    /// A session that cannot go on is closed once what it queued has been
    /// sent.
    fn settle(&mut self, result: Result<(), SessionError>) {
        if let Err(error) = result {
            self.context.status.session_failed();
            tracing::warn!(
                listener = %self.context.name,
                client = %self.peer,
                reason = error.reason(),
                "a session was ended because its traffic could not be followed"
            );
            self.close_after_flush(Leg::Client);
            self.close_after_flush(Leg::Backend);
        }
    }

    /// Carries out the effects the session logic queued, in order, and the
    /// effects of the reports that leads to.
    async fn carry_out(&mut self) {
        let mut queue: VecDeque<Effect> = mem::take(&mut self.out.effects).into();
        while let Some(effect) = queue.pop_front() {
            if self.over {
                return;
            }
            match effect {
                Effect::Close(leg) => self.close_after_flush(leg),
                Effect::Emit(body) => self.context.events.submit(body),
                Effect::QuerySeen => self.context.status.query_seen(),
                Effect::TokenHit {
                    token_id,
                    exempt,
                    actions,
                } => {
                    self.context.status.token_hit(&token_id, exempt);
                    self.context.status.actions_taken(actions);
                }
                Effect::Delay(delay) => {
                    let until = Instant::now() + delay;
                    self.hold_client_until =
                        Some(self.hold_client_until.map_or(until, |held| held.max(until)));
                }
                Effect::LoginFinished => {
                    if !self.logged_in {
                        self.logged_in = true;
                        self.context.status.login_finished();
                    }
                }
                Effect::Cancel { request } => self.cancel(&request).await,
                Effect::AcceptTls {
                    handshake,
                    alpn_required,
                } => self.accept_tls(handshake, alpn_required).await,
                Effect::ConnectBackend => self.connect_backend().await,
                // An effect this runtime does not know cannot be carried
                // out, and a session must not go on as if it had been.
                _ => {
                    tracing::error!(
                        listener = %self.context.name,
                        "a session asked for something this runtime cannot do"
                    );
                    self.over = true;
                }
            }
            queue.extend(mem::take(&mut self.out.effects));
        }
    }

    fn deadline(&self) -> Option<Instant> {
        (!self.logged_in).then_some(self.login_deadline)
    }

    /// Notes why something the session waited for was cut short.
    fn cut(&mut self, cut: &Cut) {
        if matches!(cut, Cut::Deadline) {
            self.context.status.login_timed_out();
            tracing::info!(
                listener = %self.context.name,
                client = %self.peer,
                "a client did not log in within the time allowed"
            );
        }
        self.over = true;
    }

    /// Sends a cancel request to the database on a connection of its own.
    async fn cancel(&mut self, request: &[u8]) {
        let context = Arc::clone(&self.context);
        let work = tokio::time::timeout(CANCEL_TIMEOUT, context.connector.cancel(request));
        match bounded(None, &mut self.stage, work).await {
            Ok(Ok(Ok(()))) => self.context.status.cancel_forwarded(),
            Ok(Ok(Err(error))) => {
                self.context.status.backend_failed();
                tracing::warn!(
                    listener = %self.context.name,
                    client = %self.peer,
                    reason = error.0,
                    "a cancel request could not be passed on to the database"
                );
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    listener = %self.context.name,
                    client = %self.peer,
                    "the database did not close the connection of a cancel request in time"
                );
            }
            Err(cut) => self.cut(&cut),
        }
    }

    /// Runs the TLS handshake with the client.
    async fn accept_tls(&mut self, handshake: Vec<u8>, alpn_required: bool) {
        let context = Arc::clone(&self.context);
        let Some(acceptor) = context.client_tls.acceptor() else {
            tracing::error!(
                listener = %context.name,
                "a session asked for TLS on a listener that has none"
            );
            self.over = true;
            return;
        };

        // The answer to the client's request goes out before the
        // handshake, in the clear.
        if !self.flush_client().await {
            self.over = true;
            return;
        }
        let Some((reader, writer)) = self.client.take() else {
            self.over = true;
            return;
        };
        let ClientStream::Plain(stream) = reader.unsplit(writer) else {
            self.over = true;
            return;
        };

        let accept = acceptor.accept(Rewind::new(stream, handshake));
        let stream = match bounded(self.deadline(), &mut self.stage, accept).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::info!(
                    listener = %context.name,
                    client = %self.peer,
                    reason = tls::describe(&error),
                    "the TLS handshake with a client failed"
                );
                self.over = true;
                return;
            }
            Err(cut) => {
                self.cut(&cut);
                return;
            }
        };
        if alpn_required
            && (context.alpn.is_none() || stream.get_ref().1.alpn_protocol() != context.alpn)
        {
            tracing::info!(
                listener = %context.name,
                client = %self.peer,
                "a client opened with a TLS handshake that did not name the protocol"
            );
            self.over = true;
            return;
        }

        self.client = Some(tokio::io::split(ClientStream::Tls(Box::new(stream))));
        self.client_is_tls = true;
        self.report(Report::ClientTlsEstablished);
    }

    /// Opens the connection to the database.
    async fn connect_backend(&mut self) {
        if self.backend.is_some() {
            tracing::error!(
                listener = %self.context.name,
                "a session asked for a second connection to the database"
            );
            self.over = true;
            return;
        }
        let context = Arc::clone(&self.context);
        match bounded(
            self.deadline(),
            &mut self.stage,
            context.connector.connect(),
        )
        .await
        {
            Ok(Ok(Connected { stream, tls })) => {
                self.backend_is_tls = stream.is_tls();
                self.backend = Some(tokio::io::split(stream));
                self.report(Report::BackendConnected { tls });
            }
            Ok(Err(error)) => {
                self.context.status.backend_failed();
                tracing::warn!(
                    listener = %context.name,
                    client = %self.peer,
                    upstream = %context.connector.upstream,
                    reason = error.0,
                    "the database could not be reached"
                );
                self.report(Report::BackendUnavailable);
            }
            Err(cut) => self.cut(&cut),
        }
    }

    /// Writes everything queued for the client, now. Returns whether that
    /// worked.
    async fn flush_client(&mut self) -> bool {
        let Some((_, writer)) = &mut self.client else {
            return false;
        };
        let queue = self
            .out
            .to_client
            .get(self.client_sent..)
            .unwrap_or_default();
        let work = async {
            writer.write_all(queue).await?;
            writer.flush().await
        };
        let done = bounded(
            (!self.logged_in).then_some(self.login_deadline),
            &mut self.stage,
            work,
        )
        .await;
        match done {
            Ok(Ok(())) => {
                self.out.to_client.clear();
                self.client_sent = 0;
                self.client_unflushed = false;
                true
            }
            Ok(Err(_)) => false,
            Err(cut) => {
                self.cut(&cut);
                false
            }
        }
    }

    /// The proxy is stopping: the session says what it has to say and both
    /// connections are closed.
    async fn stop(&mut self) {
        if self.told_to_stop {
            return;
        }
        self.told_to_stop = true;
        let policy = self.context.policy.snapshot();
        let result = self
            .session
            .on_report(Report::ShuttingDown, &policy, &mut self.out);
        self.settle(result);
        // Only what closes and what reports is carried out now: nothing
        // new is begun.
        for effect in mem::take(&mut self.out.effects) {
            match effect {
                Effect::Close(leg) => self.close_after_flush(leg),
                Effect::Emit(body) => self.context.events.submit(body),
                _ => {}
            }
        }
        self.close_after_flush(Leg::Client);
        self.close_after_flush(Leg::Backend);
    }

    fn close_after_flush(&mut self, leg: Leg) {
        match leg {
            Leg::Client => self.client_closing = true,
            Leg::Backend => self.backend_closing = true,
        }
        if self.linger_until.is_none() {
            self.linger_until = Some(Instant::now() + LINGER);
        }
    }

    /// Closes the connections that are being closed and have nothing left
    /// to send.
    async fn finish_closing(&mut self) {
        if self.client_closing
            && !self.client_unflushed
            && self.out.to_client.len() <= self.client_sent
        {
            if let Some((_, mut writer)) = self.client.take() {
                // A peer that does not take the goodbye is left without it.
                let _ = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await;
            }
            self.drop_client();
        }
        if self.backend_closing
            && !self.backend_unflushed
            && self.out.to_server.len() <= self.backend_sent
        {
            if let Some((_, mut writer)) = self.backend.take() {
                let _ = tokio::time::timeout(Duration::from_secs(1), writer.shutdown()).await;
            }
            self.drop_backend();
        }
    }

    /// The client leg is gone. What was queued for it is dropped, and the
    /// backend leg is closed once it has been sent what the client still
    /// wanted it to have.
    fn drop_client(&mut self) {
        self.client = None;
        self.out.to_client = Vec::new();
        self.client_sent = 0;
        self.client_unflushed = false;
        self.to_client_since = None;
        if self.backend.is_some() {
            self.close_after_flush(Leg::Backend);
        }
    }

    /// The backend leg is gone. The client is closed once it has been sent
    /// what the database still said.
    fn drop_backend(&mut self) {
        self.backend = None;
        self.out.to_server = Vec::new();
        self.backend_sent = 0;
        self.backend_unflushed = false;
        self.to_backend_since = None;
        if self.client.is_some() {
            self.close_after_flush(Leg::Client);
        }
    }

    /// Drops what has been written from the front of the queues.
    fn compact(&mut self) {
        compact_queue(&mut self.out.to_client, &mut self.client_sent);
        compact_queue(&mut self.out.to_server, &mut self.backend_sent);
    }

    /// Gives back what a quiet session does not need.
    fn release_buffers(&mut self) {
        self.client_buffer.shrink();
        self.backend_buffer.shrink();
        if self.out.to_client.is_empty() {
            self.out.to_client = Vec::new();
        }
        if self.out.to_server.is_empty() {
            self.out.to_server = Vec::new();
        }
        self.out.effects = Vec::new();
    }
}

fn compact_queue(queue: &mut Vec<u8>, sent: &mut usize) {
    if *sent >= queue.len() {
        queue.clear();
        *sent = 0;
        // A queue that grew for one large message does not stay large.
        if queue.capacity() > COMPACT_AFTER {
            *queue = Vec::new();
        }
    } else if *sent >= COMPACT_AFTER {
        queue.drain(..*sent);
        *sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_buffer_grows_when_filled_and_shrinks_when_told() {
        let status = Arc::new(Status::new());
        let held = || status.counters().read_buffer_bytes;
        let mut buffer = ReadBuffer::new(&status);
        assert_eq!(buffer.bytes.len(), SMALL_READ);
        assert_eq!(held(), SMALL_READ as u64);
        buffer.after_read(SMALL_READ - 1);
        assert_eq!(buffer.bytes.len(), SMALL_READ);
        buffer.after_read(SMALL_READ);
        assert_eq!(buffer.bytes.len(), LARGE_READ);
        assert_eq!(held(), LARGE_READ as u64);
        buffer.after_read(LARGE_READ);
        assert_eq!(buffer.bytes.len(), LARGE_READ);
        buffer.shrink();
        assert_eq!(buffer.bytes.len(), SMALL_READ);
        assert!(buffer.bytes.capacity() < LARGE_READ);
        assert_eq!(held(), SMALL_READ as u64);

        // A second buffer counts too, and a buffer that is gone does not.
        let other = ReadBuffer::new(&status);
        assert_eq!(held(), 2 * SMALL_READ as u64);
        drop(buffer);
        drop(other);
        assert_eq!(held(), 0);
    }

    #[test]
    fn a_queue_gives_up_what_has_been_written() {
        // Written in full: empty again.
        let mut queue = vec![1u8; 100];
        let mut sent = 100;
        compact_queue(&mut queue, &mut sent);
        assert!(queue.is_empty());
        assert_eq!(sent, 0);

        // A little written: nothing moves yet.
        let mut queue = vec![1u8; 100];
        let mut sent = 40;
        compact_queue(&mut queue, &mut sent);
        assert_eq!((queue.len(), sent), (100, 40));

        // A lot written: the rest moves to the front.
        let mut queue = vec![1u8; COMPACT_AFTER + 10];
        queue.extend_from_slice(b"tail");
        let mut sent = COMPACT_AFTER + 10;
        compact_queue(&mut queue, &mut sent);
        assert_eq!(queue, b"tail");
        assert_eq!(sent, 0);

        // A queue that grew large is let go once it is empty.
        let mut queue = Vec::with_capacity(4 * COMPACT_AFTER);
        queue.push(1u8);
        let mut sent = 1;
        compact_queue(&mut queue, &mut sent);
        assert_eq!(queue.capacity(), 0);
    }
}
