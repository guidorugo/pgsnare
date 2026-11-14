// SPDX-License-Identifier: Apache-2.0

//! The runtime: listeners, sessions, upstream connections and shutdown.
//!
//! The runtime owns every socket and every timer. It accepts clients,
//! creates the session logic for each, feeds it the bytes it reads and
//! carries out what the session logic decides. It knows nothing about any
//! database protocol: that is the business of the protocol module the
//! proxy was built with.
//!
//! # Using it
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use pgsnare::builder::Proxy;
//! use pgsnare::runtime::{ListenerSettings, Runtime, Settings};
//! use pgsnare_core::policy::PolicySource;
//!
//! # async fn example(
//! #     proxy: Proxy,
//! #     policy: Arc<dyn PolicySource>,
//! #     listeners: Vec<ListenerSettings>,
//! # ) -> std::io::Result<()> {
//! let runtime = Runtime::new(proxy, policy, Settings::new(listeners));
//! let bound = runtime.bind()?;
//! // Runs until the future resolves, then lets open sessions finish.
//! bound
//!     .serve(async {
//!         let _ = tokio::signal::ctrl_c().await;
//!     })
//!     .await;
//! # Ok(())
//! # }
//! ```
//!
//! # Stopping
//!
//! When the future given to [`Bound::serve`] resolves, the runtime stops
//! accepting clients and reports that it is not ready. Open sessions go on
//! for the grace period. Those that are still open then are told to end:
//! the session logic says to the client what the protocol has for that,
//! and both connections are closed. Last, the events that still wait for a
//! sink get a moment to be delivered.
//!
//! # A listener that fails
//!
//! A listener that stops accepting clients while the runtime is meant to
//! run must not go unnoticed: the process would live on, look healthy and
//! serve nobody on that address. The runtime watches the tasks of its
//! listeners. When one ends that should not have, the runtime logs an
//! error, counts the failure, reports that it is neither ready nor
//! healthy, and stops in the way described above, grace period included.
//! [`Bound::run`] then returns [`Stopped::ListenerFailed`], which the
//! `pgsnare run` command turns into an exit status that is not zero, so
//! that whatever supervises the process starts it again.
//!
//! # What it reports
//!
//! A [`Status`] says whether the runtime accepts clients and holds its
//! counters. Health and metrics endpoints are built on that and are not
//! part of the runtime.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use pgsnare_core::event::Labels;
use pgsnare_core::policy::PolicySource;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::{Id, JoinSet};

use crate::builder::Proxy;
use crate::redact::Redaction;
use crate::tls::{BackendLeg, ClientLeg};

mod backend;
mod entropy;
mod events;
mod listener;
#[cfg(feature = "rules")]
pub mod parser;
pub mod permissions;
mod session;
mod status;
mod stream;

pub use backend::Upstream;
pub use entropy::OsEntropy;
pub use status::{Counters, DropReason, Histogram, HitCounters, SinkCounters, SinkStatus, Status};

use backend::Connector;
use events::{EventSettings, Events};
use session::{ListenerContext, Stage};

/// The default for [`Settings::grace_period`].
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(25);

/// The default for [`Settings::event_capacity`].
pub const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// After the grace period, sessions get this long to send their last
/// bytes before the runtime gives up on them.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// When every session has ended, the events that still wait for a sink get
/// this long to be delivered. It is short, so that a sink that is down
/// does not keep a proxy from stopping in the time it was given.
const EVENT_DRAIN: Duration = Duration::from_secs(2);

/// How often a runtime that stops because a listener failed looks whether
/// the sessions that listener left behind have ended.
const ORPHAN_POLL: Duration = Duration::from_millis(20);

/// One listener: where clients connect, and the database behind it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ListenerSettings {
    /// A name for logs.
    pub name: String,
    /// The address to accept clients on. Port 0 lets the system choose.
    pub listen: SocketAddr,
    /// The database to relay to.
    pub upstream: Upstream,
    /// TLS between applications and pgsnare.
    pub client_tls: ClientLeg,
    /// TLS between pgsnare and the database. A leg that must use TLS does
    /// not go with a Unix socket as the upstream, because a connection
    /// over a Unix socket is never encrypted: [`Runtime::bind`] refuses
    /// the two together.
    pub backend_tls: BackendLeg,
    /// How many clients may be connected at once. Further clients are
    /// refused.
    pub max_connections: usize,
    /// How long a client may take to log in.
    pub login_timeout: Duration,
}

impl ListenerSettings {
    /// A listener without TLS on either leg, with the limits a
    /// configuration file has by default.
    #[must_use]
    pub fn new(name: impl Into<String>, listen: SocketAddr, upstream: Upstream) -> Self {
        Self {
            name: name.into(),
            listen,
            upstream,
            client_tls: ClientLeg::disabled(),
            backend_tls: BackendLeg::disabled(),
            max_connections: usize::try_from(crate::config::DEFAULT_MAX_CONNECTIONS)
                .unwrap_or(usize::MAX),
            login_timeout: crate::config::DEFAULT_LOGIN_TIMEOUT,
        }
    }

    /// Sets TLS for both legs.
    #[must_use]
    pub fn with_tls(mut self, client: ClientLeg, backend: BackendLeg) -> Self {
        self.client_tls = client;
        self.backend_tls = backend;
        self
    }

    /// Sets how many clients may be connected at once.
    #[must_use]
    pub const fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Sets how long a client may take to log in.
    #[must_use]
    pub const fn with_login_timeout(mut self, login_timeout: Duration) -> Self {
        self.login_timeout = login_timeout;
        self
    }
}

/// What a runtime is started with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Settings {
    /// The listeners.
    pub listeners: Vec<ListenerSettings>,
    /// How long open sessions get to finish after the runtime was asked to
    /// stop.
    pub grace_period: Duration,
    /// The labels every event carries.
    pub labels: Labels,
    /// How many events may wait between the sessions and the dispatcher.
    /// Events beyond that are dropped and counted. A session never waits.
    pub event_capacity: usize,
    /// How long repeated hits of one token in one session are folded into
    /// a single event. Zero turns that off.
    pub dedup_window: Duration,
    /// What removes from events what must not be shown: honeytoken values
    /// above all. The default knows nothing to remove.
    pub redaction: Redaction,
    /// The threads that analyse statements for the SQL rules. Without
    /// them every statement the rules apply to counts as one the parser
    /// was too busy for.
    #[cfg(feature = "rules")]
    pub parser: Option<Arc<parser::ParserPool>>,
    /// How long a session waits for the analysis of a statement before the
    /// statement counts as one without an analysis.
    #[cfg(feature = "rules")]
    pub analysis_deadline: Duration,
}

impl Settings {
    /// Settings with the default grace period and no labels.
    #[must_use]
    pub fn new(listeners: Vec<ListenerSettings>) -> Self {
        Self {
            listeners,
            grace_period: DEFAULT_GRACE_PERIOD,
            labels: Labels::new(),
            event_capacity: DEFAULT_EVENT_CAPACITY,
            dedup_window: crate::config::DEFAULT_DEDUP_WINDOW,
            redaction: Redaction::default(),
            #[cfg(feature = "rules")]
            parser: None,
            #[cfg(feature = "rules")]
            analysis_deadline: parser::DEFAULT_ANALYSIS_DEADLINE,
        }
    }

    /// Sets the threads that analyse statements for the SQL rules.
    #[cfg(feature = "rules")]
    #[must_use]
    pub fn with_parser(mut self, parser: Arc<parser::ParserPool>) -> Self {
        self.parser = Some(parser);
        self
    }

    /// Sets how long a session waits for the analysis of a statement.
    #[cfg(feature = "rules")]
    #[must_use]
    pub const fn with_analysis_deadline(mut self, deadline: Duration) -> Self {
        self.analysis_deadline = deadline;
        self
    }

    /// Sets how long open sessions get to finish.
    #[must_use]
    pub const fn with_grace_period(mut self, grace_period: Duration) -> Self {
        self.grace_period = grace_period;
        self
    }

    /// Sets the labels every event carries.
    #[must_use]
    pub fn with_labels(mut self, labels: Labels) -> Self {
        self.labels = labels;
        self
    }

    /// Sets how many events may wait between the sessions and the
    /// dispatcher.
    #[must_use]
    pub const fn with_event_capacity(mut self, event_capacity: usize) -> Self {
        self.event_capacity = event_capacity;
        self
    }

    /// Sets how long repeated hits are folded into a single event.
    #[must_use]
    pub const fn with_dedup_window(mut self, dedup_window: Duration) -> Self {
        self.dedup_window = dedup_window;
        self
    }

    /// Sets what removes from events what must not be shown.
    #[must_use]
    pub fn with_redaction(mut self, redaction: Redaction) -> Self {
        self.redaction = redaction;
        self
    }
}

/// A proxy that is ready to be started.
pub struct Runtime {
    proxy: Proxy,
    policy: Arc<dyn PolicySource>,
    settings: Settings,
    status: Arc<Status>,
}

impl Runtime {
    /// Puts a proxy, the source of its policy and its settings together.
    #[must_use]
    pub fn new(proxy: Proxy, policy: Arc<dyn PolicySource>, settings: Settings) -> Self {
        Self {
            proxy,
            policy,
            settings,
            status: Arc::new(Status::new()),
        }
    }

    /// What the runtime reports about itself. It can be taken before the
    /// runtime is started and read while it runs.
    #[must_use]
    pub fn status(&self) -> Arc<Status> {
        Arc::clone(&self.status)
    }

    /// Opens the sockets of every listener.
    ///
    /// Must be called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns the error of the first listener whose address cannot be
    /// bound. No listener is left open then.
    ///
    /// A listener that must use TLS to a database it reaches over a Unix
    /// socket is refused with an error of the kind
    /// [`InvalidInput`](io::ErrorKind::InvalidInput), before any socket is
    /// opened: it could not serve a single client.
    pub fn bind(self) -> io::Result<Bound> {
        let Self {
            proxy,
            policy,
            settings,
            status,
        } = self;
        if let Some(listener) = settings.listeners.iter().find(|listener| {
            backend::requires_tls_over_unix_socket(&listener.upstream, &listener.backend_tls)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "listener {}: {}",
                    listener.name,
                    backend::TLS_OVER_UNIX_SOCKET
                ),
            ));
        }
        let sinks = proxy
            .event_sinks()
            .iter()
            .cloned()
            .zip(proxy.sink_options().iter().cloned())
            .collect();
        let events = Arc::new(Events::new(
            sinks,
            EventSettings {
                capacity: settings.event_capacity,
                dedup_window: settings.dedup_window,
                labels: settings.labels,
                redaction: settings.redaction,
            },
            Arc::clone(&status),
        ));
        let module = Arc::clone(proxy.protocol_module());

        let mut listeners = Vec::with_capacity(settings.listeners.len());
        for listener in settings.listeners {
            let socket = listener::bind(listener.listen)?;
            let address = socket.local_addr()?;
            let context = Arc::new(ListenerContext {
                name: listener.name.clone(),
                proxy: proxy.clone(),
                policy: Arc::clone(&policy),
                connector: Connector {
                    upstream: listener.upstream,
                    tls: listener.backend_tls,
                    tls_request: module.backend_tls_request(),
                    client_certificate: listener.client_tls.certificate().map(<[u8]>::to_vec),
                    mismatch_logged: AtomicBool::new(false),
                    listener: listener.name,
                },
                client_tls: listener.client_tls,
                alpn: module.alpn_protocol(),
                login_timeout: listener.login_timeout,
                status: Arc::clone(&status),
                events: Arc::clone(&events),
                #[cfg(feature = "rules")]
                parser: settings.parser.clone(),
                #[cfg(feature = "rules")]
                analysis_deadline: settings.analysis_deadline,
            });
            listeners.push(BoundListener {
                socket,
                address,
                context,
                max_connections: listener.max_connections,
            });
        }
        Ok(Bound {
            listeners,
            grace_period: settings.grace_period,
            status,
            events,
        })
    }
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("proxy", &self.proxy)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

struct BoundListener {
    socket: TcpListener,
    address: SocketAddr,
    context: Arc<ListenerContext>,
    max_connections: usize,
}

/// A runtime whose listeners are open and not served yet. A client that
/// connects now waits until [`Bound::serve`] is called.
pub struct Bound {
    listeners: Vec<BoundListener>,
    grace_period: Duration,
    status: Arc<Status>,
    events: Arc<Events>,
}

/// Why a runtime stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stopped {
    /// It was asked to.
    Asked,
    /// One of its listeners stopped accepting clients while the runtime
    /// was meant to run. The runtime is at fault, and whatever started it
    /// should start it again.
    ListenerFailed,
}

impl Bound {
    /// The address each listener is bound to, in the order of the
    /// settings. This tells the port the system chose for port 0.
    #[must_use]
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .map(|listener| listener.address)
            .collect()
    }

    /// What the runtime reports about itself.
    #[must_use]
    pub fn status(&self) -> Arc<Status> {
        Arc::clone(&self.status)
    }

    /// For every listener with TLS on both legs, connects to the database
    /// once and compares the certificate it presents with the one the
    /// listener presents to clients. A difference is logged as a warning.
    ///
    /// Returns, for each listener in the order of the settings, whether
    /// the certificates are the same. `None` stands for a listener where
    /// there is nothing to compare, or whose database did not answer
    /// within `timeout`.
    pub async fn compare_certificates(&self, timeout: Duration) -> Vec<Option<bool>> {
        let mut results = Vec::with_capacity(self.listeners.len());
        for listener in &self.listeners {
            let connector = &listener.context.connector;
            let result = tokio::time::timeout(timeout, connector.probe_certificate())
                .await
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        listener = %listener.context.name,
                        "the certificate of the database could not be compared with the one \
                         of the client leg, because the database did not answer in time"
                    );
                    None
                });
            results.push(result);
        }
        results
    }

    /// Serves clients until `stop` resolves, then stops as the
    /// [module documentation](self) describes. Returns when every session
    /// has ended.
    ///
    /// A listener that fails stops the runtime too. [`Bound::run`] does
    /// the same and says which of the two it was.
    pub async fn serve(self, stop: impl Future<Output = ()>) {
        self.run(stop).await;
    }

    /// Serves clients until `stop` resolves or a listener fails, then
    /// stops as the [module documentation](self) describes. Returns why
    /// it stopped, once every session has ended.
    pub async fn run(self, stop: impl Future<Output = ()>) -> Stopped {
        let Self {
            listeners,
            grace_period,
            status,
            events,
        } = self;
        let (stage, _) = watch::channel(Stage::Running);
        let mut tasks = JoinSet::new();
        let mut names = HashMap::with_capacity(listeners.len());
        for listener in listeners {
            let name = listener.context.name.clone();
            let task = tasks.spawn(listener::serve(
                listener.socket,
                listener.context,
                listener.max_connections,
                stage.subscribe(),
            ));
            names.insert(task.id(), name);
        }
        let supervised = Supervised {
            tasks,
            names,
            stage,
            grace_period,
            status,
        };
        let stopped = supervised.run(stop).await;
        events.close(EVENT_DRAIN).await;
        tracing::info!("stopped");
        stopped
    }
}

/// The tasks of the listeners of a runtime that is being served, and what
/// it takes to watch over them and to stop them.
struct Supervised {
    tasks: JoinSet<()>,
    /// The name of the listener behind each task.
    names: HashMap<Id, String>,
    stage: watch::Sender<Stage>,
    grace_period: Duration,
    status: Arc<Status>,
}

impl Supervised {
    /// Runs until `stop` resolves or a listener fails, and then stops the
    /// listeners and their sessions.
    async fn run(mut self, stop: impl Future<Output = ()>) -> Stopped {
        self.status.set_ready(true);
        let stopped = tokio::select! {
            () = stop => Stopped::Asked,
            // A listener only ends when it is told to stop, and nobody has
            // told it to.
            Some(ended) = self.tasks.join_next_with_id() => {
                self.listener_failed(&ended);
                Stopped::ListenerFailed
            }
        };

        self.status.set_ready(false);
        tracing::info!(
            grace_period_seconds = self.grace_period.as_secs(),
            sessions = self.status.counters().sessions_active,
            "stopping: no new clients are accepted and open sessions may finish"
        );
        self.stage.send_replace(Stage::Draining);
        let orphans = stopped == Stopped::ListenerFailed;
        if tokio::time::timeout(self.grace_period, self.all_ended(orphans))
            .await
            .is_err()
        {
            tracing::info!(
                sessions = self.status.counters().sessions_active,
                "the grace period is over: the sessions that are still open are closed"
            );
            self.stage.send_replace(Stage::Stopping);
            if tokio::time::timeout(STOP_TIMEOUT, self.all_ended(orphans))
                .await
                .is_err()
            {
                self.tasks.shutdown().await;
            }
        }
        stopped
    }

    /// Notes that the task of a listener has ended while the runtime was
    /// meant to run.
    fn listener_failed(&self, ended: &Result<(Id, ()), tokio::task::JoinError>) {
        let (id, panicked) = match ended {
            Ok((id, ())) => (*id, false),
            Err(error) => (error.id(), error.is_panic()),
        };
        self.status.listener_failed(panicked);
        tracing::error!(
            listener = self.names.get(&id).map_or("unknown", String::as_str),
            panicked,
            "a listener stopped accepting clients while the proxy was meant to run: the proxy \
             stops, so that whatever supervises it can start it again"
        );
    }

    /// Resolves when every listener has ended, and every session with it.
    ///
    /// A listener that was told to stop waits for its sessions. One that
    /// failed could not, and left them behind: with `orphans`, those are
    /// waited for too.
    async fn all_ended(&mut self, orphans: bool) {
        while self.tasks.join_next().await.is_some() {}
        while orphans && self.status.counters().sessions_active > 0 {
            tokio::time::sleep(ORPHAN_POLL).await;
        }
    }
}

impl std::fmt::Debug for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bound")
            .field("listeners", &self.local_addrs())
            .field("grace_period", &self.grace_period)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    use super::*;

    /// What a listener does when it works: nothing, until it is told to
    /// stop.
    async fn obedient(mut stage: watch::Receiver<Stage>) {
        while *stage.borrow_and_update() == Stage::Running {
            if stage.changed().await.is_err() {
                return;
            }
        }
    }

    /// A listener that ends when a test says so, with a panic or without.
    async fn doomed(end: oneshot::Receiver<bool>) {
        if end.await.unwrap_or(false) {
            panic!("a panic that a test asked for");
        }
    }

    /// Waits for a runtime to stop by itself. A runtime that does not
    /// notice that a listener has failed would run for ever. The clock of
    /// these tests jumps ahead when everything waits, so that shows as a
    /// failure here and not as a test that never ends.
    async fn stopped(running: tokio::task::JoinHandle<Stopped>) -> Stopped {
        tokio::time::timeout(Duration::from_secs(24 * 3600), running)
            .await
            .expect("the runtime stops when one of its listeners has failed")
            .unwrap()
    }

    /// A runtime with two listeners, one of which a test can end.
    fn supervised(grace_period: Duration) -> (Supervised, oneshot::Sender<bool>, Arc<Status>) {
        let (stage, _) = watch::channel(Stage::Running);
        let status = Arc::new(Status::new());
        let (end, ended) = oneshot::channel();
        let mut tasks = JoinSet::new();
        let mut names = HashMap::new();
        names.insert(
            tasks.spawn(obedient(stage.subscribe())).id(),
            "steady".to_owned(),
        );
        names.insert(tasks.spawn(doomed(ended)).id(), "doomed".to_owned());
        (
            Supervised {
                tasks,
                names,
                stage,
                grace_period,
                status: Arc::clone(&status),
            },
            end,
            status,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_that_is_asked_to_stop_was_not_at_fault() {
        let (supervised, _end, status) = supervised(Duration::from_secs(25));
        let (stop, stopped) = oneshot::channel::<()>();
        let running = tokio::spawn(supervised.run(async {
            let _ = stopped.await;
        }));

        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(status.is_ready());
        assert!(status.is_healthy());
        assert!(!running.is_finished());

        // Both listeners are told to stop. The one that does not listen is
        // given up on when the time is over.
        let asked = Instant::now();
        stop.send(()).unwrap();
        assert_eq!(running.await.unwrap(), Stopped::Asked);
        assert_eq!(
            asked.elapsed(),
            Duration::from_secs(25) + STOP_TIMEOUT,
            "the grace period, and then the time to stop"
        );
        assert!(!status.is_ready());
        assert!(status.is_healthy());
        assert_eq!(status.counters().listener_failures, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_that_panics_is_noticed_counted_and_stops_the_runtime() {
        let (supervised, end, status) = supervised(Duration::from_secs(25));
        // Nobody asks this runtime to stop.
        let running = tokio::spawn(supervised.run(std::future::pending()));

        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(status.is_ready());
        assert!(!running.is_finished());

        let failed = Instant::now();
        end.send(true).unwrap();
        assert_eq!(stopped(running).await, Stopped::ListenerFailed);

        assert!(!status.is_ready());
        assert!(!status.is_healthy());
        let counters = status.counters();
        assert_eq!(counters.listener_failures, 1);
        assert_eq!(counters.listener_panics, 1);
        // The listener that works was told to stop and did, at once.
        assert_eq!(failed.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_that_ends_without_a_panic_has_failed_all_the_same() {
        let (supervised, end, status) = supervised(Duration::from_secs(25));
        let running = tokio::spawn(supervised.run(std::future::pending()));
        tokio::time::sleep(Duration::from_secs(1)).await;

        end.send(false).unwrap();
        assert_eq!(stopped(running).await, Stopped::ListenerFailed);
        assert!(!status.is_healthy());
        assert_eq!(status.counters().listener_failures, 1);
        assert_eq!(status.counters().listener_panics, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_sessions_a_failed_listener_left_behind_get_the_grace_period() {
        let (supervised, end, status) = supervised(Duration::from_secs(25));
        // A session of the listener that is about to fail.
        status.session_accepted();
        let running = tokio::spawn(supervised.run(std::future::pending()));
        tokio::time::sleep(Duration::from_secs(1)).await;

        let failed = Instant::now();
        end.send(true).unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
        // The listener is gone and its session is not: the runtime waits.
        assert!(!running.is_finished());
        assert!(!status.is_ready());

        // The session ends by itself, and with it the runtime.
        status.session_ended();
        assert_eq!(stopped(running).await, Stopped::ListenerFailed);
        let waited = failed.elapsed();
        assert!(waited >= Duration::from_secs(10), "{waited:?}");
        assert!(waited < Duration::from_secs(11), "{waited:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_session_that_never_ends_does_not_keep_a_failed_runtime_alive() {
        let (supervised, end, status) = supervised(Duration::from_secs(25));
        status.session_accepted();
        let running = tokio::spawn(supervised.run(std::future::pending()));
        tokio::time::sleep(Duration::from_secs(1)).await;

        let failed = Instant::now();
        end.send(true).unwrap();
        assert_eq!(stopped(running).await, Stopped::ListenerFailed);
        let waited = failed.elapsed();
        assert!(
            waited >= Duration::from_secs(25) + STOP_TIMEOUT,
            "{waited:?}"
        );
        assert!(
            waited < Duration::from_secs(25) + STOP_TIMEOUT + Duration::from_secs(1),
            "{waited:?}"
        );
    }
}
