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
//! and both connections are closed.
//!
//! # What it reports
//!
//! A [`Status`] says whether the runtime accepts clients and holds its
//! counters. Health and metrics endpoints are built on that and are not
//! part of the runtime.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use pgsnare_core::event::Labels;
use pgsnare_core::policy::PolicySource;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::builder::Proxy;
use crate::tls::{BackendLeg, ClientLeg};

mod backend;
mod events;
mod listener;
pub mod permissions;
mod session;
mod status;
mod stream;

pub use backend::Upstream;
pub use status::{Counters, Status};

use backend::Connector;
use events::Events;
use session::{ListenerContext, Stage};

/// The default for [`Settings::grace_period`].
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(25);

/// The default for [`Settings::event_capacity`].
pub const DEFAULT_EVENT_CAPACITY: usize = 1024;

/// After the grace period, sessions get this long to send their last
/// bytes before the runtime gives up on them.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// How many deliveries of events may be under way at once. Events
    /// beyond that are dropped and counted.
    pub event_capacity: usize,
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
        }
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

    /// Sets how many deliveries of events may be under way at once.
    #[must_use]
    pub const fn with_event_capacity(mut self, event_capacity: usize) -> Self {
        self.event_capacity = event_capacity;
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
        let events = Arc::new(Events::new(
            proxy.event_sinks().to_vec(),
            settings.labels,
            settings.event_capacity,
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
    pub async fn serve(self, stop: impl Future<Output = ()>) {
        let Self {
            listeners,
            grace_period,
            status,
        } = self;
        let (stage, _) = watch::channel(Stage::Running);
        let mut tasks = JoinSet::new();
        for listener in listeners {
            tasks.spawn(listener::serve(
                listener.socket,
                listener.context,
                listener.max_connections,
                stage.subscribe(),
            ));
        }
        status.set_ready(true);

        stop.await;

        status.set_ready(false);
        tracing::info!(
            grace_period_seconds = grace_period.as_secs(),
            sessions = status.counters().sessions_active,
            "stopping: no new clients are accepted and open sessions may finish"
        );
        stage.send_replace(Stage::Draining);
        let all_ended = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(grace_period, all_ended).await.is_err() {
            tracing::info!(
                sessions = status.counters().sessions_active,
                "the grace period is over: the sessions that are still open are closed"
            );
            stage.send_replace(Stage::Stopping);
            let all_ended = async { while tasks.join_next().await.is_some() {} };
            if tokio::time::timeout(STOP_TIMEOUT, all_ended).await.is_err() {
                tasks.shutdown().await;
            }
        }
        tracing::info!("stopped");
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
