// SPDX-License-Identifier: Apache-2.0

//! The admin listener with the health endpoints, and the metrics listener.
//!
//! Two listeners, each with an address of its own, so that one can be
//! opened to a scraper without the other:
//!
//! | Listener | Path | Answer |
//! |---|---|---|
//! | Admin | `/healthz` | `200` while the proxy works as it should, `503` once one of its listeners has failed |
//! | Admin | `/readyz` | `200` while the proxy accepts clients, `503` before that, while it stops and once a listener has failed |
//! | Metrics | `/metrics` | The metrics, in the text format Prometheus reads: see [`metrics`](self) |
//!
//! `pgsnare healthcheck` asks the admin listener, so that neither endpoint
//! has to be reachable from another machine for a container or a pod to be
//! checked.
//!
//! # Read-only
//!
//! Both listeners answer `GET` on the paths above and refuse everything
//! else: another method with `405`, another path with `404`. Nothing can
//! be changed through them, and what they show is a state and numbers: no
//! configuration, no address of a client, and no list of tokens.
//!
//! They speak plain HTTP. The addresses they are given by default are on
//! the loopback interface, and an operator who gives them another one is
//! told so in the log when the proxy starts.
//!
//! # Limits
//!
//! Whoever connects is not trusted to behave.
//!
//! - **One request for each connection.** The answer closes it.
//! - **A connection has [`CONNECTION_TIMEOUT`] in all.** A client that
//!   sends nothing, sends slowly, never stops sending or does not read its
//!   answer is dropped when the time is over.
//! - **The head of a request may have [`MAX_REQUEST_BYTES`] and
//!   [`MAX_HEADERS`] headers.** A larger one is refused. The body of a
//!   request is never read.
//! - **A listener holds at most [`MAX_CONNECTIONS`] connections.** One
//!   more is closed at once.
//!
//! The protocol itself is left to the HTTP library: nothing here parses a
//! request.
//!
//! # When the code here fails
//!
//! A panic while a request is answered ends that one connection. A panic
//! in the loop that accepts connections ends the loop, and the loop is
//! started again after a moment. Both are counted and logged. Database
//! traffic does not depend on either listener and goes on throughout.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use crate::http::{Body, Io};
use crate::redact::Redaction;
use crate::runtime::Status;

mod metrics;

/// How long a connection may last, from the moment it is accepted to the
/// last byte of its answer.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes the head of a request may have: its first line and its
/// headers.
pub const MAX_REQUEST_BYTES: usize = 8192;

/// The most headers a request may have.
pub const MAX_HEADERS: usize = 64;

/// The most connections one listener holds at once.
pub const MAX_CONNECTIONS: usize = 32;

/// How many connections may wait to be accepted.
const BACKLOG: u32 = 128;

/// How long a listener waits after it failed to accept a connection, and
/// before the loop that accepts connections is started again after a
/// panic.
const PAUSE: Duration = Duration::from_millis(100);

/// The least time between two log lines about refused connections.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

const PLAIN_TEXT: &str = "text/plain; charset=utf-8";

/// Which of the two listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Which {
    Admin,
    Metrics,
}

impl Which {
    const fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Metrics => "metrics",
        }
    }
}

/// What both listeners answer from.
struct State {
    status: Arc<Status>,
    redaction: Redaction,
}

/// The two listeners, open and not served yet.
pub struct Listeners {
    admin: TcpListener,
    metrics: TcpListener,
    state: Arc<State>,
}

/// Opens the admin listener and the metrics listener.
///
/// `status` is what they report, and `redaction` is what every label of a
/// metric passes through. Port 0 lets the system choose a port.
///
/// Must be called inside a tokio runtime.
///
/// # Errors
///
/// Returns the error of the first address that cannot be bound.
pub fn bind(
    admin: SocketAddr,
    metrics: SocketAddr,
    status: Arc<Status>,
    redaction: Redaction,
) -> io::Result<Listeners> {
    let open = |address: SocketAddr| {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(address)?;
        socket.listen(BACKLOG)
    };
    Ok(Listeners {
        admin: open(admin)?,
        metrics: open(metrics)?,
        state: Arc::new(State { status, redaction }),
    })
}

impl Listeners {
    /// The address the admin listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns the error of the system when it cannot tell.
    pub fn admin_addr(&self) -> io::Result<SocketAddr> {
        self.admin.local_addr()
    }

    /// The address the metrics listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns the error of the system when it cannot tell.
    pub fn metrics_addr(&self) -> io::Result<SocketAddr> {
        self.metrics.local_addr()
    }

    /// Serves both listeners until `stop` resolves.
    pub async fn serve(self, stop: impl Future<Output = ()>) {
        let Self {
            admin,
            metrics,
            state,
        } = self;
        let listeners =
            [(Which::Admin, admin), (Which::Metrics, metrics)].map(|(which, listener)| {
                let (listener, state) = (Arc::new(listener), Arc::clone(&state));
                let status = Arc::clone(&state.status);
                tokio::spawn(supervise(which, status, move || {
                    accept(which, Arc::clone(&listener), Arc::clone(&state))
                }))
            });
        stop.await;
        for listener in listeners {
            listener.abort();
            let _ = listener.await;
        }
    }
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("admin", &self.admin.local_addr().ok())
            .field("metrics", &self.metrics.local_addr().ok())
            .finish_non_exhaustive()
    }
}

/// Ends a task when whoever watches over it goes away.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps the loop of one listener running: when it ends in a panic, the
/// panic is counted and logged and the loop is started again.
async fn supervise<F>(which: Which, status: Arc<Status>, start: impl Fn() -> F)
where
    F: Future<Output = ()> + Send + 'static,
{
    loop {
        let accepting = tokio::spawn(start());
        let _guard = AbortOnDrop(accepting.abort_handle());
        match accepting.await {
            Err(ended) if ended.is_panic() => {
                status.admin_panicked();
                tracing::error!(
                    listener = which.name(),
                    "the code that accepts connections for health or metrics panicked: it is \
                     started again"
                );
                tokio::time::sleep(PAUSE).await;
            }
            _ => return,
        }
    }
}

/// Accepts connections on one listener, for as long as it is polled.
async fn accept(which: Which, listener: Arc<TcpListener>, state: Arc<State>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    let mut refusals_logged: Option<Instant> = None;

    loop {
        tokio::select! {
            Some(ended) = connections.join_next(), if !connections.is_empty() => {
                if ended.is_err_and(|error| error.is_panic()) {
                    state.status.admin_panicked();
                    tracing::error!(
                        listener = which.name(),
                        "the code that answers a request for health or metrics panicked"
                    );
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(PAUSE).await;
                    continue;
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(stream);
                    let now = Instant::now();
                    if refusals_logged.is_none_or(|last| now.duration_since(last) >= REFUSAL_LOG_INTERVAL) {
                        refusals_logged = Some(now);
                        tracing::warn!(
                            listener = which.name(),
                            limit = MAX_CONNECTIONS,
                            "connections for health or metrics are being refused: the listener \
                             holds as many as it may"
                        );
                    }
                    continue;
                };
                let state = Arc::clone(&state);
                connections.spawn(async move {
                    let _slot = slot;
                    // Whatever the client does, the connection ends in time.
                    let _ = tokio::time::timeout(CONNECTION_TIMEOUT, serve(which, stream, state)).await;
                });
            }
        }
    }
}

/// Answers the one request of a connection.
async fn serve(which: Which, stream: TcpStream, state: Arc<State>) {
    let service = service_fn(move |request: Request<Incoming>| {
        let response = answer(which, &request, &state);
        async move { Ok::<_, Infallible>(response) }
    });
    let mut http = http1::Builder::new();
    http.keep_alive(false)
        .max_buf_size(MAX_REQUEST_BYTES)
        .max_headers(MAX_HEADERS)
        // The limit of the whole connection covers the head too.
        .header_read_timeout(None::<Duration>);
    // An error here is a client that sent something else than a request, or
    // went away. There is nothing to do about either.
    let _ = http.serve_connection(Io(stream), service).await;
}

/// The answer to a request.
fn answer(which: Which, request: &Request<Incoming>, state: &State) -> Response<Body> {
    if request.method() != Method::GET {
        let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "only GET is answered\n");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET"));
        return response;
    }
    match (which, request.uri().path()) {
        (Which::Admin, "/healthz") => {
            if state.status.is_healthy() {
                plain(StatusCode::OK, "ok\n")
            } else {
                plain(StatusCode::SERVICE_UNAVAILABLE, "unhealthy\n")
            }
        }
        (Which::Admin, "/readyz") => {
            if state.status.is_ready() {
                plain(StatusCode::OK, "ready\n")
            } else {
                plain(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
            }
        }
        (Which::Metrics, "/metrics") => respond(
            StatusCode::OK,
            metrics::CONTENT_TYPE,
            metrics::render(&state.status, &state.redaction),
        ),
        _ => plain(StatusCode::NOT_FOUND, "not found\n"),
    }
}

fn plain(status: StatusCode, text: &'static str) -> Response<Body> {
    respond(status, PLAIN_TEXT, text.to_owned())
}

fn respond(status: StatusCode, content_type: &'static str, text: String) -> Response<Body> {
    let mut response = Response::new(Body::new(text));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    // What is asked now is not what is true a second later.
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests;
