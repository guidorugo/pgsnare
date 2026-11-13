// SPDX-License-Identifier: Apache-2.0

//! Accepting clients on one listener.
//!
//! Every accepted connection becomes a task of its own. The listener keeps
//! track of those tasks, so that it can wait for them when the proxy stops
//! and can tell when one of them panicked.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::session::{self, ListenerContext, Stage};
use super::status::Status;

/// How many connections may wait to be accepted.
const BACKLOG: u32 = 1024;

/// How long the listener waits after it failed to accept a connection, for
/// example because the process has run out of file descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// The least time between two log lines about refused clients.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Opens the socket of a listener.
pub(crate) fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // A restart does not have to wait for old connections to time out.
    socket.set_reuseaddr(true)?;
    // Accepted connections inherit this: a client that has gone away is
    // noticed even when nothing is being sent.
    socket.set_keepalive(true)?;
    socket.bind(address)?;
    socket.listen(BACKLOG)
}

/// Counts a session as open for as long as it exists, whatever way its
/// task ends.
struct Open(Arc<Status>);

impl Open {
    fn new(status: &Arc<Status>) -> Self {
        status.session_accepted();
        Self(Arc::clone(status))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.0.session_ended();
    }
}

/// Accepts clients until the proxy is asked to stop, then waits for the
/// sessions that are still open.
pub(crate) async fn serve(
    listener: TcpListener,
    context: Arc<ListenerContext>,
    max_connections: usize,
    mut stage: watch::Receiver<Stage>,
) {
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut sessions = JoinSet::new();
    let mut refusals_logged: Option<Instant> = None;

    loop {
        tokio::select! {
            changed = stage.changed() => {
                if changed.is_err() || *stage.borrow() != Stage::Running {
                    break;
                }
            }
            Some(ended) = sessions.join_next(), if !sessions.is_empty() => {
                note_end(&context, ended);
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(
                            listener = %context.name,
                            reason = %error.kind(),
                            "a connection could not be accepted"
                        );
                        tokio::time::sleep(ACCEPT_PAUSE).await;
                        continue;
                    }
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    // Closing the connection is all the refusal there is:
                    // nothing has been read, so nothing can be answered.
                    drop(stream);
                    context.status.session_refused();
                    let now = Instant::now();
                    if refusals_logged.is_none_or(|last| now.duration_since(last) >= REFUSAL_LOG_INTERVAL) {
                        refusals_logged = Some(now);
                        tracing::warn!(
                            listener = %context.name,
                            limit = max_connections,
                            "clients are being refused: the listener has reached its connection limit"
                        );
                    }
                    continue;
                };
                // Nothing is held back to be sent in larger pieces.
                let _ = stream.set_nodelay(true);
                let open = Open::new(&context.status);
                let context = Arc::clone(&context);
                let stage = stage.clone();
                sessions.spawn(async move {
                    let (_slot, _open) = (slot, open);
                    session::run(context, stream, peer, stage).await;
                });
            }
        }
    }

    // No new clients from here on. The sessions that are open end by
    // themselves, or when the proxy runs out of time and tells them to.
    drop(listener);
    while let Some(ended) = sessions.join_next().await {
        note_end(&context, ended);
    }
}

/// A session that panicked took nothing else with it. It is counted.
fn note_end(context: &ListenerContext, ended: Result<(), tokio::task::JoinError>) {
    if let Err(error) = ended
        && error.is_panic()
    {
        context.status.session_panicked();
        tracing::error!(
            listener = %context.name,
            "a session ended because its code panicked"
        );
    }
}
