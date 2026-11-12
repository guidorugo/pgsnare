// SPDX-License-Identifier: Apache-2.0

//! What the runtime reports about itself: whether it is ready, and its
//! counters.
//!
//! This is the whole interface between the runtime and whatever exposes
//! health and metrics. The runtime updates a [`Status`]. A health endpoint
//! asks [`Status::is_ready`], and a metrics endpoint takes the
//! [`Counters`]. Nothing here formats or serves anything.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The state of a running proxy, shared between the runtime and its
/// observers.
#[derive(Debug, Default)]
pub struct Status {
    ready: AtomicBool,
    sessions_accepted: AtomicU64,
    sessions_refused: AtomicU64,
    sessions_active: AtomicU64,
    sessions_failed: AtomicU64,
    session_panics: AtomicU64,
    login_timeouts: AtomicU64,
    logins_finished: AtomicU64,
    backend_failures: AtomicU64,
    cancels_forwarded: AtomicU64,
    bytes_from_clients: AtomicU64,
    bytes_from_servers: AtomicU64,
    events_emitted: AtomicU64,
    events_dropped: AtomicU64,
    event_delivery_failures: AtomicU64,
}

/// The counters of a proxy at one moment.
///
/// All of them only ever grow, except `sessions_active`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// Client connections that were given a session.
    pub sessions_accepted: u64,
    /// Client connections that were closed at once because the listener had
    /// reached its connection limit.
    pub sessions_refused: u64,
    /// Sessions that are open right now.
    pub sessions_active: u64,
    /// Sessions that ended because the session logic could not go on.
    pub sessions_failed: u64,
    /// Sessions that ended because their code panicked. This must stay at
    /// zero.
    pub session_panics: u64,
    /// Sessions that were closed because the client took too long to log
    /// in.
    pub login_timeouts: u64,
    /// Sessions whose login the database accepted.
    pub logins_finished: u64,
    /// Attempts to connect to the database that failed.
    pub backend_failures: u64,
    /// Cancel requests that were passed on to the database.
    pub cancels_forwarded: u64,
    /// Bytes read from clients.
    pub bytes_from_clients: u64,
    /// Bytes read from the database.
    pub bytes_from_servers: u64,
    /// Events the session logic raised.
    pub events_emitted: u64,
    /// Events that were dropped because too many were waiting to be
    /// delivered.
    pub events_dropped: u64,
    /// Attempts to deliver an event to a sink that failed.
    pub event_delivery_failures: u64,
}

impl Status {
    /// A status that is not ready, with every counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the proxy accepts clients. It does from the moment its
    /// listeners are bound until it is asked to stop.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// The counters as they stand.
    #[must_use]
    pub fn counters(&self) -> Counters {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Counters {
            sessions_accepted: read(&self.sessions_accepted),
            sessions_refused: read(&self.sessions_refused),
            sessions_active: read(&self.sessions_active),
            sessions_failed: read(&self.sessions_failed),
            session_panics: read(&self.session_panics),
            login_timeouts: read(&self.login_timeouts),
            logins_finished: read(&self.logins_finished),
            backend_failures: read(&self.backend_failures),
            cancels_forwarded: read(&self.cancels_forwarded),
            bytes_from_clients: read(&self.bytes_from_clients),
            bytes_from_servers: read(&self.bytes_from_servers),
            events_emitted: read(&self.events_emitted),
            events_dropped: read(&self.events_dropped),
            event_delivery_failures: read(&self.event_delivery_failures),
        }
    }

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    pub(crate) fn session_accepted(&self) {
        self.sessions_accepted.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn session_ended(&self) {
        self.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn session_refused(&self) {
        self.sessions_refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn session_failed(&self) {
        self.sessions_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn session_panicked(&self) {
        self.session_panics.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn login_timed_out(&self) {
        self.login_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn login_finished(&self) {
        self.logins_finished.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn cancel_forwarded(&self) {
        self.cancels_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn read_from_client(&self, bytes: usize) {
        self.bytes_from_clients
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn read_from_server(&self, bytes: usize) {
        self.bytes_from_servers
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn event_emitted(&self) {
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_delivery_failed(&self) {
        self.event_delivery_failures.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_status_is_not_ready_and_counts_nothing() {
        let status = Status::new();
        assert!(!status.is_ready());
        assert_eq!(status.counters(), Counters::default());
    }

    #[test]
    fn the_counters_follow_what_the_runtime_reports() {
        let status = Status::new();
        status.set_ready(true);
        status.session_accepted();
        status.session_accepted();
        status.session_ended();
        status.session_refused();
        status.session_failed();
        status.session_panicked();
        status.login_timed_out();
        status.login_finished();
        status.backend_failed();
        status.cancel_forwarded();
        status.read_from_client(10);
        status.read_from_client(5);
        status.read_from_server(7);
        status.event_emitted();
        status.event_dropped();
        status.event_delivery_failed();

        assert!(status.is_ready());
        let counters = status.counters();
        assert_eq!(counters.sessions_accepted, 2);
        assert_eq!(counters.sessions_active, 1);
        assert_eq!(counters.sessions_refused, 1);
        assert_eq!(counters.sessions_failed, 1);
        assert_eq!(counters.session_panics, 1);
        assert_eq!(counters.login_timeouts, 1);
        assert_eq!(counters.logins_finished, 1);
        assert_eq!(counters.backend_failures, 1);
        assert_eq!(counters.cancels_forwarded, 1);
        assert_eq!(counters.bytes_from_clients, 15);
        assert_eq!(counters.bytes_from_servers, 7);
        assert_eq!(counters.events_emitted, 1);
        assert_eq!(counters.events_dropped, 1);
        assert_eq!(counters.event_delivery_failures, 1);

        status.set_ready(false);
        assert!(!status.is_ready());
    }
}
