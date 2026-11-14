// SPDX-License-Identifier: Apache-2.0

//! What the runtime reports about itself: whether it is ready, and its
//! counters.
//!
//! This is the whole interface between the runtime and whatever exposes
//! health and metrics. The runtime and the dispatcher update a [`Status`].
//! A health endpoint asks [`Status::is_healthy`] and [`Status::is_ready`],
//! and a metrics endpoint takes the [`Counters`], the [`SinkCounters`], the
//! [`HitCounters`] and the [`Histogram`] of added latency. Nothing here
//! formats or serves anything.
//!
//! # Nothing from the network
//!
//! A counter is a number, and what tells two counters of a kind apart is a
//! name from the configuration: the name of a sink, the id of a token or of
//! a rule. Those are the types the methods take, so that nothing a client
//! or a database sent can become the label of a metric.
//!
//! # Where detection counts
//!
//! Queries, hits, responses, statements that could not be parsed and
//! reloads that failed are counted by [`Status::query_seen`],
//! [`Status::token_hit`], [`Status::rule_hit`], [`Status::actions_taken`],
//! [`Status::parse_failed`] and [`Status::reload_failed`]. The session
//! logic decides, and the task that drives a session calls them for the
//! effects it is handed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use pgsnare_core::event::EventKind;
use pgsnare_core::policy::{Action, ActionSet, RuleId, TokenId};

/// The upper bounds of the buckets of the histogram of added latency, in
/// nanoseconds. Observations above the last one fall into a bucket of
/// their own.
const LATENCY_BOUNDS_NANOS: [u64; 15] = [
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_500_000_000,
];

/// How many tokens get a hit counter of their own. A hit of a further token
/// is still part of the totals.
const MAX_HIT_SERIES: usize = 4096;

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
    listener_panics: AtomicU64,
    sink_panics: AtomicU64,
    admin_panics: AtomicU64,
    listener_failures: AtomicU64,
    login_timeouts: AtomicU64,
    logins_finished: AtomicU64,
    backend_failures: AtomicU64,
    cancels_forwarded: AtomicU64,
    bytes_from_clients: AtomicU64,
    bytes_from_servers: AtomicU64,
    read_buffer_bytes: AtomicU64,
    events_emitted: AtomicU64,
    events_dropped: AtomicU64,
    events_deduplicated: AtomicU64,
    event_delivery_failures: AtomicU64,
    event_queue_depth: AtomicU64,
    event_queue_capacity: AtomicU64,
    events_by_kind: [AtomicU64; EVENT_KIND_COUNT],
    queries: AtomicU64,
    token_hits: AtomicU64,
    exempt_token_hits: AtomicU64,
    rule_hits: AtomicU64,
    actions: [AtomicU64; ACTION_COUNT],
    parse_failures: AtomicU64,
    reload_failures: AtomicU64,
    latency: Latency,
    hits: Mutex<Hits>,
    sinks: RwLock<Vec<Arc<SinkStatus>>>,
}

/// The kinds of event that are counted apart, and one more for a kind this
/// build does not know.
const EVENT_KIND_COUNT: usize = 6;

/// The names of [`Counters::events_by_kind`], in its order.
const EVENT_KIND_NAMES: [&str; EVENT_KIND_COUNT] = [
    "token_hit",
    "rule_hit",
    "parse_failure",
    "session_activity",
    "inspection_bypassed",
    "other",
];

const fn event_kind_index(kind: EventKind) -> usize {
    match kind {
        EventKind::TokenHit => 0,
        EventKind::RuleHit => 1,
        EventKind::ParseFailure => 2,
        EventKind::SessionActivity => 3,
        EventKind::InspectionBypassed => 4,
        _ => 5,
    }
}

/// The responses that are counted apart.
const ACTION_COUNT: usize = 4;

/// The names of [`Counters::actions`], in its order.
const ACTION_NAMES: [&str; ACTION_COUNT] = ["alert", "kill", "tarpit", "fake_data"];

const fn action_index(action: Action) -> Option<usize> {
    match action {
        Action::Alert => Some(0),
        Action::Kill => Some(1),
        Action::Tarpit => Some(2),
        Action::FakeData => Some(3),
        _ => None,
    }
}

/// The counters of a proxy at one moment.
///
/// All of them only ever grow, except `sessions_active`,
/// `read_buffer_bytes`, `event_queue_depth` and `event_queue_capacity`,
/// which say what is there right now.
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
    /// Listeners that stopped accepting clients because their code
    /// panicked. This must stay at zero.
    pub listener_panics: u64,
    /// Attempts to deliver an event that ended because the code of a sink
    /// panicked. This must stay at zero.
    pub sink_panics: u64,
    /// Panics in the code that serves the health endpoints and the
    /// metrics. This must stay at zero.
    pub admin_panics: u64,
    /// Listeners that stopped accepting clients while the proxy was meant
    /// to run, for whatever reason. This must stay at zero.
    pub listener_failures: u64,
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
    /// The size of the buffers all open sessions read into, right now. A
    /// session that is quiet holds a small buffer for each direction, and
    /// a busy one a large one.
    pub read_buffer_bytes: u64,
    /// Events the session logic raised.
    pub events_emitted: u64,
    /// Events that never reached the dispatcher, because its queue was
    /// full. What a sink dropped is in its [`SinkCounters`].
    pub events_dropped: u64,
    /// Hits that were folded into another event instead of being delivered
    /// as an event of their own.
    pub events_deduplicated: u64,
    /// Attempts to deliver an event to a sink that failed, for all sinks
    /// together.
    pub event_delivery_failures: u64,
    /// Events that wait for the dispatcher, right now.
    pub event_queue_depth: u64,
    /// How many events may wait for the dispatcher.
    pub event_queue_capacity: u64,
    /// Events the dispatcher took, by kind, in the order of
    /// [`Counters::EVENT_KINDS`].
    pub events_by_kind: [u64; 6],
    /// Statements clients ran.
    pub queries: u64,
    /// Honeytoken hits in sessions that are not exempt.
    pub token_hits: u64,
    /// Honeytoken hits in exempt sessions, which are counted and trigger
    /// nothing.
    pub exempt_token_hits: u64,
    /// Statements that matched an SQL rule.
    pub rule_hits: u64,
    /// Responses that were carried out, in the order of
    /// [`Counters::ACTIONS`].
    pub actions: [u64; 4],
    /// Statements that could not be parsed, so that no rule could judge
    /// them.
    pub parse_failures: u64,
    /// Reloads that were refused, so that the policy stayed as it was.
    pub reload_failures: u64,
}

impl Counters {
    /// The names of the kinds of event in [`Counters::events_by_kind`].
    /// The last one stands for every kind this build does not know.
    pub const EVENT_KINDS: [&'static str; 6] = EVENT_KIND_NAMES;

    /// The names of the responses in [`Counters::actions`].
    pub const ACTIONS: [&'static str; 4] = ACTION_NAMES;
}

/// Why a sink did not deliver an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DropReason {
    /// The queue of the sink was full.
    QueueFull,
    /// The sink said that no further attempt can succeed.
    Rejected,
    /// Every attempt failed, the last retry included.
    RetriesExhausted,
    /// The proxy stopped before the event could be delivered.
    Stopping,
}

impl DropReason {
    /// Every reason, in the order of [`SinkCounters::dropped`].
    pub const ALL: [Self; 4] = [
        Self::QueueFull,
        Self::Rejected,
        Self::RetriesExhausted,
        Self::Stopping,
    ];

    /// A fixed name, for logs and metrics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::Rejected => "rejected",
            Self::RetriesExhausted => "retries_exhausted",
            Self::Stopping => "stopping",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::QueueFull => 0,
            Self::Rejected => 1,
            Self::RetriesExhausted => 2,
            Self::Stopping => 3,
        }
    }
}

/// What the dispatcher counts for one sink.
#[derive(Debug)]
pub struct SinkStatus {
    name: String,
    queue_capacity: u64,
    queue_depth: AtomicU64,
    delivered: AtomicU64,
    failed_attempts: AtomicU64,
    dropped: [AtomicU64; 4],
}

impl SinkStatus {
    /// The name of the sink.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The counters as they stand.
    #[must_use]
    pub fn counters(&self) -> SinkCounters {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        SinkCounters {
            name: self.name.clone(),
            queue_depth: read(&self.queue_depth),
            queue_capacity: self.queue_capacity,
            delivered: read(&self.delivered),
            failed_attempts: read(&self.failed_attempts),
            dropped: [
                read(&self.dropped[0]),
                read(&self.dropped[1]),
                read(&self.dropped[2]),
                read(&self.dropped[3]),
            ],
        }
    }

    pub(crate) fn queued(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dequeued(&self) {
        // Never below zero, whatever the order two threads count in.
        let _ = self
            .queue_depth
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    pub(crate) fn delivered(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn attempt_failed(&self) {
        self.failed_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dropped(&self, reason: DropReason) {
        self.dropped[reason.index()].fetch_add(1, Ordering::Relaxed);
    }
}

/// The counters of one sink at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkCounters {
    /// The name of the sink. It comes from the configuration or from the
    /// code of the sink, never from the network.
    pub name: String,
    /// Events that wait in the queue of the sink, right now.
    pub queue_depth: u64,
    /// How many events may wait in the queue of the sink.
    pub queue_capacity: u64,
    /// Events the sink delivered.
    pub delivered: u64,
    /// Attempts to deliver an event that failed. An event that is tried
    /// again counts once for each failed attempt.
    pub failed_attempts: u64,
    /// Events that were not delivered, by reason, in the order of
    /// [`DropReason::ALL`].
    pub dropped: [u64; 4],
}

impl SinkCounters {
    /// Events that were not delivered, for every reason together.
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped
            .iter()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }
}

/// How often each token and each rule was hit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HitCounters {
    /// For each token that was hit: its id, the hits in sessions that are
    /// not exempt, and the hits in exempt sessions. Ordered by id. A token
    /// that was never hit is not listed.
    pub tokens: Vec<(String, u64, u64)>,
    /// For each rule that matched: its id and how often. Ordered by id.
    pub rules: Vec<(String, u64)>,
}

#[derive(Debug, Default)]
struct Hits {
    /// Hits in sessions that are not exempt, and in exempt ones.
    tokens: BTreeMap<String, (u64, u64)>,
    rules: BTreeMap<String, u64>,
}

/// A histogram at one moment.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Histogram {
    /// The upper bound of each bucket, ascending, in seconds.
    pub bounds: Vec<f64>,
    /// How many observations fell into each bucket: one count for each
    /// bound, and a last one for everything above the largest bound. The
    /// counts are not cumulative.
    pub counts: Vec<u64>,
    /// The sum of all observations, in seconds.
    pub sum: f64,
}

impl Histogram {
    /// How many observations there were.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.counts
            .iter()
            .fold(0u64, |sum, count| sum.saturating_add(*count))
    }
}

/// The histogram of added latency. Observing takes no lock.
#[derive(Debug, Default)]
struct Latency {
    buckets: [AtomicU64; LATENCY_BOUNDS_NANOS.len() + 1],
    sum_nanos: AtomicU64,
}

impl Latency {
    fn observe(&self, latency: Duration) {
        let nanos = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        let bucket = LATENCY_BOUNDS_NANOS
            .iter()
            .position(|bound| nanos <= *bound)
            .unwrap_or(LATENCY_BOUNDS_NANOS.len());
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    fn snapshot(&self) -> Histogram {
        // A count of nanoseconds that an `f64` cannot hold exactly is far
        // beyond what a histogram of latencies has to tell apart.
        let seconds = |nanos: u64| nanos as f64 / 1e9;
        Histogram {
            bounds: LATENCY_BOUNDS_NANOS.iter().copied().map(seconds).collect(),
            counts: self
                .buckets
                .iter()
                .map(|bucket| bucket.load(Ordering::Relaxed))
                .collect(),
            sum: seconds(self.sum_nanos.load(Ordering::Relaxed)),
        }
    }
}

impl Status {
    /// A status that is not ready, with every counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the proxy accepts clients. It does from the moment its
    /// listeners are served until it is asked to stop, or until one of its
    /// listeners fails.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Whether the proxy works as it should. It does not once one of its
    /// listeners has stopped accepting clients without having been asked
    /// to.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.listener_failures.load(Ordering::Relaxed) == 0
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
            listener_panics: read(&self.listener_panics),
            sink_panics: read(&self.sink_panics),
            admin_panics: read(&self.admin_panics),
            listener_failures: read(&self.listener_failures),
            login_timeouts: read(&self.login_timeouts),
            logins_finished: read(&self.logins_finished),
            backend_failures: read(&self.backend_failures),
            cancels_forwarded: read(&self.cancels_forwarded),
            bytes_from_clients: read(&self.bytes_from_clients),
            bytes_from_servers: read(&self.bytes_from_servers),
            read_buffer_bytes: read(&self.read_buffer_bytes),
            events_emitted: read(&self.events_emitted),
            events_dropped: read(&self.events_dropped),
            events_deduplicated: read(&self.events_deduplicated),
            event_delivery_failures: read(&self.event_delivery_failures),
            event_queue_depth: read(&self.event_queue_depth),
            event_queue_capacity: read(&self.event_queue_capacity),
            events_by_kind: self.events_by_kind.each_ref().map(read),
            queries: read(&self.queries),
            token_hits: read(&self.token_hits),
            exempt_token_hits: read(&self.exempt_token_hits),
            rule_hits: read(&self.rule_hits),
            actions: self.actions.each_ref().map(read),
            parse_failures: read(&self.parse_failures),
            reload_failures: read(&self.reload_failures),
        }
    }

    /// The counters of every sink, in the order the sinks were added to the
    /// proxy.
    #[must_use]
    pub fn sinks(&self) -> Vec<SinkCounters> {
        self.sinks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|sink| sink.counters())
            .collect()
    }

    /// How often each token and each rule was hit.
    #[must_use]
    pub fn hits(&self) -> HitCounters {
        let hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        HitCounters {
            tokens: hits
                .tokens
                .iter()
                .map(|(id, (hits, exempt))| (id.clone(), *hits, *exempt))
                .collect(),
            rules: hits
                .rules
                .iter()
                .map(|(id, hits)| (id.clone(), *hits))
                .collect(),
        }
    }

    /// The histogram of added latency: for what a session read from one
    /// connection, the time until everything that came of it was written
    /// to the other connection.
    #[must_use]
    pub fn added_latency(&self) -> Histogram {
        self.latency.snapshot()
    }

    // ----------------------------------------------------------------------
    // What detection counts
    // ----------------------------------------------------------------------

    /// A client ran a statement.
    pub fn query_seen(&self) {
        self.queries.fetch_add(1, Ordering::Relaxed);
    }

    /// A honeytoken was hit. `exempt` says that the session is exempt, so
    /// that the hit is counted and triggers nothing.
    ///
    /// The token is named by its id, which comes from the configuration.
    pub fn token_hit(&self, token: &TokenId, exempt: bool) {
        let total = if exempt {
            &self.exempt_token_hits
        } else {
            &self.token_hits
        };
        total.fetch_add(1, Ordering::Relaxed);

        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        if !hits.tokens.contains_key(token.as_str()) && hits.tokens.len() >= MAX_HIT_SERIES {
            return;
        }
        let counts = hits.tokens.entry(token.as_str().to_owned()).or_default();
        let count = if exempt { &mut counts.1 } else { &mut counts.0 };
        *count = count.saturating_add(1);
    }

    /// A statement matched an SQL rule.
    ///
    /// The rule is named by its id, which comes from the configuration.
    pub fn rule_hit(&self, rule: &RuleId) {
        self.rule_hits.fetch_add(1, Ordering::Relaxed);
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        if !hits.rules.contains_key(rule.as_str()) && hits.rules.len() >= MAX_HIT_SERIES {
            return;
        }
        let count = hits.rules.entry(rule.as_str().to_owned()).or_default();
        *count = count.saturating_add(1);
    }

    /// These responses were carried out for one hit.
    pub fn actions_taken(&self, actions: ActionSet) {
        for index in actions.iter().filter_map(action_index) {
            self.actions[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A statement could not be parsed, so that no rule could judge it.
    pub fn parse_failed(&self) {
        self.parse_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A reload was refused, and the policy stays as it was.
    pub fn reload_failed(&self) {
        self.reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    // ----------------------------------------------------------------------
    // What the runtime counts
    // ----------------------------------------------------------------------

    pub(crate) fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    /// A listener stopped accepting clients while the proxy was meant to
    /// run. From here on the proxy is neither ready nor healthy.
    pub(crate) fn listener_failed(&self, panicked: bool) {
        self.ready.store(false, Ordering::Relaxed);
        self.listener_failures.fetch_add(1, Ordering::Relaxed);
        if panicked {
            self.listener_panics.fetch_add(1, Ordering::Relaxed);
        }
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

    /// A session's read buffer changed its size, from `old` to `new`
    /// bytes. A buffer that comes into being was 0 bytes before, and one
    /// that goes away is 0 bytes after.
    pub(crate) fn read_buffer_resized(&self, old: usize, new: usize) {
        let (old, new) = (
            u64::try_from(old).unwrap_or(u64::MAX),
            u64::try_from(new).unwrap_or(u64::MAX),
        );
        if new >= old {
            self.read_buffer_bytes
                .fetch_add(new.saturating_sub(old), Ordering::Relaxed);
        } else {
            self.read_buffer_bytes
                .fetch_sub(old.saturating_sub(new), Ordering::Relaxed);
        }
    }

    /// Everything a session read at one moment has reached the other
    /// connection, this long after it was read.
    pub(crate) fn latency_added(&self, latency: Duration) {
        self.latency.observe(latency);
    }

    // ----------------------------------------------------------------------
    // What the dispatcher counts
    // ----------------------------------------------------------------------

    pub(crate) fn event_emitted(&self) {
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// An event did not fit into the queue of the dispatcher.
    pub(crate) fn event_dropped(&self) {
        self.events_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_delivery_failed(&self) {
        self.event_delivery_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_deduplicated(&self) {
        self.events_deduplicated.fetch_add(1, Ordering::Relaxed);
    }

    /// The dispatcher took an event of this kind from its queue.
    pub(crate) fn event_taken(&self, kind: EventKind) {
        self.events_by_kind[event_kind_index(kind)].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_queue_capacity(&self, capacity: usize) {
        self.event_queue_capacity.store(
            u64::try_from(capacity).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn event_queued(&self) {
        self.event_queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event_dequeued(&self) {
        let _ = self
            .event_queue_depth
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                Some(depth.saturating_sub(1))
            });
    }

    /// The code of a sink panicked while it delivered an event.
    pub(crate) fn sink_panicked(&self) {
        self.sink_panics.fetch_add(1, Ordering::Relaxed);
    }

    /// The code that serves the health endpoints or the metrics panicked.
    pub(crate) fn admin_panicked(&self) {
        self.admin_panics.fetch_add(1, Ordering::Relaxed);
    }

    /// Makes the counters of the sinks of a proxy, one for each name and
    /// queue length, and keeps them for [`Status::sinks`]. The sinks a
    /// status knew before are forgotten.
    pub(crate) fn register_sinks(&self, sinks: &[(String, usize)]) -> Vec<Arc<SinkStatus>> {
        let registered: Vec<Arc<SinkStatus>> = sinks
            .iter()
            .map(|(name, queue_capacity)| {
                Arc::new(SinkStatus {
                    name: name.clone(),
                    queue_capacity: u64::try_from(*queue_capacity).unwrap_or(u64::MAX),
                    queue_depth: AtomicU64::new(0),
                    delivered: AtomicU64::new(0),
                    failed_attempts: AtomicU64::new(0),
                    dropped: Default::default(),
                })
            })
            .collect();
        *self.sinks.write().unwrap_or_else(PoisonError::into_inner) = registered.clone();
        registered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_status_is_not_ready_and_counts_nothing() {
        let status = Status::new();
        assert!(!status.is_ready());
        assert!(status.is_healthy());
        assert_eq!(status.counters(), Counters::default());
        assert!(status.sinks().is_empty());
        assert_eq!(status.hits(), HitCounters::default());
        assert_eq!(status.added_latency().count(), 0);
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
        status.read_buffer_resized(0, 1024);
        status.read_buffer_resized(0, 1024);
        status.read_buffer_resized(1024, 65536);
        status.read_buffer_resized(1024, 0);
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
        assert_eq!(counters.read_buffer_bytes, 65536);
        assert_eq!(counters.events_emitted, 1);
        assert_eq!(counters.events_dropped, 1);
        assert_eq!(counters.event_delivery_failures, 1);

        status.set_ready(false);
        assert!(!status.is_ready());
    }

    #[test]
    fn a_listener_that_fails_makes_the_proxy_unready_and_unhealthy() {
        let status = Status::new();
        status.set_ready(true);
        assert!(status.is_healthy());

        status.listener_failed(true);
        assert!(!status.is_ready());
        assert!(!status.is_healthy());
        assert_eq!(status.counters().listener_failures, 1);
        assert_eq!(status.counters().listener_panics, 1);

        // A listener that ended without a panic has failed all the same.
        status.listener_failed(false);
        assert_eq!(status.counters().listener_failures, 2);
        assert_eq!(status.counters().listener_panics, 1);
    }

    #[test]
    fn the_dispatcher_counts_what_it_takes_and_what_waits() {
        let status = Status::new();
        status.event_queue_capacity(8);
        status.event_queued();
        status.event_queued();
        status.event_dequeued();
        status.event_taken(EventKind::TokenHit);
        status.event_taken(EventKind::InspectionBypassed);
        status.event_taken(EventKind::InspectionBypassed);
        status.event_deduplicated();
        status.sink_panicked();
        status.admin_panicked();

        let counters = status.counters();
        assert_eq!(counters.event_queue_capacity, 8);
        assert_eq!(counters.event_queue_depth, 1);
        assert_eq!(counters.events_by_kind, [1, 0, 0, 0, 2, 0]);
        assert_eq!(counters.events_deduplicated, 1);
        assert_eq!(counters.sink_panics, 1);
        assert_eq!(counters.admin_panics, 1);

        // A queue is never emptier than empty.
        status.event_dequeued();
        status.event_dequeued();
        assert_eq!(status.counters().event_queue_depth, 0);
    }

    #[test]
    fn every_sink_has_counters_of_its_own() {
        let status = Status::new();
        let sinks =
            status.register_sinks(&[("webhook-0".to_owned(), 4), ("stdout-1".to_owned(), 2)]);
        assert_eq!(sinks[0].name(), "webhook-0");

        sinks[0].queued();
        sinks[0].queued();
        sinks[0].dequeued();
        sinks[0].delivered();
        sinks[0].attempt_failed();
        sinks[0].dropped(DropReason::QueueFull);
        sinks[0].dropped(DropReason::RetriesExhausted);
        sinks[0].dropped(DropReason::RetriesExhausted);
        sinks[1].dropped(DropReason::Rejected);
        sinks[1].dropped(DropReason::Stopping);
        sinks[1].dequeued();

        let counters = status.sinks();
        assert_eq!(counters.len(), 2);
        assert_eq!(counters[0].name, "webhook-0");
        assert_eq!(counters[0].queue_capacity, 4);
        assert_eq!(counters[0].queue_depth, 1);
        assert_eq!(counters[0].delivered, 1);
        assert_eq!(counters[0].failed_attempts, 1);
        assert_eq!(counters[0].dropped, [1, 0, 2, 0]);
        assert_eq!(counters[0].dropped_total(), 3);
        assert_eq!(counters[1].name, "stdout-1");
        assert_eq!(counters[1].queue_depth, 0);
        assert_eq!(counters[1].dropped, [0, 1, 0, 1]);

        let names: Vec<&str> = DropReason::ALL.iter().map(|reason| reason.name()).collect();
        assert_eq!(
            names,
            ["queue_full", "rejected", "retries_exhausted", "stopping"]
        );
    }

    #[test]
    fn detection_has_a_place_to_count_into() {
        let status = Status::new();
        let backup = TokenId::new("users-admin-backup").unwrap();
        let card = TokenId::new("card-test-0002").unwrap();
        let rule = RuleId::new("catalog_enumeration").unwrap();

        status.query_seen();
        status.query_seen();
        status.token_hit(&backup, false);
        status.token_hit(&backup, false);
        status.token_hit(&backup, true);
        status.token_hit(&card, true);
        status.rule_hit(&rule);
        status.actions_taken(ActionSet::of(&[Action::Alert, Action::Kill]));
        status.actions_taken(ActionSet::ALERT);
        status.actions_taken(ActionSet::EMPTY);
        status.parse_failed();
        status.reload_failed();

        let counters = status.counters();
        assert_eq!(counters.queries, 2);
        assert_eq!(counters.token_hits, 2);
        assert_eq!(counters.exempt_token_hits, 2);
        assert_eq!(counters.rule_hits, 1);
        assert_eq!(counters.actions, [2, 1, 0, 0]);
        assert_eq!(counters.parse_failures, 1);
        assert_eq!(counters.reload_failures, 1);
        assert_eq!(Counters::ACTIONS, ["alert", "kill", "tarpit", "fake_data"]);
        assert_eq!(Counters::EVENT_KINDS[4], "inspection_bypassed");

        // Only tokens that were hit are listed, ordered by id.
        assert_eq!(
            status.hits(),
            HitCounters {
                tokens: vec![
                    ("card-test-0002".to_owned(), 0, 1),
                    ("users-admin-backup".to_owned(), 2, 1),
                ],
                rules: vec![("catalog_enumeration".to_owned(), 1)],
            }
        );
    }

    #[test]
    fn the_tokens_that_are_counted_apart_are_bounded() {
        let status = Status::new();
        for index in 0..MAX_HIT_SERIES + 10 {
            status.token_hit(&TokenId::new(&format!("token-{index}")).unwrap(), false);
        }
        // Every hit is in the total, and the list stops growing.
        assert_eq!(
            status.counters().token_hits,
            u64::try_from(MAX_HIT_SERIES + 10).unwrap()
        );
        assert_eq!(status.hits().tokens.len(), MAX_HIT_SERIES);
        // A token that has a counter keeps counting.
        status.token_hit(&TokenId::new("token-0").unwrap(), false);
        let hits = status.hits();
        let first = hits
            .tokens
            .iter()
            .find(|(id, _, _)| id == "token-0")
            .unwrap();
        assert_eq!(first.1, 2);
    }

    #[test]
    fn added_latency_is_sorted_into_buckets() {
        let status = Status::new();
        status.latency_added(Duration::from_micros(10));
        status.latency_added(Duration::from_micros(50));
        status.latency_added(Duration::from_micros(51));
        status.latency_added(Duration::from_millis(2));
        status.latency_added(Duration::from_secs(60));

        let histogram = status.added_latency();
        assert_eq!(histogram.bounds.len(), LATENCY_BOUNDS_NANOS.len());
        assert_eq!(histogram.counts.len(), LATENCY_BOUNDS_NANOS.len() + 1);
        assert!(histogram.bounds.windows(2).all(|pair| pair[0] < pair[1]));
        assert!((histogram.bounds[0] - 0.000_05).abs() < 1e-12);

        // 10 and 50 microseconds: the first bucket, whose bound is included.
        assert_eq!(histogram.counts[0], 2);
        assert_eq!(histogram.counts[1], 1);
        // 2 milliseconds: the bucket up to 2.5 milliseconds.
        assert_eq!(histogram.counts[5], 1);
        // A minute is above every bound.
        assert_eq!(*histogram.counts.last().unwrap(), 1);
        assert_eq!(histogram.count(), 5);
        assert!(
            (histogram.sum - 60.002_111).abs() < 1e-6,
            "{}",
            histogram.sum
        );
    }
}
