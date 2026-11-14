// SPDX-License-Identifier: Apache-2.0

//! The dispatcher: from the session that raised an event to the sinks.
//!
//! ```text
//! sessions --> queue --> dispatcher --+--> queue --> worker --> sink
//!                                     +--> queue --> worker --> sink
//! ```
//!
//! # The data path never waits
//!
//! A session hands an event over with [`Dispatcher::submit`], which puts
//! it into a queue of fixed length and returns. It takes no lock and waits
//! for nothing. When the queue is full the event is dropped and counted.
//!
//! Everything after that happens in tasks of their own. A sink that is
//! slow, that is down or that never answers therefore costs events, which
//! are counted, and never a query.
//!
//! # What the dispatcher does with an event
//!
//! 1. It removes what must not be shown from the texts of the event that
//!    come from the network: see [`crate::redact`].
//! 2. It folds a repeated hit into the event that reported the first one:
//!    see [`super::dedup`](self).
//! 3. It seals the event with an identifier, the time it was raised and
//!    the labels of this instance.
//! 4. It puts the event into the queue of every sink. A queue that is
//!    full drops the event for its sink, and the other sinks still get it.
//!    A quarter of each queue is kept for hits (`token_hit`, `rule_hit`):
//!    other events are dropped once only that share is left, so a flood
//!    of lesser events cannot crowd out a hit.
//!
//! # What a worker does with an event
//!
//! Every sink has a worker, which takes one event after another from the
//! queue of its sink.
//!
//! - **The rate limit.** A sink with a limit delivers at most so many
//!   events per second. An event that comes too early waits in the worker,
//!   while the queue takes what follows.
//! - **One attempt at a time, with a time limit.** An attempt that takes
//!   longer than the sink is allowed is given up.
//! - **Retries with backoff.** An attempt that failed for a reason that
//!   may pass is made again, after a pause that doubles each time, up to
//!   the number of retries the sink is allowed. A sink that refuses an
//!   event for good is not asked again.
//! - **A panic in a sink ends one attempt.** It is counted, and the worker
//!   goes on with the next event.
//!
//! # Everything is bounded
//!
//! The queue between the sessions and the dispatcher, the queue of every
//! sink, the table of events that are being folded, the time of an
//! attempt, the number of retries and the pause between them all have a
//! limit. What does not fit is dropped and counted in
//! [`Status`](crate::runtime::Status): by the dispatcher in
//! `events_dropped`, and by each sink with the reason.
//!
//! # Stopping
//!
//! [`Dispatcher::stop`] lets the queues run empty for a short while, so
//! that the last events of a proxy that stops are still delivered. What is
//! left after that is dropped and counted.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pgsnare_core::event::{Event, EventBody, EventId, EventKind, Labels, Timestamp};
use pgsnare_core::extension::EventSink;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::redact::Redaction;
use crate::runtime::{DropReason, SinkStatus, Status};

use super::SinkOptions;
use super::dedup::{Dedup, Raised};
use super::pace::{LogGate, Pace, SharedLogGate, backoff, jitter};

/// What a dispatcher is started with.
pub(crate) struct DispatcherSettings {
    /// How many events may wait between the sessions and the dispatcher.
    pub(crate) queue_size: usize,
    /// How long repeated hits are folded into one event. Zero turns that
    /// off.
    pub(crate) dedup_window: Duration,
    /// The labels every event carries.
    pub(crate) labels: Labels,
    /// What removes from an event what must not be shown.
    pub(crate) redaction: Redaction,
    /// What gives each event its identifier.
    pub(crate) event_id: fn() -> EventId,
}

/// The share of the queue of a sink that only hits may take: a quarter.
/// A queue of fewer than four places keeps none.
const KEPT_FOR_HITS: usize = 4;

/// One sink as the dispatcher sees it.
struct Outlet {
    queue: mpsc::Sender<Arc<Event>>,
    /// The places of the queue that only a hit may take.
    kept_for_hits: usize,
    status: Arc<SinkStatus>,
    full: LogGate,
}

/// The handle the runtime holds: where sessions hand their events, and
/// what stops the tasks behind it.
pub(crate) struct Dispatcher {
    intake: mpsc::Sender<Raised>,
    status: Arc<Status>,
    full: SharedLogGate,
    stopping: watch::Sender<bool>,
    tasks: Mutex<Option<Tasks>>,
}

struct Tasks {
    dispatcher: JoinHandle<()>,
    workers: Vec<Worker>,
}

struct Worker {
    task: JoinHandle<()>,
    status: Arc<SinkStatus>,
    /// Whether the worker holds an event it has taken from its queue.
    busy: Arc<AtomicBool>,
}

/// Waits for a task until `deadline`. Returns the task when it has not
/// ended by then.
async fn ended_by(deadline: Instant, mut task: JoinHandle<()>) -> Option<JoinHandle<()>> {
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(_) => None,
        Err(_) => Some(task),
    }
}

impl Dispatcher {
    /// Starts the dispatcher and one worker for each sink.
    ///
    /// Must be called inside a tokio runtime.
    pub(crate) fn start(
        settings: DispatcherSettings,
        sinks: Vec<(Arc<dyn EventSink>, SinkOptions)>,
        status: Arc<Status>,
    ) -> Self {
        let queue_size = settings.queue_size.max(1);
        let (intake, raised) = mpsc::channel(queue_size);
        let (stopping, stop) = watch::channel(false);
        status.event_queue_capacity(queue_size);

        let names: Vec<(String, usize)> = unique_names(&sinks, &settings.redaction)
            .into_iter()
            .zip(&sinks)
            .map(|(name, (_, options))| (name, options.queue_size.max(1)))
            .collect();
        let statuses = status.register_sinks(&names);

        let mut outlets = Vec::with_capacity(sinks.len());
        let mut workers = Vec::with_capacity(sinks.len());
        for ((sink, options), sink_status) in sinks.into_iter().zip(statuses) {
            let (queue, events) = mpsc::channel(options.queue_size.max(1));
            let busy = Arc::new(AtomicBool::new(false));
            outlets.push(Outlet {
                queue,
                kept_for_hits: options.queue_size.max(1) / KEPT_FOR_HITS,
                status: Arc::clone(&sink_status),
                full: LogGate::new(),
            });
            let work = WorkerState {
                sink,
                options,
                status: Arc::clone(&sink_status),
                proxy: Arc::clone(&status),
                stop: stop.clone(),
                orphaned: false,
                busy: Arc::clone(&busy),
                trouble: LogGate::new(),
            };
            workers.push(Worker {
                task: tokio::spawn(work.run(events)),
                status: sink_status,
                busy,
            });
        }

        let core = Core {
            raised,
            stop,
            status: Arc::clone(&status),
            redaction: settings.redaction,
            dedup: Dedup::new(settings.dedup_window),
            labels: settings.labels,
            event_id: settings.event_id,
            outlets,
            due: Vec::new(),
        };
        Self {
            intake,
            status,
            full: SharedLogGate::new(Instant::now()),
            stopping,
            tasks: Mutex::new(Some(Tasks {
                dispatcher: tokio::spawn(core.run()),
                workers,
            })),
        }
    }

    /// Takes an event from a session. Returns at once, whatever the sinks
    /// are doing.
    pub(crate) fn submit(&self, body: Box<EventBody>, at: Timestamp) {
        // Counted before it is queued, so that the count can never fall
        // behind the dispatcher taking the event out again.
        self.status.event_queued();
        if self.intake.try_send(Raised { body, at }).is_err() {
            self.status.event_dequeued();
            self.status.event_dropped();
            if let Some(held_back) = self.full.pass(Instant::now()) {
                tracing::warn!(
                    more_like_this = held_back,
                    "an event was dropped: too many are waiting for the dispatcher"
                );
            }
        }
    }

    /// Stops the dispatcher. The events that wait are delivered for up to
    /// `patience`. What is left then is dropped and counted.
    pub(crate) async fn stop(&self, patience: Duration) {
        let tasks = self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(Tasks {
            dispatcher,
            workers,
        }) = tasks
        else {
            return;
        };
        self.stopping.send_replace(true);

        // The dispatcher ends first: it empties its queue into the queues
        // of the sinks. Each worker ends when its queue is empty.
        let deadline = Instant::now() + patience;
        let mut late = Vec::new();
        let mut left = 0u64;
        if let Some(dispatcher) = ended_by(deadline, dispatcher).await {
            dispatcher.abort();
            let _ = dispatcher.await;
            // What it had not taken from its queue reaches no sink.
            let waiting = self.status.counters().event_queue_depth;
            for _ in 0..waiting {
                self.status.event_dequeued();
                self.status.event_dropped();
            }
            left = waiting;
        }
        for worker in workers {
            let Worker { task, status, busy } = worker;
            if let Some(task) = ended_by(deadline, task).await {
                late.push((task, status, busy));
            }
        }

        // Out of time. A worker is ended before what it left behind is
        // counted, so that nothing is counted twice.
        for (task, status, busy) in late {
            task.abort();
            let _ = task.await;
            let waiting = status.counters().queue_depth;
            let held = u64::from(busy.load(Ordering::Relaxed));
            for _ in 0..waiting {
                status.dequeued();
            }
            for _ in 0..waiting.saturating_add(held) {
                status.dropped(DropReason::Stopping);
            }
            left = left.saturating_add(waiting).saturating_add(held);
        }
        if left > 0 {
            tracing::warn!(
                events = left,
                "events were dropped: the sinks did not take them before the proxy stopped"
            );
        }
    }
}

/// The names the sinks go by in metrics and logs: the label of the name
/// each sink gives itself, with a number added where two would be the
/// same.
fn unique_names(sinks: &[(Arc<dyn EventSink>, SinkOptions)], redaction: &Redaction) -> Vec<String> {
    let mut names: Vec<String> = Vec::with_capacity(sinks.len());
    for (sink, _) in sinks {
        let base = redaction.label(sink.name());
        let base = if base.is_empty() {
            "sink".to_owned()
        } else {
            base
        };
        let mut name = base.clone();
        let mut number = 2usize;
        while names.contains(&name) {
            name = format!("{base}-{number}");
            number = number.saturating_add(1);
        }
        names.push(name);
    }
    names
}

/// The dispatcher task.
struct Core {
    raised: mpsc::Receiver<Raised>,
    stop: watch::Receiver<bool>,
    status: Arc<Status>,
    redaction: Redaction,
    dedup: Dedup,
    labels: Labels,
    event_id: fn() -> EventId,
    outlets: Vec<Outlet>,
    /// What is to be delivered next. Kept between events so that it does
    /// not have to be allocated for each.
    due: Vec<Raised>,
}

async fn sleep_until_some(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

impl Core {
    async fn run(mut self) {
        let mut stop_can_change = true;
        loop {
            let next_close = self.dedup.next_close();
            tokio::select! {
                biased;
                raised = self.raised.recv() => match raised {
                    Some(raised) => self.take(raised),
                    // Every handle is gone: nothing can be raised any more.
                    None => break,
                },
                () = sleep_until_some(next_close) => {
                    self.dedup.close_due(Instant::now(), &mut self.due);
                    self.deliver_due();
                }
                changed = self.stop.changed(), if stop_can_change => {
                    if changed.is_err() {
                        stop_can_change = false;
                    } else if *self.stop.borrow() {
                        break;
                    }
                }
            }
        }

        // Stopping: what is in the queue is still taken, and what was
        // being folded is reported now.
        while let Ok(raised) = self.raised.try_recv() {
            self.take(raised);
        }
        self.dedup.close_all(&mut self.due);
        self.deliver_due();
        // Dropping the queues of the sinks tells the workers that nothing
        // more will come.
    }

    fn take(&mut self, mut raised: Raised) {
        self.status.event_dequeued();
        self.status.event_taken(raised.body.kind);
        self.redaction.current().event(&mut raised.body);
        if self.dedup.take(raised, Instant::now(), &mut self.due) {
            self.status.event_deduplicated();
        }
        self.deliver_due();
    }

    /// Seals what is due and puts it into the queue of every sink.
    fn deliver_due(&mut self) {
        for raised in self.due.drain(..) {
            let Raised { body, at } = raised;
            let is_hit = matches!(body.kind, EventKind::TokenHit | EventKind::RuleHit);
            let event = Arc::new((*body).seal((self.event_id)(), at, self.labels.clone()));
            for outlet in &mut self.outlets {
                outlet.status.queued();
                // A flood of lesser events cannot crowd out a hit.
                let room = is_hit || outlet.queue.capacity() > outlet.kept_for_hits;
                if room && outlet.queue.try_send(Arc::clone(&event)).is_ok() {
                    continue;
                }
                outlet.status.dequeued();
                outlet.status.dropped(DropReason::QueueFull);
                if let Some(held_back) = outlet.full.pass(Instant::now()) {
                    tracing::warn!(
                        sink = outlet.status.name(),
                        more_like_this = held_back,
                        "an event was dropped: the queue of the sink is full"
                    );
                }
            }
        }
    }
}

/// How an attempt to deliver an event ended.
enum Attempt {
    Delivered,
    /// It failed. `retry` says whether another attempt can succeed.
    Failed {
        retry: bool,
        reason: String,
    },
}

/// The worker of one sink.
struct WorkerState {
    sink: Arc<dyn EventSink>,
    options: SinkOptions,
    status: Arc<SinkStatus>,
    proxy: Arc<Status>,
    stop: watch::Receiver<bool>,
    /// Whether the handle on the dispatcher is gone, which stops a worker
    /// as a request to stop does.
    orphaned: bool,
    busy: Arc<AtomicBool>,
    trouble: LogGate,
}

/// Ends the task of an attempt when the worker that waits for it goes
/// away.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(context)
    }
}

impl WorkerState {
    async fn run(mut self, mut events: mpsc::Receiver<Arc<Event>>) {
        let mut pace = self
            .options
            .max_events_per_second
            .map(|rate| Pace::new(rate, Instant::now()));
        while let Some(event) = events.recv().await {
            self.busy.store(true, Ordering::Relaxed);
            self.status.dequeued();
            if let Some(pace) = &mut pace {
                let wait = pace.wait(Instant::now());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
            }
            self.deliver(&event).await;
            self.busy.store(false, Ordering::Relaxed);
        }
    }

    /// Delivers one event: the first attempt, and the retries it needs and
    /// is allowed.
    async fn deliver(&mut self, event: &Arc<Event>) {
        let mut retries = 0u32;
        loop {
            let (retry, reason) = match self.attempt(event).await {
                Attempt::Delivered => {
                    self.status.delivered();
                    return;
                }
                Attempt::Failed { retry, reason } => (retry, reason),
            };
            self.status.attempt_failed();
            self.proxy.event_delivery_failed();

            let stopping = self.orphaned || *self.stop.borrow();
            let dropped = if !retry {
                Some(DropReason::Rejected)
            } else if stopping {
                Some(DropReason::Stopping)
            } else if retries >= self.options.max_retries {
                Some(DropReason::RetriesExhausted)
            } else {
                None
            };
            if let Some(dropped) = dropped {
                self.status.dropped(dropped);
                if let Some(held_back) = self.trouble.pass(Instant::now()) {
                    tracing::warn!(
                        sink = self.status.name(),
                        reason = %reason,
                        dropped = dropped.name(),
                        attempts = retries.saturating_add(1),
                        more_like_this = held_back,
                        "an event was dropped: the sink did not take it"
                    );
                }
                return;
            }

            retries = retries.saturating_add(1);
            if let Some(held_back) = self.trouble.pass(Instant::now()) {
                tracing::warn!(
                    sink = self.status.name(),
                    reason = %reason,
                    retry = retries,
                    more_like_this = held_back,
                    "an event could not be delivered and will be tried again"
                );
            }
            // A proxy that stops does not wait out the pause: one more
            // attempt is made at once, and it is the last.
            let pause = tokio::time::sleep(backoff(retries, jitter()));
            let orphaned = tokio::select! {
                () = pause => false,
                stopping = self.stop.wait_for(|stopping| *stopping) => stopping.is_err(),
            };
            self.orphaned |= orphaned;
        }
    }

    /// One attempt, in a task of its own, so that a sink that panics takes
    /// nothing else with it.
    async fn attempt(&self, event: &Arc<Event>) -> Attempt {
        let (sink, event) = (Arc::clone(&self.sink), Arc::clone(event));
        let attempt = AbortOnDrop(tokio::spawn(async move { sink.deliver(&event).await }));
        match tokio::time::timeout(self.options.attempt_timeout, attempt).await {
            Ok(Ok(Ok(()))) => Attempt::Delivered,
            Ok(Ok(Err(error))) => Attempt::Failed {
                retry: error.is_retryable(),
                reason: error.message().to_owned(),
            },
            Ok(Err(ended)) => {
                if ended.is_panic() {
                    self.proxy.sink_panicked();
                    tracing::error!(
                        sink = self.status.name(),
                        "the code of a sink panicked while it delivered an event"
                    );
                }
                Attempt::Failed {
                    retry: false,
                    reason: "the attempt ended without an answer".to_owned(),
                }
            }
            // Dropping the attempt ends its task.
            Err(_) => Attempt::Failed {
                retry: true,
                reason: "the sink did not answer in time".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests;
