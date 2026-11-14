// SPDX-License-Identifier: Apache-2.0

//! Tests of the dispatcher.
//!
//! The clock of these tests stands still unless a test waits, and then
//! jumps to the next moment anything is due. A window of a minute and a
//! sink that never answers therefore take no time, and what a test sees is
//! the same on every run.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU64;

use pgsnare_core::event::{EventKind, SessionId};
use pgsnare_core::extension::{SinkError, SinkFuture};
use pgsnare_core::policy::{Action, ActionSet, TokenId};
use pgsnare_core::session::SessionOrigin;

use crate::redact::{REDACTED, Redactor};
use crate::sinks::pace::{FIRST_BACKOFF, MAX_BACKOFF};

use super::*;

/// What a test sink does with one attempt.
#[derive(Clone, Debug)]
enum Do {
    /// Take the event.
    Take,
    /// Fail in a way that may pass.
    FailForNow,
    /// Refuse for good.
    Refuse,
    /// Never answer.
    Hang,
    /// Panic.
    Panic,
}

/// A sink that does what a test tells it, attempt by attempt, and keeps
/// what it took.
struct Scripted {
    name: String,
    /// What to do with the next attempts. When this runs out, `then` is
    /// done for ever.
    script: Mutex<VecDeque<Do>>,
    then: Do,
    /// When each attempt began.
    attempts: Mutex<Vec<Instant>>,
    taken: Mutex<Vec<(Instant, Event)>>,
}

impl Scripted {
    fn new(name: &str, script: &[Do], then: Do) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            script: Mutex::new(script.iter().cloned().collect()),
            then,
            attempts: Mutex::default(),
            taken: Mutex::default(),
        })
    }

    /// A sink that takes everything.
    fn taking(name: &str) -> Arc<Self> {
        Self::new(name, &[], Do::Take)
    }

    fn taken(&self) -> Vec<Event> {
        self.taken
            .lock()
            .unwrap()
            .iter()
            .map(|(_, event)| event.clone())
            .collect()
    }

    fn taken_at(&self) -> Vec<Instant> {
        self.taken
            .lock()
            .unwrap()
            .iter()
            .map(|(at, _)| *at)
            .collect()
    }

    fn attempts(&self) -> Vec<Instant> {
        self.attempts.lock().unwrap().clone()
    }
}

impl EventSink for Scripted {
    fn name(&self) -> &str {
        &self.name
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push(Instant::now());
            let what = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.then.clone());
            match what {
                Do::Take => {
                    self.taken
                        .lock()
                        .unwrap()
                        .push((Instant::now(), event.clone()));
                    Ok(())
                }
                Do::FailForNow => Err(SinkError::retryable("not now")),
                Do::Refuse => Err(SinkError::permanent("never")),
                Do::Hang => std::future::pending().await,
                Do::Panic => panic!("a panic that a test asked for"),
            }
        })
    }
}

fn identifier() -> EventId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    EventId::from_u128(u128::from(NEXT.fetch_add(1, Ordering::Relaxed)))
}

fn settings() -> DispatcherSettings {
    DispatcherSettings {
        queue_size: 64,
        dedup_window: Duration::from_secs(60),
        labels: Labels::from([("POD_NAME".to_owned(), "pgsnare-0".to_owned())]),
        redaction: Redaction::default(),
        event_id: identifier,
    }
}

fn origin(session: u128) -> SessionOrigin {
    SessionOrigin::new(
        SessionId::from_u128(session),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        49_152,
        true,
    )
}

/// An event that is never folded. `row` tells the events of a test apart.
fn bypass(row: u64) -> Box<EventBody> {
    let mut body = EventBody::new(EventKind::InspectionBypassed, &origin(1));
    body.rows_so_far = Some(row);
    Box::new(body)
}

fn hit(session: u128, token: &str, row: u64) -> Box<EventBody> {
    let mut body = EventBody::new(EventKind::TokenHit, &origin(session));
    body.token_id = Some(TokenId::new(token).unwrap());
    body.action_taken = ActionSet::ALERT;
    body.rows_so_far = Some(row);
    Box::new(body)
}

fn at(micros: u64) -> Timestamp {
    Timestamp::from_unix_micros(micros).unwrap()
}

fn rows(events: &[Event]) -> Vec<u64> {
    events
        .iter()
        .map(|event| event.body.rows_so_far.unwrap())
        .collect()
}

/// Lets every task run until none of them can go on without time passing.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

fn start(
    settings: DispatcherSettings,
    sinks: Vec<(Arc<Scripted>, SinkOptions)>,
) -> (Dispatcher, Arc<Status>) {
    let status = Arc::new(Status::new());
    let sinks = sinks
        .into_iter()
        .map(|(sink, options)| (sink as Arc<dyn EventSink>, options))
        .collect();
    (
        Dispatcher::start(settings, sinks, Arc::clone(&status)),
        status,
    )
}

#[tokio::test(start_paused = true)]
async fn an_event_is_sealed_and_reaches_every_sink() {
    let (first, second) = (Scripted::taking("first"), Scripted::taking("second"));
    let (dispatcher, status) = start(
        settings(),
        vec![
            (first.clone(), SinkOptions::default()),
            (second.clone(), SinkOptions::default()),
        ],
    );

    dispatcher.submit(bypass(1), at(1_000));
    dispatcher.submit(bypass(2), at(2_000));
    settle().await;

    for sink in [&first, &second] {
        let taken = sink.taken();
        assert_eq!(rows(&taken), [1, 2]);
        assert_eq!(taken[0].timestamp, at(1_000));
        assert_eq!(taken[1].timestamp, at(2_000));
        assert_eq!(taken[0].labels["POD_NAME"], "pgsnare-0");
        assert_ne!(taken[0].event_id, taken[1].event_id);
        assert_eq!(taken[0].body.kind, EventKind::InspectionBypassed);
    }
    // Every sink is given the same event.
    assert_eq!(first.taken(), second.taken());

    let counters = status.counters();
    assert_eq!(counters.events_dropped, 0);
    assert_eq!(counters.event_queue_depth, 0);
    assert_eq!(counters.event_queue_capacity, 64);
    assert_eq!(counters.events_by_kind, [0, 0, 0, 0, 2, 0]);
    let sinks = status.sinks();
    assert_eq!(sinks.len(), 2);
    assert_eq!((sinks[0].name.as_str(), sinks[0].delivered), ("first", 2));
    assert_eq!((sinks[1].name.as_str(), sinks[1].delivered), ("second", 2));
    assert_eq!(sinks[0].queue_depth, 0);
    assert_eq!(sinks[0].queue_capacity, 1_024);
    assert_eq!(sinks[0].dropped_total(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_sink_that_never_answers_costs_events_and_never_a_wait() {
    let stuck = Scripted::new("stuck", &[], Do::Hang);
    let fine = Scripted::taking("fine");
    let (dispatcher, status) = start(
        DispatcherSettings {
            queue_size: 4,
            ..settings()
        },
        vec![
            (
                stuck.clone(),
                SinkOptions::new()
                    .with_queue_size(2)
                    .with_attempt_timeout(Duration::from_secs(3600)),
            ),
            (fine.clone(), SinkOptions::default()),
        ],
    );

    // A hundred events in one go. `submit` is not even asynchronous: there
    // is nothing in it that could wait. The test does not yield in between,
    // so the dispatcher gets no chance to run and its queue fills up.
    for row in 1..=100 {
        dispatcher.submit(bypass(row), at(row));
    }
    let counters = status.counters();
    assert_eq!(counters.event_queue_depth, 4);
    assert_eq!(counters.events_dropped, 96);

    // The dispatcher takes the four. The sink that works gets them all.
    // The queue of the sink that hangs has room for two: the third and
    // the fourth are dropped, for that sink alone. Its worker then takes
    // the first and holds it for ever.
    settle().await;
    assert_eq!(rows(&fine.taken()), [1, 2, 3, 4]);
    assert!(stuck.taken().is_empty());
    assert_eq!(stuck.attempts().len(), 1);
    let sinks = status.sinks();
    assert_eq!(sinks[0].queue_depth, 1);
    assert_eq!(sinks[0].queue_capacity, 2);
    assert_eq!(sinks[0].dropped, [2, 0, 0, 0]);
    assert_eq!(sinks[1].delivered, 4);
    assert_eq!(sinks[1].dropped_total(), 0);
    assert_eq!(status.counters().event_queue_depth, 0);

    // It goes on like that: every further event reaches the sink that
    // works. The queue of the one that hangs takes one more and no other,
    // and nobody waits.
    for row in 101..=104 {
        dispatcher.submit(bypass(row), at(row));
    }
    settle().await;
    assert_eq!(rows(&fine.taken()), [1, 2, 3, 4, 101, 102, 103, 104]);
    assert_eq!(status.sinks()[0].queue_depth, 2);
    assert_eq!(status.sinks()[0].dropped, [5, 0, 0, 0]);
    assert_eq!(status.counters().events_dropped, 96);
}

#[tokio::test(start_paused = true)]
async fn what_must_not_be_shown_is_removed_before_any_sink_sees_the_event() {
    const VALUE: &str = "svc.backup.8f3k2q@mail.example";
    let sink = Scripted::taking("sink");
    let redaction = Redaction::new(
        Redactor::builder()
            .token("users-admin-backup", [VALUE], false)
            .build()
            .unwrap(),
    );
    let (dispatcher, _status) = start(
        DispatcherSettings {
            redaction: redaction.clone(),
            ..settings()
        },
        vec![(sink.clone(), SinkOptions::default())],
    );

    let mut body = hit(1, "users-admin-backup", 1);
    body.db_user = Some(VALUE.to_owned());
    body.application_name = Some(format!("psql {VALUE}"));
    dispatcher.submit(body, at(1));
    settle().await;

    let taken = sink.taken();
    assert_eq!(taken[0].body.db_user.as_deref(), Some(REDACTED));
    assert_eq!(
        taken[0].body.application_name.as_deref(),
        Some("psql [redacted]")
    );
    // The id of the token is what an event names it by.
    assert_eq!(
        taken[0].body.token_id.as_ref().unwrap().as_str(),
        "users-admin-backup"
    );
    assert!(!serde_json::to_string(&taken[0]).unwrap().contains(VALUE));

    // A redactor that is put in force later is used from then on.
    redaction.replace(Redactor::nothing());
    let mut body = bypass(2);
    body.db_user = Some(VALUE.to_owned());
    dispatcher.submit(body, at(2));
    settle().await;
    assert_eq!(sink.taken()[1].body.db_user.as_deref(), Some(VALUE));
}

#[tokio::test(start_paused = true)]
async fn repeated_hits_are_one_event_now_and_one_when_the_window_closes() {
    let sink = Scripted::taking("sink");
    let (dispatcher, status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);
    let began = Instant::now();

    for row in 1..=5 {
        dispatcher.submit(hit(1, "users-admin-backup", row), at(row));
    }
    // Another session and another token are told apart.
    dispatcher.submit(hit(2, "users-admin-backup", 6), at(6));
    dispatcher.submit(hit(1, "card-test-0002", 7), at(7));
    settle().await;

    // The first hit of each is delivered at once, with nothing held back.
    let taken = sink.taken();
    assert_eq!(rows(&taken), [1, 6, 7]);
    assert!(taken.iter().all(|event| event.body.hit_count == 1));
    assert!(
        sink.taken_at()
            .iter()
            .all(|at| *at - began < Duration::from_secs(1))
    );
    assert_eq!(status.counters().events_deduplicated, 4);
    assert_eq!(status.counters().events_by_kind[0], 7);

    // Nothing more before the window closes.
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert_eq!(sink.taken().len(), 3);

    // When it does, one event stands for the four that were folded: the
    // last of them, under an identifier of its own.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let taken = sink.taken();
    assert_eq!(rows(&taken), [1, 6, 7, 5]);
    assert_eq!(taken[3].body.hit_count, 4);
    assert_eq!(taken[3].timestamp, at(5));
    assert_ne!(taken[3].event_id, taken[0].event_id);
    assert!(sink.taken_at()[3] - began >= Duration::from_secs(60));

    // After that the next hit is news again.
    dispatcher.submit(hit(1, "users-admin-backup", 8), at(8));
    settle().await;
    assert_eq!(rows(&sink.taken()), [1, 6, 7, 5, 8]);
}

#[tokio::test(start_paused = true)]
async fn a_hit_that_was_answered_differently_is_delivered_at_once() {
    let sink = Scripted::taking("sink");
    let (dispatcher, _status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);

    dispatcher.submit(hit(1, "users-admin-backup", 1), at(1));
    dispatcher.submit(hit(1, "users-admin-backup", 2), at(2));
    let mut killed = hit(1, "users-admin-backup", 3);
    killed.action_taken = ActionSet::of(&[Action::Alert, Action::Kill]);
    dispatcher.submit(killed, at(3));
    settle().await;

    let taken = sink.taken();
    assert_eq!(rows(&taken), [1, 2, 3]);
    assert!(taken[2].body.action_taken.contains(Action::Kill));
}

#[tokio::test(start_paused = true)]
async fn a_window_of_zero_delivers_every_hit() {
    let sink = Scripted::taking("sink");
    let (dispatcher, status) = start(
        DispatcherSettings {
            dedup_window: Duration::ZERO,
            ..settings()
        },
        vec![(sink.clone(), SinkOptions::default())],
    );
    for row in 1..=3 {
        dispatcher.submit(hit(1, "users-admin-backup", row), at(row));
    }
    settle().await;
    assert_eq!(rows(&sink.taken()), [1, 2, 3]);
    assert_eq!(status.counters().events_deduplicated, 0);
}

#[tokio::test(start_paused = true)]
async fn a_sink_with_a_rate_limit_is_given_no_more_than_that() {
    let sink = Scripted::taking("limited");
    let (dispatcher, status) = start(
        settings(),
        vec![(
            sink.clone(),
            SinkOptions::new()
                .with_queue_size(4)
                .with_max_events_per_second(Some(2)),
        )],
    );
    let began = Instant::now();

    // Four events for a sink that takes two per second: a second's worth
    // goes out at once, the third waits in the worker for its turn, and
    // the fourth waits in the queue.
    for row in 1..=4 {
        dispatcher.submit(bypass(row), at(row));
    }
    settle().await;
    assert_eq!(rows(&sink.taken()), [1, 2]);
    assert_eq!(status.sinks()[0].queue_depth, 1);

    // Six more: the queue has room for three of them, and the other three
    // are dropped. Nothing is delivered early to make room.
    for row in 5..=10 {
        dispatcher.submit(bypass(row), at(row));
    }
    settle().await;
    assert_eq!(rows(&sink.taken()), [1, 2]);
    assert_eq!(status.sinks()[0].dropped, [3, 0, 0, 0]);
    assert_eq!(status.sinks()[0].queue_depth, 4);

    // The rest follows at two per second.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(rows(&sink.taken()), [1, 2, 3, 4, 5, 6, 7]);
    let after: Vec<Duration> = sink.taken_at().iter().map(|at| *at - began).collect();
    for (index, half_seconds) in [(2, 1), (3, 2), (4, 3), (5, 4), (6, 5)] {
        assert_eq!(
            after[index],
            Duration::from_millis(500) * half_seconds,
            "{after:?}"
        );
    }
    assert_eq!(status.sinks()[0].delivered, 7);
    assert_eq!(status.sinks()[0].queue_depth, 0);
}

#[tokio::test(start_paused = true)]
async fn a_failed_attempt_is_made_again_after_a_pause_that_grows() {
    let sink = Scripted::new(
        "flaky",
        &[Do::FailForNow, Do::FailForNow, Do::FailForNow],
        Do::Take,
    );
    let (dispatcher, status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);

    dispatcher.submit(bypass(1), at(1));
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Three failures, then it is taken: delivered once.
    assert_eq!(rows(&sink.taken()), [1]);
    let attempts = sink.attempts();
    assert_eq!(attempts.len(), 4);
    let sinks = status.sinks();
    assert_eq!(sinks[0].delivered, 1);
    assert_eq!(sinks[0].failed_attempts, 3);
    assert_eq!(sinks[0].dropped_total(), 0);
    assert_eq!(status.counters().event_delivery_failures, 3);

    // Each pause is between half of its full length and all of it, and the
    // full length doubles.
    let pauses: Vec<Duration> = attempts.windows(2).map(|pair| pair[1] - pair[0]).collect();
    for (pause, full) in pauses
        .iter()
        .zip([FIRST_BACKOFF, FIRST_BACKOFF * 2, FIRST_BACKOFF * 4])
    {
        assert!(*pause >= full / 2 && *pause <= full, "{pauses:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn after_the_last_retry_the_event_is_dropped_and_the_next_one_gets_its_turn() {
    let sink = Scripted::new(
        "down",
        &[Do::FailForNow, Do::FailForNow, Do::FailForNow],
        Do::Take,
    );
    let (dispatcher, status) = start(
        settings(),
        vec![(sink.clone(), SinkOptions::new().with_max_retries(2))],
    );

    dispatcher.submit(bypass(1), at(1));
    dispatcher.submit(bypass(2), at(2));
    tokio::time::sleep(Duration::from_secs(60)).await;

    // The first event: one attempt and two retries, all failed. The second
    // is delivered.
    assert_eq!(sink.attempts().len(), 4);
    assert_eq!(rows(&sink.taken()), [2]);
    let sinks = status.sinks();
    assert_eq!(sinks[0].failed_attempts, 3);
    assert_eq!(sinks[0].dropped, [0, 0, 1, 0]);
    assert_eq!(sinks[0].delivered, 1);
}

#[tokio::test(start_paused = true)]
async fn the_pause_between_attempts_has_a_limit() {
    let sink = Scripted::new("down", &[], Do::FailForNow);
    let (dispatcher, status) = start(
        settings(),
        vec![(sink.clone(), SinkOptions::new().with_max_retries(12))],
    );
    dispatcher.submit(bypass(1), at(1));
    tokio::time::sleep(Duration::from_secs(3600)).await;

    let attempts = sink.attempts();
    assert_eq!(attempts.len(), 13);
    let longest = attempts
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .max()
        .unwrap();
    assert!(longest <= MAX_BACKOFF, "{longest:?}");
    assert!(longest >= MAX_BACKOFF / 2, "{longest:?}");
    assert_eq!(status.sinks()[0].dropped, [0, 0, 1, 0]);
}

#[tokio::test(start_paused = true)]
async fn an_event_a_sink_refuses_for_good_is_not_tried_again() {
    let sink = Scripted::new("picky", &[Do::Refuse], Do::Take);
    let (dispatcher, status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);

    dispatcher.submit(bypass(1), at(1));
    dispatcher.submit(bypass(2), at(2));
    tokio::time::sleep(Duration::from_secs(60)).await;

    assert_eq!(sink.attempts().len(), 2);
    assert_eq!(rows(&sink.taken()), [2]);
    assert_eq!(status.sinks()[0].dropped, [0, 1, 0, 0]);
    assert_eq!(status.sinks()[0].failed_attempts, 1);
}

#[tokio::test(start_paused = true)]
async fn an_attempt_that_takes_too_long_is_given_up_and_made_again() {
    let sink = Scripted::new("slow", &[Do::Hang], Do::Take);
    let (dispatcher, status) = start(
        settings(),
        vec![(
            sink.clone(),
            SinkOptions::new().with_attempt_timeout(Duration::from_secs(2)),
        )],
    );
    let began = Instant::now();

    dispatcher.submit(bypass(1), at(1));
    tokio::time::sleep(Duration::from_secs(60)).await;

    assert_eq!(rows(&sink.taken()), [1]);
    let attempts = sink.attempts();
    assert_eq!(attempts.len(), 2);
    // The second attempt came after the time limit of the first and one
    // pause.
    let waited = attempts[1] - began;
    assert!(
        waited >= Duration::from_secs(2) + FIRST_BACKOFF / 2,
        "{waited:?}"
    );
    assert!(waited <= Duration::from_secs(2) + FIRST_BACKOFF + Duration::from_millis(10));
    assert_eq!(status.sinks()[0].failed_attempts, 1);
    assert_eq!(status.sinks()[0].delivered, 1);
}

#[tokio::test(start_paused = true)]
async fn a_sink_that_panics_loses_one_event_and_nothing_else() {
    let fragile = Scripted::new("fragile", &[Do::Panic], Do::Take);
    let steady = Scripted::taking("steady");
    let (dispatcher, status) = start(
        settings(),
        vec![
            (fragile.clone(), SinkOptions::default()),
            (steady.clone(), SinkOptions::default()),
        ],
    );

    dispatcher.submit(bypass(1), at(1));
    dispatcher.submit(bypass(2), at(2));
    tokio::time::sleep(Duration::from_secs(60)).await;

    // The event that met the panic is dropped, and the panic is counted.
    // The sink is asked again for the next event, and the other sink is
    // not affected at all.
    assert_eq!(rows(&fragile.taken()), [2]);
    assert_eq!(rows(&steady.taken()), [1, 2]);
    assert_eq!(status.counters().sink_panics, 1);
    let sinks = status.sinks();
    assert_eq!(sinks[0].dropped, [0, 1, 0, 0]);
    assert_eq!(sinks[0].delivered, 1);
    assert_eq!(sinks[1].delivered, 2);
}

#[tokio::test(start_paused = true)]
async fn stopping_delivers_what_waits_and_reports_what_was_folded() {
    let sink = Scripted::taking("sink");
    let (dispatcher, status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);

    // Nothing has run yet when the dispatcher is told to stop.
    dispatcher.submit(bypass(1), at(1));
    dispatcher.submit(hit(1, "users-admin-backup", 2), at(2));
    dispatcher.submit(hit(1, "users-admin-backup", 3), at(3));
    dispatcher.submit(hit(1, "users-admin-backup", 4), at(4));
    let began = Instant::now();
    dispatcher.stop(Duration::from_secs(2)).await;

    // Everything was delivered, and the window that was open did not have
    // to run out first.
    let taken = sink.taken();
    assert_eq!(rows(&taken), [1, 2, 4]);
    assert_eq!(taken[2].body.hit_count, 2);
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(status.sinks()[0].delivered, 3);
    assert_eq!(status.sinks()[0].dropped_total(), 0);

    // An event that is raised after that is dropped and counted, and
    // stopping twice does no harm.
    dispatcher.submit(bypass(5), at(5));
    assert_eq!(status.counters().events_dropped, 1);
    assert_eq!(status.counters().event_queue_depth, 0);
    dispatcher.stop(Duration::from_secs(2)).await;
}

#[tokio::test(start_paused = true)]
async fn stopping_does_not_wait_for_a_sink_that_never_answers() {
    let stuck = Scripted::new("stuck", &[], Do::Hang);
    let fine = Scripted::taking("fine");
    let (dispatcher, status) = start(
        settings(),
        vec![
            (
                stuck.clone(),
                SinkOptions::new().with_attempt_timeout(Duration::from_secs(3600)),
            ),
            (fine.clone(), SinkOptions::default()),
        ],
    );
    for row in 1..=5 {
        dispatcher.submit(bypass(row), at(row));
    }
    let began = Instant::now();
    dispatcher.stop(Duration::from_secs(2)).await;

    // Out of time after two seconds, not after an hour.
    assert_eq!(began.elapsed(), Duration::from_secs(2));
    assert_eq!(rows(&fine.taken()), [1, 2, 3, 4, 5]);
    // The one the sink held and the four that waited are counted as
    // dropped because the proxy stopped.
    let sinks = status.sinks();
    assert_eq!(sinks[0].dropped, [0, 0, 0, 5]);
    assert_eq!(sinks[0].queue_depth, 0);
    assert_eq!(sinks[0].delivered, 0);
    assert_eq!(sinks[1].delivered, 5);
}

#[tokio::test(start_paused = true)]
async fn a_sink_that_fails_while_the_proxy_stops_is_not_waited_for() {
    let down = Scripted::new("down", &[], Do::FailForNow);
    let (dispatcher, status) = start(
        settings(),
        vec![(down.clone(), SinkOptions::new().with_max_retries(100))],
    );
    dispatcher.submit(bypass(1), at(1));
    dispatcher.submit(bypass(2), at(2));
    settle().await;
    assert_eq!(down.attempts().len(), 1);

    // The pause before the retry is cut short. One more attempt is made
    // for each event, and then it is dropped.
    let began = Instant::now();
    dispatcher.stop(Duration::from_secs(2)).await;
    assert!(began.elapsed() < Duration::from_millis(100));
    assert_eq!(down.attempts().len(), 3);
    assert_eq!(status.sinks()[0].dropped, [0, 0, 0, 2]);
}

#[tokio::test(start_paused = true)]
async fn sinks_with_the_same_name_are_told_apart_and_a_name_is_made_plain() {
    let (dispatcher, status) = start(
        settings(),
        vec![
            (Scripted::taking("memory"), SinkOptions::default()),
            (Scripted::taking("memory"), SinkOptions::default()),
            (
                Scripted::taking("a \"name\"\nof its own"),
                SinkOptions::default(),
            ),
            (Scripted::taking("memory"), SinkOptions::default()),
            (Scripted::taking(""), SinkOptions::default()),
        ],
    );
    let names: Vec<String> = status.sinks().into_iter().map(|sink| sink.name).collect();
    assert_eq!(
        names,
        [
            "memory",
            "memory-2",
            "a__name__of_its_own",
            "memory-3",
            "sink"
        ]
    );
    dispatcher.stop(Duration::from_secs(1)).await;
}

#[tokio::test(start_paused = true)]
async fn a_dispatcher_nobody_holds_any_more_ends_by_itself() {
    let sink = Scripted::taking("sink");
    let (dispatcher, status) = start(settings(), vec![(sink.clone(), SinkOptions::default())]);
    dispatcher.submit(bypass(1), at(1));
    drop(dispatcher);
    settle().await;
    // What was queued is still delivered, and then the tasks are gone: the
    // sink is held by the test alone.
    assert_eq!(rows(&sink.taken()), [1]);
    assert_eq!(status.sinks()[0].delivered, 1);
    assert_eq!(Arc::strong_count(&sink), 1);
}
