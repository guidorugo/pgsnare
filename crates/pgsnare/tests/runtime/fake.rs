// SPDX-License-Identifier: Apache-2.0

//! `fake_data` through the runtime: what the event of a hit and the
//! counters say was carried out, and how long the event may wait for the
//! end of the result.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pgsnare::redact::Sha256;
use pgsnare::runtime::OsEntropy;
use pgsnare_core::actions::TarpitPlaces;
use pgsnare_core::bait::Entropy;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::event::{Event, EventKind};
use pgsnare_core::policy::{
    Action, ActionSet, ActionSettings, FakeDataSettings, Inspection, KillSettings, OnError,
    PolicySnapshot, TarpitSettings, TokenId, TokenPolicy,
};
use pgsnare_core::session::postgres::{Postgres, Responses};
use tokio::io::AsyncWriteExt;

use crate::support::{
    A_WHILE, Database, ProxyOptions, Running, frame, query, read_frame, read_packet,
    read_until_ready, soon, until, welcome,
};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";
const ADDED: u32 = 3;
const TEXT: u32 = 25;

/// Longer than a report waits for the end of its result.
const TOO_LONG: Duration = Duration::from_millis(1_500);

fn options() -> ProxyOptions {
    let mut token = TokenPolicy::new(TokenId::new(TOKEN_ID).unwrap());
    token.actions = ActionSet::of(&[Action::FakeData]);
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .token(token)
        .actions(ActionSettings::new(
            KillSettings::default(),
            TarpitSettings::default(),
            FakeDataSettings::new(ADDED),
        ))
        .matcher(Matcher::build(&[TokenSpec::new(TOKEN_ID, [VALUE])]).unwrap())
        .build()
        .unwrap();
    let entropy = OsEntropy::new().unwrap();
    let responses = Responses::new(
        move || -> Box<dyn Entropy + Send> { Box::new(entropy) },
        Arc::new(TarpitPlaces::new()),
    );
    ProxyOptions {
        module: Arc::new(Postgres::responding(Arc::new(Sha256), responses)),
        policy,
        grace_period: Duration::from_secs(5),
    }
}

fn row(value: &str) -> Vec<u8> {
    let mut body = vec![0, 1];
    body.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    body.extend_from_slice(value.as_bytes());
    frame(b'D', &body)
}

/// The beginning of the result: one text column, a plain row, and a row
/// with the token.
fn beginning() -> Vec<u8> {
    let mut description = 1i16.to_be_bytes().to_vec();
    description.extend_from_slice(b"note\0");
    description.extend_from_slice(&16_384u32.to_be_bytes());
    description.extend_from_slice(&1i16.to_be_bytes());
    description.extend_from_slice(&TEXT.to_be_bytes());
    description.extend_from_slice(&(-1i16).to_be_bytes());
    description.extend_from_slice(&(-1i32).to_be_bytes());
    description.extend_from_slice(&0i16.to_be_bytes());
    let mut bytes = frame(b'T', &description);
    bytes.extend_from_slice(&row("nothing to see"));
    bytes.extend_from_slice(&row(VALUE));
    bytes
}

fn ending() -> Vec<u8> {
    let mut bytes = frame(b'C', b"SELECT 2\0");
    bytes.extend_from_slice(&frame(b'Z', b"I"));
    bytes
}

/// A database that answers every query with the result above, and waits
/// for `pause` between its beginning and its ending. `None`: for ever.
async fn database(pause: Option<Duration>) -> Database {
    Database::new(move |mut stream| {
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err()
                || stream.write_all(&welcome()).await.is_err()
            {
                return;
            }
            while let Ok(message) = read_frame(&mut stream).await {
                if message[0] != b'Q' || stream.write_all(&beginning()).await.is_err() {
                    break;
                }
                match pause {
                    Some(pause) => tokio::time::sleep(pause).await,
                    None => std::future::pending().await,
                }
                if stream.write_all(&ending()).await.is_err() {
                    break;
                }
            }
        })
    })
    .await
}

fn hits(proxy: &Running) -> Vec<Event> {
    proxy
        .events
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.body.kind == EventKind::TokenHit)
        .cloned()
        .collect()
}

/// How many data rows `result` holds.
fn data_rows(result: &[u8]) -> usize {
    let mut rest = result;
    let mut rows = 0;
    while let Some((&tag, after)) = rest.split_first() {
        let length = usize::try_from(u32::from_be_bytes(after[..4].try_into().unwrap())).unwrap();
        rows += usize::from(tag == b'D');
        rest = &after[length..];
    }
    rows
}

/// The counters of the responses when one hit was answered with `alert`,
/// and when one was answered with `fake_data`.
const ONE_ALERT: [u64; 4] = [1, 0, 0, 0];
const ONE_FAKE_DATA: [u64; 4] = [0, 0, 0, 1];

/// Exactly one hit was reported and counted, with `action` and no other
/// response, and nothing more follows.
async fn reported_once(proxy: &Running, action: Action, counted: [u64; 4]) {
    until(|| !hits(proxy).is_empty()).await;
    until(|| proxy.status.counters().token_hits == 1).await;
    tokio::time::sleep(A_WHILE).await;
    let events = hits(proxy);
    assert_eq!(events.len(), 1, "one event");
    assert_eq!(events[0].body.action_taken, ActionSet::of(&[action]));
    assert_eq!(events[0].body.hit_count, 1);
    let counters = proxy.status.counters();
    assert_eq!(counters.token_hits, 1);
    assert_eq!(counters.actions, counted, "the counters say the same");
}

#[tokio::test]
async fn the_event_and_the_counters_say_fake_data_when_rows_were_added() {
    let database = database(Some(Duration::ZERO)).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    client
        .write_all(&query("SELECT note FROM notes"))
        .await
        .unwrap();
    let result = soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(data_rows(&result), 2 + usize::try_from(ADDED).unwrap());
    reported_once(&proxy, Action::FakeData, ONE_FAKE_DATA).await;
}

#[tokio::test]
async fn an_event_does_not_wait_for_a_result_that_takes_long() {
    let database = database(Some(TOO_LONG)).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    let started = Instant::now();
    client
        .write_all(&query("SELECT note FROM notes"))
        .await
        .unwrap();

    // The event is there while the database still holds the end of the
    // result back, and it says what has been done so far.
    until(|| !hits(&proxy).is_empty()).await;
    let waited = started.elapsed();
    assert!(
        waited < TOO_LONG,
        "the event waited for the result: {waited:?}"
    );
    assert_eq!(hits(&proxy)[0].body.action_taken, ActionSet::ALERT);

    // So the result ends as the database sent it.
    let result = soon(read_until_ready(&mut client)).await.unwrap();
    let mut sent = beginning();
    sent.extend_from_slice(&ending());
    assert_eq!(result, sent);
    reported_once(&proxy, Action::Alert, ONE_ALERT).await;
}

#[tokio::test]
async fn a_session_that_ends_before_its_result_still_reports_the_hit() {
    let database = database(None).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    client
        .write_all(&query("SELECT note FROM notes"))
        .await
        .unwrap();
    // The proxy has read the hit when it has passed the rows on.
    let mut seen = Vec::new();
    while data_rows(&seen) < 2 {
        seen.extend_from_slice(&soon(read_frame(&mut client)).await.unwrap());
    }
    drop(client);
    reported_once(&proxy, Action::Alert, ONE_ALERT).await;
}
