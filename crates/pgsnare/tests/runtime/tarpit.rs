// SPDX-License-Identifier: Apache-2.0

//! `tarpit` through the runtime: the client is held back, nothing more is
//! read from the database while it is, and the limits on time and on the
//! number of tarpitted sessions end a session with the error of `kill`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pgsnare::redact::Sha256;
use pgsnare::runtime::OsEntropy;
use pgsnare_core::actions::TarpitPlaces;
use pgsnare_core::bait::Entropy;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::policy::{
    Action, ActionSet, ActionSettings, FakeDataSettings, Inspection, KillSettings, OnError,
    PolicySnapshot, TarpitSettings, TokenId, TokenPolicy,
};
use pgsnare_core::session::postgres::{Postgres, Responses};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::support::{
    Database, ProxyOptions, Running, answer, error_fields, frame, query, read_frame, read_packet,
    read_to_end, welcome,
};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";
const CANCEL_CODE: [u8; 4] = 80_877_102u32.to_be_bytes();

fn options(tarpit: TarpitSettings) -> ProxyOptions {
    let mut token = TokenPolicy::new(TokenId::new(TOKEN_ID).unwrap());
    token.actions = ActionSet::of(&[Action::Tarpit]);
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .token(token)
        .actions(ActionSettings::new(
            KillSettings::default(),
            tarpit,
            FakeDataSettings::default(),
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

fn settings(delay: Duration, max_duration: Duration, max_sessions: u32) -> TarpitSettings {
    TarpitSettings::new(delay, delay, max_duration, max_sessions, None)
}

/// A database that answers every query with a row holding the token, and
/// then, if `flood`, sends plain rows for as long as it is read.
async fn database(flood: bool) -> Database {
    Database::new(move |mut stream| {
        Box::pin(async move {
            let Ok(packet) = read_packet(&mut stream).await else {
                return;
            };
            if packet.get(4..8) == Some(&CANCEL_CODE[..]) {
                return;
            }
            if stream.write_all(&welcome()).await.is_err() {
                return;
            }
            while let Ok(message) = read_frame(&mut stream).await {
                if message[0] != b'Q' || stream.write_all(&answer(VALUE.as_bytes())).await.is_err()
                {
                    break;
                }
                if flood {
                    let mut body = vec![0, 1];
                    body.extend_from_slice(&16_000u32.to_be_bytes());
                    body.resize(body.len() + 16_000, b'x');
                    let row = frame(b'D', &body);
                    for _ in 0..1024 {
                        if stream.write_all(&row).await.is_err() {
                            return;
                        }
                    }
                }
            }
        })
    })
    .await
}

#[tokio::test]
async fn a_held_session_reads_nothing_more_from_the_database() {
    let database = database(true).await;
    let options = options(settings(Duration::from_secs(3), Duration::from_secs(60), 4));
    let proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (mut client, _) = proxy.log_in().await;
    let before = proxy.status.counters().bytes_from_servers;

    client
        .write_all(&query("SELECT name FROM users"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    // The client has received nothing yet: the whole answer is held back.
    let mut buffer = [0u8; 16];
    let early = tokio::time::timeout(Duration::from_millis(100), client.read(&mut buffer)).await;
    assert!(early.is_err(), "the client was not held back");

    // The database keeps sending 16 MB, but the proxy reads no more than
    // what it had read when the hit held the client back: well below the
    // 256 KiB the relay would otherwise queue.
    let read = proxy.status.counters().bytes_from_servers - before;
    assert!(read < 160 * 1024, "{read} bytes read while held");

    // Once the delay is over the session goes on.
    let mut first = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first[0], b'D');
}

/// Whether `received` ends with the error of `kill`.
fn is_killed(received: &[u8]) -> bool {
    let Some(start) = received.iter().rposition(|byte| *byte == b'E') else {
        return false;
    };
    error_fields(&received[start..])
        .iter()
        .any(|(code, value)| *code == b'C' && value == "57P01")
}

#[tokio::test]
async fn a_session_tarpitted_past_its_longest_time_is_killed() {
    let database = database(false).await;
    let options = options(settings(
        Duration::from_millis(500),
        Duration::from_secs(2),
        4,
    ));
    let proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (mut client, _) = proxy.log_in().await;

    let started = Instant::now();
    client
        .write_all(&query("SELECT name FROM users"))
        .await
        .unwrap();
    // Keep asking, as a client reading a table would.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = client.write_all(&query("SELECT name FROM users")).await;
    }
    let received = read_to_end(&mut client).await;
    let elapsed = started.elapsed();
    assert!(received.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    assert!(is_killed(&received), "the session was not killed");
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
}

#[tokio::test]
async fn a_session_beyond_the_number_allowed_is_killed_not_held() {
    let database = database(false).await;
    let options = options(settings(
        Duration::from_secs(30),
        Duration::from_secs(60),
        1,
    ));
    let proxy = Running::start_with(Running::listener(database.upstream()), options).await;

    let (mut held, _) = proxy.log_in().await;
    held.write_all(&query("SELECT name FROM users"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (mut second, _) = proxy.log_in().await;
    let started = Instant::now();
    second
        .write_all(&query("SELECT name FROM users"))
        .await
        .unwrap();
    let received = read_to_end(&mut second).await;
    assert!(is_killed(&received), "the second session was not killed");
    assert!(!received.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(held);
}
