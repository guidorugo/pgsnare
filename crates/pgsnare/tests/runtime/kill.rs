// SPDX-License-Identifier: Apache-2.0

//! `kill` through the runtime: the client gets the error and nothing of the
//! row, the database gets the cancel request, and both connections close.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use pgsnare::redact::Sha256;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::policy::{
    Action, ActionSet, Inspection, OnError, PolicySnapshot, TokenId, TokenPolicy,
};
use pgsnare_core::session::postgres::Postgres;
use tokio::io::AsyncWriteExt;

use crate::support::{
    Database, ProxyOptions, Running, answer, error_fields, query, read_frame, read_packet,
    read_to_end, welcome,
};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";
const CANCEL_CODE: [u8; 4] = 80_877_102u32.to_be_bytes();

fn options() -> ProxyOptions {
    let mut token = TokenPolicy::new(TokenId::new(TOKEN_ID).unwrap());
    token.actions = ActionSet::of(&[Action::Kill]);
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .token(token)
        .matcher(Matcher::build(&[TokenSpec::new(TOKEN_ID, [VALUE])]).unwrap())
        .build()
        .unwrap();
    ProxyOptions {
        module: Arc::new(Postgres::scanning(Arc::new(Sha256))),
        policy,
        grace_period: Duration::from_secs(5),
    }
}

/// Counts cancel requests and sessions that ended.
#[derive(Default)]
struct Seen {
    cancels: AtomicU32,
    ended: AtomicU32,
}

/// A database that answers every query with a row holding the token.
async fn database(seen: &Arc<Seen>) -> Database {
    let seen = Arc::clone(seen);
    Database::new(move |mut stream| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            let Ok(packet) = read_packet(&mut stream).await else {
                return;
            };
            if packet.get(4..8) == Some(&CANCEL_CODE[..]) {
                seen.cancels.fetch_add(1, Ordering::SeqCst);
                return;
            }
            if stream.write_all(&welcome()).await.is_err() {
                return;
            }
            while let Ok(frame) = read_frame(&mut stream).await {
                if frame[0] == b'Q' && stream.write_all(&answer(VALUE.as_bytes())).await.is_err() {
                    break;
                }
            }
            seen.ended.fetch_add(1, Ordering::SeqCst);
        })
    })
    .await
}

#[tokio::test]
async fn a_killed_session_gets_the_error_and_not_the_row_and_the_database_is_let_go() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    client
        .write_all(&query("SELECT name FROM users"))
        .await
        .unwrap();
    let received = read_to_end(&mut client).await;
    assert!(!received.windows(VALUE.len()).any(|w| w == VALUE.as_bytes()));
    assert_eq!(
        error_fields(&received),
        [
            (b'S', "FATAL".to_owned()),
            (b'V', "FATAL".to_owned()),
            (b'C', "57P01".to_owned()),
            (
                b'M',
                "terminating connection due to administrator command".to_owned()
            ),
        ]
    );

    // The query is cancelled and the session of the database ends, within
    // a second.
    tokio::time::timeout(Duration::from_secs(1), async {
        while seen.cancels.load(Ordering::SeqCst) == 0 || seen.ended.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the database session ends within a second");

    let counters = proxy.status.counters();
    assert_eq!(counters.token_hits, 1);
    assert_eq!(counters.actions, [0, 1, 0, 0]);
}
