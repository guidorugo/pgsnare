// SPDX-License-Identifier: Apache-2.0

//! A reload while sessions run: none of them is dropped, and a new token
//! is found at once.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pgsnare::redact::Sha256;
use pgsnare::reload::SharedPolicy;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::policy::{Inspection, OnError, PolicySnapshot, TokenId, TokenPolicy};
use pgsnare_core::session::postgres::Postgres;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::support::{Database, Running, answer, query, read_until_ready, soon, until};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";
const SESSIONS: usize = 4;

fn policy(generation: u64, tokens: &[(&str, &str)]) -> PolicySnapshot {
    let specs: Vec<TokenSpec> = tokens
        .iter()
        .map(|(id, value)| TokenSpec::new(*id, [*value]))
        .collect();
    PolicySnapshot::builder()
        .generation(generation)
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .tokens(
            tokens
                .iter()
                .map(|(id, _)| TokenPolicy::new(TokenId::new(id).unwrap())),
        )
        .matcher(Matcher::build(&specs).unwrap())
        .build()
        .unwrap()
}

/// Each session asks for the value once, and gets its answer.
async fn round(clients: &mut [TcpStream]) {
    let sql = format!("SELECT '{VALUE}'");
    for client in clients {
        client.write_all(&query(&sql)).await.unwrap();
        let result = soon(read_until_ready(client)).await.unwrap();
        assert_eq!(result, answer(sql.as_bytes()));
    }
}

#[tokio::test]
async fn a_new_token_is_found_within_a_second_of_a_reload_and_no_session_is_dropped() {
    let database = Database::echo().await;
    let source = Arc::new(SharedPolicy::new(policy(1, &[])));
    let proxy = Running::start_from(
        Running::listener(database.upstream()),
        Arc::new(Postgres::scanning(Arc::new(Sha256))),
        Arc::clone(&source) as _,
        Duration::from_secs(5),
    )
    .await;
    let mut clients = Vec::new();
    for _ in 0..SESSIONS {
        clients.push(proxy.log_in().await.0);
    }

    round(&mut clients).await;
    assert_eq!(proxy.status.counters().token_hits, 0);

    source.replace(policy(2, &[(TOKEN_ID, VALUE)]));
    let reloaded = Instant::now();
    // The same sessions go on, and each finds the value both ways.
    round(&mut clients).await;
    until(|| proxy.status.counters().token_hits == 2 * SESSIONS as u64).await;
    assert!(reloaded.elapsed() < Duration::from_secs(1));
    assert_eq!(proxy.status.counters().sessions_accepted, SESSIONS as u64);
}
