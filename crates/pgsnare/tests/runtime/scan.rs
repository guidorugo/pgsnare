// SPDX-License-Identifier: Apache-2.0

//! Honeytokens in the traffic of a running proxy: what is counted and what
//! reaches a sink.

use std::sync::Arc;
use std::time::Duration;

use pgsnare::redact::Sha256;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::event::EventKind;
use pgsnare_core::policy::{Inspection, OnError, PolicySnapshot, TokenId, TokenPolicy};
use pgsnare_core::session::postgres::Postgres;
use tokio::io::AsyncWriteExt;

use crate::support::{
    Database, ProxyOptions, Running, answer, query, read_until_ready, soon, until,
};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";

fn options() -> ProxyOptions {
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .token(TokenPolicy::new(TokenId::new(TOKEN_ID).unwrap()))
        .matcher(Matcher::build(&[TokenSpec::new(TOKEN_ID, [VALUE])]).unwrap())
        .build()
        .unwrap();
    ProxyOptions {
        module: Arc::new(Postgres::scanning(Arc::new(Sha256))),
        policy,
        grace_period: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn hits_and_statements_are_counted_and_a_hit_reaches_the_sinks_without_its_value() {
    let database = Database::echo().await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    // Nothing has been found so far, and nothing was asked.
    let counters = proxy.status.counters();
    assert_eq!((counters.queries, counters.token_hits), (0, 0));

    // A statement without a value.
    client.write_all(&query("SELECT 1")).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    until(|| proxy.status.counters().queries == 1).await;
    assert_eq!(proxy.status.counters().token_hits, 0);

    // The database answers a statement with its text: the value passes
    // once in each direction, and the client still gets its answer.
    let sql = format!("SELECT '{VALUE}'");
    client.write_all(&query(&sql)).await.unwrap();
    let result = soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(result, answer(sql.as_bytes()));

    // The effects of a message are carried out after its bytes are sent.
    until(|| proxy.status.counters().token_hits == 2).await;
    let counters = proxy.status.counters();
    assert_eq!(counters.queries, 2);
    assert_eq!(counters.exempt_token_hits, 0);
    // One `alert` for each hit, and no other response.
    assert_eq!(counters.actions, [2, 0, 0, 0]);

    until(|| !proxy.events.events.lock().unwrap().is_empty()).await;
    let events = proxy.events.events.lock().unwrap().clone();
    let mut hits = 0;
    for event in &events {
        assert_eq!(event.body.kind, EventKind::TokenHit);
        assert_eq!(event.body.token_id.as_ref().unwrap().as_str(), TOKEN_ID);
        hits += event.body.hit_count;
        let json = serde_json::to_string(event).unwrap();
        assert!(!json.contains(VALUE));
        assert!(!format!("{event:?}").contains(VALUE));
    }
    assert!((1..=2).contains(&hits));
}
