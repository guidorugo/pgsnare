// SPDX-License-Identifier: Apache-2.0

//! Events on their way from a session to a sink, through a running proxy.

use std::sync::Arc;
use std::time::Duration;

use pgsnare::redact::{REDACTED, Redaction, Redactor};
use pgsnare::sinks::SinkOptions;
use pgsnare_core::event::{EventKind, Labels};
use pgsnare_core::extension::EventSink;

use crate::support::{Memory, Options, Running, say, until};

const VALUE: &str = "svc.backup.8f3k2q@mail.example";

#[tokio::test]
async fn an_event_a_session_raises_reaches_the_sinks_sealed_labelled_and_redacted() {
    let memory = Arc::new(Memory::default());
    let redaction = Redaction::new(
        Redactor::builder()
            .token("users-admin-backup", [VALUE], false)
            .build()
            .unwrap(),
    );
    let labels = Labels::from([("POD_NAME".to_owned(), "pgsnare-0".to_owned())]);
    let proxy = Running::start(Options {
        sinks: vec![(memory.clone() as Arc<dyn EventSink>, SinkOptions::default())],
        settings: Box::new(move |settings| settings.with_labels(labels).with_redaction(redaction)),
        ..Options::default()
    })
    .await;

    // A client that logs in under the value of a honeytoken, and then
    // reads that token.
    let mut client = proxy.connect().await;
    say(&mut client, &format!("user {VALUE}")).await;
    say(&mut client, "app psql").await;
    say(&mut client, "hit users-admin-backup").await;
    until(|| memory.count() == 1).await;

    let event = memory.events().remove(0);
    assert_eq!(event.body.kind, EventKind::TokenHit);
    assert_eq!(
        event.body.token_id.as_ref().unwrap().as_str(),
        "users-admin-backup"
    );
    assert_eq!(event.body.hit_count, 1);
    assert_eq!(event.labels["POD_NAME"], "pgsnare-0");
    assert_ne!(event.event_id.as_u128(), 0);
    assert_eq!(event.body.client_ip, client.local_addr().unwrap().ip());
    assert_eq!(event.body.client_port, client.local_addr().unwrap().port());
    assert_eq!(event.body.application_name.as_deref(), Some("psql"));
    // The value is not in the event, in no field and in no form.
    assert_eq!(event.body.db_user.as_deref(), Some(REDACTED));
    assert!(!serde_json::to_string(&event).unwrap().contains(VALUE));

    let counters = proxy.status.counters();
    assert_eq!(counters.events_emitted, 1);
    assert_eq!(counters.events_dropped, 0);
    assert_eq!(counters.events_by_kind[0], 1);
    assert_eq!(proxy.status.sinks()[0].delivered, 1);
}

#[tokio::test]
async fn repeated_hits_of_a_session_are_folded_and_reported_when_the_proxy_stops() {
    let memory = Arc::new(Memory::default());
    let mut proxy = Running::start(Options::with_sinks(vec![(
        memory.clone() as Arc<dyn EventSink>,
        SinkOptions::default(),
    )]))
    .await;

    let mut client = proxy.connect().await;
    for _ in 0..5 {
        say(&mut client, "hit users-admin-backup").await;
    }
    say(&mut client, "hit card-test-0002").await;
    // Another session that reads the same token is news of its own.
    let mut other = proxy.connect().await;
    say(&mut other, "hit users-admin-backup").await;
    // And an event of another kind is never folded.
    say(&mut other, "bypass").await;
    say(&mut other, "bypass").await;

    until(|| memory.count() == 5).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = memory.events();
    assert_eq!(events.len(), 5);
    assert!(events.iter().all(|event| event.body.hit_count == 1));
    assert_eq!(proxy.status.counters().events_deduplicated, 4);
    assert_eq!(proxy.status.counters().events_emitted, 9);

    // The window of a minute is still open when the proxy is stopped. What
    // was folded is reported before the proxy is gone.
    proxy.stop();
    proxy.stopped().await;
    let events = memory.events();
    assert_eq!(events.len(), 6);
    let report = &events[5];
    assert_eq!(report.body.kind, EventKind::TokenHit);
    assert_eq!(
        report.body.token_id.as_ref().unwrap().as_str(),
        "users-admin-backup"
    );
    assert_eq!(report.body.hit_count, 4);
    assert_eq!(report.body.session_id, events[0].body.session_id);
}
