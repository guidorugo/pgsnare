// SPDX-License-Identifier: Apache-2.0

//! `pgsnare run` with the `stdout` sink of a configuration file.

use pgsnare_core::event::{Event, EventKind};
use rustix::process::Signal;
use tokio::io::AsyncWriteExt;

use crate::process::{
    BROKEN, Database, Pgsnare, TempDir, answer, free_port, log_in, query, read_until_ready,
};
use crate::support::{soon, until};

#[tokio::test]
async fn an_event_of_a_session_is_one_line_of_json_on_standard_output() {
    let database = Database::start().await;
    let dir = TempDir::new();
    let port = free_port();
    let config = dir.write(
        "pgsnare.yaml",
        format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:{port}\n    upstream: {}\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\n\
             inspection:\n  on_error: fail_open\n\
             events:\n  labels: {{ environment: test }}\n  labels_from_env: [POD_NAME]\n  \
             sinks:\n    - type: stdout\n\
             admin:\n  listen: 127.0.0.1:{}\nmetrics:\n  listen: 127.0.0.1:{}\n\
             shutdown:\n  grace_period: 1s\n",
            database.address,
            free_port(),
            free_port()
        )
        .as_bytes(),
    );
    let mut pgsnare = Pgsnare::run(&config, &[("POD_NAME", "pgsnare-0")]);
    pgsnare.listening(port).await;

    // A session that works: nothing is reported.
    let mut client = log_in(port, "app", "shop", "psql").await;
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
    assert!(pgsnare.stdout.bytes().is_empty());

    // Then a message that cannot be followed. The operator chose to let
    // such a session go on, and that is what the event reports.
    client.write_all(&BROKEN).await.unwrap();
    until(|| !pgsnare.stdout.lines().is_empty()).await;

    let lines = pgsnare.stdout.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    let json: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["kind"], "inspection_bypassed");
    assert_eq!(json["direction"], "from_client");
    assert_eq!(json["message_type"], "Query");
    assert_eq!(json["db_user"], "app");
    assert_eq!(json["database"], "shop");
    assert_eq!(json["application_name"], "psql");
    assert_eq!(json["client_ip"], "127.0.0.1");
    assert_eq!(json["client_port"], client.local_addr().unwrap().port());
    assert_eq!(json["tls"], false);
    assert_eq!(json["hit_count"], 1);
    assert_eq!(
        json["labels"],
        serde_json::json!({"POD_NAME": "pgsnare-0", "environment": "test"})
    );
    // The line reads back as the event it is.
    let event: Event = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(event.body.kind, EventKind::InspectionBypassed);
    assert_ne!(event.event_id.as_u128(), 0);

    // Standard output carries events and nothing else, and the log goes
    // elsewhere.
    pgsnare.signal(Signal::TERM);
    let status = pgsnare.ended().await;
    assert!(status.success(), "{status}: {}", pgsnare.stderr.text());
    assert_eq!(pgsnare.stdout.lines().len(), 1);
    assert_eq!(
        pgsnare.stdout.bytes().last(),
        Some(&b'\n'),
        "every event ends its line"
    );
    let log = pgsnare.stderr.text();
    assert!(log.contains("listening"), "{log}");
    assert!(log.contains("stopped"), "{log}");
    assert!(!log.contains("inspection_bypassed"), "{log}");

    // The log is JSON: every line of it is one object with a time, a level
    // and a message.
    let lines = pgsnare.stderr.lines();
    assert!(lines.len() >= 5, "{log}");
    for line in &lines {
        let object: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
        assert!(object["timestamp"].is_string(), "{line}");
        assert!(
            matches!(object["level"].as_str(), Some("info" | "warn" | "error")),
            "{line}"
        );
        assert!(object["message"].is_string(), "{line}");
    }
    let listening: serde_json::Value = lines
        .iter()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|object| object["message"] == "listening")
        .expect("a line about the listener");
    assert_eq!(listening["listener"], "main");
    assert_eq!(listening["address"], format!("127.0.0.1:{port}"));
    assert_eq!(listening["max_connections"], 1000);
}

#[tokio::test]
async fn a_sink_that_cannot_be_built_keeps_the_proxy_from_starting() {
    let dir = TempDir::new();
    let missing = dir.path("no-such-directory").join("events.jsonl");
    let config = dir.write(
        "pgsnare.yaml",
        format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:{}\n    upstream: db.example.com:5432\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\n\
             events:\n  sinks:\n    - type: stdout\n    - type: file\n      path: {}\n",
            free_port(),
            missing.display()
        )
        .as_bytes(),
    );
    let mut pgsnare = Pgsnare::run(&config, &[]);
    let status = pgsnare.ended().await;
    assert_eq!(status.code(), Some(1));
    let log = pgsnare.stderr.text();
    assert!(
        log.contains(&format!(
            "events.sinks[1] (file): {}: the file cannot be opened: entity not found",
            missing.display()
        )),
        "{log}"
    );
    assert!(pgsnare.stdout.bytes().is_empty());

    // A proxy that cannot start says why in its log, as a line like any
    // other.
    let last: serde_json::Value =
        serde_json::from_str(pgsnare.stderr.lines().last().unwrap()).unwrap();
    assert_eq!(last["level"], "error");
    assert_eq!(last["message"], "pgsnare cannot go on");
    assert!(
        last["reason"]
            .as_str()
            .unwrap()
            .starts_with("events.sinks[1] (file)")
    );
}
