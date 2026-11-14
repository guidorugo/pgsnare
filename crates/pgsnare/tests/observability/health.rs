// SPDX-License-Identifier: Apache-2.0

//! The health endpoints, the metrics and `pgsnare healthcheck`, with a
//! proxy that runs as a process.

use rustix::process::Signal;
use tokio::io::AsyncWriteExt;

use crate::process::{
    BROKEN, Database, Pgsnare, TempDir, answer, free_port, http_get, log_in, metric, query,
    read_until_ready,
};
use crate::support::{soon, until};

/// A configuration with one listener and with ports of its own for health
/// and metrics. Returns the file and the three ports.
fn configuration(
    dir: &TempDir,
    database: &Database,
    grace_period: &str,
) -> (std::path::PathBuf, u16, u16, u16) {
    let (port, admin, metrics) = (free_port(), free_port(), free_port());
    let config = dir.write(
        "pgsnare.yaml",
        format!(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:{port}\n    upstream: {}\n    \
             client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\n\
             inspection:\n  on_error: fail_open\n\
             events:\n  sinks:\n    - type: stdout\n\
             admin:\n  listen: 127.0.0.1:{admin}\nmetrics:\n  listen: 127.0.0.1:{metrics}\n\
             shutdown:\n  grace_period: {grace_period}\n",
            database.address
        )
        .as_bytes(),
    );
    (config, port, admin, metrics)
}

/// Runs `pgsnare healthcheck` and returns its exit status and what it
/// wrote.
async fn healthcheck(config: &std::path::Path, ready: bool) -> (Option<i32>, String, String) {
    let mut arguments = vec!["healthcheck", "--config", config.to_str().unwrap()];
    if ready {
        arguments.push("--ready");
    }
    let mut check = Pgsnare::start(&arguments, &[]);
    let status = check.ended().await;
    (status.code(), check.stdout.text(), check.stderr.text())
}

#[tokio::test]
async fn a_running_proxy_answers_its_health_check_and_serves_its_metrics() {
    let database = Database::start().await;
    let dir = TempDir::new();
    let (config, port, admin, metrics) = configuration(&dir, &database, "1s");
    let mut pgsnare = Pgsnare::run(&config, &[]);
    pgsnare.listening(port).await;

    // Healthy and ready, and the check says nothing about it.
    for ready in [false, true] {
        assert_eq!(
            healthcheck(&config, ready).await,
            (Some(0), String::new(), String::new())
        );
    }
    assert_eq!(http_get(admin, "/healthz").await, (200, "ok\n".to_owned()));
    assert_eq!(
        http_get(admin, "/readyz").await,
        (200, "ready\n".to_owned())
    );
    assert_eq!(http_get(admin, "/metrics").await.0, 404);
    assert_eq!(http_get(metrics, "/healthz").await.0, 404);

    // Traffic, and an event.
    let mut client = log_in(port, "app", "shop", "psql").await;
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
    client.write_all(&BROKEN).await.unwrap();
    until(|| !pgsnare.stdout.lines().is_empty()).await;

    // The metrics say what happened. The numbers of connections count the
    // probes of this test too, so they are bounded from below.
    let (status, text) = http_get(metrics, "/metrics").await;
    assert_eq!(status, 200);
    let number = |series: &str| metric(&text, series).unwrap_or_else(|| panic!("{series}\n{text}"));
    assert_eq!(number("pgsnare_ready"), 1.0);
    assert_eq!(number("pgsnare_healthy"), 1.0);
    assert!(number("pgsnare_connections_accepted_total") >= 1.0);
    assert_eq!(number("pgsnare_logins_total"), 1.0);
    assert!(number("pgsnare_bytes_total{direction=\"from_client\"}") > 0.0);
    assert!(number("pgsnare_bytes_total{direction=\"from_server\"}") > 0.0);
    assert_eq!(number("pgsnare_events_raised_total"), 1.0);
    assert_eq!(
        number("pgsnare_events_total{kind=\"inspection_bypassed\"}"),
        1.0
    );
    assert_eq!(number("pgsnare_events_dropped_total"), 0.0);
    assert_eq!(
        number("pgsnare_sink_events_delivered_total{sink=\"stdout-0\"}"),
        1.0
    );
    assert_eq!(
        number("pgsnare_sink_events_dropped_total{sink=\"stdout-0\",reason=\"queue_full\"}"),
        0.0
    );
    assert_eq!(
        number("pgsnare_sink_queue_capacity{sink=\"stdout-0\"}"),
        1024.0
    );
    assert_eq!(number("pgsnare_panics_total{scope=\"session\"}"), 0.0);
    assert_eq!(number("pgsnare_listener_failures_total"), 0.0);
    // The session measured what it added to the traffic it relayed.
    assert!(number("pgsnare_added_latency_seconds_count") >= 1.0);
    assert_eq!(
        number("pgsnare_added_latency_seconds_bucket{le=\"+Inf\"}"),
        number("pgsnare_added_latency_seconds_count")
    );
    // Nothing detects yet, so these have no source and say zero.
    assert_eq!(number("pgsnare_queries_total"), 0.0);
    assert_eq!(number("pgsnare_hits_total{kind=\"token\"}"), 0.0);
    assert_eq!(number("pgsnare_actions_total{action=\"kill\"}"), 0.0);
    assert_eq!(number("pgsnare_parse_failures_total"), 0.0);
    assert_eq!(number("pgsnare_reload_failures_total"), 0.0);
    // What the endpoint does not show: who connected.
    assert!(!text.contains("127.0.0.1"), "{text}");
    assert!(!text.contains("shop"), "{text}");

    drop(client);
    pgsnare.signal(Signal::TERM);
    assert!(pgsnare.ended().await.success());
}

#[tokio::test]
async fn a_proxy_that_stops_is_healthy_and_not_ready() {
    let database = Database::start().await;
    let dir = TempDir::new();
    let (config, port, admin, _metrics) = configuration(&dir, &database, "30s");
    let mut pgsnare = Pgsnare::run(&config, &[]);
    pgsnare.listening(port).await;

    // A session that stays open keeps the proxy in its grace period.
    let client = log_in(port, "app", "shop", "psql").await;
    pgsnare.signal(Signal::TERM);
    until(|| pgsnare.stderr.text().contains("stopping")).await;

    assert_eq!(http_get(admin, "/healthz").await, (200, "ok\n".to_owned()));
    assert_eq!(
        http_get(admin, "/readyz").await,
        (503, "not ready\n".to_owned())
    );
    assert_eq!(
        healthcheck(&config, false).await,
        (Some(0), String::new(), String::new())
    );
    let (status, stdout, stderr) = healthcheck(&config, true).await;
    assert_eq!(status, Some(1));
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "pgsnare healthcheck: the admin listener answered /readyz with status 503\n"
    );

    // The last session ends, and with it the proxy and its endpoints.
    drop(client);
    assert!(pgsnare.ended().await.success());
    let (status, stdout, stderr) = healthcheck(&config, false).await;
    assert_eq!(status, Some(1));
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        "pgsnare healthcheck: the admin listener could not be asked: the connection was refused\n"
    );
}

#[tokio::test]
async fn a_port_that_is_taken_keeps_the_proxy_from_starting() {
    let database = Database::start().await;
    let dir = TempDir::new();
    let (config, _port, admin, _metrics) = configuration(&dir, &database, "1s");
    // Something else listens where the admin listener is meant to.
    let _taken = std::net::TcpListener::bind(("127.0.0.1", admin)).unwrap();

    let mut pgsnare = Pgsnare::run(&config, &[]);
    let status = pgsnare.ended().await;
    assert_eq!(status.code(), Some(1));
    let log = pgsnare.stderr.text();
    assert!(
        log.contains("cannot open the admin listener or the metrics listener: address in use"),
        "{log}"
    );
}
