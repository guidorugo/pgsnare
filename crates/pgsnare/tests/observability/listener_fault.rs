// SPDX-License-Identifier: Apache-2.0

//! A listener that fails while the proxy is meant to run.
//!
//! The code that ships has no switch to make a listener fail. This test
//! makes the code of a real listener panic from the outside: it gives the
//! test's own thread a log that panics on one line a listener writes, the
//! one about a client it had to refuse. The panic then happens inside the
//! accept loop of the listener, where a defect of the listener would.

use std::time::{Duration, Instant};

use pgsnare::runtime::Stopped;
use tokio::net::TcpStream;
use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Metadata, Subscriber};

use crate::support::{Options, Running, exchange, read_to_end, until};

/// A log that panics when a line with a certain text is written.
struct PanicsOn(&'static str);

struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl Subscriber for PanicsOn {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        assert!(
            !message.0.contains(self.0),
            "a panic that a test asked for, in the code that wrote this line to the log"
        );
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

#[tokio::test]
async fn a_listener_that_panics_stops_the_proxy_and_its_sessions_get_the_grace_period() {
    // The test runs on one thread, and so does everything it starts: the
    // log of this thread is the log of the listener.
    let _log = tracing::subscriber::set_default(PanicsOn("clients are being refused"));

    let mut proxy = Running::start(Options {
        max_connections: 1,
        ..Options::default()
    })
    .await;
    let status = proxy.status.clone();
    assert!(status.is_ready());
    assert!(status.is_healthy());

    // One client is in, and the listener is at its limit.
    let mut inside = proxy.connect().await;
    exchange(&mut inside, b"hello", b"hello").await;

    // The next client is refused. The listener says so in its log, and
    // that is where its code panics.
    let mut refused = proxy.connect().await;
    assert!(read_to_end(&mut refused).await.is_empty());

    // The runtime notices: it counts the failure and is neither ready nor
    // healthy from here on.
    until(|| !status.is_healthy()).await;
    let failed = Instant::now();
    assert!(!status.is_ready());
    let counters = status.counters();
    assert_eq!(counters.listener_failures, 1);
    assert_eq!(counters.listener_panics, 1);
    assert_eq!(counters.session_panics, 0);

    // Nobody listens on the address any more.
    until(|| std::net::TcpStream::connect(proxy.address).is_err()).await;
    assert!(TcpStream::connect(proxy.address).await.is_err());

    // The session that was open did nothing wrong. It goes on for the
    // grace period, and is then told to end like every session of a proxy
    // that stops.
    exchange(&mut inside, b"still here", b"still here").await;
    assert_eq!(read_to_end(&mut inside).await, b"closing time");
    assert!(
        failed.elapsed() >= Duration::from_millis(250),
        "{:?}",
        failed.elapsed()
    );

    // Nobody asked the proxy to stop. It stopped by itself, and says why.
    assert_eq!(proxy.stopped().await, Stopped::ListenerFailed);
    assert_eq!(status.counters().sessions_active, 0);
    assert!(!status.is_healthy());
}

#[tokio::test]
async fn a_proxy_that_is_asked_to_stop_says_so() {
    let mut proxy = Running::start(Options::default()).await;
    let mut client = proxy.connect().await;
    exchange(&mut client, b"hello", b"hello").await;

    proxy.stop();
    assert_eq!(read_to_end(&mut client).await, b"closing time");
    assert_eq!(proxy.stopped().await, Stopped::Asked);
    assert!(proxy.status.is_healthy());
    assert!(!proxy.status.is_ready());
    assert_eq!(proxy.status.counters().listener_failures, 0);
}
