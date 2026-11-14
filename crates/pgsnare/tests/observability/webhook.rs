// SPDX-License-Identifier: Apache-2.0

//! The webhook sink, from a session that raises an event to a receiver
//! that checks what it gets.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use pgsnare::sinks::{SinkOptions, Trust, WebhookSettings, WebhookSink};
use pgsnare_core::event::{Event, EventKind};
use pgsnare_core::extension::EventSink;

use crate::receiver::{Answer, Received, Receiver, Refused, Verifier, unix_seconds};
use crate::support::{Authority, Options, Running, exchange, say, until};

const KEY: &[u8] = b"a key that is made up for these tests";

/// A proxy whose only sink is a webhook for this URL.
async fn proxy_with(url: &str, settings: WebhookSettings, options: SinkOptions) -> Running {
    let sink = WebhookSink::new("webhook-0", url, KEY, settings).unwrap();
    Running::start(Options::with_sinks(vec![(
        Arc::new(sink) as Arc<dyn EventSink>,
        options,
    )]))
    .await
}

/// A receiver that speaks HTTPS as `localhost`, and settings that trust
/// the authority that signed its certificate.
async fn trusted_receiver(script: &[Answer], then: Answer) -> (Receiver, WebhookSettings) {
    let authority = Authority::new("the authority of a test");
    let receiver = Receiver::tls(&authority.issue(&["localhost"]), script, then).await;
    let settings = WebhookSettings::new().with_trust(Trust::Roots(authority.roots()));
    (receiver, settings)
}

fn https(receiver: &Receiver, path: &str) -> String {
    format!("https://localhost:{}{path}", receiver.address.port())
}

/// Raises one event in a session of its own. Sessions do not share a
/// window, so none of these events is folded into another.
async fn raise(proxy: &Running) {
    let mut client = proxy.connect().await;
    say(&mut client, "bypass").await;
}

#[tokio::test]
async fn an_event_arrives_as_a_signed_request_over_verified_tls() {
    let (receiver, settings) = trusted_receiver(&[], Answer::Status(200)).await;
    let url = https(&receiver, "/hooks/pgsnare?source=test");
    let proxy = proxy_with(&url, settings, SinkOptions::default()).await;

    let before = SystemTime::now();
    let mut client = proxy.connect().await;
    say(&mut client, "user app").await;
    say(&mut client, "hit users-admin-backup").await;
    until(|| receiver.count() == 1).await;
    until(|| proxy.status.sinks()[0].delivered == 1).await;

    let request = receiver.received().remove(0);
    assert_eq!(
        request.request_line,
        "POST /hooks/pgsnare?source=test HTTP/1.1"
    );
    assert_eq!(
        request.header("host"),
        Some(format!("localhost:{}", receiver.address.port()).as_str())
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("content-length"),
        Some(request.body.len().to_string().as_str())
    );
    assert_eq!(request.header("connection"), Some("close"));
    assert!(
        request
            .header("user-agent")
            .unwrap()
            .starts_with("pgsnare/")
    );

    // The body is the event, as every sink writes it.
    let event: Event = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(event.body.kind, EventKind::TokenHit);
    assert_eq!(
        event.body.token_id.as_ref().unwrap().as_str(),
        "users-admin-backup"
    );
    assert_eq!(event.body.db_user.as_deref(), Some("app"));
    assert_eq!(
        request.header("x-pgsnare-event-id"),
        Some(event.event_id.to_string().as_str())
    );

    // The timestamp is the time of the attempt, in seconds.
    let sent: u64 = request
        .header("x-pgsnare-timestamp")
        .unwrap()
        .parse()
        .unwrap();
    assert!(sent >= unix_seconds(before) && sent <= unix_seconds(SystemTime::now()));

    // And a receiver that follows the documentation accepts it.
    let mut verifier = Verifier::new(KEY, Duration::from_secs(300));
    assert_eq!(verifier.check_received(&request), Ok(()));
}

#[tokio::test]
async fn a_receiver_can_tell_a_forged_and_a_repeated_request_from_a_real_one() {
    let (receiver, settings) = trusted_receiver(&[], Answer::Status(204)).await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;
    raise(&proxy).await;
    raise(&proxy).await;
    until(|| receiver.count() == 2).await;

    let requests = receiver.received();
    let (first, second) = (&requests[0], &requests[1]);
    let timestamp = first.header("x-pgsnare-timestamp");
    let signature = first.header("x-pgsnare-signature");
    let now = unix_seconds(first.at);
    let verifier = || Verifier::new(KEY, Duration::from_secs(300));
    let check = |timestamp: Option<&str>, signature: Option<&str>, body: &[u8], now: u64| {
        verifier().check(timestamp, signature, body, now)
    };

    // The real request passes.
    assert_eq!(check(timestamp, signature, &first.body, now), Ok(()));

    // Sent again, it does not: the receiver has seen this event. Another
    // event still passes.
    let mut remembering = verifier();
    assert_eq!(remembering.check_received(first), Ok(()));
    assert_eq!(remembering.check_received(first), Err(Refused::Repeated));
    assert_eq!(remembering.check_received(second), Ok(()));
    assert_eq!(remembering.check_received(second), Err(Refused::Repeated));

    // Recorded and sent again later, it is too old, whoever sends it.
    assert_eq!(
        check(timestamp, signature, &first.body, now + 301),
        Err(Refused::TooOld)
    );
    assert_eq!(check(timestamp, signature, &first.body, now + 300), Ok(()));
    // A timestamp from the future is no better.
    assert_eq!(
        check(timestamp, signature, &first.body, now - 301),
        Err(Refused::TooOld)
    );

    // A body that was changed, by one byte or altogether.
    let mut changed = first.body.clone();
    let last = changed.len() - 2;
    changed[last] ^= 1;
    assert_eq!(
        check(timestamp, signature, &changed, now),
        Err(Refused::Forged)
    );
    assert_eq!(
        check(timestamp, signature, &second.body, now),
        Err(Refused::Forged)
    );

    // A timestamp that was changed, to make an old request look new.
    let later = (now + 200).to_string();
    assert_eq!(
        check(Some(&later), signature, &first.body, now + 200),
        Err(Refused::Forged)
    );

    // A signature that was made with another key, or made up.
    let mut stranger = Verifier::new(b"another key", Duration::from_secs(300));
    assert_eq!(stranger.check_received(first), Err(Refused::Forged));
    let made_up = format!("v1={}", "0".repeat(64));
    assert_eq!(
        check(timestamp, Some(&made_up), &first.body, now),
        Err(Refused::Forged)
    );

    // And what does not even look like the scheme.
    let bare = signature.unwrap().trim_start_matches("v1=").to_owned();
    for (timestamp, signature) in [
        (None, signature),
        (timestamp, None),
        (Some(""), signature),
        (Some("yesterday"), signature),
        (Some("+1794416791"), signature),
        (Some("01794416791"), signature),
        (timestamp, Some(bare.as_str())),
        (timestamp, Some("v1=")),
        (timestamp, Some("v1=abc")),
        (timestamp, Some("v2=0000")),
    ] {
        assert_eq!(
            check(timestamp, signature, &first.body, now),
            Err(Refused::Malformed),
            "{timestamp:?} {signature:?}"
        );
    }
}

/// What the sink counts, once it has dealt with one event.
async fn outcome_of_one_event(proxy: &Running) -> (u64, u64, [u64; 4]) {
    raise(proxy).await;
    until(|| {
        let sink = &proxy.status.sinks()[0];
        sink.delivered + sink.dropped_total() == 1
    })
    .await;
    let sink = proxy.status.sinks().remove(0);
    (sink.delivered, sink.failed_attempts, sink.dropped)
}

#[tokio::test]
async fn a_receiver_whose_certificate_is_not_trusted_gets_no_event() {
    let authority = Authority::new("an authority nobody trusts");
    let receiver = Receiver::tls(&authority.issue(&["localhost"]), &[], Answer::Status(200)).await;
    let once = SinkOptions::new().with_max_retries(1);

    // Trusting another authority.
    let other = Authority::new("another authority");
    let settings = WebhookSettings::new().with_trust(Trust::Roots(other.roots()));
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, once.clone()).await;
    assert_eq!(outcome_of_one_event(&proxy).await, (0, 2, [0, 0, 1, 0]));

    // Trusting the certificate store of the system, which is what a sink
    // of a configuration does. It does not know the authority of a test.
    let proxy = proxy_with(&https(&receiver, "/hook"), WebhookSettings::new(), once).await;
    assert_eq!(outcome_of_one_event(&proxy).await, (0, 2, [0, 0, 1, 0]));

    // Nothing was sent: the handshake never got that far.
    assert_eq!(receiver.count(), 0);
}

#[tokio::test]
async fn a_certificate_for_another_name_is_not_accepted() {
    let authority = Authority::new("the authority of a test");
    let receiver = Receiver::tls(
        &authority.issue(&["other.example.com"]),
        &[],
        Answer::Status(200),
    )
    .await;
    let settings = WebhookSettings::new().with_trust(Trust::Roots(authority.roots()));
    let proxy = proxy_with(
        &https(&receiver, "/hook"),
        settings,
        SinkOptions::new().with_max_retries(0),
    )
    .await;
    assert_eq!(outcome_of_one_event(&proxy).await, (0, 1, [0, 0, 1, 0]));
    assert_eq!(receiver.count(), 0);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let elsewhere = Receiver::plain(&[], Answer::Status(200)).await;
    let location = format!("http://127.0.0.1:{}/elsewhere", elsewhere.address.port());
    let (receiver, settings) = trusted_receiver(&[], Answer::Redirect(location)).await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;

    // The event is dropped as refused, at the first attempt.
    assert_eq!(outcome_of_one_event(&proxy).await, (0, 1, [0, 1, 0, 0]));
    assert_eq!(receiver.count(), 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(elsewhere.count(), 0);
}

#[tokio::test]
async fn an_event_that_is_refused_for_now_is_sent_again_and_signed_again() {
    let (receiver, settings) = trusted_receiver(
        &[Answer::Status(503), Answer::Garbage, Answer::Status(429)],
        Answer::Status(200),
    )
    .await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;
    assert_eq!(outcome_of_one_event(&proxy).await, (1, 3, [0, 0, 0, 0]));

    // Four requests for one event. Each is signed for the time it was
    // sent, and a receiver that remembers what it accepted takes the
    // event once.
    let requests = receiver.received();
    assert_eq!(requests.len(), 4);
    let mut verifier = Verifier::new(KEY, Duration::from_secs(300));
    assert_eq!(verifier.check_received(&requests[0]), Ok(()));
    for request in &requests[1..] {
        assert_eq!(request.body, requests[0].body);
        assert_eq!(verifier.check_received(request), Err(Refused::Repeated));
        assert_eq!(
            Verifier::new(KEY, Duration::from_secs(300)).check_received(request),
            Ok(())
        );
    }
}

#[tokio::test]
async fn a_request_that_is_refused_for_good_is_not_sent_again() {
    let (receiver, settings) = trusted_receiver(&[Answer::Status(401)], Answer::Status(200)).await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;
    assert_eq!(outcome_of_one_event(&proxy).await, (0, 1, [0, 1, 0, 0]));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(receiver.count(), 1);
}

#[tokio::test]
async fn an_answer_that_never_ends_does_not_hold_the_sink() {
    let (receiver, settings) = trusted_receiver(&[], Answer::Endless).await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;
    // The status is what counts. The rest of the answer is not waited for,
    // and the sink is free for the next event.
    assert_eq!(outcome_of_one_event(&proxy).await, (1, 0, [0, 0, 0, 0]));
    raise(&proxy).await;
    until(|| proxy.status.sinks()[0].delivered == 2).await;
    assert_eq!(receiver.count(), 2);
}

#[tokio::test]
async fn plain_http_works_where_it_was_allowed() {
    let receiver = Receiver::plain(&[], Answer::Status(200)).await;
    let url = format!("http://127.0.0.1:{}/hook", receiver.address.port());
    let settings = WebhookSettings::new().with_allow_insecure_http(true);
    let proxy = proxy_with(&url, settings, SinkOptions::default()).await;
    assert_eq!(outcome_of_one_event(&proxy).await, (1, 0, [0, 0, 0, 0]));

    let request: Received = receiver.received().remove(0);
    assert_eq!(request.request_line, "POST /hook HTTP/1.1");
    let mut verifier = Verifier::new(KEY, Duration::from_secs(300));
    assert_eq!(verifier.check_received(&request), Ok(()));
}

#[tokio::test]
async fn a_receiver_that_never_answers_costs_events_and_delays_no_session() {
    let (receiver, settings) = trusted_receiver(&[], Answer::Hang).await;
    // An attempt may take three seconds, and nothing is tried twice.
    let settings = settings.with_timeout(Duration::from_secs(3));
    let options = SinkOptions::new().with_queue_size(8).with_max_retries(0);
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, options).await;

    // A session raises two hundred events and goes on with its traffic in
    // between. If it waited for the sink, each event would cost it three
    // seconds.
    let mut client = proxy.connect().await;
    let started = Instant::now();
    for _ in 0..200 {
        say(&mut client, "bypass").await;
        exchange(&mut client, b"SELECT 1", b"SELECT 1").await;
    }
    let took = started.elapsed();
    assert!(took < Duration::from_secs(3), "{took:?}");

    // The sink holds one event and eight wait for it. The rest were
    // dropped, and counted.
    until(|| receiver.count() == 1).await;
    let counters = proxy.status.counters();
    assert_eq!(counters.events_emitted, 200);
    assert_eq!(counters.events_dropped, 0);
    let sink = proxy.status.sinks().remove(0);
    assert_eq!(sink.delivered, 0);
    assert_eq!(sink.queue_depth, 8);
    assert_eq!(sink.dropped, [191, 0, 0, 0]);

    // The attempt is given up after its three seconds, and the next event
    // gets its turn.
    until(|| proxy.status.sinks()[0].dropped[2] >= 1).await;
    until(|| receiver.count() >= 2).await;
    assert_eq!(proxy.status.sinks()[0].delivered, 0);
}

#[tokio::test]
async fn from_a_hit_to_its_receipt_takes_less_than_two_seconds() {
    const EVENTS: usize = 300;

    let (receiver, settings) = trusted_receiver(&[], Answer::Status(200)).await;
    let proxy = proxy_with(&https(&receiver, "/hook"), settings, SinkOptions::default()).await;

    // Hits come one at a time, a hundred in a second, each from a session
    // of its own.
    for _ in 0..EVENTS {
        raise(&proxy).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until(|| receiver.count() == EVENTS).await;

    // For each event: from the moment the session handed it over, which is
    // its timestamp, to the moment the receiver had read the request.
    let mut latencies: Vec<Duration> = receiver
        .received()
        .iter()
        .map(|request| {
            let event: Event = serde_json::from_slice(&request.body).unwrap();
            let raised = Duration::from_micros(event.timestamp.unix_micros());
            let received = request.at.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            received.saturating_sub(raised)
        })
        .collect();
    latencies.sort();
    let percentile = |percent: usize| latencies[(latencies.len() * percent).div_ceil(100) - 1];
    let (median, p99, worst) = (percentile(50), percentile(99), percentile(100));
    println!(
        "from hit to webhook receipt, {EVENTS} events over HTTPS: median {median:?}, \
         99th percentile {p99:?}, worst {worst:?}"
    );
    assert!(p99 <= Duration::from_secs(2), "{p99:?}");
    assert_eq!(
        proxy.status.sinks()[0].delivered,
        u64::try_from(EVENTS).unwrap()
    );
    assert_eq!(proxy.status.sinks()[0].dropped_total(), 0);
}
