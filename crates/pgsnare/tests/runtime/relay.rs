// SPDX-License-Identifier: Apache-2.0

//! The runtime without TLS: relaying, limits, stopping, cancel requests and
//! what happens when things go wrong.
//!
//! Each test starts a proxy on a free port of this machine, in front of a
//! database that is a few lines of test code.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::support::{
    A_WHILE, Database, GSSENC_REQUEST, ProxyOptions, Running, SSL_REQUEST, TempDir, answer,
    cancel_request, error_fields, frame, policy, query, read_frame, read_packet, read_to_end,
    read_until_ready, serve_queries, serve_session, soon, startup_message, until, welcome,
};
use pgsnare::runtime::Upstream;
use pgsnare_core::event::EventKind;
use pgsnare_core::extension::{LoginStrategy, ProtocolModule, ProtocolSession, SessionError};
use pgsnare_core::policy::{OnError, PolicySnapshot};
use pgsnare_core::session::{Direction, Effect, Leg, Output, Report, SessionOrigin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};

#[tokio::test]
async fn a_session_is_relayed_as_the_bytes_that_arrived_and_is_counted() {
    let database = Database::echo().await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    assert!(proxy.status.is_ready());

    let (mut client, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());

    for sql in ["SELECT 1", "SELECT 'a second query'", ""] {
        client.write_all(&query(sql)).await.unwrap();
        let result = soon(read_until_ready(&mut client)).await.unwrap();
        assert_eq!(result, answer(sql.as_bytes()));
    }

    let counters = proxy.status.counters();
    assert_eq!(counters.sessions_accepted, 1);
    assert_eq!(counters.sessions_active, 1);
    assert_eq!(counters.logins_finished, 1);
    assert_eq!(counters.sessions_failed, 0);
    assert_eq!(counters.session_panics, 0);
    let sent = startup_message().len()
        + query("SELECT 1").len()
        + query("SELECT 'a second query'").len()
        + query("").len();
    assert_eq!(counters.bytes_from_clients, sent as u64);
    assert!(counters.bytes_from_servers > welcome().len() as u64);

    // The client says goodbye, and the database is told.
    client.write_all(&frame(b'X', b"")).await.unwrap();
    drop(client);
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(database.connection_count(), 1);
}

#[tokio::test]
async fn requests_for_encryption_are_declined_on_a_listener_without_tls() {
    let database = Database::echo().await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    let mut client = proxy.connect().await;

    let mut answer_byte = [0u8; 1];
    client.write_all(&GSSENC_REQUEST).await.unwrap();
    soon(client.read_exact(&mut answer_byte)).await.unwrap();
    assert_eq!(&answer_byte, b"N");
    client.write_all(&SSL_REQUEST).await.unwrap();
    soon(client.read_exact(&mut answer_byte)).await.unwrap();
    assert_eq!(&answer_byte, b"N");
    // No connection to the database has been opened for any of this.
    assert_eq!(database.connection_count(), 0);

    // The client goes on in plaintext.
    client.write_all(&startup_message()).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        welcome()
    );
}

#[tokio::test]
async fn a_listener_refuses_clients_beyond_its_connection_limit() {
    let database = Database::echo().await;
    let proxy =
        Running::start(Running::listener(database.upstream()).with_max_connections(2)).await;

    let (mut first, _) = proxy.log_in().await;
    let (second, _) = proxy.log_in().await;

    // A third client is closed at once, without a word.
    let mut third = proxy.connect().await;
    assert!(read_to_end(&mut third).await.is_empty());
    until(|| proxy.status.counters().sessions_refused == 1).await;
    assert_eq!(proxy.status.counters().sessions_active, 2);
    assert_eq!(database.connection_count(), 2);

    // The two that are in are not disturbed.
    first.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut first)).await.unwrap(),
        answer(b"SELECT 1")
    );

    // When one leaves, there is room again.
    drop(second);
    until(|| proxy.status.counters().sessions_active == 1).await;
    let (_fourth, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());
    assert_eq!(proxy.status.counters().sessions_refused, 1);
}

#[tokio::test]
async fn a_client_that_does_not_log_in_in_time_is_closed() {
    // A database that accepts connections and never says anything.
    let silent = Database::new(|mut stream| {
        Box::pin(async move {
            let mut sink = [0u8; 1024];
            while matches!(stream.read(&mut sink).await, Ok(count) if count > 0) {}
        })
    })
    .await;
    let timeout = Duration::from_millis(400);
    let proxy = Running::start(
        Running::listener(silent.upstream())
            .with_login_timeout(timeout)
            .with_max_connections(3),
    )
    .await;

    // A client that says nothing, one that stops in the middle of its
    // startup message, and one whose database does not answer.
    let started = Instant::now();
    let mut quiet = proxy.connect().await;
    let mut half = proxy.connect().await;
    half.write_all(&startup_message()[..10]).await.unwrap();
    let mut waiting = proxy.connect().await;
    waiting.write_all(&startup_message()).await.unwrap();

    for client in [&mut quiet, &mut half, &mut waiting] {
        assert!(read_to_end(client).await.is_empty());
    }
    let elapsed = started.elapsed();
    assert!(elapsed >= timeout, "{elapsed:?}");
    assert!(elapsed < timeout + Duration::from_secs(3), "{elapsed:?}");
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(proxy.status.counters().login_timeouts, 3);
    // Every slot is free again.
    for _ in 0..3 {
        let _ = proxy.connect().await;
    }
    assert_eq!(proxy.status.counters().sessions_refused, 0);
}

#[tokio::test]
async fn a_client_that_has_logged_in_may_stay_idle() {
    let database = Database::echo().await;
    let timeout = Duration::from_millis(300);
    let proxy =
        Running::start(Running::listener(database.upstream()).with_login_timeout(timeout)).await;
    let (mut client, _) = proxy.log_in().await;

    tokio::time::sleep(timeout * 3).await;
    client
        .write_all(&query("SELECT 'still here'"))
        .await
        .unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 'still here'")
    );
    assert_eq!(proxy.status.counters().login_timeouts, 0);
}

#[tokio::test]
async fn a_cancel_request_goes_to_the_database_verbatim_on_a_connection_of_its_own() {
    // The database keeps the first packet of every connection, and closes
    // a connection that brought a cancel request, as PostgreSQL does.
    let packets: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let seen = Arc::clone(&packets);
    let database = Database::new(move |mut stream| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            let Ok(packet) = read_packet(&mut stream).await else {
                return;
            };
            let cancel = packet[4..8] == 80_877_102u32.to_be_bytes();
            seen.lock().unwrap().push(packet);
            if cancel {
                // Not at once: the client must wait for it.
                tokio::time::sleep(A_WHILE).await;
                return;
            }
            let _ = stream.write_all(&welcome()).await;
            let _ = serve_queries(&mut stream).await;
        })
    })
    .await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    let (_session, _) = proxy.log_in().await;

    // A key of four bytes, as in protocol 3.0, and the longest one of 3.2.
    for key in [vec![9u8; 4], (0..=255u8).collect::<Vec<u8>>()] {
        let request = cancel_request(4242, &key);
        let started = Instant::now();
        let mut canceller = proxy.connect().await;
        canceller.write_all(&request).await.unwrap();
        // Nothing comes back, and the connection ends when the database
        // has dealt with the request, not before.
        assert!(read_to_end(&mut canceller).await.is_empty());
        assert!(started.elapsed() >= A_WHILE);
        assert_eq!(packets.lock().unwrap().last().unwrap(), &request);
    }
    assert_eq!(proxy.status.counters().cancels_forwarded, 2);
    // One connection for the session and one for each cancel request.
    assert_eq!(database.connection_count(), 3);
    assert_eq!(proxy.status.counters().logins_finished, 1);
}

#[tokio::test]
async fn a_database_that_cannot_be_reached_is_reported_to_the_client() {
    // A port nobody listens on.
    let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = free.local_addr().unwrap();
    drop(free);
    let proxy = Running::start(Running::listener(Upstream::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    }))
    .await;

    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let all = read_to_end(&mut client).await;
    let fields = error_fields(&all);
    assert_eq!(fields[0], (b'S', "FATAL".to_owned()));
    assert_eq!(fields[2], (b'C', "57P03".to_owned()));
    assert_eq!(proxy.status.counters().backend_failures, 1);
    until(|| proxy.status.counters().sessions_active == 0).await;

    // A name that does not resolve fails the same way.
    let proxy = Running::start(Running::listener(Upstream::Tcp {
        host: "database.invalid".to_owned(),
        port: 5432,
    }))
    .await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    assert_eq!(error_fields(&read_to_end(&mut client).await)[2].1, "57P03");
}

#[tokio::test]
async fn the_database_can_be_reached_over_a_unix_socket() {
    let dir = TempDir::new();
    let path = dir.0.join(".s.PGSQL.5432");
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_session(&mut stream).await;
            });
        }
    });
    let proxy = Running::start(Running::listener(Upstream::Unix(path))).await;

    let (mut client, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());
    client
        .write_all(&query("SELECT 'over a socket'"))
        .await
        .unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 'over a socket'")
    );

    // A socket that is not there is a database that cannot be reached.
    let proxy = Running::start(Running::listener(Upstream::Unix(
        dir.0.join("no-such-socket"),
    )))
    .await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    assert_eq!(error_fields(&read_to_end(&mut client).await)[2].1, "57P03");
}

#[tokio::test]
async fn large_messages_pass_unchanged_in_both_directions() {
    // The database answers each query with a row as large as the query
    // says, and then with the size of the query it received.
    let database = Database::new(|mut stream| {
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err() {
                return;
            }
            let _ = stream.write_all(&welcome()).await;
            while let Ok(message) = read_frame(&mut stream).await {
                if message[0] != b'Q' {
                    return;
                }
                let size = message.len().to_string();
                let row: Vec<u8> = (0..message.len())
                    .map(|index| (index % 251) as u8)
                    .collect();
                let mut reply = frame(b'D', &row);
                reply.extend_from_slice(&frame(b'C', size.as_bytes()));
                reply.extend_from_slice(&frame(b'Z', b"I"));
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
            }
        })
    })
    .await;
    // Every message of any size is larger than what is held whole.
    let options = ProxyOptions {
        policy: policy(OnError::FailClosed, 1024),
        ..ProxyOptions::default()
    };
    let proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (client, _) = proxy.log_in().await;
    let (mut reader, mut writer) = client.into_split();

    let sql = "x".repeat(6 * 1024 * 1024);
    let request = query(&sql);
    let expected_row: Vec<u8> = (0..request.len())
        .map(|index| (index % 251) as u8)
        .collect();
    let mut expected = frame(b'D', &expected_row);
    expected.extend_from_slice(&frame(b'C', request.len().to_string().as_bytes()));
    expected.extend_from_slice(&frame(b'Z', b"I"));

    // The client writes and reads at the same time, as a real one would
    // have to with messages of this size.
    let sending = tokio::spawn(async move {
        writer.write_all(&request).await.unwrap();
        writer
    });
    let result = soon(read_until_ready(&mut reader)).await.unwrap();
    assert!(result == expected, "the reply differs from what was sent");
    soon(sending).await.unwrap();
}

#[tokio::test]
async fn a_client_that_stops_reading_holds_back_the_database_and_loses_nothing() {
    const TOTAL: usize = 64 * 1024 * 1024;
    let written = Arc::new(AtomicU64::new(0));
    let progress = Arc::clone(&written);
    let database = Database::new(move |mut stream| {
        let progress = Arc::clone(&progress);
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err() {
                return;
            }
            let _ = stream.write_all(&welcome()).await;
            if read_frame(&mut stream).await.is_err() {
                return;
            }
            // One row after the other, 64 MiB in all.
            let row = frame(b'D', &[7u8; 64 * 1024 - 5]);
            for _ in 0..TOTAL / row.len() {
                if stream.write_all(&row).await.is_err() {
                    return;
                }
                progress.fetch_add(row.len() as u64, Ordering::SeqCst);
            }
            let _ = stream.write_all(&frame(b'Z', b"I")).await;
        })
    })
    .await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    let (mut client, _) = proxy.log_in().await;
    client.write_all(&query("SELECT everything")).await.unwrap();

    // The client reads nothing. The database gets rid of what fits into
    // the buffers on the way, and then has to wait.
    let mut before = u64::MAX;
    soon(async {
        loop {
            tokio::time::sleep(A_WHILE).await;
            let now = written.load(Ordering::SeqCst);
            if now == before {
                break;
            }
            before = now;
        }
    })
    .await;
    let stalled_at = written.load(Ordering::SeqCst);
    assert!(stalled_at > 0);
    assert!(
        stalled_at < (TOTAL / 2) as u64,
        "the database wrote {stalled_at} bytes to a client that reads nothing"
    );

    // Once the client reads, everything arrives.
    let result = soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(result.len(), TOTAL + 6);
    assert!(
        result[..TOTAL]
            .chunks(64 * 1024)
            .all(|row| row[0] == b'D' && row[5..] == [7u8; 64 * 1024 - 5])
    );
}

#[tokio::test]
async fn a_session_gives_back_its_buffers_when_it_goes_quiet() {
    // What a quiet session reads into, for both directions together, and
    // what a busy direction reads into.
    const QUIET: u64 = 2 * 1024;
    const BUSY: u64 = 64 * 1024;

    let database = Database::echo().await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    let held = || proxy.status.counters().read_buffer_bytes;
    assert_eq!(held(), 0);

    let (mut client, _) = proxy.log_in().await;
    assert_eq!(held(), QUIET);

    // A megabyte in each direction: both buffers grow.
    let sql = "z".repeat(1024 * 1024);
    client.write_all(&query(&sql)).await.unwrap();
    let reply = soon(read_until_ready(&mut client)).await.unwrap();
    assert!(reply == answer(sql.as_bytes()));
    assert_eq!(held(), 2 * BUSY);

    // Nothing happens for a while: the session is down to what a quiet
    // one holds, and it still works.
    until(|| held() == QUIET).await;
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
    assert_eq!(held(), QUIET);

    // A session that is over holds nothing.
    drop(client);
    until(|| held() == 0).await;
}

#[tokio::test]
async fn with_fail_closed_traffic_that_cannot_be_followed_ends_the_session() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = recording_database(Arc::clone(&received)).await;
    let proxy = Running::start(Running::listener(database.upstream())).await;
    let (mut client, _) = proxy.log_in().await;

    // A message whose length is below the minimum: where the next one
    // begins cannot be known.
    client.write_all(&query("SELECT 1")).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    client
        .write_all(&[b'Q', 0, 0, 0, 1, b'x', b'y'])
        .await
        .unwrap();

    // The client is closed without a word, and the database sees nothing
    // of what could not be read.
    assert!(read_to_end(&mut client).await.is_empty());
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(proxy.status.counters().sessions_failed, 1);
    assert_eq!(*received.lock().unwrap(), query("SELECT 1"));
    assert!(proxy.events.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn with_fail_open_the_session_goes_on_as_a_tunnel_and_an_event_is_raised() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = recording_database(Arc::clone(&received)).await;
    let options = ProxyOptions {
        policy: policy(OnError::FailOpen, 1024 * 1024),
        ..ProxyOptions::default()
    };
    let proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (mut client, _) = proxy.log_in().await;

    let broken = [b'Q', 0, 0, 0, 1, b'x', b'y'];
    client.write_all(&broken).await.unwrap();
    // The database gets exactly what the client sent, and its answer
    // comes back.
    until(|| received.lock().unwrap().ends_with(&broken)).await;
    let mut reply = [0u8; 4];
    soon(client.read_exact(&mut reply)).await.unwrap();
    assert_eq!(&reply, b"what");

    until(|| !proxy.events.events.lock().unwrap().is_empty()).await;
    let events = proxy.events.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].body.kind, EventKind::InspectionBypassed);
    assert_eq!(events[0].body.direction, Some(Direction::FromClient));
    assert_eq!(events[0].body.db_user.as_deref(), Some("app"));
    assert_ne!(events[0].event_id.as_u128(), 0);
    assert_eq!(proxy.status.counters().sessions_failed, 0);
    assert_eq!(proxy.status.counters().events_emitted, 1);
    assert_eq!(proxy.status.counters().sessions_active, 1);
}

/// A database that lets a client in, keeps everything the client sends
/// after that, answers a query like the echo database and anything else
/// with four bytes that are no message at all.
async fn recording_database(received: Arc<Mutex<Vec<u8>>>) -> Database {
    Database::new(move |mut stream| {
        let received = Arc::clone(&received);
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err() {
                return;
            }
            let _ = stream.write_all(&welcome()).await;
            let mut buffer = [0u8; 4096];
            loop {
                let count = match stream.read(&mut buffer).await {
                    Ok(count) if count > 0 => count,
                    _ => return,
                };
                received.lock().unwrap().extend_from_slice(&buffer[..count]);
                let reply = if buffer[..count] == query("SELECT 1")[..] {
                    answer(b"SELECT 1")
                } else {
                    b"what".to_vec()
                };
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
            }
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Stopping
// ---------------------------------------------------------------------------

const ADMIN_SHUTDOWN: &str = "terminating connection due to administrator command";

#[tokio::test]
async fn stopping_lets_open_sessions_finish_and_then_closes_them_with_the_error_of_the_database() {
    let database = Database::echo().await;
    let grace_period = Duration::from_millis(600);
    let options = ProxyOptions {
        grace_period,
        ..ProxyOptions::default()
    };
    let mut proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (mut staying, _) = proxy.log_in().await;
    let (mut leaving, _) = proxy.log_in().await;

    let asked = Instant::now();
    proxy.stop();
    until(|| !proxy.status.is_ready()).await;

    // No new client is accepted.
    until(|| std::net::TcpStream::connect(proxy.address).is_err()).await;

    // The sessions that are open go on.
    for client in [&mut staying, &mut leaving] {
        client
            .write_all(&query("SELECT 'during the grace period'"))
            .await
            .unwrap();
        assert_eq!(
            soon(read_until_ready(client)).await.unwrap(),
            answer(b"SELECT 'during the grace period'")
        );
    }
    assert!(asked.elapsed() < grace_period);

    // One of them ends by itself. The other is still there when the grace
    // period is over, and is told what the database tells a session that
    // an administrator ends.
    leaving.write_all(&frame(b'X', b"")).await.unwrap();
    drop(leaving);
    let last = read_to_end(&mut staying).await;
    assert!(asked.elapsed() >= grace_period);
    let fields = error_fields(&last);
    assert_eq!(
        fields,
        [
            (b'S', "FATAL".to_owned()),
            (b'V', "FATAL".to_owned()),
            (b'C', "57P01".to_owned()),
            (b'M', ADMIN_SHUTDOWN.to_owned()),
        ]
    );

    proxy.stopped().await;
    assert_eq!(proxy.status.counters().sessions_active, 0);
    assert!(!proxy.status.is_ready());
}

#[tokio::test]
async fn stopping_does_not_wait_for_the_grace_period_when_nobody_is_left() {
    let database = Database::echo().await;
    let options = ProxyOptions {
        grace_period: Duration::from_secs(3600),
        ..ProxyOptions::default()
    };
    let mut proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    let (mut client, _) = proxy.log_in().await;

    proxy.stop();
    until(|| !proxy.status.is_ready()).await;
    client.write_all(&frame(b'X', b"")).await.unwrap();
    drop(client);
    // An hour of grace, and the proxy is gone within seconds.
    proxy.stopped().await;
}

#[tokio::test]
async fn stopping_closes_clients_that_have_not_logged_in_without_a_word() {
    let database = Database::echo().await;
    let options = ProxyOptions {
        grace_period: Duration::from_millis(200),
        ..ProxyOptions::default()
    };
    let mut proxy = Running::start_with(Running::listener(database.upstream()), options).await;
    // One client has sent nothing, another half of a request for TLS.
    let mut quiet = proxy.connect().await;
    let mut half = proxy.connect().await;
    half.write_all(&SSL_REQUEST[..5]).await.unwrap();
    until(|| proxy.status.counters().sessions_active == 2).await;

    proxy.stop();
    assert!(read_to_end(&mut quiet).await.is_empty());
    assert!(read_to_end(&mut half).await.is_empty());
    proxy.stopped().await;
}

// ---------------------------------------------------------------------------
// Protocol modules that misbehave, or ask for things
// ---------------------------------------------------------------------------

/// A protocol without a database: what a client sends comes back to it.
/// The word `panic` makes the session panic, and `later` is answered after
/// a delay.
struct Fragile;

struct FragileSession;

impl ProtocolModule for Fragile {
    fn name(&self) -> &'static str {
        "fragile"
    }

    fn start_session(
        &self,
        _origin: SessionOrigin,
        _login: Arc<dyn LoginStrategy>,
    ) -> Box<dyn ProtocolSession> {
        Box::new(FragileSession)
    }
}

impl ProtocolSession for FragileSession {
    fn on_bytes(
        &mut self,
        _from: Direction,
        input: &[u8],
        _policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        match input {
            b"panic" => panic!("a panic that a test asked for"),
            b"later" => {
                out.to_client.extend_from_slice(b"at last");
                out.effects.push(Effect::Delay(A_WHILE));
            }
            b"bye" => {
                out.to_client.extend_from_slice(b"goodbye");
                out.effects.push(Effect::Close(Leg::Client));
            }
            _ => out.to_client.extend_from_slice(input),
        }
        Ok(())
    }

    fn on_report(
        &mut self,
        report: Report,
        _policy: &PolicySnapshot,
        out: &mut Output,
    ) -> Result<(), SessionError> {
        if report == Report::ShuttingDown {
            out.to_client.extend_from_slice(b"closing time");
        }
        Ok(())
    }
}

fn fragile() -> ProxyOptions {
    ProxyOptions {
        module: Arc::new(Fragile),
        grace_period: Duration::from_millis(100),
        ..ProxyOptions::default()
    }
}

/// A listener whose database is never used.
fn nowhere() -> pgsnare::runtime::ListenerSettings {
    Running::listener(Upstream::Tcp {
        host: "127.0.0.1".to_owned(),
        port: 1,
    })
}

async fn exchange(client: &mut TcpStream, send: &[u8], expect: &[u8]) {
    client.write_all(send).await.unwrap();
    let mut reply = vec![0u8; expect.len()];
    soon(client.read_exact(&mut reply)).await.unwrap();
    assert_eq!(reply, expect);
}

#[tokio::test]
async fn a_panic_ends_one_session_and_is_counted() {
    let proxy = Running::start_with(nowhere().with_max_connections(2), fragile()).await;
    let mut steady = proxy.connect().await;
    let mut doomed = proxy.connect().await;
    exchange(&mut steady, b"hello", b"hello").await;
    exchange(&mut doomed, b"hello", b"hello").await;

    doomed.write_all(b"panic").await.unwrap();
    // The session that panicked is gone.
    assert!(read_to_end(&mut doomed).await.is_empty());
    until(|| proxy.status.counters().session_panics == 1).await;
    assert_eq!(proxy.status.counters().sessions_active, 1);

    // The process is not, and neither is the other session.
    exchange(&mut steady, b"still here", b"still here").await;
    // The place of the session that panicked is free again.
    let mut next = proxy.connect().await;
    exchange(&mut next, b"hello", b"hello").await;
    assert_eq!(proxy.status.counters().sessions_refused, 0);
    assert_eq!(proxy.status.counters().session_panics, 1);
}

#[tokio::test]
async fn a_delay_holds_back_what_is_sent_to_the_client() {
    let proxy = Running::start_with(nowhere(), fragile()).await;
    let mut client = proxy.connect().await;
    exchange(&mut client, b"now", b"now").await;

    let asked = Instant::now();
    exchange(&mut client, b"later", b"at last").await;
    assert!(asked.elapsed() >= A_WHILE, "{:?}", asked.elapsed());
    // Only once.
    let asked = Instant::now();
    exchange(&mut client, b"now", b"now").await;
    assert!(asked.elapsed() < A_WHILE);
}

#[tokio::test]
async fn a_connection_is_closed_after_what_was_queued_for_it_has_been_sent() {
    let mut proxy = Running::start_with(nowhere(), fragile()).await;
    let mut client = proxy.connect().await;
    client.write_all(b"bye").await.unwrap();
    assert_eq!(read_to_end(&mut client).await, b"goodbye");
    until(|| proxy.status.counters().sessions_active == 0).await;

    // The same when the proxy stops: the last words of a session arrive.
    let mut client = proxy.connect().await;
    exchange(&mut client, b"hello", b"hello").await;
    proxy.stop();
    assert_eq!(read_to_end(&mut client).await, b"closing time");
    proxy.stopped().await;
}
