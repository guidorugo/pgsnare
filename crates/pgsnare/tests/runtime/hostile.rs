// SPDX-License-Identifier: Apache-2.0

//! Peers that do not keep to the protocol: clients and databases that send
//! what cannot be a message, more than a message may be, or their bytes one
//! at a time, and clients that come in numbers.
//!
//! The sizes are the limits of the protocol crate and of the session
//! logic, each tried at the limit and one byte over it. The proxy inspects
//! what passes, with a honeytoken loaded, and ends a session it cannot
//! follow.
//!
//! Every test ends the same way, in [`unharmed`]: no session is left, no
//! task of the proxy has panicked, no read buffer is held, and a client
//! that behaves is let in and gets its answer. What a peer of a hostile
//! peer received is checked by [`only_whole_messages`]: whole messages
//! only, and none of the bytes that could not be followed.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pgsnare::redact::Sha256;
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::policy::{Inspection, OnError, PolicySnapshot, TokenId, TokenPolicy};
use pgsnare_core::session::postgres::{MAX_LOGIN_FRAME, Postgres};
use pgsnare_proto::startup::{MAX_STARTUP_PACKET_LEN, MIN_STARTUP_PACKET_LEN};
use pgsnare_proto::{HEADER_LEN, MAX_LENGTH, MIN_LENGTH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::support::{
    Database, ProxyOptions, Running, answer, frame, query, read_packet, read_to_end,
    read_until_ready, soon, startup_message, until, welcome,
};

/// The largest message the proxy keeps whole in these tests.
const KEPT_WHOLE: usize = 64 * 1024;

/// The largest message the database of these tests reads whole. A larger
/// one is read and thrown away as it comes, so that a length a client made
/// up never becomes memory of the test.
const READ_WHOLE: usize = 4 * 1024 * 1024;

/// Bytes that must never be passed on: they come after the point where a
/// stream could no longer be followed.
const POISON: &[u8] = b"bytes-after-the-fault";

/// A proxy that inspects what passes and ends what it cannot follow.
fn options() -> ProxyOptions {
    let id = "hostile-peers";
    let policy = PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, KEPT_WHOLE))
        .token(TokenPolicy::new(TokenId::new(id).unwrap()))
        .matcher(
            Matcher::build(&[TokenSpec::new(id, ["svc.hostile.4c1d9e@mail.example"])]).unwrap(),
        )
        .build()
        .unwrap();
    ProxyOptions {
        module: Arc::new(Postgres::scanning(Arc::new(Sha256))),
        policy,
        grace_period: Duration::from_secs(5),
    }
}

/// What a database of these tests does when a statement arrives.
#[derive(Clone)]
enum Reply {
    /// These bytes, and then the next statement is awaited.
    Send(Vec<u8>),
    /// These bytes, and then the connection is closed.
    SendAndClose(Vec<u8>),
}

type Script = fn(&[u8]) -> Option<Reply>;

/// A database that lets every client in, keeps the messages it receives,
/// and answers a statement as `script` says, or with the text of the
/// statement when the script says nothing.
async fn database(password: bool, received: Arc<Mutex<Vec<u8>>>, script: Script) -> Database {
    Database::new(move |mut stream| {
        let received = Arc::clone(&received);
        Box::pin(async move {
            let _ = serve(&mut stream, password, &received, script).await;
        })
    })
    .await
}

async fn serve(
    stream: &mut TcpStream,
    password: bool,
    received: &Mutex<Vec<u8>>,
    script: Script,
) -> io::Result<()> {
    read_packet(stream).await?;
    if password {
        // AuthenticationCleartextPassword, and whatever answers it.
        stream.write_all(&frame(b'R', &3u32.to_be_bytes())).await?;
        let Some(message) = read_message(stream).await? else {
            return Ok(());
        };
        received.lock().unwrap().extend_from_slice(&message);
    }
    stream.write_all(&welcome()).await?;
    loop {
        let Some(message) = read_message(stream).await? else {
            return Ok(());
        };
        received.lock().unwrap().extend_from_slice(&message);
        match message[0] {
            b'X' => return Ok(()),
            b'Q' => {
                let sql = &message[HEADER_LEN..message.len() - 1];
                match script(sql) {
                    None => stream.write_all(&answer(sql)).await?,
                    Some(Reply::Send(bytes)) => stream.write_all(&bytes).await?,
                    Some(Reply::SendAndClose(bytes)) => {
                        stream.write_all(&bytes).await?;
                        stream.shutdown().await?;
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Reads one message with a type byte. A message larger than
/// [`READ_WHOLE`] is not kept: `None` after everything that follows has
/// been read and thrown away.
async fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_be_bytes(header[1..].try_into().unwrap())).unwrap();
    if !(4..=READ_WHOLE).contains(&length) {
        let mut sink = vec![0u8; 64 * 1024];
        while stream.read(&mut sink).await? > 0 {}
        return Ok(None);
    }
    let mut message = header.to_vec();
    message.resize(1 + length, 0);
    stream.read_exact(&mut message[HEADER_LEN..]).await?;
    Ok(Some(message))
}

fn no_script(_: &[u8]) -> Option<Reply> {
    None
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Splits bytes into messages with a type byte. `None` when they do not
/// end where a message ends.
fn messages(mut bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut all = Vec::new();
    while !bytes.is_empty() {
        let header = bytes.get(..HEADER_LEN)?;
        let length = usize::try_from(u32::from_be_bytes(header[1..].try_into().unwrap())).ok()?;
        if length < 4 {
            return None;
        }
        let message = bytes.get(..1 + length)?;
        all.push(message);
        bytes = &bytes[1 + length..];
    }
    Some(all)
}

/// What a client or a database may have received once its session with a
/// hostile peer is over: whole messages, none of them holding the bytes
/// that followed the fault. An error among them is one the proxy wrote: it
/// ends the session and says nothing the peer sent.
fn only_whole_messages(received: &[u8], what: &str) {
    assert!(
        !contains(received, POISON),
        "{what}: bytes after the fault were passed on"
    );
    let all = messages(received).unwrap_or_else(|| panic!("{what}: part of a message was sent"));
    for message in all {
        if message[0] == b'E' {
            assert!(
                contains(message, b"SFATAL\0"),
                "{what}: an error that does not end the session"
            );
        }
    }
}

/// The end of every test: the proxy has nothing left of what happened and
/// goes on serving.
async fn unharmed(proxy: &Running) {
    until(|| proxy.status.counters().sessions_active == 0).await;
    let counters = proxy.status.counters();
    assert_eq!(
        (
            counters.session_panics,
            counters.listener_panics,
            counters.sink_panics,
            counters.admin_panics
        ),
        (0, 0, 0, 0),
        "a task of the proxy panicked"
    );
    assert_eq!(counters.listener_failures, 0);
    until(|| proxy.status.counters().read_buffer_bytes == 0).await;

    let (mut client, greeting) = proxy.log_in().await;
    assert_eq!(greeting, welcome());
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
}

/// A startup message for protocol 3.0 that is `length` bytes long.
fn startup_of(length: usize) -> Vec<u8> {
    // The length, the version, `user`, the name and two terminators.
    let name = length - 4 - 4 - 5 - 2;
    let mut bytes = u32::try_from(length).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(&196_608u32.to_be_bytes());
    bytes.extend_from_slice(b"user\0");
    bytes.resize(bytes.len() + name, b'a');
    bytes.extend_from_slice(b"\0\0");
    assert_eq!(bytes.len(), length);
    bytes
}

// ---------------------------------------------------------------------------
// Hostile clients
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_message_with_a_length_that_cannot_be_ends_its_session_alone() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(false, Arc::clone(&received), no_script).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    // A session that behaves, open all the while.
    let (mut steady, _) = proxy.log_in().await;

    let below = MIN_LENGTH - 1;
    let above = MAX_LENGTH + 1;
    let lengths = [0, 1, below, above, u32::MAX];
    for (round, length) in lengths.into_iter().enumerate() {
        let (mut client, _) = proxy.log_in().await;
        client.write_all(&query("SELECT 'before'")).await.unwrap();
        soon(read_until_ready(&mut client)).await.unwrap();

        let mut hostile = vec![b'Q'];
        hostile.extend_from_slice(&length.to_be_bytes());
        hostile.extend_from_slice(POISON);
        hostile.extend_from_slice(&query("SELECT 'after'"));
        // The proxy may have closed before all of it is written.
        let _ = client.write_all(&hostile).await;

        let reply = read_to_end(&mut client).await;
        only_whole_messages(&reply, "the client");
        let failed = u64::try_from(round + 1).unwrap();
        until(|| proxy.status.counters().sessions_failed == failed).await;
        until(|| proxy.status.counters().sessions_active == 1).await;

        // The other session saw nothing of it.
        steady.write_all(&query("SELECT 2")).await.unwrap();
        assert_eq!(
            soon(read_until_ready(&mut steady)).await.unwrap(),
            answer(b"SELECT 2")
        );
    }

    // The database got what could be followed and nothing after it.
    let reached = received.lock().unwrap().clone();
    only_whole_messages(&reached, "the database");
    assert!(contains(&reached, b"SELECT 'before'"));
    assert!(!contains(&reached, b"SELECT 'after'"));
    assert!(proxy.events.events.lock().unwrap().is_empty());

    drop(steady);
    unharmed(&proxy).await;
}

#[tokio::test]
async fn a_startup_packet_is_taken_up_to_the_limit_and_not_one_byte_over_it() {
    let database = Database::echo().await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;

    // At the limit, the client is let in.
    let mut client = proxy.connect().await;
    client
        .write_all(&startup_of(MAX_STARTUP_PACKET_LEN))
        .await
        .unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        welcome()
    );
    drop(client);
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(database.connection_count(), 1);
    assert_eq!(proxy.status.counters().sessions_failed, 0);

    // One byte over it, a length below the smallest packet, no length, a
    // negative one, and a packet of the right size that is no startup
    // message: each is closed, and the database is not asked.
    let over = startup_of(MAX_STARTUP_PACKET_LEN + 1);
    let short = u32::try_from(MIN_STARTUP_PACKET_LEN - 1)
        .unwrap()
        .to_be_bytes();
    let mut unknown = 16u32.to_be_bytes().to_vec();
    unknown.extend_from_slice(&[0xff; 12]);
    let hostile: [&[u8]; 6] = [
        &over,
        &short,
        &[0, 0, 0, 0],
        &[0xff, 0xff, 0xff, 0xff],
        &[0x80, 0, 0, 0],
        &unknown,
    ];
    for (round, packet) in hostile.into_iter().enumerate() {
        let mut client = proxy.connect().await;
        let mut bytes = packet.to_vec();
        bytes.extend_from_slice(POISON);
        let _ = client.write_all(&bytes).await;
        let reply = read_to_end(&mut client).await;
        only_whole_messages(&reply, "the client");
        let failed = u64::try_from(round + 1).unwrap();
        until(|| proxy.status.counters().sessions_failed == failed).await;
    }
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(
        database.connection_count(),
        1,
        "a packet that was refused reached the database"
    );
    assert_eq!(proxy.status.counters().logins_finished, 1);

    unharmed(&proxy).await;
}

#[tokio::test]
async fn a_login_message_is_taken_up_to_the_limit_and_not_one_byte_over_it() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(true, Arc::clone(&received), no_script).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let request = frame(b'R', &3u32.to_be_bytes());

    // A password message of exactly the largest size passes.
    let largest = frame(b'p', &vec![b'a'; MAX_LOGIN_FRAME - HEADER_LEN]);
    assert_eq!(largest.len(), MAX_LOGIN_FRAME);
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let mut asked = vec![0u8; request.len()];
    soon(client.read_exact(&mut asked)).await.unwrap();
    assert_eq!(asked, request);
    client.write_all(&largest).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        welcome()
    );
    assert_eq!(*received.lock().unwrap(), largest);
    drop(client);
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(proxy.status.counters().sessions_failed, 0);

    // One byte more ends the session, and the database gets none of it.
    received.lock().unwrap().clear();
    let mut body = vec![b'a'; MAX_LOGIN_FRAME - HEADER_LEN + 1 - POISON.len()];
    body.extend_from_slice(POISON);
    let too_large = frame(b'p', &body);
    assert_eq!(too_large.len(), MAX_LOGIN_FRAME + 1);
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    soon(client.read_exact(&mut asked)).await.unwrap();
    let _ = client.write_all(&too_large).await;
    let reply = read_to_end(&mut client).await;
    only_whole_messages(&reply, "the client");
    until(|| proxy.status.counters().sessions_failed == 1).await;
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert!(received.lock().unwrap().is_empty());
    assert_eq!(proxy.status.counters().logins_finished, 1);

    unharmed_after_a_password(&proxy, &request).await;
}

/// [`unharmed`] for a database that asks for a password.
async fn unharmed_after_a_password(proxy: &Running, request: &[u8]) {
    let counters = proxy.status.counters();
    assert_eq!(
        (counters.session_panics, counters.listener_panics),
        (0, 0),
        "a task of the proxy panicked"
    );
    until(|| proxy.status.counters().read_buffer_bytes == 0).await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let mut asked = vec![0u8; request.len()];
    soon(client.read_exact(&mut asked)).await.unwrap();
    client
        .write_all(&frame(b'p', b"a password\0"))
        .await
        .unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        welcome()
    );
    client.write_all(&query("SELECT 1")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut client)).await.unwrap(),
        answer(b"SELECT 1")
    );
}

#[tokio::test]
async fn a_client_that_sends_a_byte_at_a_time_is_served_and_holds_up_nobody() {
    let database = Database::echo().await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut slow, _) = proxy.log_in().await;
    let (mut other, _) = proxy.log_in().await;

    let statement = query("SELECT 'slowly'");
    let (first, rest) = statement.split_at(statement.len() / 2);
    for byte in first {
        slow.write_all(&[*byte]).await.unwrap();
        slow.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // In the middle of the message, another client gets its answer.
    other.write_all(&query("SELECT 2")).await.unwrap();
    assert_eq!(
        soon(read_until_ready(&mut other)).await.unwrap(),
        answer(b"SELECT 2")
    );
    // What the slow client holds in the proxy is its half message.
    assert!(proxy.status.counters().read_buffer_bytes < 2 * 64 * 1024);
    for byte in rest {
        slow.write_all(&[*byte]).await.unwrap();
        slow.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        soon(read_until_ready(&mut slow)).await.unwrap(),
        answer(b"SELECT 'slowly'")
    );
    assert_eq!(proxy.status.counters().sessions_failed, 0);

    drop((slow, other));
    unharmed(&proxy).await;
}

#[tokio::test]
async fn a_client_that_logs_in_a_byte_at_a_time_is_closed_when_the_time_is_up() {
    let database = Database::echo().await;
    let timeout = Duration::from_millis(600);
    let proxy = Running::start_with(
        Running::listener(database.upstream()).with_login_timeout(timeout),
        options(),
    )
    .await;

    // Every byte arrives well within the time: it is the login as a whole
    // that has a limit, not the pause between two bytes.
    let started = Instant::now();
    let mut client = proxy.connect().await;
    let sender = async {
        for byte in startup_message() {
            if client.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        read_to_end(&mut client).await
    };
    let reply = sender.await;
    let elapsed = started.elapsed();
    assert!(reply.is_empty(), "{reply:?}");
    assert!(elapsed >= timeout, "{elapsed:?}");
    until(|| proxy.status.counters().login_timeouts == 1).await;
    assert_eq!(database.connection_count(), 0);

    unharmed(&proxy).await;
}

#[tokio::test]
async fn a_message_that_claims_to_be_huge_takes_no_memory_before_its_bytes_arrive() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(false, Arc::clone(&received), no_script).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    // The largest length there is, and a thousand bytes of it.
    let mut hostile = vec![b'Q'];
    hostile.extend_from_slice(&MAX_LENGTH.to_be_bytes());
    hostile.extend_from_slice(&[b'a'; 1000]);
    client.write_all(&hostile).await.unwrap();
    until(|| proxy.status.counters().bytes_from_clients >= 1000).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let held = proxy.status.counters().read_buffer_bytes;
    assert!(
        held <= 4 * 64 * 1024,
        "{held} bytes are held for a message of which 1000 arrived"
    );
    assert_eq!(proxy.status.counters().sessions_active, 1);

    drop(client);
    unharmed(&proxy).await;
}

#[tokio::test]
async fn clients_beyond_the_limit_of_a_listener_are_turned_away_and_the_rest_are_served() {
    const PLACES: usize = 16;
    const HELD: usize = 4;
    const FLOOD: usize = 300;
    let database = Database::echo().await;
    let timeout = Duration::from_secs(4);
    let proxy = Running::start_with(
        Running::listener(database.upstream())
            .with_max_connections(PLACES)
            .with_login_timeout(timeout),
        options(),
    )
    .await;
    let mut held = Vec::new();
    for _ in 0..HELD {
        held.push(proxy.log_in().await.0);
    }

    // Clients that connect and then say nothing, half a startup message,
    // or something that is none. The first of them take the places that
    // are left; every other one is closed at once.
    let mut flood = Vec::new();
    for number in 0..FLOOD {
        let mut client = proxy.connect().await;
        let _ = match number % 3 {
            0 => Ok(()),
            1 => client.write_all(&startup_message()[..10]).await,
            _ => client.write_all(&[0, 0, 0]).await,
        };
        flood.push(client);
    }
    let refused = u64::try_from(FLOOD - (PLACES - HELD)).unwrap();
    until(|| proxy.status.counters().sessions_refused == refused).await;
    let last = flood.last_mut().unwrap();
    assert!(read_to_end(last).await.is_empty());
    // Nothing was asked of the database for any of them.
    assert_eq!(database.connections.load(Ordering::SeqCst), 4);

    // Those that are in are served while the others wait.
    for client in &mut held {
        client.write_all(&query("SELECT 3")).await.unwrap();
        assert_eq!(
            soon(read_until_ready(client)).await.unwrap(),
            answer(b"SELECT 3")
        );
    }

    // The places taken by the flood come back when the time for a login
    // is up, without anyone closing a connection.
    let waiting = u64::try_from(PLACES - HELD).unwrap();
    until(|| proxy.status.counters().login_timeouts == waiting).await;
    until(|| proxy.status.counters().sessions_active == u64::try_from(HELD).unwrap()).await;
    assert_eq!(proxy.status.counters().sessions_refused, refused);

    drop(held);
    drop(flood);
    unharmed(&proxy).await;
}

// ---------------------------------------------------------------------------
// Hostile databases
// ---------------------------------------------------------------------------

/// A row that holds `text`.
fn row(text: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 1];
    body.extend_from_slice(&u32::try_from(text.len()).unwrap().to_be_bytes());
    body.extend_from_slice(text);
    frame(b'D', &body)
}

/// A whole row, and then a message with the length the statement names.
fn broken_answers(sql: &[u8]) -> Option<Reply> {
    let length: u32 = match sql {
        b"no length" => 0,
        b"one" => 1,
        b"below the smallest" => MIN_LENGTH - 1,
        b"above the largest" => MAX_LENGTH + 1,
        b"all bits" => u32::MAX,
        _ => return None,
    };
    let mut bytes = row(b"before");
    bytes.push(b'D');
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(POISON);
    bytes.extend_from_slice(&answer(b"after"));
    Some(Reply::Send(bytes))
}

#[tokio::test]
async fn a_database_message_with_a_length_that_cannot_be_ends_the_session_alone() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(false, received, broken_answers).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut steady, _) = proxy.log_in().await;

    let statements = [
        "no length",
        "one",
        "below the smallest",
        "above the largest",
        "all bits",
    ];
    for (round, statement) in statements.into_iter().enumerate() {
        let (mut client, _) = proxy.log_in().await;
        client.write_all(&query(statement)).await.unwrap();
        let reply = read_to_end(&mut client).await;
        only_whole_messages(&reply, statement);
        assert!(!contains(&reply, b"after"), "{statement}");
        let failed = u64::try_from(round + 1).unwrap();
        until(|| proxy.status.counters().sessions_failed == failed).await;
        until(|| proxy.status.counters().sessions_active == 1).await;

        steady.write_all(&query("SELECT 2")).await.unwrap();
        assert_eq!(
            soon(read_until_ready(&mut steady)).await.unwrap(),
            answer(b"SELECT 2")
        );
    }

    drop(steady);
    unharmed(&proxy).await;
}

/// A whole row, and then a row that stops in the middle.
fn cut_answers(sql: &[u8]) -> Option<Reply> {
    let mut bytes = row(b"before");
    let mut second = vec![0u8; 2000];
    second.extend_from_slice(POISON);
    let second = row(&second);
    let kept = match sql {
        b"cut in the header" => 3,
        b"cut in the body" => second.len() - 1,
        _ => return None,
    };
    bytes.extend_from_slice(&second[..kept]);
    Some(Reply::SendAndClose(bytes))
}

#[tokio::test]
async fn a_database_that_stops_in_the_middle_of_a_message_leaves_the_client_no_part_of_it() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(false, received, cut_answers).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;

    for statement in ["cut in the header", "cut in the body"] {
        let (mut client, _) = proxy.log_in().await;
        client.write_all(&query(statement)).await.unwrap();
        let reply = read_to_end(&mut client).await;
        only_whole_messages(&reply, statement);
        until(|| proxy.status.counters().sessions_active == 0).await;
    }

    unharmed(&proxy).await;
}

/// The size of the message [`large_answers`] claims to send.
const CLAIMED: u32 = MAX_LENGTH;
/// How much of it arrives.
const ARRIVING: usize = 1024 * 1024;

/// The header of a row of the largest size there is, a part of it, and
/// the end of the connection.
fn large_answers(sql: &[u8]) -> Option<Reply> {
    if sql != b"a row without end" {
        return None;
    }
    let mut bytes = vec![b'D'];
    bytes.extend_from_slice(&CLAIMED.to_be_bytes());
    bytes.resize(bytes.len() + ARRIVING, b'x');
    Some(Reply::SendAndClose(bytes))
}

#[tokio::test]
async fn a_database_message_that_claims_to_be_huge_is_passed_on_as_it_comes_and_held_nowhere() {
    let received: Arc<Mutex<Vec<u8>>> = Arc::default();
    let database = database(false, received, large_answers).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let (mut client, _) = proxy.log_in().await;

    client.write_all(&query("a row without end")).await.unwrap();
    // The client reads slowly at first: what it has not taken stays in
    // the sockets and with the database, not in the proxy.
    let mut reply = vec![0u8; HEADER_LEN];
    soon(client.read_exact(&mut reply)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let held = proxy.status.counters().read_buffer_bytes;
    assert!(
        held <= u64::try_from(4 * 64 * 1024 + KEPT_WHOLE).unwrap(),
        "{held} bytes are held of a message that is passed on in parts"
    );
    reply.extend_from_slice(&read_to_end(&mut client).await);
    // Nothing more than what the database sent, and no message the proxy
    // made up in the middle of the one that was cut off.
    assert!(reply.len() <= HEADER_LEN + ARRIVING, "{}", reply.len());
    assert_eq!(reply[0], b'D');
    assert_eq!(reply[1..HEADER_LEN], CLAIMED.to_be_bytes());
    assert!(reply[HEADER_LEN..].iter().all(|byte| *byte == b'x'));

    unharmed(&proxy).await;
}

/// The size of the message a database sends before it has let anyone in.
fn login_answer(size: usize) -> Vec<u8> {
    let mut body = b"SFATAL\0M".to_vec();
    body.resize(size - HEADER_LEN - POISON.len() - 2, b'a');
    body.extend_from_slice(POISON);
    body.extend_from_slice(b"\0\0");
    let message = frame(b'E', &body);
    assert_eq!(message.len(), size);
    message
}

#[tokio::test]
async fn a_database_message_before_the_login_is_taken_up_to_the_limit_and_not_over_it() {
    // A database that refuses every client with an error of a given size.
    async fn refusing(size: usize) -> Database {
        Database::new(move |mut stream| {
            Box::pin(async move {
                if read_packet(&mut stream).await.is_ok() {
                    let _ = stream.write_all(&login_answer(size)).await;
                    let _ = stream.shutdown().await;
                    let mut sink = [0u8; 1024];
                    while matches!(stream.read(&mut sink).await, Ok(count) if count > 0) {}
                }
            })
        })
        .await
    }

    // At the limit the client gets the error of its database, whole.
    let database = refusing(MAX_LOGIN_FRAME).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let reply = read_to_end(&mut client).await;
    assert_eq!(reply, login_answer(MAX_LOGIN_FRAME));
    until(|| proxy.status.counters().sessions_active == 0).await;
    assert_eq!(proxy.status.counters().session_panics, 0);

    // One byte over it, the client gets none of it.
    let database = refusing(MAX_LOGIN_FRAME + 1).await;
    let proxy = Running::start_with(Running::listener(database.upstream()), options()).await;
    let mut client = proxy.connect().await;
    client.write_all(&startup_message()).await.unwrap();
    let reply = read_to_end(&mut client).await;
    only_whole_messages(&reply, "the client");
    until(|| proxy.status.counters().sessions_failed == 1).await;
    until(|| proxy.status.counters().sessions_active == 0).await;
    let counters = proxy.status.counters();
    assert_eq!((counters.session_panics, counters.listener_panics), (0, 0));
    assert_eq!(counters.logins_finished, 0);
    until(|| proxy.status.counters().read_buffer_bytes == 0).await;
}
