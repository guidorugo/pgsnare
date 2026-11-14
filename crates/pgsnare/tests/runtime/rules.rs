// SPDX-License-Identifier: Apache-2.0

//! The SQL rules through the runtime: a statement waits for the parser
//! threads before it reaches the database, and a statement they give no
//! analysis for meets `on_parse_failure`, whether they refused it, were
//! busy, or did not answer in time.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use pgsnare::redact::Sha256;
use pgsnare::runtime::parser::{ParserPool, ParserSettings};
use pgsnare::runtime::{Runtime, Settings, Status};
use pgsnare_core::detect::{Matcher, TokenSpec};
use pgsnare_core::event::EventKind;
use pgsnare_core::extension::ProtocolModule;
use pgsnare_core::policy::{
    ActionSet, FixedPolicy, Inspection, OnError, PolicySnapshot, TokenId, TokenPolicy,
};
use pgsnare_core::rules::{Limits, OnParseFailure, RuleScope, RuleSet};
use pgsnare_core::session::postgres::Postgres;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::support::{
    Database, Memory, PATIENCE, Running, answer, error_fields, frame, proxy_of, query, read_frame,
    read_packet, read_to_end, read_until_ready, soon, startup_message, until,
};

const TOKEN_ID: &str = "users-admin-backup";
const VALUE: &str = "svc.backup.8f3k2q@mail.example";

/// Longer than any of these tests runs.
const NEVER: Duration = Duration::from_secs(600);

fn policy(on_failure: OnParseFailure) -> PolicySnapshot {
    let rules = RuleSet::builder()
        .on_parse_failure(on_failure)
        .functions(
            &["pg_sleep".to_owned()],
            ActionSet::ALERT,
            RuleScope::default(),
        )
        .unwrap()
        .build();
    PolicySnapshot::builder()
        .inspection(Inspection::new(OnError::FailClosed, 1024 * 1024))
        .token(TokenPolicy::new(TokenId::new(TOKEN_ID).unwrap()))
        .matcher(Matcher::build(&[TokenSpec::new(TOKEN_ID, [VALUE])]).unwrap())
        .rules(rules)
        .build()
        .unwrap()
}

/// What the database was sent once a client was let in.
#[derive(Default)]
struct Seen {
    messages: Mutex<Vec<Vec<u8>>>,
    ended: AtomicU32,
}

impl Seen {
    fn messages(&self) -> Vec<Vec<u8>> {
        self.messages.lock().unwrap().clone()
    }
}

/// A database that reports the settings a statement is read under, keeps
/// every message it is sent, and answers both ways of running a statement.
async fn database(seen: &Arc<Seen>) -> Database {
    let seen = Arc::clone(seen);
    Database::new(move |mut stream| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            if read_packet(&mut stream).await.is_err() {
                return;
            }
            let welcome = [
                frame(b'R', &0u32.to_be_bytes()),
                frame(b'S', b"client_encoding\0UTF8\0"),
                frame(b'S', b"standard_conforming_strings\0on\0"),
                frame(b'Z', b"I"),
            ]
            .concat();
            if stream.write_all(&welcome).await.is_err() {
                return;
            }
            while let Ok(message) = read_frame(&mut stream).await {
                let reply = match message[0] {
                    b'Q' => answer(&message[5..message.len() - 1]),
                    b'P' => frame(b'1', b""),
                    b'B' => frame(b'2', b""),
                    b'E' => frame(b'C', b"SELECT 1\0"),
                    b'S' => frame(b'Z', b"I"),
                    _ => Vec::new(),
                };
                seen.messages.lock().unwrap().push(message);
                if stream.write_all(&reply).await.is_err() {
                    break;
                }
            }
            seen.ended.fetch_add(1, Ordering::SeqCst);
        })
    })
    .await
}

/// A proxy in front of `database`, for as long as a test holds it.
struct Proxied {
    status: Arc<Status>,
    events: Arc<Memory>,
    address: std::net::SocketAddr,
    task: JoinHandle<()>,
}

impl Proxied {
    async fn start(
        database: &Database,
        policy: PolicySnapshot,
        pool: Option<&Arc<ParserPool>>,
        deadline: Duration,
    ) -> Self {
        let events = Arc::new(Memory::default());
        let module: Arc<dyn ProtocolModule> = Arc::new(Postgres::scanning(Arc::new(Sha256)));
        let mut settings = Settings::new(vec![Running::listener(database.upstream())])
            .with_analysis_deadline(deadline);
        if let Some(pool) = pool {
            settings = settings.with_parser(Arc::clone(pool));
        }
        let runtime = Runtime::new(
            proxy_of(module, &events),
            Arc::new(FixedPolicy::new(policy)),
            settings,
        );
        let bound = runtime.bind().unwrap();
        let address = bound.local_addrs()[0];
        let status = bound.status();
        let task = tokio::spawn(bound.serve(std::future::pending()));
        until(|| status.is_ready()).await;
        Self {
            status,
            events,
            address,
            task,
        }
    }

    async fn log_in(&self) -> TcpStream {
        let mut client = TcpStream::connect(self.address).await.unwrap();
        client.write_all(&startup_message()).await.unwrap();
        soon(read_until_ready(&mut client)).await.unwrap();
        client
    }

    fn parse_failure_events(&self) -> usize {
        self.events
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.body.kind == EventKind::ParseFailure)
            .count()
    }
}

impl Drop for Proxied {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn pool(threads: usize, queue: usize) -> Arc<ParserPool> {
    let mut settings = ParserSettings::default();
    settings.threads = threads;
    settings.queue = queue;
    Arc::new(ParserPool::start(settings).unwrap())
}

/// Keeps one thread of `pool` busy until what is returned is dropped.
fn stall(pool: &ParserPool) -> mpsc::Sender<()> {
    let (release, released) = mpsc::channel::<()>();
    let (started, has_started) = mpsc::channel::<()>();
    pool.submit(b"SELECT 0".to_vec(), Limits::default(), move |_| {
        let _ = started.send(());
        let _ = released.recv();
    })
    .unwrap();
    has_started.recv_timeout(PATIENCE).unwrap();
    release
}

fn is_fatal(received: &[u8]) -> bool {
    error_fields(received).first() == Some(&(b'S', "FATAL".to_owned()))
}

#[tokio::test]
async fn a_statement_is_analysed_before_it_reaches_the_database() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 16);
    let proxy = Proxied::start(
        &database,
        policy(OnParseFailure::Block),
        Some(&pool),
        PATIENCE,
    )
    .await;
    let mut client = proxy.log_in().await;

    client.write_all(&query("SELECT 1")).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(seen.messages(), [query("SELECT 1")]);
    assert_eq!(pool.stats().analysed, 1);

    // The same text again is answered from what is kept.
    client.write_all(&query("SELECT 1")).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    let stats = pool.stats();
    assert_eq!((stats.analysed, stats.cache_hits), (1, 1));

    let counters = proxy.status.counters();
    assert_eq!(counters.parse_failures, 0);
    assert_eq!(counters.actions, [0, 0, 0, 0]);
    assert_eq!(proxy.parse_failure_events(), 0);
}

#[tokio::test]
async fn a_statement_the_parser_refuses_meets_the_policy() {
    // Block: the client gets the error, and the database not one message.
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 16);
    let proxy = Proxied::start(
        &database,
        policy(OnParseFailure::Block),
        Some(&pool),
        PATIENCE,
    )
    .await;
    let mut client = proxy.log_in().await;
    client.write_all(&query("SELEC 1")).await.unwrap();
    assert!(is_fatal(&read_to_end(&mut client).await));
    until(|| seen.ended.load(Ordering::SeqCst) == 1).await;
    assert!(seen.messages().is_empty());
    let counters = proxy.status.counters();
    assert_eq!(counters.parse_failures, 1);
    assert_eq!(counters.actions, [1, 1, 0, 0]);
    until(|| proxy.parse_failure_events() == 1).await;

    // Alert: the statement goes on, and is reported.
    let seen = Arc::new(Seen::default());
    let database = self::database(&seen).await;
    let proxy = Proxied::start(
        &database,
        policy(OnParseFailure::Alert),
        Some(&pool),
        PATIENCE,
    )
    .await;
    let mut client = proxy.log_in().await;
    client.write_all(&query("SELEC 1")).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(seen.messages(), [query("SELEC 1")]);
    let counters = proxy.status.counters();
    assert_eq!(counters.parse_failures, 1);
    assert_eq!(counters.actions, [1, 0, 0, 0]);
    until(|| proxy.parse_failure_events() == 1).await;
}

#[tokio::test]
async fn a_token_is_found_while_the_parser_is_stalled_and_the_statement_waits() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 16);
    let proxy = Proxied::start(&database, policy(OnParseFailure::Block), Some(&pool), NEVER).await;
    let mut client = proxy.log_in().await;

    let release = stall(&pool);
    let statement = query(&format!("SELECT '{VALUE}'"));
    client.write_all(&statement).await.unwrap();
    // More of the client, which waits behind the statement.
    client.write_all(&query("SELECT 2")).await.unwrap();

    // The hit is raised though the parser has said nothing.
    until(|| proxy.status.counters().token_hits == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(seen.messages().is_empty());
    assert_eq!(proxy.status.counters().parse_failures, 0);

    // Once the parser answers, everything goes on in order.
    drop(release);
    soon(read_until_ready(&mut client)).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();
    assert_eq!(seen.messages(), [statement, query("SELECT 2")]);
    assert_eq!(proxy.status.counters().parse_failures, 0);
}

#[tokio::test]
async fn a_client_is_not_read_while_its_statement_waits() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 16);
    let proxy = Proxied::start(&database, policy(OnParseFailure::Block), Some(&pool), NEVER).await;
    let client = proxy.log_in().await;
    let (mut reader, mut writer) = client.into_split();

    // Behind one held statement, more than a session would keep: two
    // megabytes of further statements.
    let release = stall(&pool);
    let filler = query(&format!("SELECT '{}'", "a".repeat(50_000)));
    let count = 40;
    let sent = tokio::spawn(async move {
        writer.write_all(&query("SELECT 1")).await.unwrap();
        for _ in 0..count {
            writer.write_all(&filler).await.unwrap();
        }
        writer
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(seen.messages().is_empty());
    assert_eq!(proxy.status.counters().sessions_failed, 0);

    // They were left with the client, and arrive once the parser answers.
    drop(release);
    for _ in 0..=count {
        soon(read_until_ready(&mut reader)).await.unwrap();
    }
    let _writer = soon(sent).await.unwrap();
    assert_eq!(seen.messages().len(), count + 1);
    let counters = proxy.status.counters();
    assert_eq!(counters.sessions_failed, 0);
    assert_eq!(counters.parse_failures, 0);
}

#[tokio::test]
async fn a_parser_that_does_not_answer_in_time_fails_the_statement() {
    let deadline = Duration::from_millis(150);
    for on_failure in [OnParseFailure::Block, OnParseFailure::Alert] {
        let seen = Arc::new(Seen::default());
        let database = database(&seen).await;
        let pool = pool(1, 16);
        let proxy = Proxied::start(&database, policy(on_failure), Some(&pool), deadline).await;
        let mut client = proxy.log_in().await;

        let _release = stall(&pool);
        let asked = Instant::now();
        client.write_all(&query("SELECT 1")).await.unwrap();
        if on_failure == OnParseFailure::Block {
            assert!(is_fatal(&read_to_end(&mut client).await));
            assert!(seen.messages().is_empty());
        } else {
            soon(read_until_ready(&mut client)).await.unwrap();
            assert_eq!(seen.messages(), [query("SELECT 1")]);
        }
        // Not before the time allowed had passed.
        assert!(asked.elapsed() >= deadline, "{on_failure:?}");
        assert_eq!(proxy.status.counters().parse_failures, 1, "{on_failure:?}");
        until(|| proxy.parse_failure_events() == 1).await;
    }
}

#[tokio::test]
async fn a_full_queue_fails_the_statement_at_once() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 1);
    let proxy = Proxied::start(&database, policy(OnParseFailure::Block), Some(&pool), NEVER).await;
    let mut client = proxy.log_in().await;

    // One statement on the only thread, and one in the only place behind
    // it.
    let _release = stall(&pool);
    pool.submit(b"SELECT 0".to_vec(), Limits::default(), |_| {})
        .unwrap();

    client.write_all(&query("SELECT 1")).await.unwrap();
    // Without waiting for the parser, which never answers here.
    assert!(is_fatal(&read_to_end(&mut client).await));
    assert!(seen.messages().is_empty());
    assert_eq!(pool.stats().busy, 1);
    assert_eq!(proxy.status.counters().parse_failures, 1);
}

#[tokio::test]
async fn without_parser_threads_no_statement_has_an_analysis() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let proxy = Proxied::start(&database, policy(OnParseFailure::Block), None, NEVER).await;
    let mut client = proxy.log_in().await;

    client.write_all(&query("SELECT 1")).await.unwrap();
    assert!(is_fatal(&read_to_end(&mut client).await));
    assert!(seen.messages().is_empty());
    assert_eq!(proxy.status.counters().parse_failures, 1);
}

#[tokio::test]
async fn a_prepared_statement_is_analysed_once_however_often_it_runs() {
    let seen = Arc::new(Seen::default());
    let database = database(&seen).await;
    let pool = pool(1, 16);
    let proxy = Proxied::start(
        &database,
        policy(OnParseFailure::Block),
        Some(&pool),
        PATIENCE,
    )
    .await;
    let mut client = proxy.log_in().await;

    let prepare = [frame(b'P', b"s1\0SELECT 1\0\0\0"), frame(b'S', b"")].concat();
    client.write_all(&prepare).await.unwrap();
    soon(read_until_ready(&mut client)).await.unwrap();

    let run = [
        frame(b'B', b"\0s1\0\0\0\0\0\0\0"),
        frame(b'E', b"\0\0\0\0\0"),
        frame(b'S', b""),
    ]
    .concat();
    for _ in 0..50 {
        client.write_all(&run).await.unwrap();
        soon(read_until_ready(&mut client)).await.unwrap();
    }

    assert_eq!(seen.messages().len(), 2 + 50 * 3);
    let stats = pool.stats();
    assert_eq!((stats.analysed, stats.cache_hits), (1, 0));
    assert_eq!(proxy.status.counters().parse_failures, 0);
}
