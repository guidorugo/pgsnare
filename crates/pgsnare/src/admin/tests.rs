// SPDX-License-Identifier: Apache-2.0

//! Tests of the admin and metrics listeners, over real connections on the
//! loopback interface.

use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::metrics::tests::{parse, value};
use super::*;

/// Both listeners on free ports of this machine, for as long as a test
/// holds them.
struct Serving {
    admin: SocketAddr,
    metrics: SocketAddr,
    status: Arc<Status>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Serving {
    fn start() -> Self {
        let status = Arc::new(Status::new());
        let any = "127.0.0.1:0".parse().unwrap();
        let listeners = bind(any, any, Arc::clone(&status), Redaction::default()).unwrap();
        let (admin, metrics) = (
            listeners.admin_addr().unwrap(),
            listeners.metrics_addr().unwrap(),
        );
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(listeners.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            admin,
            metrics,
            status,
            stop: Some(stop),
            task,
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An answer as a test reads it: the status, the headers and the body.
struct Answered {
    status: u16,
    head: String,
    body: String,
}

impl Answered {
    fn header(&self, name: &str) -> Option<&str> {
        self.head
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    }
}

/// Sends these bytes and reads until the listener closes the connection.
async fn send(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut answer))
        .await
        .expect("the listener closes the connection");
    answer
}

fn read(answer: &[u8]) -> Answered {
    let text = String::from_utf8(answer.to_vec()).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("a head and a body");
    let status = head
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    Answered {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

async fn request(address: SocketAddr, method: &str, path: &str) -> Answered {
    let request = format!("{method} {path} HTTP/1.1\r\nhost: localhost\r\n\r\n");
    read(&send(address, request.as_bytes()).await)
}

async fn get(address: SocketAddr, path: &str) -> Answered {
    request(address, "GET", path).await
}

#[tokio::test]
async fn health_follows_whether_a_listener_has_failed() {
    let serving = Serving::start();
    let answer = get(serving.admin, "/healthz").await;
    assert_eq!((answer.status, answer.body.as_str()), (200, "ok\n"));
    assert_eq!(
        answer.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(answer.header("cache-control"), Some("no-store"));
    assert_eq!(answer.header("connection"), Some("close"));

    // Healthy does not depend on being ready: a proxy that starts or stops
    // is not at fault.
    serving.status.set_ready(true);
    assert_eq!(get(serving.admin, "/healthz").await.status, 200);
    serving.status.set_ready(false);
    assert_eq!(get(serving.admin, "/healthz").await.status, 200);

    serving.status.listener_failed(true);
    let answer = get(serving.admin, "/healthz").await;
    assert_eq!((answer.status, answer.body.as_str()), (503, "unhealthy\n"));
}

#[tokio::test]
async fn readiness_follows_whether_clients_are_accepted() {
    let serving = Serving::start();
    let answer = get(serving.admin, "/readyz").await;
    assert_eq!((answer.status, answer.body.as_str()), (503, "not ready\n"));

    serving.status.set_ready(true);
    let answer = get(serving.admin, "/readyz").await;
    assert_eq!((answer.status, answer.body.as_str()), (200, "ready\n"));
    // A query string does not change which path is asked for.
    assert_eq!(get(serving.admin, "/readyz?verbose").await.status, 200);

    // A proxy that was asked to stop.
    serving.status.set_ready(false);
    assert_eq!(get(serving.admin, "/readyz").await.status, 503);

    // A proxy one of whose listeners failed.
    serving.status.set_ready(true);
    serving.status.listener_failed(false);
    assert_eq!(get(serving.admin, "/readyz").await.status, 503);
}

#[tokio::test]
async fn the_metrics_are_served_in_the_format_a_scraper_reads() {
    let serving = Serving::start();
    serving.status.set_ready(true);
    serving.status.session_accepted();
    serving.status.read_from_client(42);

    let answer = get(serving.metrics, "/metrics").await;
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert_eq!(
        answer.header("content-length"),
        Some(answer.body.len().to_string().as_str())
    );
    let samples = parse(&answer.body);
    assert_eq!(value(&samples, "pgsnare_ready", &[]), Some(1.0));
    assert_eq!(
        value(&samples, "pgsnare_connections_accepted_total", &[]),
        Some(1.0)
    );
    assert_eq!(
        value(
            &samples,
            "pgsnare_bytes_total",
            &[("direction", "from_client")]
        ),
        Some(42.0)
    );
}

#[tokio::test]
async fn each_listener_answers_its_own_paths_and_nothing_else() {
    let serving = Serving::start();
    for (address, path) in [
        (serving.admin, "/"),
        (serving.admin, "/metrics"),
        (serving.admin, "/healthz/"),
        (serving.admin, "/healthz/extra"),
        (serving.admin, "/HEALTHZ"),
        (serving.admin, "/config"),
        (serving.admin, "/tokens"),
        (serving.admin, "/../etc/passwd"),
        (serving.metrics, "/"),
        (serving.metrics, "/healthz"),
        (serving.metrics, "/readyz"),
        (serving.metrics, "/metrics/"),
    ] {
        let answer = get(address, path).await;
        assert_eq!(
            (answer.status, answer.body.as_str()),
            (404, "not found\n"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn nothing_but_get_is_answered() {
    let serving = Serving::start();
    for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"] {
        for (address, path) in [
            (serving.admin, "/healthz"),
            (serving.admin, "/readyz"),
            (serving.metrics, "/metrics"),
            (serving.admin, "/no-such-path"),
        ] {
            let answer = request(address, method, path).await;
            assert_eq!(answer.status, 405, "{method} {path}");
            assert_eq!(answer.header("allow"), Some("GET"), "{method} {path}");
            // The answer to HEAD has no body, as HTTP says. No other
            // answer says anything about the proxy.
            if method != "HEAD" {
                assert_eq!(answer.body, "only GET is answered\n", "{method} {path}");
            }
        }
    }
}

#[tokio::test]
async fn a_connection_gets_one_answer_and_is_closed() {
    let serving = Serving::start();
    // Two requests in one go. The second is not answered.
    let two = b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n\r\nGET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n";
    let answer = String::from_utf8(send(serving.admin, two).await).unwrap();
    assert_eq!(answer.matches("HTTP/1.1 ").count(), 1, "{answer}");
    assert!(answer.ends_with("ok\n"), "{answer}");

    // A request that asks to keep the connection is told it will not be.
    let keep = b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: keep-alive\r\n\r\n";
    let answer = read(&send(serving.admin, keep).await);
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("connection"), Some("close"));
}

#[tokio::test]
async fn the_body_of_a_request_is_never_waited_for() {
    let serving = Serving::start();
    // A request that announces a gigabyte and sends none of it. The answer
    // comes at once and the connection is closed.
    let request = b"GET /healthz HTTP/1.1\r\nhost: localhost\r\ncontent-length: 1073741824\r\n\r\n";
    let started = std::time::Instant::now();
    let answer = read(&send(serving.admin, request).await);
    assert_eq!(answer.status, 200);
    assert!(started.elapsed() < CONNECTION_TIMEOUT / 2);
}

// The clock stands still while anything happens, so the cases that end with
// the time a connection is given take no time here.
#[tokio::test(start_paused = true)]
async fn what_is_not_a_request_gets_no_information() {
    let serving = Serving::start();
    for bytes in [
        &b"\x00\x00\x00\x08\x04\xd2\x16\x2f"[..],
        b"SSH-2.0-OpenSSH_9.9\r\n",
        b"GET\r\n\r\n",
        b"GET /healthz HTTP/9.9\r\n\r\n",
        b"\r\n\r\n",
    ] {
        let answer = send(serving.admin, bytes).await;
        let text = String::from_utf8_lossy(&answer);
        // Closed without a word, or refused as a bad request. Never an
        // answer of the proxy.
        assert!(
            answer.is_empty() || text.starts_with("HTTP/1.1 400"),
            "{text}"
        );
        assert!(!text.contains("ok\n"), "{text}");
    }
}

#[tokio::test]
async fn a_head_that_is_too_large_is_refused() {
    let serving = Serving::start();
    let mut request = b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nx-padding: ".to_vec();
    request.extend(std::iter::repeat_n(b'a', 4 * MAX_REQUEST_BYTES));
    request.extend_from_slice(b"\r\n\r\n");
    let answer = send(serving.admin, &request).await;
    let text = String::from_utf8_lossy(&answer);
    assert!(
        answer.is_empty() || text.starts_with("HTTP/1.1 431"),
        "{text}"
    );
    assert!(!text.contains("ok\n"), "{text}");

    let mut request = b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n".to_vec();
    for number in 0..=MAX_HEADERS {
        request.extend_from_slice(format!("x-header-{number}: 1\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    let answer = send(serving.admin, &request).await;
    let text = String::from_utf8_lossy(&answer);
    assert!(
        answer.is_empty() || text.starts_with("HTTP/1.1 431"),
        "{text}"
    );
    assert_eq!(get(serving.admin, "/healthz").await.status, 200);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_sends_nothing_or_never_finishes_is_dropped() {
    let serving = Serving::start();

    // Nothing at all.
    let mut silent = TcpStream::connect(serving.admin).await.unwrap();
    // The beginning of a request, and never its end.
    let mut slow = TcpStream::connect(serving.admin).await.unwrap();
    slow.write_all(b"GET /healthz HTTP/1.1\r\nhost: loc")
        .await
        .unwrap();

    let started = Instant::now();
    let mut answer = Vec::new();
    for client in [&mut silent, &mut slow] {
        answer.clear();
        client.read_to_end(&mut answer).await.unwrap();
        assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    }
    // The clock of this test only moves when everything waits. It moved by
    // the time a connection is given, and by no more.
    assert_eq!(started.elapsed(), CONNECTION_TIMEOUT);
}

#[tokio::test]
async fn a_listener_holds_only_so_many_connections() {
    let serving = Serving::start();

    // As many silent clients as the listener holds.
    let mut holding = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        holding.push(TcpStream::connect(serving.admin).await.unwrap());
    }
    // The listener has to have taken them all before the next one counts
    // as one too many.
    let mut refused = None;
    for _ in 0..200 {
        let mut extra = TcpStream::connect(serving.admin).await.unwrap();
        extra
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        let _ = extra.read_to_end(&mut answer).await;
        if answer.is_empty() {
            refused = Some(());
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        refused.is_some(),
        "one connection more is closed without an answer"
    );

    // The other listener has room of its own.
    assert_eq!(get(serving.metrics, "/metrics").await.status, 200);

    // When one of the clients leaves, there is room again.
    holding.pop();
    let mut served = false;
    for _ in 0..200 {
        let answer = send(
            serving.admin,
            b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n\r\n",
        )
        .await;
        if !answer.is_empty() {
            assert_eq!(read(&answer).status, 200);
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(served);
}

#[tokio::test]
async fn stopping_closes_both_listeners() {
    let mut serving = Serving::start();
    assert_eq!(get(serving.admin, "/healthz").await.status, 200);

    serving.stop.take().unwrap().send(()).unwrap();
    (&mut serving.task).await.unwrap();
    assert!(TcpStream::connect(serving.admin).await.is_err());
    assert!(TcpStream::connect(serving.metrics).await.is_err());
}

#[tokio::test]
async fn an_address_that_is_taken_cannot_be_bound() {
    let serving = Serving::start();
    let status = Arc::new(Status::new());
    let free = "127.0.0.1:0".parse().unwrap();
    for (admin, metrics) in [(serving.admin, free), (free, serving.metrics)] {
        let error = bind(admin, metrics, Arc::clone(&status), Redaction::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }
}

#[tokio::test(start_paused = true)]
async fn a_loop_that_panics_is_counted_and_started_again() {
    let status = Arc::new(Status::new());
    let starts = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&starts);
    let supervised = tokio::spawn(supervise(Which::Metrics, Arc::clone(&status), move || {
        let start = counted.fetch_add(1, Ordering::SeqCst);
        async move {
            // The first two loops panic, the third runs on.
            assert!(start >= 2, "a panic that a test asked for");
            std::future::pending::<()>().await;
        }
    }));

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 3);
    assert_eq!(status.counters().admin_panics, 2);
    assert!(!supervised.is_finished());

    // Whoever stops the supervisor stops the loop with it.
    supervised.abort();
    let _ = supervised.await;
}
