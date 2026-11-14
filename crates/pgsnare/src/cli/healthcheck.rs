// SPDX-License-Identifier: Apache-2.0

//! `pgsnare healthcheck`: ask the admin listener of a running proxy whether
//! it is healthy.
//!
//! The exit status is 0 for healthy and 1 for anything else, which is what
//! a container health check and a Kubernetes exec probe expect. The command
//! needs nothing but the binary: no shell and no other tool. On success it
//! writes nothing. On failure it writes one line to standard error.
//!
//! # What is asked
//!
//! | Command | Endpoint | Status 0 means |
//! |---|---|---|
//! | `pgsnare healthcheck` | `/healthz` | The proxy works as it should. This is what a liveness probe asks |
//! | `pgsnare healthcheck --ready` | `/readyz` | The proxy accepts clients. This is what a readiness probe asks |
//!
//! A proxy that is starting or that was asked to stop is healthy and not
//! ready. A proxy one of whose listeners has failed is neither.
//!
//! # Where it asks
//!
//! The admin listener of this machine, and nothing else.
//!
//! - The address is the one the configuration gives the admin listener, or
//!   the default when no configuration is named. A listener that is bound
//!   to every address of the machine is asked over the loopback interface.
//! - The connection is made from the very address it goes to. Only an
//!   address of this machine can be used that way, so the request cannot
//!   leave the machine, whatever the configuration says. The one exception
//!   is a system that was set to let a process bind to an address that is
//!   not its own (`ip_nonlocal_bind` on Linux).
//! - The answer is a status and nothing more. A redirect is not followed:
//!   it is not the answer of a healthy proxy.
//! - The whole check has [`TIME_LIMIT`]. A listener that does not answer
//!   in that time is not healthy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper::header::HOST;
use hyper::{Method, Request, StatusCode};
use tokio::net::TcpSocket;

use crate::config::{Admin, Config};
use crate::http::{self, Body};

use super::{FAILURE, SUCCESS};

/// How long the whole check may take.
pub const TIME_LIMIT: Duration = Duration::from_secs(2);

/// The most bytes of a configuration file the check reads.
const MAX_CONFIG_BYTES: u64 = crate::config::MAX_FILE_BYTES;

/// The arguments of `pgsnare healthcheck`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration file, to find the admin listener. Without it the
    /// default address is asked.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Ask whether the proxy accepts clients, which it does not while it
    /// starts or stops. Without this, the question is whether the proxy
    /// works as it should.
    #[arg(long)]
    pub ready: bool,
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(args: &Args) -> u8 {
    let listen = match &args.config {
        Some(file) => admin_listener(file),
        None => Ok(Admin::default().listen.socket_addr()),
    };
    match listen.and_then(|listen| check(listen, args.ready)) {
        Ok(()) => SUCCESS,
        Err(reason) => {
            eprintln!("pgsnare healthcheck: {reason}");
            FAILURE
        }
    }
}

/// The address a configuration gives the admin listener.
fn admin_listener(file: &Path) -> Result<SocketAddr, String> {
    use std::io::Read;

    // The file may hold the values of honeytokens, and this process holds
    // them for a moment while it reads the file.
    disable_core_dumps();
    let failed = |problem: String| format!("{}: {problem}", file.display());
    let opened = std::fs::File::open(file)
        .map_err(|error| failed(format!("cannot read the file: {}", error.kind())))?;
    let mut text = String::new();
    opened
        .take(MAX_CONFIG_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|error| failed(format!("cannot read the file: {}", error.kind())))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(failed("the file is too large".to_owned()));
    }
    // The error of the loader never repeats what the file contains.
    let config = Config::from_yaml(&text).map_err(|error| failed(error.to_string()))?;
    Ok(config.admin.listen.socket_addr())
}

/// A core dump of this process could hold what it read.
fn disable_core_dumps() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    // Nothing can be done about a failure here, and the check is no less
    // right for it.
    let _ = setrlimit(Resource::Core, none);
}

/// Where to ask a listener that is bound to `listen`: the address itself,
/// or the loopback address when the listener is bound to every address of
/// the machine.
fn target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

/// Asks the admin listener that is bound to `listen`, and says what is
/// wrong when the answer is not that of a healthy proxy.
fn check(listen: SocketAddr, ready: bool) -> Result<(), String> {
    let path = if ready { "/readyz" } else { "/healthz" };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the check: {}", error.kind()))?;
    let answer = runtime
        .block_on(async { tokio::time::timeout(TIME_LIMIT, ask(target(listen), path)).await });
    match answer {
        Ok(Ok(StatusCode::OK)) => Ok(()),
        Ok(Ok(status)) => Err(format!(
            "the admin listener answered {path} with status {}",
            status.as_u16()
        )),
        Ok(Err(reason)) => Err(format!("the admin listener could not be asked: {reason}")),
        Err(_) => Err("the admin listener did not answer in time".to_owned()),
    }
}

/// Sends one request to the admin listener and returns the status of its
/// answer.
async fn ask(target: SocketAddr, path: &'static str) -> Result<StatusCode, &'static str> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|error| http::io_reason(&error))?;
    // From the address the request goes to. That works for an address of
    // this machine and for no other, so the request stays on the machine.
    socket
        .bind(SocketAddr::new(target.ip(), 0))
        .map_err(|_| "its address is not an address of this machine")?;
    let stream = socket
        .connect(target)
        .await
        .map_err(|error| http::io_reason(&error))?;

    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, target.to_string())
        .body(Body::default())
        .map_err(|_| "the request could not be put together")?;
    http::exchange(stream, request).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::admin;
    use crate::redact::Redaction;
    use crate::runtime::Status;

    use super::*;

    /// The admin listener of a proxy, on a free port and on a runtime of
    /// its own, as it is in another process.
    struct Proxy {
        /// Kept so that the listener runs for as long as the test holds
        /// the proxy.
        _runtime: tokio::runtime::Runtime,
        listen: SocketAddr,
        status: Arc<Status>,
    }

    impl Proxy {
        fn start() -> Self {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let status = Arc::new(Status::new());
            let any = "127.0.0.1:0".parse().unwrap();
            let listeners = runtime
                .block_on(async {
                    admin::bind(any, any, Arc::clone(&status), Redaction::default())
                })
                .unwrap();
            let listen = listeners.admin_addr().unwrap();
            runtime.spawn(listeners.serve(std::future::pending()));
            Self {
                _runtime: runtime,
                listen,
                status,
            }
        }
    }

    /// A server that reads a request and answers with these bytes, or
    /// never.
    fn answering(runtime: &tokio::runtime::Runtime, answer: Option<&'static [u8]>) -> SocketAddr {
        let listener = runtime.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let address = listener.local_addr().unwrap();
        runtime.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let _ = stream.read(&mut buffer).await;
                    match answer {
                        Some(answer) => {
                            let _ = stream.write_all(answer).await;
                        }
                        None => std::future::pending().await,
                    }
                });
            }
        });
        address
    }

    #[test]
    fn a_healthy_proxy_is_healthy_and_a_ready_one_is_ready() {
        let proxy = Proxy::start();
        // Starting: healthy, and not ready yet.
        assert_eq!(check(proxy.listen, false), Ok(()));
        assert_eq!(
            check(proxy.listen, true),
            Err("the admin listener answered /readyz with status 503".to_owned())
        );

        proxy.status.set_ready(true);
        assert_eq!(check(proxy.listen, false), Ok(()));
        assert_eq!(check(proxy.listen, true), Ok(()));

        // Asked to stop: still healthy, no longer ready.
        proxy.status.set_ready(false);
        assert_eq!(check(proxy.listen, false), Ok(()));
        assert!(check(proxy.listen, true).is_err());

        // A listener has failed: neither.
        proxy.status.listener_failed(true);
        assert_eq!(
            check(proxy.listen, false),
            Err("the admin listener answered /healthz with status 503".to_owned())
        );
        assert!(check(proxy.listen, true).is_err());
    }

    #[test]
    fn the_command_exits_with_0_or_1() {
        let proxy = Proxy::start();
        let dir = TempDir::new();
        let config = dir.config(proxy.listen);
        let args = |ready| Args {
            config: Some(config.clone()),
            ready,
        };
        assert_eq!(run(&args(false)), SUCCESS);
        assert_eq!(run(&args(true)), FAILURE);
        proxy.status.set_ready(true);
        assert_eq!(run(&args(true)), SUCCESS);

        // Once the proxy is gone, nothing answers.
        drop(proxy);
        assert_eq!(run(&args(false)), FAILURE);
        assert_eq!(run(&args(true)), FAILURE);
    }

    #[test]
    fn nothing_that_listens_is_not_healthy() {
        // A port nothing listens on.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        assert_eq!(
            check(listen, false),
            Err("the admin listener could not be asked: the connection was refused".to_owned())
        );
    }

    #[test]
    fn only_the_answer_of_a_healthy_proxy_counts() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        for (answer, expected) in [
            // A redirect is not followed, wherever it points.
            (
                &b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/healthz\r\ncontent-length: 0\r\n\r\n"[..],
                "the admin listener answered /healthz with status 302",
            ),
            (
                b"HTTP/1.1 204 No Content\r\n\r\n",
                "the admin listener answered /healthz with status 204",
            ),
            (
                b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n",
                "the admin listener answered /healthz with status 404",
            ),
            (
                b"this is not HTTP\r\n\r\n",
                "the admin listener could not be asked: the answer is not valid HTTP",
            ),
        ] {
            let listen = answering(&runtime, Some(answer));
            assert_eq!(check(listen, false), Err(expected.to_owned()));
        }
    }

    #[test]
    fn a_listener_that_does_not_answer_is_not_waited_for() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listen = answering(&runtime, None);
        let started = std::time::Instant::now();
        assert_eq!(
            check(listen, false),
            Err("the admin listener did not answer in time".to_owned())
        );
        let took = started.elapsed();
        assert!(took >= TIME_LIMIT, "{took:?}");
        assert!(took < TIME_LIMIT + Duration::from_secs(2), "{took:?}");
    }

    #[test]
    fn a_listener_on_every_address_is_asked_over_loopback() {
        let address = |text: &str| text.parse::<SocketAddr>().unwrap();
        assert_eq!(target(address("0.0.0.0:9641")), address("127.0.0.1:9641"));
        assert_eq!(target(address("[::]:9641")), address("[::1]:9641"));
        assert_eq!(
            target(address("127.0.0.1:19641")),
            address("127.0.0.1:19641")
        );
        assert_eq!(target(address("[::1]:9641")), address("[::1]:9641"));
        // An address of its own stays what it is: only this machine can
        // have it.
        assert_eq!(
            target(address("192.0.2.10:9641")),
            address("192.0.2.10:9641")
        );
    }

    #[test]
    fn an_address_of_another_machine_is_never_asked() {
        // An address that is reserved for documentation: no interface of
        // this machine has it, so the check ends before anything is sent.
        let listen: SocketAddr = "192.0.2.10:9641".parse().unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            check(listen, false),
            Err(
                "the admin listener could not be asked: its address is not an address of this \
                 machine"
                    .to_owned()
            )
        );
        assert!(started.elapsed() < TIME_LIMIT);
    }

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-healthcheck-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// A configuration whose admin listener is at this address.
        fn config(&self, admin: SocketAddr) -> PathBuf {
            let path = self.0.join("pgsnare.yaml");
            let text = format!(
                "listeners:\n  - name: main\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
                 client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\n\
                 tokens:\n  - id: users-admin-backup\n    values: [\"svc.backup.8f3k2q@mail.example\"]\n\
                 events:\n  sinks:\n    - type: stdout\n\
                 admin:\n  listen: {admin}\n"
            );
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_configuration_says_where_the_admin_listener_is() {
        let dir = TempDir::new();
        let listen: SocketAddr = "127.0.0.1:19641".parse().unwrap();
        assert_eq!(admin_listener(&dir.config(listen)), Ok(listen));

        // Without the section, the default.
        let path = dir.0.join("default.yaml");
        std::fs::write(
            &path,
            "listeners:\n  - name: main\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
             client_tls: { mode: disable }\n    upstream_tls: { mode: disable }\n\
             events:\n  sinks:\n    - type: stdout\n",
        )
        .unwrap();
        assert_eq!(admin_listener(&path), Ok("127.0.0.1:9641".parse().unwrap()));
    }

    #[test]
    fn a_configuration_that_cannot_be_used_fails_the_check_and_is_not_repeated() {
        let dir = TempDir::new();
        let missing = dir.0.join("missing.yaml");
        assert_eq!(
            admin_listener(&missing),
            Err(format!(
                "{}: cannot read the file: entity not found",
                missing.display()
            ))
        );
        assert_eq!(
            run(&Args {
                config: Some(missing),
                ready: false
            }),
            FAILURE
        );

        let broken = dir.0.join("broken.yaml");
        std::fs::write(
            &broken,
            "tokens:\n  - id: t\n    values: [\"Zq7honeytokenValue9xK\"]\nnonsense: true\n",
        )
        .unwrap();
        let error = admin_listener(&broken).unwrap_err();
        assert!(error.starts_with(&broken.display().to_string()), "{error}");
        assert!(!error.contains("Zq7honeytokenValue9xK"), "{error}");
    }
}
