// SPDX-License-Identifier: Apache-2.0

//! `pgsnare run`: start the proxy.
//!
//! The command reads the configuration, checks the access rights of the
//! files that hold secrets, opens the listeners and relays traffic until
//! it is told to stop with `SIGTERM` or `SIGINT`. It then lets open
//! sessions finish for the grace period of the configuration and exits
//! with status 0.
//!
//! It logs to standard error, one line for each thing worth knowing. No
//! line contains anything a client or a database sent.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::event::{Event, Labels};
use pgsnare_core::extension::{EventSink, Relay, SinkFuture};
use pgsnare_core::policy::FixedPolicy;
use pgsnare_core::session::postgres::Postgres;
use tokio::signal::unix::{SignalKind, signal};

use crate::builder::{Proxy, ProxyBuilder};
use crate::config::{self, Config, UpstreamTlsMode};
use crate::runtime::{ListenerSettings, Runtime, Settings, Upstream, permissions};
use crate::tls::{BackendLeg, ClientLeg};

use super::{FAILURE, SUCCESS};

/// How long the comparison of certificates may wait for a database when
/// the proxy starts.
const CERTIFICATE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The arguments of `pgsnare run`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The configuration file.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// Start even when the configuration file, a token file or a private
    /// key can be read by other users. Each such file is named in the log.
    #[arg(long)]
    pub allow_insecure_file_permissions: bool,
}

/// Runs the command and returns its exit status.
#[must_use]
pub fn run(args: &Args) -> u8 {
    install_log();
    match start(args) {
        Ok(()) => SUCCESS,
        Err(message) => {
            // The log may not be what the operator is looking at when the
            // proxy does not even start.
            eprintln!("pgsnare run: {message}");
            FAILURE
        }
    }
}

/// Makes log lines visible: one line each, on standard error.
fn install_log() {
    // A second call in one process, as in tests, keeps the first setup.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

/// A panic is logged with the place it happened and nothing else: its
/// message could repeat what a session was working on.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let (file, line) = info.location().map_or(("unknown", 0), |location| {
            (location.file(), location.line())
        });
        tracing::error!(file, line, "a panic occurred");
    }));
}

fn start(args: &Args) -> Result<(), String> {
    // Before the first secret is read: the token files hold some.
    disable_core_dumps();
    let loaded = config::load(&args.config).map_err(|error| error.to_string())?;
    check_permissions(&loaded, args.allow_insecure_file_permissions)?;

    let config = loaded.config;
    let policy = config.policy(1).map_err(|error| error.to_string())?;
    let module = Postgres::new();
    let listeners = listeners(&config, &module)?;
    let proxy = ProxyBuilder::new()
        .protocol_module(Arc::new(module))
        .login_strategy(Arc::new(Relay))
        .event_sink(Arc::new(LogSink))
        .build()
        .map_err(|error| error.to_string())?;

    tracing::warn!(
        tokens = config.tokens.len(),
        sinks = config.events.sinks.len(),
        "this build relays traffic and detects nothing: honeytoken detection, responses and \
         event sinks are not built yet, and events are written to this log only"
    );

    let settings = Settings::new(listeners)
        .with_grace_period(config.shutdown.grace_period)
        .with_labels(labels(&config))
        .with_event_capacity(usize::try_from(config.events.queue_size).unwrap_or(usize::MAX));

    let workers = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("pgsnare-worker")
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the runtime: {}", error.kind()))?;
    tracing::info!(
        worker_threads = workers,
        "starting, with one worker thread for each processor this process may use"
    );
    install_panic_hook();
    runtime.block_on(serve(proxy, Arc::new(FixedPolicy::new(policy)), settings))
}

async fn serve(proxy: Proxy, policy: Arc<FixedPolicy>, settings: Settings) -> Result<(), String> {
    // The handlers are in place before the first client is accepted. As
    // process 1 of a container, pgsnare would otherwise not be stopped by
    // these signals at all.
    let failed = |error: std::io::Error| format!("cannot handle signals: {}", error.kind());
    let mut terminate = signal(SignalKind::terminate()).map_err(failed)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(failed)?;
    let mut hangup = signal(SignalKind::hangup()).map_err(failed)?;

    for listener in &settings.listeners {
        tracing::info!(
            listener = %listener.name,
            address = %listener.listen,
            upstream = %listener.upstream,
            client_tls = ?listener.client_tls.policy(),
            upstream_tls = ?listener.backend_tls.usage(),
            max_connections = listener.max_connections,
            "listening"
        );
    }
    let bound = Runtime::new(proxy, policy, settings)
        .bind()
        .map_err(|error| format!("cannot open a listener: {}", error.kind()))?;
    bound.compare_certificates(CERTIFICATE_PROBE_TIMEOUT).await;

    bound
        .serve(async move {
            loop {
                tokio::select! {
                    _ = terminate.recv() => {
                        tracing::info!("received SIGTERM");
                        break;
                    }
                    _ = interrupt.recv() => {
                        tracing::info!("received SIGINT");
                        break;
                    }
                    _ = hangup.recv() => {
                        tracing::warn!(
                            "received SIGHUP: reloading is not built yet, and the \
                             configuration stays as it was read at the start"
                        );
                    }
                }
            }
        })
        .await;
    Ok(())
}

/// Refuses to start when a file that holds secrets is open to other users,
/// unless the operator said to start all the same.
fn check_permissions(loaded: &config::Loaded, allow: bool) -> Result<(), String> {
    let refused = permissions::check_all(loaded.secret_files());
    if refused.is_empty() {
        return Ok(());
    }
    if allow {
        for file in &refused {
            tracing::warn!(
                file = %file.file.display(),
                problem = %file.problem,
                "starting although a file that holds secrets is not protected, because \
                 --allow-insecure-file-permissions was given"
            );
        }
        return Ok(());
    }
    let mut message =
        String::from("refusing to start, because files that hold secrets are not protected:");
    for file in &refused {
        message.push_str("\n  ");
        message.push_str(&file.to_string());
    }
    message.push_str(
        "\nRestrict the access to these files, or start with \
         --allow-insecure-file-permissions to accept the risk.",
    );
    Err(message)
}

/// A core dump would write keys and traffic to disk.
fn disable_core_dumps() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if setrlimit(Resource::Core, none).is_err() {
        tracing::warn!("core dumps could not be switched off");
    }
}

/// Turns the listeners of a configuration into what the runtime takes.
fn listeners(config: &Config, module: &Postgres) -> Result<Vec<ListenerSettings>, String> {
    use pgsnare_core::extension::ProtocolModule;

    let alpn = module.alpn_protocol();
    let mut listeners = Vec::with_capacity(config.listeners.len());
    for listener in &config.listeners {
        let name = listener.name.as_str();
        let failed = |error: crate::tls::TlsError| format!("listener {name}: {error}");
        let client = ClientLeg::from_config(&listener.client_tls, alpn).map_err(failed)?;
        let backend = BackendLeg::from_config(&listener.upstream_tls, &listener.upstream, alpn)
            .map_err(failed)?;
        if matches!(
            listener.upstream_tls.mode,
            UpstreamTlsMode::Prefer | UpstreamTlsMode::Require
        ) {
            tracing::warn!(
                listener = %name,
                "the certificate of the database is not verified, because upstream_tls.mode \
                 is not verify-full: whoever answers at its address is taken for the database"
            );
        }
        listeners.push(
            ListenerSettings::new(
                name,
                listener.listen.socket_addr(),
                Upstream::from(&listener.upstream),
            )
            .with_tls(client, backend)
            .with_max_connections(usize::try_from(listener.max_connections).unwrap_or(usize::MAX))
            .with_login_timeout(listener.login_timeout),
        );
    }
    Ok(listeners)
}

/// The labels every event carries: the ones written in the configuration,
/// and the values of the environment variables it names.
fn labels(config: &Config) -> Labels {
    let mut labels: Labels = config
        .events
        .labels
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.clone()))
        .collect();
    for variable in &config.events.labels_from_env {
        // A variable that is not set, or whose value would not be accepted
        // as a label in the configuration, gives no label.
        let value = std::env::var(variable.as_str()).ok().filter(|value| {
            !value.is_empty()
                && value.len() <= config::MAX_LABEL_VALUE_BYTES
                && !value.chars().any(char::is_control)
        });
        match value {
            Some(value) => {
                labels.insert(variable.as_str().to_owned(), value);
            }
            None => tracing::warn!(
                variable = variable.as_str(),
                "an environment variable named in labels_from_env gives no label: it is not \
                 set, or its value is empty, too long or contains control characters"
            ),
        }
    }
    labels
}

/// Writes events to the log: what happened, in which session and to which
/// client. The texts of an event that come from the network are left out.
struct LogSink;

impl EventSink for LogSink {
    fn name(&self) -> &str {
        "log"
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move {
            tracing::warn!(
                kind = ?event.body.kind,
                event_id = %event.event_id,
                session_id = %event.body.session_id,
                client = %event.body.client_ip,
                client_port = event.body.client_port,
                "event"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configuration_that_cannot_be_read_fails_the_command() {
        let args = Args {
            config: PathBuf::from("/nonexistent/pgsnare.yaml"),
            allow_insecure_file_permissions: false,
        };
        assert_eq!(run(&args), FAILURE);
        let error = start(&args).unwrap_err();
        assert!(error.contains("cannot read the file"), "{error}");
    }
}
