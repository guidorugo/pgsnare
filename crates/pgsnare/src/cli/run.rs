// SPDX-License-Identifier: Apache-2.0

//! `pgsnare run`: start the proxy.
//!
//! The command reads the configuration, checks the access rights of the
//! files that hold secrets, opens the listeners and relays traffic until
//! it is told to stop with `SIGTERM` or `SIGINT`. It then lets open
//! sessions finish for the grace period of the configuration and exits
//! with status 0.
//!
//! A listener that fails while the proxy runs stops it in the same way,
//! and the command then exits with status 1.
//!
//! It logs to standard error, one JSON object for each line: see
//! [`crate::log`]. No line contains anything a client or a database sent.
//! A proxy that cannot start says why in the same log, and exits with
//! status 1. Events go to the sinks of the configuration, and standard
//! output carries nothing but the events of a `stdout` sink.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pgsnare_core::event::Labels;
use pgsnare_core::extension::Relay;
use pgsnare_core::policy::FixedPolicy;
use pgsnare_core::session::postgres::Postgres;
use tokio::signal::unix::{SignalKind, signal};

use crate::admin;
use crate::builder::{Proxy, ProxyBuilder};
use crate::config::{self, Config, UpstreamTlsMode};
use crate::redact::{Redaction, Redactor, RedactorBuilder};
use crate::runtime::{ListenerSettings, Runtime, Settings, Stopped, Upstream, permissions};
use crate::sinks;
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
    // The log comes first, and what it must not show follows as soon as
    // the configuration has been read. A second call in one process, as in
    // tests, keeps the first log.
    let redaction = Redaction::default();
    crate::log::install(redaction.clone());
    match start(args, &redaction) {
        Ok(()) => SUCCESS,
        Err(reason) => {
            tracing::error!(reason = %reason, "pgsnare cannot go on");
            FAILURE
        }
    }
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

fn start(args: &Args, redaction: &Redaction) -> Result<(), String> {
    // Before the first secret is read: the token files hold some.
    disable_core_dumps();
    let loaded = config::load(&args.config).map_err(|error| error.to_string())?;
    check_permissions(&loaded, args.allow_insecure_file_permissions)?;

    let config = loaded.config;
    // From here on no line of the log can show a honeytoken value.
    redaction.replace(
        redactor(&config)
            .build()
            .map_err(|error| error.to_string())?,
    );
    let policy = config.policy(1).map_err(|error| error.to_string())?;
    let module = Postgres::new();
    let listeners = listeners(&config, &module)?;

    // The sinks add what they must keep to themselves to what the redactor
    // looks for, so the redactor is complete once they are built.
    let (sinks, redactor) =
        sinks::from_config(&config.events, redactor(&config)).map_err(|error| error.to_string())?;
    redaction.replace(redactor.build().map_err(|error| error.to_string())?);
    let mut builder = ProxyBuilder::new()
        .protocol_module(Arc::new(module))
        .login_strategy(Arc::new(Relay));
    for built in sinks {
        builder = builder.event_sink_with(built.sink, built.options);
    }
    let proxy = builder.build().map_err(|error| error.to_string())?;

    tracing::warn!(
        tokens = config.tokens.len(),
        sinks = config.events.sinks.len(),
        "this build relays traffic and detects nothing: honeytoken detection and responses \
         are not built yet, so the only events are those of sessions that inspection gave up on"
    );

    let settings = Settings::new(listeners)
        .with_grace_period(config.shutdown.grace_period)
        .with_labels(labels(&config))
        .with_event_capacity(usize::try_from(config.events.queue_size).unwrap_or(usize::MAX))
        .with_dedup_window(config.events.dedup_window)
        .with_redaction(redaction.clone());
    let observed = Observed {
        admin: config.admin.listen.socket_addr(),
        metrics: config.metrics.listen.socket_addr(),
        redaction: redaction.clone(),
    };

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
    runtime.block_on(serve(
        proxy,
        Arc::new(FixedPolicy::new(policy)),
        settings,
        observed,
    ))
}

/// Where the proxy can be watched from, and what its metrics pass through.
struct Observed {
    /// The address of the admin listener, with the health endpoints.
    admin: SocketAddr,
    /// The address of the metrics listener.
    metrics: SocketAddr,
    redaction: Redaction,
}

async fn serve(
    proxy: Proxy,
    policy: Arc<FixedPolicy>,
    settings: Settings,
    observed: Observed,
) -> Result<(), String> {
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
    let runtime = Runtime::new(proxy, policy, settings);

    // The health endpoints and the metrics answer from before the first
    // client is accepted until after the last session has ended, so that
    // a proxy that starts or stops can be told from one that is gone.
    for (name, address) in [("admin", observed.admin), ("metrics", observed.metrics)] {
        if !address.ip().is_loopback() {
            tracing::warn!(
                listener = name,
                address = %address,
                "this listener is not bound to the loopback interface: whoever can reach its \
                 address can read what it serves, without encryption and without a login"
            );
        }
    }
    let watchers = admin::bind(
        observed.admin,
        observed.metrics,
        runtime.status(),
        observed.redaction,
    )
    .map_err(|error| {
        format!(
            "cannot open the admin listener or the metrics listener: {}",
            error.kind()
        )
    })?;
    tracing::info!(
        admin = %observed.admin,
        metrics = %observed.metrics,
        "serving the health endpoints and the metrics"
    );
    let (stop_watchers, watchers_stopped) = tokio::sync::oneshot::channel::<()>();
    let watching = tokio::spawn(watchers.serve(async move {
        let _ = watchers_stopped.await;
    }));

    let bound = runtime
        .bind()
        .map_err(|error| format!("cannot open a listener: {}", error.kind()))?;
    bound.compare_certificates(CERTIFICATE_PROBE_TIMEOUT).await;

    let stopped = bound
        .run(async move {
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
    let _ = stop_watchers.send(());
    let _ = watching.await;
    outcome(stopped)
}

/// What the command makes of the way the runtime stopped. A runtime that
/// stopped without having been asked to is a failure: the exit status then
/// tells whatever supervises the process to start it again.
fn outcome(stopped: Stopped) -> Result<(), String> {
    match stopped {
        Stopped::Asked => Ok(()),
        _ => Err("a listener stopped accepting clients while the proxy was running".to_owned()),
    }
}

/// What must never be written anywhere, as far as the configuration says
/// it: the values of the honeytokens.
fn redactor(config: &Config) -> RedactorBuilder {
    let mut builder = Redactor::builder();
    for token in &config.tokens {
        builder = builder.token(
            token.id.as_str(),
            token.values.iter().map(config::TokenValue::expose),
            token.case_insensitive,
        );
    }
    builder
}

/// Refuses to start when a file that holds secrets is open to other users,
/// unless the operator said to start all the same.
fn check_permissions(loaded: &config::Loaded, allow: bool) -> Result<(), String> {
    let mut files = loaded.secret_files();
    for file in sink_secrets(&loaded.config) {
        if !files.contains(&file) {
            files.push(file);
        }
    }
    let refused = permissions::check_all(files);
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

/// The files the sinks of a configuration read a secret from: the signing
/// key of a webhook, and its URL when that is kept in a file because it is
/// a secret too.
fn sink_secrets(config: &Config) -> Vec<&Path> {
    let mut files = Vec::new();
    for sink in &config.events.sinks {
        if let config::Sink::Webhook(webhook) = sink {
            if let config::SecretRef::File(file) = &webhook.hmac_secret {
                files.push(file.as_path());
            }
            if let config::UrlSource::File(file) = &webhook.url {
                files.push(file.as_path());
            }
        }
    }
    files
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
        let error = start(&args, &Redaction::default()).unwrap_err();
        assert!(error.contains("cannot read the file"), "{error}");
    }

    #[test]
    fn a_runtime_that_stopped_by_itself_fails_the_command() {
        assert_eq!(outcome(Stopped::Asked), Ok(()));
        let error = outcome(Stopped::ListenerFailed).unwrap_err();
        assert!(
            error.contains("a listener stopped accepting clients"),
            "{error}"
        );
    }

    #[test]
    fn the_values_of_the_tokens_are_what_must_never_be_written() {
        let config = Config::from_yaml(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
             client_tls: { mode: disable }\n    upstream_tls: { mode: disable }\n\
             tokens:\n  - id: users-admin-backup\n    values: [\"svc.backup.8f3k2q@mail.example\"]\n\
             \x20 - id: billing-canary\n    values: [\"Canary.Invoice.000417\"]\n    case_insensitive: true\n\
             events:\n  sinks:\n    - type: stdout\n",
        )
        .unwrap();
        let built = redactor(&config).build().unwrap();
        assert_eq!(
            built.text("user svc.backup.8f3k2q@mail.example"),
            "user [redacted]"
        );
        assert_eq!(built.text("CANARY.INVOICE.000417"), "[redacted]");

        // A token list the matcher refuses is refused when the
        // configuration is read, so no redactor is ever built from one. The
        // reason names the place of a value and never the value.
        let error = Config::from_yaml(
            "listeners:\n  - name: main\n    listen: 127.0.0.1:5432\n    upstream: db.example.com:5432\n    \
             client_tls: { mode: disable }\n    upstream_tls: { mode: disable }\n\
             tokens:\n  - id: inner\n    values: [\"svc.backup.8f3k2q@mail.example\"]\n\
             \x20 - id: outer\n    values: [\"x-svc.backup.8f3k2q@mail.example-x\"]\n\
             events:\n  sinks:\n    - type: stdout\n",
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("svc.backup"), "{error}");
        assert!(error.contains("contains another value"), "{error}");
    }
}
