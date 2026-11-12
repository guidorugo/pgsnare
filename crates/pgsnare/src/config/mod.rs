// SPDX-License-Identifier: Apache-2.0

//! The configuration: its schema and its loader.
//!
//! pgsnare is configured by one YAML file. Honeytokens may also live in
//! separate token files, so that they can be stored and mounted as a
//! secret.
//!
//! # Reading a configuration
//!
//! - [`load`] reads a configuration from disk, with its token files.
//! - [`Config::from_yaml`] reads one from text, without touching the disk.
//!
//! Both return a [`Config`] that has been checked completely, or an error
//! that lists everything that is wrong.
//!
//! # Rules the loader enforces
//!
//! - **Unknown fields are errors.** A misspelt setting is never ignored.
//! - **Encryption is explicit.** Every listener states the TLS mode of both
//!   legs. Nothing falls back to plaintext by default.
//! - **Secrets are never written here.** A secret is named by an environment
//!   variable or a file: see [`SecretRef`]. No field of the schema can hold
//!   the secret itself.
//! - **Durations and sizes carry a unit**, as in `30s` and `1MiB`.
//! - **One meaning only.** One document per file, no repeated keys, no
//!   anchors, aliases, merge keys or custom tags, and text that looks like a
//!   number or a boolean must be quoted.
//! - **Errors never repeat the document.** A message names a place and says
//!   what was expected. It contains no text from the file, so a honeytoken
//!   value cannot leak into a log through a configuration error.
//!
//! # Paths
//!
//! A relative path in a file that [`load`] reads is relative to the
//! directory of the main configuration file, not to the directory pgsnare
//! was started from.

// This module reads files that an operator wrote, and it is fuzzed. It is
// held to the rules of the protocol and core crates: no panics.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

use std::path::PathBuf;

use pgsnare_core::policy::{PolicyError, PolicySnapshot};
use serde::Deserialize;

mod actions;
mod admin;
mod error;
mod events;
mod exemption;
mod inspection;
mod listener;
mod load;
mod names;
mod rules;
mod sinks;
mod tls;
mod token;
pub mod units;
mod yaml;

pub use actions::{Actions, FakeData, Kill, Tarpit};
pub use admin::{
    Admin, DEFAULT_ADMIN_PORT, DEFAULT_GRACE_PERIOD, DEFAULT_METRICS_PORT, MAX_GRACE_PERIOD,
    Metrics, Shutdown,
};
pub use error::{ConfigError, Problem};
pub use events::{
    DEFAULT_DEDUP_WINDOW, Events, MAX_DEDUP_WINDOW, MAX_LABEL_VALUE_BYTES, MAX_LABELS,
};
pub use exemption::Exemption;
pub use inspection::Inspection;
pub use listener::{
    DEFAULT_LOGIN_TIMEOUT, DEFAULT_MAX_CONNECTIONS, Listener, MAX_LOGIN_TIMEOUT,
    MAX_MAX_CONNECTIONS,
};
pub use load::{LoadError, Loaded, MAX_FILE_BYTES, load};
pub use names::{Endpoint, EnvVarName, Host, InvalidText, LabelName, ListenAddr, Name, WebhookUrl};
pub use rules::{
    CatalogEnumerationRule, DEFAULT_MAX_PARSE_BYTES, FunctionsRule, MAX_MAX_PARSE_BYTES,
    ParseFailurePolicy, RowThresholdRule, Rules, UnboundedReadRule,
};
pub use sinks::{
    DEFAULT_QUEUE_SIZE, DEFAULT_WEBHOOK_RETRIES, DEFAULT_WEBHOOK_TIMEOUT, FileSink, MAX_QUEUE_SIZE,
    SecretRef, Sink, StdoutSink, SyslogFacility, SyslogSink, SyslogTransport, UrlSource,
    WebhookSink,
};
pub use tls::{ClientTls, ClientTlsMode, TlsVersion, UpstreamTls, UpstreamTlsMode};
pub use token::{
    MAX_VALUE_BYTES, MIN_VALUE_BYTES, Token, TokenFile, TokenOrigin, TokenScope, TokenValue,
};

use error::{At, Problems};

/// A complete configuration.
///
/// Get one from [`load`] or [`Config::from_yaml`]. Both check everything, so
/// a `Config` that exists is valid.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    /// Where pgsnare accepts clients and where it sends them. At least one
    /// listener is required. Changing listeners needs a restart.
    pub listeners: Vec<Listener>,
    /// How traffic is inspected.
    #[serde(default)]
    pub inspection: Inspection,
    /// Files with more honeytokens. An entry is a file, or a pattern with
    /// `*` and `?` in its file name, such as `/etc/pgsnare/tokens/*.yaml`.
    /// Each file is a [`TokenFile`].
    #[serde(default)]
    pub token_files: Vec<PathBuf>,
    /// The honeytokens. After [`load`], this also holds the tokens of every
    /// token file.
    #[serde(default)]
    pub tokens: Vec<Token>,
    /// Who may read honeytokens without triggering anything.
    #[serde(default)]
    pub exemptions: Vec<Exemption>,
    /// Optional SQL rules. Left out, no rule is on.
    #[serde(default)]
    pub rules: Option<Rules>,
    /// The settings of the responses.
    #[serde(default)]
    pub actions: Actions,
    /// What events show, how they are labelled and where they go.
    pub events: Events,
    /// The admin listener, which serves the health endpoints.
    #[serde(default)]
    pub admin: Admin,
    /// The metrics listener.
    #[serde(default)]
    pub metrics: Metrics,
    /// How pgsnare stops.
    #[serde(default)]
    pub shutdown: Shutdown,
}

impl Config {
    /// Reads a configuration from YAML text and checks it completely.
    ///
    /// Nothing is read from disk: the files named by `token_files` are not
    /// loaded and paths stay as written. Use [`load`] for a configuration
    /// file.
    ///
    /// # Errors
    ///
    /// Returns everything that is wrong with the document. The error never
    /// contains text from the document.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let config = Self::parse(text, None)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads the document without checking what serde cannot check.
    fn parse(text: &str, file: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut config: Self = yaml::from_str(text).map_err(|problem| {
            let error = ConfigError::one(problem);
            match file {
                Some(file) => error.in_file(file),
                None => error,
            }
        })?;
        token::set_origins(&mut config.tokens, file);
        Ok(config)
    }

    /// Checks everything that needs more than one field to judge.
    fn validate(&self) -> Result<(), ConfigError> {
        let root = At::root();
        let mut problems = Problems::new();

        let listeners = root.field("listeners");
        listener::validate_all(&self.listeners, &listeners, &mut problems);

        // No two listeners of any kind share an address.
        let admin = root.field("admin").field("listen");
        let metrics = root.field("metrics").field("listen");
        if self.admin.listen == self.metrics.listen {
            problems.add_with(&metrics, "this address is already used", &admin);
        }
        for (index, listener) in self.listeners.iter().enumerate() {
            let here = listeners.index(index).field("listen");
            if listener.listen == self.admin.listen {
                problems.add_with(&here, "this address is already used", &admin);
            }
            if listener.listen == self.metrics.listen {
                problems.add_with(&here, "this address is already used", &metrics);
            }
        }

        self.inspection
            .validate(&root.field("inspection"), &mut problems);

        let token_files = root.field("token_files");
        for (index, pattern) in self.token_files.iter().enumerate() {
            tls::check_path(pattern, &token_files.index(index), &mut problems);
        }
        token::validate_all(&self.tokens, &mut problems);

        let exemptions = root.field("exemptions");
        for (index, exemption) in self.exemptions.iter().enumerate() {
            exemption.validate(&exemptions.index(index), &mut problems);
        }

        if let Some(rules) = &self.rules {
            rules.validate(&root.field("rules"), &mut problems);
        }
        self.actions.validate(&root.field("actions"), &mut problems);
        self.events.validate(&root.field("events"), &mut problems);
        self.shutdown
            .validate(&root.field("shutdown"), &mut problems);

        problems.into_result()
    }

    /// Builds the policy snapshot the session logic works with.
    ///
    /// `generation` tells this snapshot apart from earlier ones. The source
    /// of snapshots raises it with every reload.
    ///
    /// # Errors
    ///
    /// A checked configuration always gives a valid policy. The error is
    /// passed on all the same, so that a mistake in this crate cannot turn
    /// into a panic.
    pub fn policy(&self, generation: u64) -> Result<PolicySnapshot, PolicyError> {
        PolicySnapshot::builder()
            .generation(generation)
            .inspection(self.inspection.policy())
            .tokens(self.tokens.iter().map(Token::policy))
            .exemptions(self.exemptions.iter().map(Exemption::policy))
            .actions(self.actions.policy())
            .query_redaction(self.events.query_redaction)
            .build()
    }

    /// Calls `visit` with every file path of the configuration.
    fn for_each_path_mut(&mut self, visit: &mut dyn FnMut(&mut PathBuf)) {
        for listener in &mut self.listeners {
            for path in [
                &mut listener.client_tls.cert,
                &mut listener.client_tls.key,
                &mut listener.upstream_tls.ca,
            ]
            .into_iter()
            .flatten()
            {
                visit(path);
            }
        }
        for pattern in &mut self.token_files {
            visit(pattern);
        }
        for sink in &mut self.events.sinks {
            sink.for_each_path_mut(visit);
        }
    }
}

#[cfg(test)]
mod tests;
