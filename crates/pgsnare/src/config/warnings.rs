// SPDX-License-Identifier: Apache-2.0

//! Settings that are valid and give up some protection.
//!
//! A configuration with such a setting loads and runs. Each of these is a
//! choice an operator may make on purpose, and each has to be written down
//! to take effect: none is a default. `pgsnare config check` lists them, so
//! that nobody makes the choice without noticing.

use std::fmt;

use pgsnare_core::policy::OnError;

use super::Config;
use super::error::At;
use super::sinks::{Sink, UrlSource};
use super::tls::UpstreamTlsMode;

/// A setting that is valid and gives up some protection.
///
/// It is made of the place of the setting in the schema and a fixed text.
/// It contains no text from the document.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// Where in the schema the setting is, such as `inspection.on_error`.
    pub path: String,
    /// What the setting gives up.
    pub message: &'static str,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl Config {
    /// The settings of this configuration that give up some protection, in
    /// the order of the document.
    ///
    /// - A listener that does not verify the certificate of the database:
    ///   `upstream_tls.mode` is `prefer` or `require`.
    /// - `inspection.on_error` is `fail_open`.
    /// - A webhook that sends events over plain HTTP, or that would accept
    ///   a plain `http` URL from its environment variable or file.
    /// - An admin or metrics listener that other machines can reach.
    ///
    /// Only the configuration is looked at. Nothing is read from disk and
    /// nothing is connected to.
    #[must_use]
    pub fn warnings(&self) -> Vec<Warning> {
        let root = At::root();
        let mut warnings = Vec::new();
        let mut warn = |at: At, message: &'static str| {
            warnings.push(Warning {
                path: at.to_string(),
                message,
            });
        };

        let listeners = root.field("listeners");
        for (index, listener) in self.listeners.iter().enumerate() {
            let mode = listeners.index(index).field("upstream_tls").field("mode");
            match listener.upstream_tls.mode {
                UpstreamTlsMode::Prefer => warn(
                    mode,
                    "the certificate of the database is not verified, and the connection is \
                     not encrypted at all when the database offers no TLS: whoever answers at \
                     its address is taken for the database",
                ),
                UpstreamTlsMode::Require => warn(
                    mode,
                    "the certificate of the database is not verified: whoever answers at its \
                     address is taken for the database",
                ),
                _ => {}
            }
        }

        if self.inspection.on_error == OnError::FailOpen {
            warn(
                root.field("inspection").field("on_error"),
                "fail_open lets a session go on without inspection when inspecting it fails: \
                 honeytokens then pass unseen",
            );
        }

        let sinks = root.field("events").field("sinks");
        for (index, sink) in self.events.sinks.iter().enumerate() {
            let Sink::Webhook(webhook) = sink else {
                continue;
            };
            let here = sinks.index(index);
            match &webhook.url {
                UrlSource::Inline(url) if !url.is_https() => warn(
                    here.field("url"),
                    "events are sent over plain HTTP: whoever is on the way can read and \
                     change them",
                ),
                UrlSource::Env(_) | UrlSource::File(_) if webhook.allow_insecure_http => warn(
                    here.field("allow_insecure_http"),
                    "a plain http URL is accepted for this sink: events are then sent \
                     unencrypted, and whoever is on the way can read and change them",
                ),
                _ => {}
            }
        }

        if !self.admin.listen.is_loopback() {
            warn(
                root.field("admin").field("listen"),
                "the admin listener can be reached from other machines: it is meant for this \
                 machine alone",
            );
        }
        if !self.metrics.listen.is_loopback() {
            warn(
                root.field("metrics").field("listen"),
                "the metrics listener can be reached from other machines: make sure that only \
                 the scraper can connect to it",
            );
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: verify-full }
events:
  sinks:
    - type: stdout
";

    fn warnings(text: &str) -> Vec<String> {
        Config::from_yaml(text)
            .unwrap_or_else(|error| panic!("{error}"))
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn a_configuration_with_the_safe_defaults_has_no_warning() {
        assert!(warnings(BASE).is_empty());
        // Plaintext to the database is a setup of its own, for a database
        // on the same machine, and not a verification that was turned off.
        assert!(warnings(&BASE.replace("verify-full", "disable")).is_empty());
    }

    #[test]
    fn a_database_whose_certificate_is_not_verified_is_a_warning() {
        assert_eq!(
            warnings(&BASE.replace("verify-full", "require")),
            [
                "listeners[0].upstream_tls.mode: the certificate of the database is not verified: \
              whoever answers at its address is taken for the database"
            ]
        );
        assert_eq!(
            warnings(&BASE.replace("verify-full", "prefer")),
            [
                "listeners[0].upstream_tls.mode: the certificate of the database is not verified, \
              and the connection is not encrypted at all when the database offers no TLS: \
              whoever answers at its address is taken for the database"
            ]
        );
    }

    #[test]
    fn every_listener_that_does_not_verify_is_named() {
        let text = BASE.replace(
            "events:",
            "  - name: second\n    listen: 0.0.0.0:5433\n    upstream: db.example.com:5432\n    \
             client_tls: { mode: disable }\n    upstream_tls: { mode: verify-full }\n  \
             - name: third\n    listen: 0.0.0.0:5434\n    upstream: db.example.com:5432\n    \
             client_tls: { mode: disable }\n    upstream_tls: { mode: require }\nevents:",
        );
        let found = warnings(&text.replacen("verify-full", "prefer", 1));
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].starts_with("listeners[0].upstream_tls.mode: "));
        assert!(found[1].starts_with("listeners[2].upstream_tls.mode: "));
    }

    #[test]
    fn fail_open_is_a_warning() {
        assert_eq!(
            warnings(&format!("{BASE}inspection: {{ on_error: fail_open }}\n")),
            [
                "inspection.on_error: fail_open lets a session go on without inspection when \
              inspecting it fails: honeytokens then pass unseen"
            ]
        );
        assert!(warnings(&format!("{BASE}inspection: {{ on_error: fail_closed }}\n")).is_empty());
    }

    #[test]
    fn a_sink_over_plain_http_is_a_warning() {
        let webhook = |settings: &str| {
            warnings(&format!(
                "{BASE}    - type: webhook\n      hmac_secret_env: PGSNARE_WEBHOOK_SECRET\n{settings}"
            ))
        };
        assert!(webhook("      url: https://alerts.example.com/hook\n").is_empty());
        // An https URL stays encrypted whatever else is allowed.
        assert!(
            webhook(
                "      url: https://alerts.example.com/hook\n      allow_insecure_http: true\n"
            )
            .is_empty()
        );
        assert_eq!(
            webhook("      url: http://alerts.example.com/hook\n      allow_insecure_http: true\n"),
            [
                "events.sinks[1].url: events are sent over plain HTTP: whoever is on the way can \
              read and change them"
            ]
        );
        // A URL that is not in the configuration cannot be looked at. What
        // counts is whether a plain one would be accepted.
        assert!(webhook("      url_env: PGSNARE_WEBHOOK_URL\n").is_empty());
        assert!(webhook("      url_file: /etc/pgsnare/webhook-url\n").is_empty());
        for source in [
            "url_env: PGSNARE_WEBHOOK_URL",
            "url_file: /etc/pgsnare/webhook-url",
        ] {
            assert_eq!(
                webhook(&format!(
                    "      {source}\n      allow_insecure_http: true\n"
                )),
                [
                    "events.sinks[1].allow_insecure_http: a plain http URL is accepted for this \
                  sink: events are then sent unencrypted, and whoever is on the way can read \
                  and change them"
                ]
            );
        }
    }

    #[test]
    fn an_admin_or_metrics_listener_beyond_loopback_is_a_warning() {
        assert!(warnings(&format!("{BASE}admin: {{ listen: 127.0.0.1:19641 }}\n")).is_empty());
        assert!(warnings(&format!("{BASE}metrics: {{ listen: \"[::1]:9642\" }}\n")).is_empty());
        assert_eq!(
            warnings(&format!("{BASE}admin: {{ listen: 0.0.0.0:9641 }}\n")),
            [
                "admin.listen: the admin listener can be reached from other machines: it is meant \
              for this machine alone"
            ]
        );
        assert_eq!(
            warnings(&format!("{BASE}metrics: {{ listen: 192.0.2.10:9642 }}\n")),
            [
                "metrics.listen: the metrics listener can be reached from other machines: make \
              sure that only the scraper can connect to it"
            ]
        );
        assert_eq!(
            warnings(&format!("{BASE}metrics: {{ listen: \"[::]:9642\" }}\n")).len(),
            1
        );
    }

    #[test]
    fn warnings_come_in_the_order_of_the_document() {
        let text = format!(
            "{}    - type: webhook\n      url: http://alerts.example.com/hook\n      \
             hmac_secret_env: PGSNARE_WEBHOOK_SECRET\n      allow_insecure_http: true\n\
             inspection: {{ on_error: fail_open }}\nadmin: {{ listen: 0.0.0.0:9641 }}\n\
             metrics: {{ listen: 0.0.0.0:9642 }}\n",
            BASE.replace("verify-full", "require")
        );
        let paths: Vec<String> = Config::from_yaml(&text)
            .unwrap()
            .warnings()
            .into_iter()
            .map(|warning| warning.path)
            .collect();
        assert_eq!(
            paths,
            [
                "listeners[0].upstream_tls.mode",
                "inspection.on_error",
                "events.sinks[1].url",
                "admin.listen",
                "metrics.listen"
            ]
        );
    }

    #[test]
    fn the_complete_example_has_no_warning() {
        // The example turns SQL rules on, which only a build with them
        // accepts.
        if cfg!(feature = "rules") {
            let text = include_str!("../../../../examples/config/pgsnare.yaml");
            assert!(warnings(text).is_empty());
        }
    }
}
