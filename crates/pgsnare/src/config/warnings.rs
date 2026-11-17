// SPDX-License-Identifier: Apache-2.0

//! Settings that are valid and give up some protection.
//!
//! A configuration with such a setting loads and runs. Each of these is a
//! choice an operator may make on purpose, and each has to be written down
//! to take effect: none is a default. `pgsnare config check` lists them, so
//! that nobody makes the choice without noticing.

use std::fmt;

use pgsnare_core::detect::{uuid_bytes, varied_enough};
use pgsnare_core::policy::{Action, ActionSet, OnError};

use super::Config;
use super::error::At;
use super::rules::{PARSER_MEMORY_BUDGET, ParseFailurePolicy};
use super::sinks::{Sink, UrlSource};
use super::tls::UpstreamTlsMode;

/// A setting that is valid and gives up some protection.
///
/// It is made of the place of the setting in the schema and a text. It names
/// a token by its id only, never by the values it watches for.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// Where in the schema the setting is, such as `inspection.on_error`.
    pub path: String,
    /// What the setting gives up.
    pub message: String,
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
    /// - A token with a value that is a canonical UUID whose sixteen bytes
    ///   hold too few distinct values to be searched for in a binary result
    ///   or a binary COPY.
    /// - A webhook that sends events over plain HTTP, or that would accept
    ///   a plain `http` URL from its environment variable or file.
    /// - An admin or metrics listener that other machines can reach.
    /// - A SQL rule that judges a statement and answers with `kill` or
    ///   `tarpit`, while `rules.on_parse_failure` is not `block`: a
    ///   statement that cannot be analysed is then passed on, and the rule
    ///   does not judge it.
    /// - `rules.max_parse_bytes` so large that the parser threads can take
    ///   more than [`PARSER_MEMORY_BUDGET`] at their worst: a client that
    ///   is logged in can then use up the memory limit that the deployment
    ///   documents give a proxy with rules.
    ///
    /// Only the configuration is looked at. Nothing is read from disk and
    /// nothing is connected to.
    #[must_use]
    pub fn warnings(&self) -> Vec<Warning> {
        let root = At::root();
        let mut warnings = Vec::new();
        let mut warn = |at: At, message: &str| {
            warnings.push(Warning {
                path: at.to_string(),
                message: message.to_owned(),
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

        let tokens = At::root().field("tokens");
        for token in &self.tokens {
            // The id is safe to print: it is a label an operator chose. The
            // values stay where they are, in the configuration.
            let little_variety = token.values.iter().any(|value| {
                uuid_bytes(value.expose().as_bytes()).is_some_and(|bytes| !varied_enough(&bytes))
            });
            if little_variety {
                let id = token.id.as_str();
                let message = format!(
                    "the token `{id}` has a value whose sixteen bytes hold too few \
                     distinct values to be searched for in a binary result or a binary \
                     COPY, where unrelated sixteen-byte values would match it by chance: \
                     use a random, generated UUID for that value"
                );
                warn(tokens.index(token.origin.index), &message);
            }
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

        if let Some(rules) = &self.rules
            && rules.on_parse_failure != ParseFailurePolicy::Block
        {
            // The row threshold counts the rows of a result, also of a
            // statement that was not analysed, so it is not among them.
            let certain = |actions: ActionSet| {
                actions.contains(Action::Kill) || actions.contains(Action::Tarpit)
            };
            let judged = [
                rules.catalog_enumeration.as_ref().map(|rule| rule.actions),
                rules.unbounded_read.as_ref().map(|rule| rule.actions),
                rules.functions.as_ref().map(|rule| rule.actions),
            ];
            if judged.into_iter().flatten().any(certain) {
                warn(
                    root.field("rules").field("on_parse_failure"),
                    "a rule answers a statement with kill or tarpit, and a statement that \
                     cannot be analysed is passed on without being judged by it: only block \
                     makes the response of such a rule certain",
                );
            }
        }

        if let Some(rules) = &self.rules
            && rules.parser_memory() > PARSER_MEMORY_BUDGET
        {
            warn(
                root.field("rules").field("max_parse_bytes"),
                "the two parser threads can each take about 1,500 times the size of a \
                 statement while they read it, which for this value is more than 256 MiB \
                 together: give the process a memory limit of at least 256 MiB plus 3,000 \
                 times this value, or a client that is logged in can have it ended for lack \
                 of memory",
            );
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
    fn a_token_with_a_low_variety_uuid_is_a_warning() {
        let with = |id: &str, value: &str| {
            warnings(&format!(
                "{BASE}tokens:\n  - id: {id}\n    values: [{value}]\n"
            ))
        };
        let message = |id: &str| {
            format!(
                "tokens[0]: the token `{id}` has a value whose sixteen bytes hold too few \
                 distinct values to be searched for in a binary result or a binary COPY, \
                 where unrelated sixteen-byte values would match it by chance: use a random, \
                 generated UUID for that value"
            )
        };
        // The nil UUID, a value of one byte and a sequential counter hold too
        // few distinct values to be searched for in sixteen bytes.
        for (id, value) in [
            ("nil", "00000000-0000-0000-0000-000000000000"),
            ("max", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
            ("counter", "00000000-0000-0000-0000-000000000417"),
            // Seven distinct values, the most below the line.
            ("seven", "00000000-0102-0304-0506-060606060606"),
        ] {
            let found = with(id, value);
            assert_eq!(found, [message(id)], "{value}");
            // The warning names the token, never the value it watches for.
            assert!(!found[0].contains(value), "{value}");
            assert!(found[0].contains(&format!("`{id}`")), "{value}");
        }
        // Eight distinct values is the least that earns the binary form, and
        // a generated UUID has all sixteen different.
        for (id, value) in [
            ("eight", "00000000-0102-0304-0506-070606060606"),
            ("row", "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
        ] {
            assert!(with(id, value).is_empty(), "{value}");
        }
        // A value that is not a canonical UUID has no sixteen bytes at all.
        assert!(with("mail", "svc.backup.8f3k2q@mail.example").is_empty());
        // One warning per token, however many of its values warn.
        assert_eq!(
            warnings(&format!(
                "{BASE}tokens:\n  - id: counter\n    values: \
                     [00000000-0000-0000-0000-000000000000, 00000000-0000-0000-0000-000000000417]\n"
            )),
            [message("counter")]
        );
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
    fn a_statement_size_that_outgrows_the_documented_memory_limit_is_a_warning() {
        use super::super::rules::{PARSE_MEMORY_FACTOR, PARSER_THREADS};

        if !cfg!(feature = "rules") {
            return;
        }
        let warning = "rules.max_parse_bytes: the two parser threads can each take about 1,500 \
                       times the size of a statement while they read it, which for this value \
                       is more than 256 MiB together: give the process a memory limit of at \
                       least 256 MiB plus 3,000 times this value, or a client that is logged \
                       in can have it ended for lack of memory";
        // The figures of the text are those of the check.
        assert_eq!((PARSER_THREADS, PARSE_MEMORY_FACTOR), (2, 1_500));
        assert_eq!(PARSER_THREADS * PARSE_MEMORY_FACTOR, 3_000);
        assert_eq!(PARSER_MEMORY_BUDGET, 256 * 1024 * 1024);

        let with = |size: &str| warnings(&format!("{BASE}rules:\n  max_parse_bytes: {size}\n"));
        // The default, and the largest size that stays within 256 MiB.
        assert!(warnings(&format!("{BASE}rules: {{}}\n")).is_empty());
        assert!(with("64KiB").is_empty());
        assert!(with("89478B").is_empty());
        // One byte more, and every size up to the largest accepted.
        assert_eq!(with("89479B"), [warning]);
        assert_eq!(with("128KiB"), [warning]);
        assert_eq!(with("1MiB"), [warning]);
    }

    #[test]
    fn a_rule_that_ends_sessions_while_unread_statements_pass_is_a_warning() {
        if !cfg!(feature = "rules") {
            return;
        }
        let warning = "rules.on_parse_failure: a rule answers a statement with kill or tarpit, \
                       and a statement that cannot be analysed is passed on without being \
                       judged by it: only block makes the response of such a rule certain";
        let with = |rules: &str| warnings(&format!("{BASE}rules:\n{rules}"));
        for policy in [
            "",
            "  on_parse_failure: alert\n",
            "  on_parse_failure: allow\n",
        ] {
            for rule in [
                "  functions: { names: [pg_sleep], actions: [alert, kill] }\n",
                "  functions: { names: [pg_sleep], actions: [tarpit] }\n",
                "  catalog_enumeration: { actions: [kill] }\n",
                "  unbounded_read: { tables: [users], actions: [alert, tarpit] }\n",
            ] {
                assert_eq!(
                    with(&format!("{policy}{rule}")),
                    [warning],
                    "{policy}{rule}"
                );
            }
            // A rule that only reports loses nothing it promised, and the
            // row threshold counts the rows of every result.
            for rule in [
                "  functions: { names: [pg_sleep] }\n",
                "  functions: { names: [pg_sleep], actions: [alert, fake_data] }\n",
                "  row_threshold: { tables: [users], max_rows: 10, actions: [kill] }\n",
            ] {
                assert!(
                    with(&format!("{policy}{rule}")).is_empty(),
                    "{policy}{rule}"
                );
            }
        }
        assert!(
            with(
                "  on_parse_failure: block\n  functions: { names: [pg_sleep], actions: [kill] }\n"
            )
            .is_empty()
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
