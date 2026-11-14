// SPDX-License-Identifier: Apache-2.0

//! The metrics, in the text format Prometheus reads.
//!
//! [`render`] turns what the [`Status`] counts into one text. Nothing here
//! counts anything itself.
//!
//! # Names and labels
//!
//! Every name of a metric, every name of a label and every help text is a
//! fixed text of this file. A label value is one of three things:
//!
//! - a fixed word of the code, such as a direction or the reason an event
//!   was dropped
//! - the name of a sink, which comes from the configuration or from the
//!   code of the sink
//! - the id of a token or of a rule, which comes from the configuration
//!
//! Each of them becomes a label through the redaction layer and in no
//! other way, so a label is short, is made of a plain alphabet and never
//! holds a honeytoken value. Nothing a client or a database sent is a
//! label or a part of a name.
//!
//! # What is not shown
//!
//! No configuration, no address of a client, and no list of the tokens
//! there are: a token gets a counter of its own only once it was hit, and
//! by then its id has been in an event.
//!
//! # Metrics without a source yet
//!
//! Queries, hits, responses, statements that could not be parsed and
//! reloads that failed are counted by the code that detects and responds,
//! which is not built yet. Their metrics are here already, with their
//! names, help texts and labels, and say zero.

use std::fmt::{Display, Write as _};

use crate::redact::Redaction;
use crate::runtime::{Counters, DropReason, Status};

/// The content type of the text [`render`] gives.
pub(crate) const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The metrics as they stand, in the text format of Prometheus.
pub(crate) fn render(status: &Status, redaction: &Redaction) -> String {
    let counters = status.counters();
    let mut text = Exposition {
        text: String::with_capacity(8 * 1024),
        redaction,
    };

    text.family(
        "pgsnare_build_info",
        "gauge",
        "The version of pgsnare that is running. The value is always 1.",
    );
    text.sample(
        "pgsnare_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    text.single(
        "pgsnare_ready",
        "gauge",
        "Whether the proxy accepts clients: 1 from the moment its listeners are served until it \
         is asked to stop or a listener fails.",
        u8::from(status.is_ready()),
    );
    text.single(
        "pgsnare_healthy",
        "gauge",
        "Whether the proxy works as it should: 0 once a listener has stopped accepting clients \
         without having been asked to.",
        u8::from(status.is_healthy()),
    );

    sessions(&mut text, &counters);
    detection(&mut text, status, &counters);
    events(&mut text, status, &counters);
    faults(&mut text, &counters);
    latency(&mut text, status);
    text.text
}

/// Connections, logins and bytes.
fn sessions(text: &mut Exposition<'_>, counters: &Counters) {
    text.single(
        "pgsnare_connections_accepted_total",
        "counter",
        "Client connections that were given a session.",
        counters.sessions_accepted,
    );
    text.single(
        "pgsnare_connections_refused_total",
        "counter",
        "Client connections that were closed at once because a listener had reached its \
         connection limit.",
        counters.sessions_refused,
    );
    text.single(
        "pgsnare_connections_active",
        "gauge",
        "Sessions that are open right now.",
        counters.sessions_active,
    );
    text.single(
        "pgsnare_sessions_failed_total",
        "counter",
        "Sessions that were ended because their traffic could not be followed.",
        counters.sessions_failed,
    );
    text.single(
        "pgsnare_logins_total",
        "counter",
        "Sessions whose login the database accepted.",
        counters.logins_finished,
    );
    text.single(
        "pgsnare_login_timeouts_total",
        "counter",
        "Sessions that were closed because the client took too long to log in.",
        counters.login_timeouts,
    );
    text.single(
        "pgsnare_backend_connection_failures_total",
        "counter",
        "Attempts to connect to the database that failed.",
        counters.backend_failures,
    );
    text.single(
        "pgsnare_cancel_requests_forwarded_total",
        "counter",
        "Cancel requests that were passed on to the database.",
        counters.cancels_forwarded,
    );
    text.family(
        "pgsnare_bytes_total",
        "counter",
        "Bytes read, by the side they came from.",
    );
    text.sample(
        "pgsnare_bytes_total",
        &[("direction", "from_client")],
        counters.bytes_from_clients,
    );
    text.sample(
        "pgsnare_bytes_total",
        &[("direction", "from_server")],
        counters.bytes_from_servers,
    );
    text.single(
        "pgsnare_read_buffer_bytes",
        "gauge",
        "The size of the buffers all open sessions read into, right now.",
        counters.read_buffer_bytes,
    );
}

/// Queries, hits and responses: what the code that detects will count.
fn detection(text: &mut Exposition<'_>, status: &Status, counters: &Counters) {
    text.single(
        "pgsnare_queries_total",
        "counter",
        "Statements clients ran.",
        counters.queries,
    );
    text.family(
        "pgsnare_hits_total",
        "counter",
        "Hits, by what was hit: a honeytoken in a session that is not exempt, a honeytoken in \
         an exempt session, which is counted and triggers nothing, or an SQL rule.",
    );
    for (kind, hits) in [
        ("token", counters.token_hits),
        ("token_exempt", counters.exempt_token_hits),
        ("rule", counters.rule_hits),
    ] {
        text.sample("pgsnare_hits_total", &[("kind", kind)], hits);
    }

    let hits = status.hits();
    text.family(
        "pgsnare_token_hits_total",
        "counter",
        "Hits of each honeytoken that was hit, by the id of the token and by whether the \
         session was exempt. A token that was never hit is not listed.",
    );
    for (token, plain, exempt) in &hits.tokens {
        for (exempt, hits) in [("false", plain), ("true", exempt)] {
            if *hits > 0 {
                text.sample(
                    "pgsnare_token_hits_total",
                    &[("token_id", token.as_str()), ("exempt", exempt)],
                    hits,
                );
            }
        }
    }
    text.family(
        "pgsnare_rule_hits_total",
        "counter",
        "Statements that matched each SQL rule that matched, by the id of the rule.",
    );
    for (rule, hits) in &hits.rules {
        text.sample(
            "pgsnare_rule_hits_total",
            &[("rule_id", rule.as_str())],
            hits,
        );
    }

    text.family(
        "pgsnare_actions_total",
        "counter",
        "Responses that were carried out, by response.",
    );
    for (action, taken) in Counters::ACTIONS.iter().zip(counters.actions) {
        text.sample("pgsnare_actions_total", &[("action", action)], taken);
    }
    text.single(
        "pgsnare_parse_failures_total",
        "counter",
        "Statements that could not be parsed, so that no rule could judge them.",
        counters.parse_failures,
    );
    text.single(
        "pgsnare_reload_failures_total",
        "counter",
        "Reloads that were refused, so that the policy stayed as it was.",
        counters.reload_failures,
    );
}

/// Events on their way to the sinks: how many, how many wait, how many
/// were lost and why.
fn events(text: &mut Exposition<'_>, status: &Status, counters: &Counters) {
    text.single(
        "pgsnare_events_raised_total",
        "counter",
        "Events sessions raised.",
        counters.events_emitted,
    );
    text.family(
        "pgsnare_events_total",
        "counter",
        "Events the dispatcher took from its queue, by kind.",
    );
    for (kind, taken) in Counters::EVENT_KINDS.iter().zip(counters.events_by_kind) {
        text.sample("pgsnare_events_total", &[("kind", kind)], taken);
    }
    text.single(
        "pgsnare_events_deduplicated_total",
        "counter",
        "Hits that were folded into another event instead of being delivered as an event of \
         their own.",
        counters.events_deduplicated,
    );
    text.single(
        "pgsnare_event_queue_depth",
        "gauge",
        "Events that wait for the dispatcher, right now.",
        counters.event_queue_depth,
    );
    text.single(
        "pgsnare_event_queue_capacity",
        "gauge",
        "How many events may wait for the dispatcher.",
        counters.event_queue_capacity,
    );
    text.single(
        "pgsnare_events_dropped_total",
        "counter",
        "Events that reached no sink because the queue of the dispatcher was full.",
        counters.events_dropped,
    );

    let sinks = status.sinks();
    text.family(
        "pgsnare_sink_queue_depth",
        "gauge",
        "Events that wait for each sink, right now.",
    );
    for sink in &sinks {
        text.sample(
            "pgsnare_sink_queue_depth",
            &[("sink", sink.name.as_str())],
            sink.queue_depth,
        );
    }
    text.family(
        "pgsnare_sink_queue_capacity",
        "gauge",
        "How many events may wait for each sink.",
    );
    for sink in &sinks {
        text.sample(
            "pgsnare_sink_queue_capacity",
            &[("sink", sink.name.as_str())],
            sink.queue_capacity,
        );
    }
    text.family(
        "pgsnare_sink_events_delivered_total",
        "counter",
        "Events each sink delivered.",
    );
    for sink in &sinks {
        text.sample(
            "pgsnare_sink_events_delivered_total",
            &[("sink", sink.name.as_str())],
            sink.delivered,
        );
    }
    text.family(
        "pgsnare_sink_delivery_attempts_failed_total",
        "counter",
        "Attempts of each sink to deliver an event that failed. An event that is tried again \
         counts once for each failed attempt.",
    );
    for sink in &sinks {
        text.sample(
            "pgsnare_sink_delivery_attempts_failed_total",
            &[("sink", sink.name.as_str())],
            sink.failed_attempts,
        );
    }
    text.family(
        "pgsnare_sink_events_dropped_total",
        "counter",
        "Events each sink did not deliver, by reason: its queue was full, it refused the event, \
         every attempt failed, or the proxy stopped first.",
    );
    for sink in &sinks {
        for (reason, dropped) in DropReason::ALL.iter().zip(sink.dropped) {
            text.sample(
                "pgsnare_sink_events_dropped_total",
                &[("sink", sink.name.as_str()), ("reason", reason.name())],
                dropped,
            );
        }
    }
}

/// What must stay at zero.
fn faults(text: &mut Exposition<'_>, counters: &Counters) {
    text.family(
        "pgsnare_panics_total",
        "counter",
        "Panics in the code of pgsnare, by where: a session, a listener, a sink, or the \
         listeners for health and metrics. Every one of them is a defect.",
    );
    for (scope, panics) in [
        ("session", counters.session_panics),
        ("listener", counters.listener_panics),
        ("sink", counters.sink_panics),
        ("admin", counters.admin_panics),
    ] {
        text.sample("pgsnare_panics_total", &[("scope", scope)], panics);
    }
    text.single(
        "pgsnare_listener_failures_total",
        "counter",
        "Listeners that stopped accepting clients while the proxy was meant to run.",
        counters.listener_failures,
    );
}

/// The histogram of added latency.
fn latency(text: &mut Exposition<'_>, status: &Status) {
    const NAME: &str = "pgsnare_added_latency_seconds";
    let histogram = status.added_latency();
    text.family(
        NAME,
        "histogram",
        "The time bytes spend in the proxy once a client has logged in: from reading \
         something from one connection to having written everything that came of it to the \
         other.",
    );
    let mut cumulative = 0u64;
    for (bound, count) in histogram.bounds.iter().zip(&histogram.counts) {
        cumulative = cumulative.saturating_add(*count);
        text.sample_with(NAME, "_bucket", &[("le", &bound.to_string())], cumulative);
    }
    let count = histogram.count();
    text.sample_with(NAME, "_bucket", &[("le", "+Inf")], count);
    text.sample_with(NAME, "_sum", &[], histogram.sum);
    text.sample_with(NAME, "_count", &[], count);
}

/// The text that is being written.
struct Exposition<'a> {
    text: String,
    redaction: &'a Redaction,
}

impl Exposition<'_> {
    /// The two lines that introduce a metric.
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        // Writing to a `String` cannot fail.
        let _ = writeln!(self.text, "# HELP {name} {}", escape(help, false));
        let _ = writeln!(self.text, "# TYPE {name} {kind}");
    }

    /// A metric that is one number.
    fn single(&mut self, name: &str, kind: &str, help: &str, value: impl Display) {
        self.family(name, kind, help);
        self.sample(name, &[], value);
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl Display) {
        self.sample_with(name, "", labels, value);
    }

    /// One line: a name, labels and a value. `suffix` is what a histogram
    /// adds to its name.
    fn sample_with(
        &mut self,
        name: &str,
        suffix: &str,
        labels: &[(&str, &str)],
        value: impl Display,
    ) {
        self.text.push_str(name);
        self.text.push_str(suffix);
        for (index, (label, value)) in labels.iter().enumerate() {
            self.text.push(if index == 0 { '{' } else { ',' });
            // A bound of a histogram is a number, and its sign and its
            // decimal point are not for a label of the redaction layer.
            let value = if *label == "le" {
                (*value).to_owned()
            } else {
                self.redaction.label(value)
            };
            let _ = write!(self.text, "{label}=\"{}\"", escape(&value, true));
        }
        if !labels.is_empty() {
            self.text.push('}');
        }
        let _ = writeln!(self.text, " {value}");
    }
}

/// A text as the format wants it: a backslash and a line break are escaped
/// everywhere, and a quotation mark in the value of a label.
fn escape(text: &str, label: bool) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '"' if label => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use pgsnare_core::event::EventKind;
    use pgsnare_core::policy::{Action, ActionSet, RuleId, TokenId};

    use crate::redact::Redactor;

    use super::*;

    /// One sample of an exposition: the name, the labels and the value.
    pub(crate) type Sample = (String, BTreeMap<String, String>, f64);

    /// Reads an exposition the way a scraper does, strictly: every line
    /// must be a comment of a known form or a sample, every sample must
    /// belong to the family that was introduced last, and no sample may be
    /// there twice.
    pub(crate) fn parse(text: &str) -> Vec<Sample> {
        assert!(text.ends_with('\n'), "the last line is complete");
        let mut samples: Vec<Sample> = Vec::new();
        let mut family: Option<(String, String)> = None;
        let mut helped: Option<String> = None;
        let mut families: Vec<String> = Vec::new();

        for line in text.lines() {
            assert!(!line.is_empty(), "no empty lines");
            if let Some(help) = line.strip_prefix("# HELP ") {
                let (name, text) = help.split_once(' ').expect("a help text");
                assert!(!text.is_empty());
                assert!(
                    !families.contains(&name.to_owned()),
                    "{name} is introduced twice"
                );
                helped = Some(name.to_owned());
                continue;
            }
            if let Some(kind) = line.strip_prefix("# TYPE ") {
                let (name, kind) = kind.split_once(' ').expect("a type");
                assert_eq!(helped.as_deref(), Some(name), "HELP comes before TYPE");
                assert!(matches!(kind, "counter" | "gauge" | "histogram"), "{kind}");
                assert!(is_metric_name(name), "{name}");
                if kind == "counter" {
                    assert!(name.ends_with("_total"), "{name} is a counter");
                }
                families.push(name.to_owned());
                family = Some((name.to_owned(), kind.to_owned()));
                continue;
            }
            assert!(!line.starts_with('#'), "an unknown comment: {line}");

            let (series, value) = line.rsplit_once(' ').expect("a value");
            let value: f64 = value.parse().unwrap_or_else(|_| panic!("a number: {line}"));
            let (name, labels) = match series.split_once('{') {
                Some((name, rest)) => {
                    let inner = rest.strip_suffix('}').expect("labels end with a brace");
                    (name, parse_labels(inner))
                }
                None => (series, BTreeMap::new()),
            };
            let (family_name, kind) = family.as_ref().expect("a sample follows its family");
            let base = if kind == "histogram" {
                name.strip_suffix("_bucket")
                    .or_else(|| name.strip_suffix("_sum"))
                    .or_else(|| name.strip_suffix("_count"))
                    .expect("a sample of a histogram")
            } else {
                name
            };
            assert_eq!(
                base, family_name,
                "a sample belongs to the family before it"
            );
            assert!(
                !samples
                    .iter()
                    .any(|(other, other_labels, _)| other == name && *other_labels == labels),
                "{line} is there twice"
            );
            samples.push((name.to_owned(), labels, value));
        }
        samples
    }

    fn is_metric_name(name: &str) -> bool {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }

    /// Labels as `name="value",name="value"`, with the escapes of the
    /// format.
    fn parse_labels(text: &str) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        let mut rest = text;
        while !rest.is_empty() {
            let (name, after) = rest.split_once("=\"").expect("a label has a value");
            assert!(is_metric_name(name), "{name}");
            let mut value = String::new();
            let mut characters = after.char_indices();
            let end = loop {
                let (at, character) = characters.next().expect("a value ends with a quote");
                match character {
                    '"' => break at,
                    '\\' => match characters.next().expect("an escape").1 {
                        'n' => value.push('\n'),
                        other => value.push(other),
                    },
                    other => value.push(other),
                }
            };
            assert!(
                labels.insert(name.to_owned(), value).is_none(),
                "{name} twice"
            );
            rest = after[end + 1..]
                .strip_prefix(',')
                .unwrap_or(&after[end + 1..]);
        }
        labels
    }

    /// The value of a sample with exactly these labels.
    pub(crate) fn value(samples: &[Sample], name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        let labels: BTreeMap<String, String> = labels
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        samples
            .iter()
            .find(|(other, other_labels, _)| other == name && *other_labels == labels)
            .map(|(_, _, value)| *value)
    }

    #[test]
    fn a_proxy_that_did_nothing_yet_shows_every_metric_at_zero() {
        let status = Status::new();
        let text = render(&status, &Redaction::default());
        let samples = parse(&text);

        for name in [
            "pgsnare_connections_accepted_total",
            "pgsnare_connections_refused_total",
            "pgsnare_connections_active",
            "pgsnare_sessions_failed_total",
            "pgsnare_logins_total",
            "pgsnare_login_timeouts_total",
            "pgsnare_backend_connection_failures_total",
            "pgsnare_cancel_requests_forwarded_total",
            "pgsnare_read_buffer_bytes",
            "pgsnare_queries_total",
            "pgsnare_parse_failures_total",
            "pgsnare_reload_failures_total",
            "pgsnare_events_raised_total",
            "pgsnare_events_deduplicated_total",
            "pgsnare_event_queue_depth",
            "pgsnare_events_dropped_total",
            "pgsnare_listener_failures_total",
            "pgsnare_ready",
            "pgsnare_added_latency_seconds_sum",
            "pgsnare_added_latency_seconds_count",
        ] {
            assert_eq!(value(&samples, name, &[]), Some(0.0), "{name}");
        }
        assert_eq!(value(&samples, "pgsnare_healthy", &[]), Some(1.0));
        assert_eq!(
            value(
                &samples,
                "pgsnare_build_info",
                &[("version", env!("CARGO_PKG_VERSION"))]
            ),
            Some(1.0)
        );

        // The metrics with labels from a fixed list show every label.
        for direction in ["from_client", "from_server"] {
            assert_eq!(
                value(&samples, "pgsnare_bytes_total", &[("direction", direction)]),
                Some(0.0)
            );
        }
        for kind in ["token", "token_exempt", "rule"] {
            assert_eq!(
                value(&samples, "pgsnare_hits_total", &[("kind", kind)]),
                Some(0.0)
            );
        }
        for action in ["alert", "kill", "tarpit", "fake_data"] {
            assert_eq!(
                value(&samples, "pgsnare_actions_total", &[("action", action)]),
                Some(0.0)
            );
        }
        for scope in ["session", "listener", "sink", "admin"] {
            assert_eq!(
                value(&samples, "pgsnare_panics_total", &[("scope", scope)]),
                Some(0.0)
            );
        }
        for kind in Counters::EVENT_KINDS {
            assert_eq!(
                value(&samples, "pgsnare_events_total", &[("kind", kind)]),
                Some(0.0)
            );
        }

        // No token and no sink is there to be listed.
        assert!(!text.contains("token_id="), "{text}");
        assert!(!text.contains("rule_id="), "{text}");
        assert!(!text.contains("sink="), "{text}");
        // But their metrics are introduced all the same.
        for name in [
            "pgsnare_token_hits_total",
            "pgsnare_rule_hits_total",
            "pgsnare_sink_events_dropped_total",
        ] {
            assert!(text.contains(&format!("# TYPE {name} counter\n")), "{name}");
        }
    }

    #[test]
    fn what_the_runtime_counts_is_what_the_metrics_say() {
        let status = Status::new();
        status.set_ready(true);
        status.session_accepted();
        status.session_accepted();
        status.session_ended();
        status.session_refused();
        status.read_from_client(1000);
        status.read_from_server(2500);
        status.event_emitted();
        status.event_taken(EventKind::InspectionBypassed);
        status.event_dropped();
        status.session_panicked();
        status.sink_panicked();
        status.query_seen();
        status.token_hit(&TokenId::new("users-admin-backup").unwrap(), false);
        status.token_hit(&TokenId::new("users-admin-backup").unwrap(), false);
        status.token_hit(&TokenId::new("card-test-0002").unwrap(), true);
        status.rule_hit(&RuleId::new("catalog_enumeration").unwrap());
        status.actions_taken(ActionSet::of(&[Action::Alert, Action::Kill]));
        status.parse_failed();
        status.reload_failed();

        let samples = parse(&render(&status, &Redaction::default()));
        let number = |name: &str, labels: &[(&str, &str)]| value(&samples, name, labels);
        assert_eq!(number("pgsnare_ready", &[]), Some(1.0));
        assert_eq!(number("pgsnare_connections_accepted_total", &[]), Some(2.0));
        assert_eq!(number("pgsnare_connections_active", &[]), Some(1.0));
        assert_eq!(number("pgsnare_connections_refused_total", &[]), Some(1.0));
        assert_eq!(
            number("pgsnare_bytes_total", &[("direction", "from_client")]),
            Some(1000.0)
        );
        assert_eq!(
            number("pgsnare_bytes_total", &[("direction", "from_server")]),
            Some(2500.0)
        );
        assert_eq!(number("pgsnare_events_raised_total", &[]), Some(1.0));
        assert_eq!(
            number("pgsnare_events_total", &[("kind", "inspection_bypassed")]),
            Some(1.0)
        );
        assert_eq!(number("pgsnare_events_dropped_total", &[]), Some(1.0));
        assert_eq!(
            number("pgsnare_panics_total", &[("scope", "session")]),
            Some(1.0)
        );
        assert_eq!(
            number("pgsnare_panics_total", &[("scope", "sink")]),
            Some(1.0)
        );
        assert_eq!(number("pgsnare_queries_total", &[]), Some(1.0));
        assert_eq!(
            number("pgsnare_hits_total", &[("kind", "token")]),
            Some(2.0)
        );
        assert_eq!(
            number("pgsnare_hits_total", &[("kind", "token_exempt")]),
            Some(1.0)
        );
        assert_eq!(number("pgsnare_hits_total", &[("kind", "rule")]), Some(1.0));
        assert_eq!(
            number(
                "pgsnare_token_hits_total",
                &[("token_id", "users-admin-backup"), ("exempt", "false")]
            ),
            Some(2.0)
        );
        assert_eq!(
            number(
                "pgsnare_token_hits_total",
                &[("token_id", "card-test-0002"), ("exempt", "true")]
            ),
            Some(1.0)
        );
        // A token is listed for the kind of session it was hit in, and not
        // for the other.
        assert_eq!(
            number(
                "pgsnare_token_hits_total",
                &[("token_id", "card-test-0002"), ("exempt", "false")]
            ),
            None
        );
        assert_eq!(
            number(
                "pgsnare_rule_hits_total",
                &[("rule_id", "catalog_enumeration")]
            ),
            Some(1.0)
        );
        assert_eq!(
            number("pgsnare_actions_total", &[("action", "alert")]),
            Some(1.0)
        );
        assert_eq!(
            number("pgsnare_actions_total", &[("action", "kill")]),
            Some(1.0)
        );
        assert_eq!(
            number("pgsnare_actions_total", &[("action", "tarpit")]),
            Some(0.0)
        );
        assert_eq!(number("pgsnare_parse_failures_total", &[]), Some(1.0));
        assert_eq!(number("pgsnare_reload_failures_total", &[]), Some(1.0));
    }

    #[test]
    fn every_sink_has_its_queue_and_its_drops_by_reason() {
        let status = Status::new();
        let sinks =
            status.register_sinks(&[("webhook-0".to_owned(), 64), ("stdout-1".to_owned(), 8)]);
        sinks[0].queued();
        sinks[0].queued();
        sinks[0].delivered();
        sinks[0].attempt_failed();
        sinks[0].dropped(DropReason::QueueFull);
        sinks[0].dropped(DropReason::RetriesExhausted);
        sinks[0].dropped(DropReason::RetriesExhausted);
        sinks[1].dropped(DropReason::Rejected);
        sinks[1].dropped(DropReason::Stopping);

        let samples = parse(&render(&status, &Redaction::default()));
        let number = |name: &str, labels: &[(&str, &str)]| value(&samples, name, labels);
        let webhook = [("sink", "webhook-0")];
        assert_eq!(number("pgsnare_sink_queue_depth", &webhook), Some(2.0));
        assert_eq!(number("pgsnare_sink_queue_capacity", &webhook), Some(64.0));
        assert_eq!(
            number("pgsnare_sink_events_delivered_total", &webhook),
            Some(1.0)
        );
        assert_eq!(
            number("pgsnare_sink_delivery_attempts_failed_total", &webhook),
            Some(1.0)
        );
        for (sink, reason, dropped) in [
            ("webhook-0", "queue_full", 1.0),
            ("webhook-0", "rejected", 0.0),
            ("webhook-0", "retries_exhausted", 2.0),
            ("webhook-0", "stopping", 0.0),
            ("stdout-1", "queue_full", 0.0),
            ("stdout-1", "rejected", 1.0),
            ("stdout-1", "retries_exhausted", 0.0),
            ("stdout-1", "stopping", 1.0),
        ] {
            assert_eq!(
                number(
                    "pgsnare_sink_events_dropped_total",
                    &[("sink", sink), ("reason", reason)]
                ),
                Some(dropped),
                "{sink} {reason}"
            );
        }
        assert_eq!(
            number("pgsnare_sink_queue_capacity", &[("sink", "stdout-1")]),
            Some(8.0)
        );
    }

    #[test]
    fn the_histogram_of_added_latency_is_cumulative_and_complete() {
        let status = Status::new();
        for micros in [10, 40, 60, 700, 3_000, 3_000_000] {
            status.latency_added(Duration::from_micros(micros));
        }
        let text = render(&status, &Redaction::default());
        let samples = parse(&text);
        let bucket = |le: &str| {
            value(
                &samples,
                "pgsnare_added_latency_seconds_bucket",
                &[("le", le)],
            )
            .unwrap_or_else(|| panic!("a bucket up to {le}"))
        };
        assert_eq!(bucket("0.00005"), 2.0);
        assert_eq!(bucket("0.0001"), 3.0);
        assert_eq!(bucket("0.00025"), 3.0);
        assert_eq!(bucket("0.001"), 4.0);
        assert_eq!(bucket("0.005"), 5.0);
        assert_eq!(bucket("1"), 5.0);
        assert_eq!(bucket("2.5"), 5.0);
        assert_eq!(bucket("+Inf"), 6.0);
        assert_eq!(
            value(&samples, "pgsnare_added_latency_seconds_count", &[]),
            Some(6.0)
        );
        let sum = value(&samples, "pgsnare_added_latency_seconds_sum", &[]).unwrap();
        assert!((sum - 3.003_81).abs() < 1e-9, "{sum}");

        // The buckets never shrink from one to the next.
        let buckets: Vec<f64> = samples
            .iter()
            .filter(|(name, _, _)| name == "pgsnare_added_latency_seconds_bucket")
            .map(|(_, _, value)| *value)
            .collect();
        assert_eq!(buckets.len(), 16);
        assert!(
            buckets.windows(2).all(|pair| pair[0] <= pair[1]),
            "{buckets:?}"
        );
        assert!(text.contains("# TYPE pgsnare_added_latency_seconds histogram\n"));
    }

    #[test]
    fn a_label_never_breaks_the_format_and_never_holds_a_value() {
        const VALUE: &str = "svc.backup.8f3k2q@mail.example";
        let redaction = Redaction::new(
            Redactor::builder()
                .token("users-admin-backup", [VALUE], false)
                .build()
                .unwrap(),
        );
        let status = Status::new();
        // Names a sink of another build could give itself: one that tries
        // to break out of its label, and one that is a honeytoken value.
        status.register_sinks(&[
            ("evil\"} 1\npgsnare_ready{x=\"".to_owned(), 1),
            (VALUE.to_owned(), 1),
        ]);

        let text = render(&status, &redaction);
        let samples = parse(&text);
        assert!(!text.contains(VALUE), "{text}");
        assert_eq!(
            value(
                &samples,
                "pgsnare_sink_queue_capacity",
                &[("sink", "evil___1_pgsnare_ready_x__")]
            ),
            Some(1.0)
        );
        assert_eq!(
            value(
                &samples,
                "pgsnare_sink_queue_capacity",
                &[("sink", "_redacted_")]
            ),
            Some(1.0)
        );
        // The proxy is not ready, whatever the name of a sink says.
        assert_eq!(value(&samples, "pgsnare_ready", &[]), Some(0.0));
    }

    #[test]
    fn a_text_is_escaped_as_the_format_wants() {
        assert_eq!(escape("plain", true), "plain");
        assert_eq!(escape("a\\b\nc\"d", true), "a\\\\b\\nc\\\"d");
        assert_eq!(escape("a\\b\nc\"d", false), "a\\\\b\\nc\"d");
    }
}
