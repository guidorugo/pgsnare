// SPDX-License-Identifier: Apache-2.0

//! The log: one JSON object for each line, on standard error.
//!
//! ```text
//! {"timestamp":"2026-11-11T17:06:31.123456Z","level":"info","message":"listening","listener":"main","address":"0.0.0.0:5432"}
//! ```
//!
//! | Field | Content |
//! |---|---|
//! | `timestamp` | When the line was written, in UTC with microseconds, in the form events use |
//! | `level` | `error`, `warn`, `info`, `debug` or `trace` |
//! | `message` | What happened, in fixed words |
//! | Every other field | What it happened to: a number, a truth value or a text |
//!
//! Standard error carries the log and nothing else. Events go to the
//! sinks, and the `stdout` sink writes to standard output.
//!
//! # What a line is made of
//!
//! The message and the names of the fields are fixed texts of the code. The
//! values are counts, addresses of sockets, and names and paths from the
//! configuration. Nothing a client or a database sent is written to the
//! log, and neither is a secret: that is a rule for every line of code that
//! logs, and it is what keeps the log clean.
//!
//! The format adds two things that do not depend on that rule being kept.
//!
//! - **Every text passes through the redaction layer.** A honeytoken value,
//!   in any form the matcher finds it in, is replaced before the line is
//!   written, whatever the code that logged it meant to do.
//! - **Every line is written by the JSON encoder.** No value is escaped by
//!   hand. A text with a line break or a quotation mark in it, such as a
//!   path from the configuration, is still one field of one line.
//!
//! # A log never holds anything up
//!
//! A line is handed to one writer thread through a queue of
//! [`MAX_QUEUED_LINES`] lines and [`MAX_QUEUED_BYTES`] bytes, and the code
//! that logged it goes on at once. When standard error does not take what
//! is written, as when it is a pipe nobody reads, the queue fills up and
//! further lines are dropped and counted ([`dropped_lines`]). Once the
//! writer can write again it says how many were lost, in a line of its
//! own.
//!
//! A text is cut at [`MAX_TEXT_BYTES`] and a line has at most
//! [`MAX_FIELDS`] fields, so that the length of a line has a bound whatever
//! is logged.

use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
#[cfg(test)]
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use pgsnare_core::event::{Timestamp, text_from_wire};
use serde::ser::{SerializeMap, Serializer};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

use crate::redact::{Redaction, Redactor};

/// The most bytes of one text of a line. A longer one is cut and marked.
pub const MAX_TEXT_BYTES: usize = 4096;

/// The most fields of a line, apart from its time, its level and its
/// message. The logging library allows a line of code no more fields than
/// this, so the bound is never reached today: it is here so that the length
/// of a line does not rest on a limit of the library.
pub const MAX_FIELDS: usize = 32;

/// Makes this format the log of the process: lines of the levels `info`,
/// `warn` and `error` go to standard error.
///
/// `redaction` is what every text of a line passes through. It is a
/// handle, so the redactor can be put in force after the log is installed:
/// the first lines of a process are written before it has read the tokens
/// it must not show.
///
/// Returns whether the log was installed. A process has one log, and a
/// second call leaves the first in place.
pub fn install(redaction: Redaction) -> bool {
    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(JsonLog::new(Destination::standard_error(), redaction))
        .try_init()
        .is_ok()
}

/// The most lines waiting for the writer.
pub const MAX_QUEUED_LINES: usize = 1024;

/// The most bytes of the lines waiting for the writer.
pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;

/// Lines dropped because the writer was behind, since the process started.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// How many lines were dropped because standard error did not take them
/// fast enough.
#[must_use]
pub fn dropped_lines() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// The bytes waiting for the writer of standard error, once it runs.
static QUEUED: std::sync::OnceLock<Arc<AtomicUsize>> = std::sync::OnceLock::new();

/// Waits until the writer has written every line logged so far, but no
/// longer than `limit`.
pub fn flush(limit: std::time::Duration) {
    let Some(queued) = QUEUED.get() else {
        return;
    };
    let started = std::time::Instant::now();
    while queued.load(Ordering::Relaxed) > 0 && started.elapsed() < limit {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// The sending end of the queue of lines. Pushing never waits.
#[derive(Clone)]
struct Queue {
    lines: SyncSender<Vec<u8>>,
    /// The bytes of the lines in the queue.
    bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    dropped: &'static AtomicU64,
}

impl Queue {
    fn new(
        max_lines: usize,
        max_bytes: usize,
        dropped: &'static AtomicU64,
    ) -> (Self, Receiver<Vec<u8>>) {
        let (lines, receiver) = sync_channel(max_lines);
        let queue = Self {
            lines,
            bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes,
            dropped,
        };
        (queue, receiver)
    }

    fn push(&self, line: &[u8]) {
        let before = self.bytes.fetch_add(line.len(), Ordering::Relaxed);
        let fits = before.saturating_add(line.len()) <= self.max_bytes;
        if !fits || self.lines.try_send(line.to_vec()).is_err() {
            self.bytes.fetch_sub(line.len(), Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Writes the lines of the queue as they come, until every sender is gone,
/// and says when lines were dropped.
fn write_lines(
    lines: &Receiver<Vec<u8>>,
    bytes: &AtomicUsize,
    dropped: &AtomicU64,
    out: &mut impl Write,
) {
    let mut reported = 0;
    while let Ok(line) = lines.recv() {
        // A log that cannot be written to has nobody left to tell.
        let _ = out.write_all(&line);
        bytes.fetch_sub(line.len(), Ordering::Relaxed);
        let total = dropped.load(Ordering::Relaxed);
        if total > reported {
            tracing::warn!(
                dropped = total - reported,
                "log lines were dropped: standard error did not take them fast enough"
            );
            reported = total;
        }
    }
}

/// Where lines are written.
#[derive(Clone)]
enum Destination {
    /// The queue of the thread that writes to standard error.
    Queue(Queue),
    /// Standard error itself, written to by the thread that logs, when
    /// the writer thread could not be started.
    StandardError,
    /// Kept in memory, for a test to read.
    #[cfg(test)]
    Memory(Arc<Mutex<Vec<u8>>>),
}

impl Destination {
    /// Standard error, through a writer thread.
    fn standard_error() -> Self {
        let (queue, lines) = Queue::new(MAX_QUEUED_LINES, MAX_QUEUED_BYTES, &DROPPED);
        let bytes = Arc::clone(&queue.bytes);
        let started = std::thread::Builder::new()
            .name("pgsnare-log".to_owned())
            .spawn(move || write_lines(&lines, &bytes, &DROPPED, &mut std::io::stderr()));
        if started.is_ok() {
            let _ = QUEUED.set(Arc::clone(&queue.bytes));
            Self::Queue(queue)
        } else {
            Self::StandardError
        }
    }

    fn write(&self, line: &[u8]) {
        match self {
            Self::Queue(queue) => queue.push(line),
            // One call for a whole line, with the stream locked, so that
            // lines of different threads do not mix. A log that cannot be
            // written to has nobody left to tell.
            Self::StandardError => {
                let _ = std::io::stderr().lock().write_all(line);
            }
            #[cfg(test)]
            Self::Memory(lines) => lines
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(line),
        }
    }
}

/// The layer that writes each event of the code as one line.
struct JsonLog {
    destination: Destination,
    redaction: Redaction,
}

impl JsonLog {
    const fn new(destination: Destination, redaction: Redaction) -> Self {
        Self {
            destination,
            redaction,
        }
    }

    /// The line for an event, with its line break.
    fn line(&self, event: &Event<'_>) -> Option<Vec<u8>> {
        let mut fields = Fields {
            redactor: self.redaction.current(),
            message: None,
            values: Vec::new(),
        };
        event.record(&mut fields);

        let mut line = Vec::with_capacity(256);
        let mut serializer = serde_json::Serializer::new(&mut line);
        let mut object = serializer.serialize_map(None).ok()?;
        object.serialize_entry("timestamp", &now()).ok()?;
        object
            .serialize_entry("level", level_name(*event.metadata().level()))
            .ok()?;
        object
            .serialize_entry("message", fields.message.as_deref().unwrap_or(""))
            .ok()?;
        for (name, value) in &fields.values {
            match *name {
                // A field of the code must not take the place of one of
                // the three above.
                "timestamp" | "level" | "message" => {
                    object
                        .serialize_entry(&format!("field.{name}"), value)
                        .ok()?;
                }
                name => object.serialize_entry(name, value).ok()?,
            }
        }
        object.end().ok()?;
        line.push(b'\n');
        Some(line)
    }
}

impl<S: Subscriber> Layer<S> for JsonLog {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        if let Some(line) = self.line(event) {
            self.destination.write(&line);
        }
    }
}

const fn level_name(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

/// The time, for a line. A clock before 1970 or after 9999 gives the
/// nearest end of the range.
fn now() -> Timestamp {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => {
            Timestamp::from_unix(since.as_secs(), since.subsec_nanos()).unwrap_or(Timestamp::MAX)
        }
        Err(_) => Timestamp::UNIX_EPOCH,
    }
}

/// A value of a line.
enum Value {
    Text(String),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Truth(bool),
}

impl serde::Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(text) => serializer.serialize_str(text),
            Self::Unsigned(number) => serializer.serialize_u64(*number),
            Self::Signed(number) => serializer.serialize_i64(*number),
            // What JSON has no number for is written as text.
            Self::Float(number) if number.is_finite() => serializer.serialize_f64(*number),
            Self::Float(number) => serializer.collect_str(number),
            Self::Truth(truth) => serializer.serialize_bool(*truth),
        }
    }
}

/// Collects the fields of one event of the code.
struct Fields {
    redactor: Arc<Redactor>,
    message: Option<String>,
    values: Vec<(&'static str, Value)>,
}

impl Fields {
    /// A text as it may be written: without what must not be shown, and
    /// not longer than a text of a line may be.
    fn text(&self, text: &str) -> String {
        let clean = self.redactor.text(text);
        if clean.len() <= MAX_TEXT_BYTES {
            return clean.into_owned();
        }
        text_from_wire(clean.as_bytes(), MAX_TEXT_BYTES)
    }

    fn keep(&mut self, field: &Field, value: Value) {
        if self.values.len() < MAX_FIELDS {
            self.values.push((field.name(), value));
        }
    }

    fn keep_text(&mut self, field: &Field, text: &str) {
        let text = self.text(text);
        if field.name() == "message" {
            self.message = Some(text);
        } else {
            self.keep(field, Value::Text(text));
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.keep_text(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.keep_text(field, &format!("{value:?}"));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.keep_text(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.keep(field, Value::Unsigned(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.keep(field, Value::Signed(value));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        match u64::try_from(value) {
            Ok(value) => self.keep(field, Value::Unsigned(value)),
            Err(_) => self.keep(field, Value::Text(value.to_string())),
        }
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        match i64::try_from(value) {
            Ok(value) => self.keep(field, Value::Signed(value)),
            Err(_) => self.keep(field, Value::Text(value.to_string())),
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.keep(field, Value::Float(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.keep(field, Value::Truth(value));
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        // Bytes are what traffic and keys are made of. A line says how
        // many there were, and never which.
        self.keep(field, Value::Text(format!("{} bytes", value.len())));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as Json, json};

    use super::*;

    const VALUE: &str = "svc.backup.8f3k2q@mail.example";

    #[test]
    fn a_log_nobody_reads_drops_lines_and_never_waits() {
        static LOST: AtomicU64 = AtomicU64::new(0);
        let (queue, lines) = Queue::new(2, MAX_QUEUED_BYTES, &LOST);
        let (done, finished) = std::sync::mpsc::channel();
        // Nobody takes the lines from `lines` while the thread logs.
        std::thread::spawn(move || {
            for _ in 0..10 {
                queue.push(b"{\"message\":\"a line\"}\n");
            }
            let _ = done.send(());
        });
        finished
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("logging does not wait for the reader");
        assert_eq!(LOST.load(Ordering::Relaxed), 8);
        drop(lines);
    }

    #[test]
    fn the_queue_of_the_log_holds_a_bounded_number_of_bytes() {
        static LOST: AtomicU64 = AtomicU64::new(0);
        let (queue, lines) = Queue::new(100, 10, &LOST);
        queue.push(b"0123456");
        queue.push(b"0123456");
        assert_eq!(LOST.load(Ordering::Relaxed), 1);
        let bytes = Arc::clone(&queue.bytes);
        drop(queue);
        let mut out = Vec::new();
        write_lines(&lines, &bytes, &LOST, &mut out);
        assert_eq!(out, b"0123456");
        assert_eq!(bytes.load(Ordering::Relaxed), 0);
    }

    /// Runs `log` with this format as the log of the thread, and returns
    /// the lines it wrote.
    fn lines_of(redaction: Redaction, log: impl FnOnce()) -> Vec<String> {
        let written = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(JsonLog::new(
                Destination::Memory(Arc::clone(&written)),
                redaction,
            ));
        tracing::subscriber::with_default(subscriber, log);
        let bytes = written.lock().unwrap().clone();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.is_empty() || text.ends_with('\n'),
            "every line is complete"
        );
        text.lines().map(str::to_owned).collect()
    }

    fn one_line(log: impl FnOnce()) -> Json {
        let lines = lines_of(Redaction::default(), log);
        assert_eq!(lines.len(), 1, "{lines:?}");
        serde_json::from_str(&lines[0]).unwrap()
    }

    #[test]
    fn a_line_is_one_json_object_with_the_time_the_level_and_the_message_first() {
        let before = now();
        let lines = lines_of(Redaction::default(), || {
            tracing::info!(listener = "main", address = %"0.0.0.0:5432", max_connections = 1000, "listening");
        });
        let after = now();
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert!(line.starts_with("{\"timestamp\":\""), "{line}");
        assert!(
            line.ends_with(
                "Z\",\"level\":\"info\",\"message\":\"listening\",\"listener\":\"main\",\
                 \"address\":\"0.0.0.0:5432\",\"max_connections\":1000}"
            ),
            "{line}"
        );

        let object: Json = serde_json::from_str(line).unwrap();
        let written: Timestamp = serde_json::from_value(object["timestamp"].clone()).unwrap();
        assert!(written >= before && written <= after);
        assert_eq!(object["level"], "info");
        assert_eq!(object["message"], "listening");
        assert_eq!(object.as_object().unwrap().len(), 6);
    }

    #[test]
    fn every_level_has_its_name_and_the_quiet_ones_are_left_out() {
        let lines = lines_of(Redaction::default(), || {
            tracing::error!("an error");
            tracing::warn!("a warning");
            tracing::info!("a piece of news");
            tracing::debug!("a detail");
            tracing::trace!("a trace");
        });
        let levels: Vec<String> = lines
            .iter()
            .map(|line| {
                let object: Json = serde_json::from_str(line).unwrap();
                object["level"].as_str().unwrap().to_owned()
            })
            .collect();
        assert_eq!(levels, ["error", "warn", "info"]);
        assert_eq!(level_name(Level::DEBUG), "debug");
        assert_eq!(level_name(Level::TRACE), "trace");
    }

    #[test]
    fn a_value_keeps_its_kind() {
        let error = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let object = one_line(|| {
            tracing::warn!(
                count = 3u64,
                change = -4i64,
                ratio = 0.5f64,
                nothing = f64::NAN,
                ready = true,
                large = u128::MAX,
                small = 7u128,
                name = "main",
                shown = %"as it prints",
                debugged = ?Some("in detail"),
                failure = &error as &dyn std::error::Error,
                "kinds"
            );
        });
        assert_eq!(object["count"], json!(3));
        assert_eq!(object["change"], json!(-4));
        assert_eq!(object["ratio"], json!(0.5));
        assert_eq!(object["nothing"], json!("NaN"));
        assert_eq!(object["ready"], json!(true));
        assert_eq!(object["large"], json!(u128::MAX.to_string()));
        assert_eq!(object["small"], json!(7));
        assert_eq!(object["name"], json!("main"));
        assert_eq!(object["shown"], json!("as it prints"));
        assert_eq!(object["debugged"], json!("Some(\"in detail\")"));
        assert_eq!(object["failure"], json!("connection refused"));
    }

    #[test]
    fn a_text_with_a_line_break_or_a_quote_is_still_one_field_of_one_line() {
        let path =
            "/etc/pgsnare/odd\n{\"level\":\"error\",\"message\":\"forged\"}\r\n\"name\".yaml";
        let lines = lines_of(Redaction::default(), || {
            tracing::warn!(file = %path, "a file that holds secrets is not protected");
        });
        // One line went in, and one came out.
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(!lines[0].contains('\r'));
        let object: Json = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(object["file"], path);
        assert_eq!(object["level"], "warn");
        assert_eq!(
            object["message"],
            "a file that holds secrets is not protected"
        );
    }

    #[test]
    fn a_honeytoken_value_is_removed_from_every_text_of_a_line() {
        let redaction = Redaction::default();
        let log = || {
            tracing::warn!(
                user = VALUE,
                shown = %format_args!("user {VALUE} logged in"),
                debugged = ?VALUE,
                hex = "7376632e6261636b75702e3866336b3271406d61696c2e6578616d706c65",
                "a line that should never have been written: {VALUE}"
            );
        };

        // Without a redactor in force the value is there: this is what the
        // next lines are measured against.
        let unprotected = lines_of(redaction.clone(), log);
        assert_eq!(unprotected[0].matches(VALUE).count(), 4);

        // The redactor is put in force after the log was set up, as it is
        // when the process starts.
        redaction.replace(
            Redactor::builder()
                .token("users-admin-backup", [VALUE], false)
                .build()
                .unwrap(),
        );
        let lines = lines_of(redaction, log);
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains("svc.backup"), "{}", lines[0]);
        assert!(!lines[0].contains("7376632e"), "{}", lines[0]);
        let object: Json = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(object["user"], "[redacted]");
        assert_eq!(object["shown"], "user [redacted] logged in");
        assert_eq!(object["debugged"], "\"[redacted]\"");
        assert_eq!(object["hex"], "[redacted]");
        assert_eq!(
            object["message"],
            "a line that should never have been written: [redacted]"
        );
    }

    #[test]
    fn bytes_are_counted_and_not_shown() {
        let object = one_line(|| {
            tracing::info!(payload = &b"\x00secret-bytes"[..], "bytes");
        });
        assert_eq!(object["payload"], "13 bytes");
    }

    #[test]
    fn a_long_text_is_cut() {
        let long = "x".repeat(3 * MAX_TEXT_BYTES);
        let object = one_line(|| {
            tracing::info!(long = %long, "cut");
        });
        let text = object["long"].as_str().unwrap();
        assert!(text.len() <= MAX_TEXT_BYTES + 4, "{}", text.len());
        assert!(text.ends_with('\u{2026}'));

        // A text of exactly the largest size is left as it is.
        let fits = "x".repeat(MAX_TEXT_BYTES);
        let object = one_line(|| {
            tracing::info!(fits = %fits, "whole");
        });
        assert_eq!(object["fits"].as_str().unwrap().len(), MAX_TEXT_BYTES);
    }

    #[test]
    fn a_field_cannot_take_the_place_of_the_time_the_level_or_the_message() {
        let lines = lines_of(Redaction::default(), || {
            tracing::info!(timestamp = "never", level = "panic", "the real message");
        });
        let object: Json = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(object["level"], "info");
        assert_eq!(object["message"], "the real message");
        assert_ne!(object["timestamp"], "never");
        assert_eq!(object["field.timestamp"], "never");
        assert_eq!(object["field.level"], "panic");
        // No name is there twice.
        assert_eq!(lines[0].matches("\"level\":").count(), 1);
        assert_eq!(lines[0].matches("\"timestamp\":").count(), 1);
    }

    #[test]
    fn a_line_without_a_message_has_an_empty_one() {
        let object = one_line(|| {
            tracing::info!(listener = "main");
        });
        assert_eq!(object["message"], "");
        assert_eq!(object["listener"], "main");
    }
}
