// SPDX-License-Identifier: Apache-2.0

//! The shared code of the fuzz targets of `pgsnare-core`.
//!
//! There are two targets. `rules` feeds bytes to the SQL parser and the
//! rules, see [`fuzz_rules`]. `session` is described here: it drives the whole logic of a
//! PostgreSQL session the way a runtime does: with bytes from the client
//! and from the server in any order and cut anywhere, with reports, and
//! with a policy that changes on the way.
//!
//! The target does more than wait for a panic. For every input it checks
//! what the session logic promises:
//!
//! - **It never holds more than it may.** What a session keeps of
//!   incomplete messages stays within the limits of the policy.
//! - **It neither loses nor invents a byte.** Once the server has accepted
//!   the login, every byte that goes in comes out on the other side or is
//!   still held, until the session ends.
//! - **A session that has ended stays silent.** After an error or a close
//!   nothing more is produced.
//! - **How the bytes are cut does not matter.** The same streams, fed byte
//!   by byte, produce the same bytes and the same effects.
//!
//! A setting can turn the SQL rules on. The session then holds every
//! statement until its analysis is there, and the target answers late: not
//! before the next thing that is not bytes of the client. So bytes pile up
//! behind a held statement, as they do when the parser is slow, and all of
//! the above must still hold. The answer depends on the statement alone:
//! an analysis, or one of the reasons there is none. The parser itself is
//! not run here; the `rules` target does that.
//!
//! # Inputs
//!
//! The first two bytes of an input choose the setting: whether the listener
//! offers TLS, the failure policy, the limit for a message that is held
//! whole, how the connection to the database turns out, and what the rest
//! of the input means. The rest is one of two things:
//!
//! - **Steps**, each a kind, a length and a payload: bytes from one side, a
//!   report, or a change of policy. This reaches everything, including
//!   what no real peer would send.
//! - **Cuts of a captured session.** The session is one of the captures of
//!   `pgsnare-proto`, built into the target, and the input says how to cut
//!   it, in which order to feed the two sides, and where to damage a byte.
//!   This starts the fuzzer deep inside real sessions.
//!
//! # Running
//!
//! From the root of the repository:
//!
//! ```sh
//! make fuzz FUZZ_CRATE=pgsnare-core FUZZ_SECONDS=60
//! ```

mod rules;

pub use rules::fuzz_rules;

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use pgsnare_core::event::SessionId;
use pgsnare_core::extension::{ProtocolSession, Relay};
use pgsnare_core::policy::{ActionSet, Inspection, OnError, PolicySnapshot};
use pgsnare_core::rules::{
    Analysis, Limits, OnParseFailure, ParseFailure, RuleScope, RuleSet, analyse, on_parser_thread,
};
use pgsnare_core::session::postgres::{MAX_LOGIN_FRAME, Postgres, PostgresSession};
use pgsnare_core::session::{Direction, Effect, Output, Report, SessionOrigin, TlsPolicy};

/// A captured session: what the client sent and what the server sent.
struct Capture {
    client: &'static [u8],
    server: &'static [u8],
}

macro_rules! capture {
    ($dir:literal, $scenario:literal) => {
        Capture {
            client: include_bytes!(concat!(
                "../../../pgsnare-proto/tests/fixtures/",
                $dir,
                "/",
                $scenario,
                ".client.bin"
            )),
            server: include_bytes!(concat!(
                "../../../pgsnare-proto/tests/fixtures/",
                $dir,
                "/",
                $scenario,
                ".server.bin"
            )),
        }
    };
}

/// The captured sessions an input can choose from.
static CAPTURES: [Capture; 7] = [
    capture!("pg18-3.2", "simple"),
    capture!("pg18-3.2", "extended"),
    capture!("pg18-3.2", "copy"),
    capture!("pg18-3.2", "replication"),
    capture!("pg18-3.2", "cancel"),
    capture!("pg17-3.0", "negotiate"),
    capture!("pg15-3.0", "auth-md5"),
];

/// What the runtime answers when a session asks for the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Connect {
    /// The connection is opened, with or without TLS.
    Connected { tls: bool },
    /// The database cannot be reached.
    Unavailable,
    /// Nothing, unless the input holds a report.
    Silent,
}

/// The setting of one run, from the first two bytes of the input.
#[derive(Clone, Copy, Debug)]
struct Setting {
    tls: TlsPolicy,
    on_error: OnError,
    max_buffered_frame: usize,
    connect: Connect,
    /// The captured session the input cuts. `None` when it holds steps.
    capture: Option<usize>,
    /// Whether the policy has SQL rules, so that statements are held.
    rules: bool,
}

impl Setting {
    fn new(first: u8, second: u8) -> Self {
        let tls = match first & 0b11 {
            0 | 3 => TlsPolicy::Disabled,
            1 => TlsPolicy::Optional,
            _ => TlsPolicy::Required,
        };
        let on_error = if first & 0b100 == 0 {
            OnError::FailClosed
        } else {
            OnError::FailOpen
        };
        let connect = match (first >> 3) & 0b11 {
            0 => Connect::Connected { tls: false },
            1 => Connect::Connected { tls: true },
            2 => Connect::Unavailable,
            _ => Connect::Silent,
        };
        let capture = match usize::from(first >> 5) {
            0 => None,
            index => Some((index - 1) % CAPTURES.len()),
        };
        Self {
            tls,
            on_error,
            max_buffered_frame: buffered_limit(second),
            connect,
            capture,
            rules: second & 0x80 != 0,
        }
    }

    fn policy(&self) -> PolicySnapshot {
        policy(self.on_error, self.max_buffered_frame, self.rules)
    }
}

/// A limit for messages that are held whole: 1 KiB to 1 MiB.
fn buffered_limit(choice: u8) -> usize {
    1024 << (choice % 11)
}

fn policy(on_error: OnError, max_buffered_frame: usize, rules: bool) -> PolicySnapshot {
    let mut builder =
        PolicySnapshot::builder().inspection(Inspection::new(on_error, max_buffered_frame));
    if rules {
        // A statement without an analysis goes on, so that no byte is
        // held back for good and the balance of bytes can be checked.
        let rules = RuleSet::builder()
            .on_parse_failure(OnParseFailure::Allow)
            .functions(
                &["pg_sleep".to_owned()],
                ActionSet::ALERT,
                RuleScope::default(),
            )
            .expect("a valid rule")
            .build();
        builder = builder.rules(rules);
    }
    builder
        .build()
        .expect("the limits are within the accepted range")
}

/// The most bytes of a client a session keeps behind a held statement.
const MAX_BEHIND: usize = 1024 * 1024;

/// A stand-in for the hash function of the runtime. No event is raised
/// here, so it is never asked.
fn digest(_: &[u8]) -> [u8; 32] {
    [0; 32]
}

/// The answer to a request for the analysis of `text`. It depends on the
/// text alone, so that two runs over the same streams get the same.
fn outcome(text: &[u8]) -> Result<Arc<Analysis>, ParseFailure> {
    static ANALYSIS: OnceLock<Option<Arc<Analysis>>> = OnceLock::new();
    match text.len() % 5 {
        0 => Err(ParseFailure::Rejected),
        1 => Err(ParseFailure::Busy),
        2 => Err(ParseFailure::TimedOut),
        _ => ANALYSIS
            .get_or_init(|| {
                on_parser_thread(|thread| analyse(b"SELECT 1", &Limits::default(), thread))
                    .ok()
                    .and_then(Result::ok)
                    .map(Arc::new)
            })
            .clone()
            .ok_or(ParseFailure::Unreadable),
    }
}

/// One thing a runtime does to a session.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Bytes(Direction, Vec<u8>),
    Report(Report),
    Policy(OnError, usize),
}

/// Reads steps from an input: a kind, two bytes that are a length or an
/// argument, and a payload for the kinds that have one.
fn steps(mut input: &[u8]) -> Vec<Step> {
    let mut steps = Vec::new();
    while let Some((&[kind, high, low], rest)) = input.split_first_chunk::<3>() {
        input = rest;
        let argument = usize::from(u16::from_be_bytes([high, low]));
        match kind % 8 {
            kind @ (0 | 1) => {
                let (payload, rest) = input.split_at(argument.min(input.len()));
                input = rest;
                let from = if kind == 0 {
                    Direction::FromClient
                } else {
                    Direction::FromServer
                };
                steps.push(Step::Bytes(from, payload.to_vec()));
            }
            2 => steps.push(Step::Report(Report::BackendConnected { tls: low & 1 == 1 })),
            3 => steps.push(Step::Report(Report::ClientTlsEstablished)),
            4 => steps.push(Step::Report(Report::BackendUnavailable)),
            5 => steps.push(Step::Report(Report::ShuttingDown)),
            _ => {
                let on_error = if high & 1 == 0 {
                    OnError::FailClosed
                } else {
                    OnError::FailOpen
                };
                steps.push(Step::Policy(on_error, buffered_limit(low)));
            }
        }
    }
    steps
}

/// Cuts a captured session as an input says.
///
/// The startup message goes first and whole, so that the session gets to
/// the login. After that every two bytes of the input take one piece from
/// one of the two streams: the first byte says which stream and whether a
/// byte of the piece is damaged, and the second how long the piece is.
/// What is left when the input ends is fed in order.
fn cuts(capture: &Capture, mut input: &[u8]) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut client = capture.client;
    let mut server = capture.server;

    let startup_len = client
        .first_chunk::<4>()
        .map_or(0, |length| u32::from_be_bytes(*length) as usize)
        .min(client.len());
    let (startup, rest) = client.split_at(startup_len);
    client = rest;
    steps.push(Step::Bytes(Direction::FromClient, startup.to_vec()));

    while let Some((&[choice, length], rest)) = input.split_first_chunk::<2>() {
        input = rest;
        let (stream, from) = if choice & 1 == 0 && !client.is_empty() || server.is_empty() {
            (&mut client, Direction::FromClient)
        } else {
            (&mut server, Direction::FromServer)
        };
        if stream.is_empty() {
            break;
        }
        let length = (usize::from(length) + 1).min(stream.len());
        let (piece, later) = stream.split_at(length);
        *stream = later;
        let mut piece = piece.to_vec();
        // One input in four damages a byte, and one in sixty-four ends the
        // capture there and goes on with whatever the input holds.
        if choice & 0b110 == 0b110 {
            let at = usize::from(choice >> 3) % piece.len();
            piece[at] ^= 1 << (choice >> 5);
        }
        steps.push(Step::Bytes(from, piece));
        if choice >> 2 == 0b11_1111 {
            steps.extend(self::steps(input));
            return steps;
        }
    }
    for piece in server.chunks(4096) {
        steps.push(Step::Bytes(Direction::FromServer, piece.to_vec()));
    }
    for piece in client.chunks(4096) {
        steps.push(Step::Bytes(Direction::FromClient, piece.to_vec()));
    }
    steps
}

/// Everything a run produced.
#[derive(Debug, Default, PartialEq)]
struct Record {
    to_client: Vec<u8>,
    to_server: Vec<u8>,
    effects: Vec<Effect>,
    /// The reason the session gave when it could not go on.
    error: Option<&'static str>,
}

struct Run {
    session: PostgresSession,
    setting: Setting,
    policy: PolicySnapshot,
    record: Record,
    /// The largest limit for held messages any policy of this run had.
    largest_limit: usize,
    /// Since the server accepted the login: how many bytes went in, how
    /// many came out, and how many were held at that moment.
    balance: Option<Balance>,
    /// Whether the session asked for a TLS handshake. What it does from
    /// there on depends on where the runtime stopped reading, so it is not
    /// compared between two ways of cutting the input.
    asked_for_tls: bool,
    /// The answer the session waits for: the `id` of its request and the
    /// outcome.
    asked: Option<(u64, Result<Arc<Analysis>, ParseFailure>)>,
}

#[derive(Clone, Copy)]
struct Balance {
    fed: usize,
    produced: usize,
    held_at_start: usize,
}

/// The most a session may keep before the login: a startup packet and the
/// largest message of a login.
const MAX_BEFORE_LOGIN: usize = 10_004 + MAX_LOGIN_FRAME;

impl Run {
    fn new(setting: Setting) -> Self {
        let origin = SessionOrigin::new(
            SessionId::from_u128(1),
            "192.0.2.10"
                .parse::<IpAddr>()
                .expect("a documentation address"),
            49_152,
            false,
        )
        .with_client_tls_policy(setting.tls);
        let module = if setting.rules {
            Postgres::scanning(Arc::new(digest))
        } else {
            Postgres::new()
        };
        Self {
            session: module.session(origin, Arc::new(Relay)),
            setting,
            policy: setting.policy(),
            record: Record::default(),
            largest_limit: setting.max_buffered_frame,
            balance: None,
            asked_for_tls: false,
            asked: None,
        }
    }

    /// Calls into the session and checks everything that must hold after
    /// every call. Returns the reports the runtime would answer with.
    fn call(
        &mut self,
        fed: usize,
        call: impl FnOnce(&mut Self, &mut Output) -> Result<(), &'static str>,
    ) -> Vec<Report> {
        let ended_before = self.session.is_closed();
        let established_before = self.session.is_established();
        let mut out = Output::new();
        let result = call(self, &mut out);

        if ended_before {
            assert!(
                result.is_ok() && out.is_empty(),
                "a session that had ended produced something"
            );
        }
        if let Err(reason) = result {
            assert!(
                self.session.is_closed(),
                "a session that failed is still open: {reason}"
            );
            if self.record.error.is_none() {
                self.record.error = Some(reason);
            }
        }

        // Never more held than a startup packet, a message of the login,
        // and one message within the limit for each direction. With the
        // rules, one statement more that waits for its analysis, and what
        // the client may send behind it.
        let largest = self.largest_limit.max(MAX_LOGIN_FRAME);
        let mut most = MAX_BEFORE_LOGIN + 2 * largest;
        if self.setting.rules {
            most += largest + MAX_BEHIND;
        }
        let held = self.session.buffered_bytes();
        if !self.setting.rules {
            assert!(
                !self.session.holds_client(),
                "a message is held without rules"
            );
        }
        assert!(held <= most, "the session holds {held} bytes");

        // Once established, and for as long as the session lasts, every
        // byte that goes in comes out or is still held.
        let produced = out.to_client.len() + out.to_server.len();
        if self.session.is_established() {
            match &mut self.balance {
                Some(balance) if established_before => {
                    balance.fed += fed;
                    balance.produced += produced;
                    assert_eq!(
                        balance.fed + balance.held_at_start,
                        balance.produced + held,
                        "bytes were lost or invented"
                    );
                }
                _ => {
                    self.balance = Some(Balance {
                        fed: 0,
                        produced: 0,
                        held_at_start: held,
                    });
                }
            }
        }

        let mut reports = Vec::new();
        for effect in &out.effects {
            match effect {
                Effect::AcceptTls { .. } => {
                    self.asked_for_tls = true;
                    reports.push(Report::ClientTlsEstablished);
                }
                Effect::ConnectBackend => match self.setting.connect {
                    Connect::Connected { tls } => reports.push(Report::BackendConnected { tls }),
                    Connect::Unavailable => reports.push(Report::BackendUnavailable),
                    Connect::Silent => {}
                },
                Effect::Analyse { id, text, .. } => {
                    assert!(
                        self.setting.rules,
                        "an analysis was asked for without rules"
                    );
                    assert!(
                        self.session.holds_client(),
                        "an analysis was asked for and nothing is held"
                    );
                    assert!(self.asked.is_none(), "two statements are held at once");
                    self.asked = Some((*id, outcome(text.as_bytes())));
                }
                _ => {}
            }
        }
        if self.session.holds_client() {
            assert!(
                self.asked.is_some(),
                "a statement is held and nothing was asked"
            );
        }
        self.record.to_client.append(&mut out.to_client);
        self.record.to_server.append(&mut out.to_server);
        self.record.effects.append(&mut out.effects);
        reports
    }

    fn bytes(&mut self, from: Direction, input: &[u8]) {
        let reports = self.call(input.len(), |run, out| {
            run.session
                .on_bytes(from, input, &run.policy, out)
                .map_err(|error| error.reason())
        });
        self.answer(reports);
    }

    fn report(&mut self, report: Report) {
        let reports = self.call(0, |run, out| {
            run.session
                .on_report(report, &run.policy, out)
                .map_err(|error| error.reason())
        });
        self.answer(reports);
    }

    /// Reports back what the session asked for, as a runtime does.
    fn answer(&mut self, reports: Vec<Report>) {
        for report in reports {
            self.report(report);
        }
    }

    /// Gives the session the answers it waits for, until it waits for
    /// none: letting one statement go can hold the next.
    fn settle(&mut self) {
        while let Some((id, outcome)) = self.asked.take() {
            self.report(Report::Analysed { id, outcome });
        }
    }

    fn step(&mut self, step: &Step, byte_by_byte: bool) {
        // The answer comes late: bytes of the client pile up before it,
        // and anything else finds the statement decided.
        if !matches!(step, Step::Bytes(Direction::FromClient, _)) {
            self.settle();
        }
        match step {
            Step::Bytes(from, bytes) if byte_by_byte => {
                for byte in bytes {
                    self.bytes(*from, std::slice::from_ref(byte));
                }
            }
            Step::Bytes(from, bytes) => self.bytes(*from, bytes),
            Step::Report(report) => self.report(report.clone()),
            Step::Policy(on_error, max_buffered_frame) => {
                self.policy = policy(*on_error, *max_buffered_frame, self.setting.rules);
                self.largest_limit = self.largest_limit.max(*max_buffered_frame);
            }
        }
    }
}

fn play(setting: Setting, steps: &[Step], byte_by_byte: bool) -> Run {
    let mut run = Run::new(setting);
    for step in steps {
        run.step(step, byte_by_byte);
    }
    run.settle();
    run
}

/// Fuzzes the session logic with one input.
pub fn fuzz_session(data: &[u8]) {
    let Some((&[first, second], rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let setting = Setting::new(first, second);
    let steps = match setting.capture {
        Some(index) => cuts(&CAPTURES[index], rest),
        None => steps(rest),
    };

    let as_given = play(setting, &steps, false);
    let byte_by_byte = play(setting, &steps, true);

    // A request for TLS is answered by what the runtime has read at that
    // moment, and a session that was closed for sending too much at once
    // was closed for how its bytes were cut. Everything else must not
    // depend on the cut.
    let cut_matters = as_given.asked_for_tls
        || byte_by_byte.asked_for_tls
        || [as_given.record.error, byte_by_byte.record.error]
            .iter()
            .flatten()
            .any(|reason| reason.contains("follow the request"));
    if !cut_matters {
        assert!(
            as_given.record == byte_by_byte.record,
            "the result depends on how the input was cut: {:?} and {:?}",
            as_given.record.error,
            byte_by_byte.record.error,
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_session_seed_runs_with_and_without_rules() {
        let seeds = concat!(env!("CARGO_MANIFEST_DIR"), "/seeds/session");
        let mut count = 0;
        for entry in std::fs::read_dir(seeds).unwrap() {
            let mut data = std::fs::read(entry.unwrap().path()).unwrap();
            super::fuzz_session(&data);
            if let Some(second) = data.get_mut(1) {
                *second ^= 0x80;
            }
            super::fuzz_session(&data);
            count += 1;
        }
        assert!(count >= 25, "{count} seeds");
    }

    #[test]
    fn a_seed_with_rules_holds_statements() {
        for name in ["rules-simple", "rules-extended", "rules-copy-in-turns"] {
            let path = format!("{}/seeds/session/{name}", env!("CARGO_MANIFEST_DIR"));
            let data = std::fs::read(path).unwrap();
            let setting = super::Setting::new(data[0], data[1]);
            assert!(setting.rules, "{name}");
            let steps = super::cuts(&super::CAPTURES[setting.capture.unwrap()], &data[2..]);
            let run = super::play(setting, &steps, false);
            let asked = run
                .record
                .effects
                .iter()
                .filter(|effect| matches!(effect, super::Effect::Analyse { .. }))
                .count();
            assert!(asked > 0, "{name}: no statement was held");
            assert_eq!(run.record.error, None, "{name}");
        }
    }
}
