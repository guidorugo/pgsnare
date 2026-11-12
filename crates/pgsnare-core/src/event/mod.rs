// SPDX-License-Identifier: Apache-2.0

//! The event schema.
//!
//! An [`Event`] is what pgsnare reports when something fires: a honeytoken
//! hit, a rule hit, a statement that could not be parsed, activity in a
//! flagged session, or a session that inspection had to give up on. Sinks
//! deliver events as JSON objects.
//!
//! # Two stages
//!
//! The session logic has no clock, no source of randomness and no knowledge
//! of the instance it runs in. It reports an [`EventBody`]: everything it
//! saw. The runtime then *seals* the body into an [`Event`] by adding the
//! identifier, the timestamp and the instance labels.
//!
//! # Versioning
//!
//! Every event carries [`SCHEMA_VERSION`]. Adding a field or a new value to
//! one of the enumerations does not change the version, so consumers must
//! ignore fields and values they do not know. Removing or renaming a field,
//! or changing what one means, does.
//!
//! Every field is always present. A field that does not apply is `null`.
//!
//! # What never appears in an event
//!
//! Honeytoken values, passwords and key material. An event names a token by
//! its id only. The text fields that come from the network are listed by
//! [`EventBody::for_each_text_mut`], which is how the runtime redacts every
//! one of them in a single place before an event leaves the process.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::policy::{ActionSet, QueryRedaction, RuleId, TokenId};
use crate::session::{Direction, SessionOrigin};

mod id;
mod text;
mod timestamp;

pub use id::{EventId, ParseIdError, SessionId};
pub use text::{MAX_NAME_BYTES, TRUNCATION_MARK, text_from_wire};
pub use timestamp::{ParseTimestampError, Timestamp};

/// The version of the event schema this crate writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Labels that identify the pgsnare instance, such as a pod name.
///
/// They are sorted by name, so an event always serialises the same way.
pub type Labels = BTreeMap<String, String>;

/// What an event reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// A honeytoken value appeared in a message.
    TokenHit,
    /// A statement matched an SQL rule.
    RuleHit,
    /// A statement could not be parsed, so no rule could judge it.
    ParseFailure,
    /// A session that fired earlier ran another statement.
    SessionActivity,
    /// Inspection failed and the session continues uninspected, because the
    /// operator chose `fail_open`.
    InspectionBypassed,
}

/// The statement an event belongs to, as far as it may be shown.
///
/// How much is shown follows the configured redaction mode:
///
/// | Mode | `text` | `fingerprint` | `normalized` |
/// |---|---|---|---|
/// | `full` | the statement | – | – |
/// | `fingerprint` | – | a hash of the statement | the statement with its constants removed, when the SQL parser is available |
/// | `none` | – | – | – |
///
/// Bind parameters are never part of any of these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Query {
    /// Whether the statement that produced the message is known. When the
    /// statement tracker has lost its place this is `false`, the other
    /// fields are empty, and the hit is reported all the same.
    pub known: bool,
    /// The redaction mode that was applied.
    pub redaction: QueryRedaction,
    /// The statement text. Only with [`QueryRedaction::Full`].
    pub text: Option<String>,
    /// A fingerprint of the statement. Only with
    /// [`QueryRedaction::Fingerprint`].
    pub fingerprint: Option<String>,
    /// The statement with its constants replaced by placeholders. Only with
    /// [`QueryRedaction::Fingerprint`], and only when the SQL parser is
    /// available.
    pub normalized: Option<String>,
}

impl Query {
    /// The statement could not be determined.
    #[must_use]
    pub const fn unknown(redaction: QueryRedaction) -> Self {
        Self {
            known: false,
            redaction,
            text: None,
            fingerprint: None,
            normalized: None,
        }
    }

    /// The statement is known and nothing of it is shown.
    #[must_use]
    pub const fn withheld() -> Self {
        Self {
            known: true,
            redaction: QueryRedaction::None,
            text: None,
            fingerprint: None,
            normalized: None,
        }
    }

    /// The statement is shown as a fingerprint, with its normalised form
    /// when there is one.
    #[must_use]
    pub const fn fingerprint(fingerprint: String, normalized: Option<String>) -> Self {
        Self {
            known: true,
            redaction: QueryRedaction::Fingerprint,
            text: None,
            fingerprint: Some(fingerprint),
            normalized,
        }
    }

    /// The statement is shown in full.
    #[must_use]
    pub const fn full(text: String) -> Self {
        Self {
            known: true,
            redaction: QueryRedaction::Full,
            text: Some(text),
            fingerprint: None,
            normalized: None,
        }
    }
}

/// What the session logic knows about something that fired.
///
/// The runtime seals it into an [`Event`]. The fields are public: start from
/// [`EventBody::new`] and set what applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EventBody {
    /// What this event reports.
    pub kind: EventKind,
    /// The session it happened in.
    pub session_id: SessionId,

    /// The honeytoken that was hit. Set for [`EventKind::TokenHit`].
    pub token_id: Option<TokenId>,
    /// The rule that matched. Set for [`EventKind::RuleHit`].
    pub rule_id: Option<RuleId>,
    /// What pgsnare did in response. This is what actually happened: a
    /// response that fell back to another one is reported as the other one.
    pub action_taken: ActionSet,
    /// How many occurrences this event stands for. The dispatcher raises it
    /// when it folds repeated hits into one event.
    pub hit_count: u64,
    /// The direction of the message that fired, when a message did.
    pub direction: Option<Direction>,
    /// The protocol module's name for that message, such as `DataRow`. It
    /// comes from the module's own fixed list of names and is never text
    /// taken from the network.
    pub message_type: Option<Cow<'static, str>>,

    /// The address the client connected from, as the proxy saw it.
    pub client_ip: IpAddr,
    /// The port the client connected from.
    pub client_port: u16,
    /// The database user the client logged in as, once known.
    pub db_user: Option<String>,
    /// The database the client asked for, once known.
    pub database: Option<String>,
    /// The application name the client reported, if any.
    pub application_name: Option<String>,
    /// Whether the client leg is encrypted.
    pub tls: bool,

    /// The statement this event belongs to. `None` when no statement applies,
    /// for example for a hit in a login message.
    pub query: Option<Query>,
    /// How many rows of the current result had been sent to the client when
    /// this fired, when a result was being sent.
    pub rows_so_far: Option<u64>,
    /// Whether the session had already fired before this event.
    pub session_flagged: bool,
}

impl EventBody {
    /// An event body of the given kind for a session, with nothing else set.
    #[must_use]
    pub const fn new(kind: EventKind, origin: &SessionOrigin) -> Self {
        Self {
            kind,
            session_id: origin.session_id,
            token_id: None,
            rule_id: None,
            action_taken: ActionSet::EMPTY,
            hit_count: 1,
            direction: None,
            message_type: None,
            client_ip: origin.client_ip,
            client_port: origin.client_port,
            db_user: None,
            database: None,
            application_name: None,
            tls: origin.client_tls,
            query: None,
            rows_so_far: None,
            session_flagged: false,
        }
    }

    /// Calls `visit` with every text field whose content comes from the
    /// network: the database user, the database, the application name, and
    /// the statement text and its normalised form.
    ///
    /// A honeytoken value can turn up in any of them, for example when a
    /// honeytoken is used as a user name. The runtime uses this to redact
    /// them all in one place. A new field of this kind must be added here.
    pub fn for_each_text_mut(&mut self, mut visit: impl FnMut(&mut String)) {
        let Self {
            kind: _,
            session_id: _,
            token_id: _,
            rule_id: _,
            action_taken: _,
            hit_count: _,
            direction: _,
            message_type: _,
            client_ip: _,
            client_port: _,
            db_user,
            database,
            application_name,
            tls: _,
            query,
            rows_so_far: _,
            session_flagged: _,
        } = self;

        for text in [db_user, database, application_name].into_iter().flatten() {
            visit(text);
        }
        if let Some(Query {
            known: _,
            redaction: _,
            text,
            fingerprint: _,
            normalized,
        }) = query
        {
            for text in [text, normalized].into_iter().flatten() {
                visit(text);
            }
        }
    }

    /// Completes the event with what only the runtime knows.
    #[must_use]
    pub fn seal(self, event_id: EventId, timestamp: Timestamp, labels: Labels) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            event_id,
            timestamp,
            labels,
            body: self,
        }
    }
}

/// A complete event, as sinks receive it.
///
/// In JSON the fields of [`EventBody`] sit at the top level, next to the
/// fields of this type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Event {
    /// The version of the schema this event follows: [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// A unique identifier for this event.
    pub event_id: EventId,
    /// When the event was raised.
    pub timestamp: Timestamp,
    /// Labels that identify the pgsnare instance.
    pub labels: Labels,
    /// What the session logic reported.
    #[serde(flatten)]
    pub body: EventBody,
}

#[cfg(test)]
mod tests;
