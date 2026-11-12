// SPDX-License-Identifier: Apache-2.0

//! The startup message: what is learned from it, how it is capped, and the
//! messages pgsnare itself writes before a session is established.

use core::net::IpAddr;

use pgsnare_proto::backend::{self, NegotiateProtocolVersion, error_field};
use pgsnare_proto::startup::StartupMessage;
use pgsnare_proto::{Frame, ProtocolVersion, encode};

use crate::event::{MAX_NAME_BYTES, text_from_wire};
use crate::extension::SessionError;

/// What a client said about itself in its startup message.
///
/// The texts are for events and for the inspector. They are cut to a
/// sensible length and are never written to a log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) db_user: Option<String>,
    pub(super) database: Option<String>,
    pub(super) application_name: Option<String>,
}

impl Identity {
    /// Reads the parameters the server itself would use: the last value
    /// of each, and the user name as the database when none is given.
    pub(super) fn of(message: &StartupMessage<'_>) -> Self {
        let text = |name: &[u8]| {
            message
                .get(name)
                .map(|value| text_from_wire(value, MAX_NAME_BYTES))
        };
        let db_user = text(b"user");
        let database = text(b"database").or_else(|| db_user.clone());
        Self {
            db_user,
            database,
            application_name: text(b"application_name"),
        }
    }
}

/// What the client has to be told about a startup message that was capped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Negotiation {
    /// The protocol version that was sent to the server.
    version: ProtocolVersion,
    /// The names of the protocol options that were not sent on, in the
    /// order the client gave them.
    removed: Vec<Vec<u8>>,
}

/// The startup message to send to the server, and what the client has to
/// be told about it.
///
/// A message that asks for protocol 3.2 at most and carries no protocol
/// option is sent on as the bytes that arrived. Any other is written
/// again, with the version capped at 3.2 and without the options, none of
/// which pgsnare knows.
pub(super) fn cap(
    message: &StartupMessage<'_>,
) -> Result<(Vec<u8>, Option<Negotiation>), SessionError> {
    let too_new = message.version() > ProtocolVersion::V3_2;
    let has_options = message
        .parameters()
        .any(|parameter| parameter.is_protocol_option());
    if !too_new && !has_options {
        return Ok((message.as_bytes().to_vec(), None));
    }

    let version = if too_new {
        ProtocolVersion::V3_2
    } else {
        message.version()
    };
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for parameter in message.parameters() {
        if parameter.is_protocol_option() {
            removed.push(parameter.name().to_vec());
        } else {
            kept.push((parameter.name(), parameter.value()));
        }
    }
    let mut bytes = Vec::with_capacity(message.as_bytes().len());
    encode::startup_message(version, &kept, &mut bytes)
        .map_err(|_| SessionError::new("the startup message could not be written again"))?;
    Ok((bytes, Some(Negotiation { version, removed })))
}

impl Negotiation {
    /// Writes the `NegotiateProtocolVersion` of a server that accepted the
    /// capped startup message without a word.
    pub(super) fn announce(&self, out: &mut Vec<u8>) -> Result<(), SessionError> {
        let names: Vec<&[u8]> = self.removed.iter().map(Vec::as_slice).collect();
        encode::negotiate_protocol_version(self.version, &names, out).map_err(|_| {
            SessionError::new("the protocol version could not be announced to the client")
        })
    }

    /// Writes the `NegotiateProtocolVersion` of the server again, with the
    /// options that were removed from the startup message added in front of
    /// the ones the server did not accept.
    pub(super) fn merge(&self, frame: Frame<'_>, out: &mut Vec<u8>) -> Result<(), SessionError> {
        let theirs = NegotiateProtocolVersion::from_frame(frame).map_err(|_| {
            SessionError::new("the server sent a malformed NegotiateProtocolVersion")
        })?;
        let mut names: Vec<&[u8]> = self.removed.iter().map(Vec::as_slice).collect();
        names.extend(theirs.options());
        encode::negotiate_protocol_version(theirs.version(), &names, out).map_err(|_| {
            SessionError::new("the protocol version could not be announced to the client")
        })
    }
}

/// Writes a fatal `ErrorResponse` with a severity, a code and a message.
fn fatal(sqlstate: &[u8; 5], message: &[u8], out: &mut Vec<u8>) -> Result<(), SessionError> {
    encode::error_response(
        &[
            (error_field::SEVERITY, b"FATAL"),
            (error_field::SEVERITY_NONLOCALIZED, b"FATAL"),
            (error_field::SQLSTATE, sqlstate),
            (error_field::MESSAGE, message),
        ],
        out,
    )
    .map_err(|_| SessionError::new("an error for the client could not be written"))
}

/// Writes what the database sends a session that an administrator ends:
/// `57P01`, "terminating connection due to administrator command".
pub(super) fn admin_shutdown(out: &mut Vec<u8>) -> Result<(), SessionError> {
    fatal(
        b"57P01",
        b"terminating connection due to administrator command",
        out,
    )
}

/// Writes what the client is told when the database cannot be reached:
/// `57P03`, the code a server uses while it cannot take connections. A
/// client with several hosts to choose from then tries the next one.
pub(super) fn cannot_connect_now(out: &mut Vec<u8>) -> Result<(), SessionError> {
    fatal(
        b"57P03",
        b"the database system is not accepting connections",
        out,
    )
}

/// Writes what a server answers a client that connects without encryption
/// when its access rules admit encrypted connections only: `28000` and the
/// text of PostgreSQL itself.
pub(super) fn encryption_required(
    message: &StartupMessage<'_>,
    client_ip: IpAddr,
    out: &mut Vec<u8>,
) -> Result<(), SessionError> {
    let user = message.get(b"user").unwrap_or_default();
    let database = message.get(b"database").unwrap_or(user);
    let host = client_ip.to_string();

    let mut text = Vec::new();
    if is_physical_replication(message) {
        text.extend_from_slice(b"no pg_hba.conf entry for replication connection from host \"");
        text.extend_from_slice(host.as_bytes());
        text.extend_from_slice(b"\", user \"");
        text.extend_from_slice(user);
    } else {
        text.extend_from_slice(b"no pg_hba.conf entry for host \"");
        text.extend_from_slice(host.as_bytes());
        text.extend_from_slice(b"\", user \"");
        text.extend_from_slice(user);
        text.extend_from_slice(b"\", database \"");
        text.extend_from_slice(database);
    }
    text.extend_from_slice(b"\", no encryption");
    fatal(b"28000", &text, out)
}

/// Whether the startup message asks for a physical replication connection,
/// which the server reports in other words. `replication=database` is a
/// logical one and counts as an ordinary connection here.
fn is_physical_replication(message: &StartupMessage<'_>) -> bool {
    message.get(b"replication").is_some_and(|value| {
        [&b"true"[..], b"on", b"yes", b"1"]
            .iter()
            .any(|word| value.eq_ignore_ascii_case(word))
    })
}

/// Whether a SASL mechanism binds the login to the TLS channel. The names
/// of the SCRAM family end in `-PLUS` when they do.
pub(super) fn binds_channel(mechanism: &[u8]) -> bool {
    mechanism.ends_with(b"-PLUS")
}

/// Writes an `AuthenticationSASL` again without the mechanisms that bind
/// the login to the TLS channel. Returns `None` when the server offered
/// none, so that the message can be passed on as it arrived.
pub(super) fn without_channel_binding(
    mechanisms: backend::SaslMechanisms<'_>,
) -> Result<Option<Vec<u8>>, SessionError> {
    if !mechanisms.iter().any(binds_channel) {
        return Ok(None);
    }
    let kept: Vec<&[u8]> = mechanisms
        .iter()
        .filter(|mechanism| !binds_channel(mechanism))
        .collect();
    let mut bytes = Vec::new();
    encode::authentication_sasl(&kept, &mut bytes)
        .map_err(|_| SessionError::new("the SASL mechanism list could not be written again"))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use pgsnare_proto::backend::{Authentication, ErrorResponse};
    use pgsnare_proto::startup::StartupPacket;
    use pgsnare_proto::{Direction, Framer, Limits, Step};

    use super::*;

    fn startup(version: ProtocolVersion, parameters: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode::startup_message(version, parameters, &mut bytes).unwrap();
        bytes
    }

    fn parsed(bytes: &[u8]) -> StartupMessage<'_> {
        match StartupPacket::parse(bytes) {
            Ok(Some(StartupPacket::StartupMessage(message))) => message,
            other => panic!("expected a startup message, got {other:?}"),
        }
    }

    fn server_frame(bytes: &[u8]) -> Frame<'_> {
        let mut framer = Framer::new(Direction::FromServer, Limits::buffered_only(usize::MAX));
        let mut unread = bytes;
        match framer.next(&mut unread) {
            Ok(Step::Frame(frame)) if unread.is_empty() => frame,
            other => panic!("expected exactly one frame, got {other:?}"),
        }
    }

    fn negotiated(bytes: &[u8]) -> (ProtocolVersion, Vec<Vec<u8>>) {
        let view = NegotiateProtocolVersion::from_frame(server_frame(bytes)).unwrap();
        (view.version(), view.options().map(<[u8]>::to_vec).collect())
    }

    #[test]
    fn a_startup_message_pgsnare_understands_is_sent_on_as_it_arrived() {
        for version in [
            ProtocolVersion::V3_0,
            ProtocolVersion::new(3, 1),
            ProtocolVersion::V3_2,
        ] {
            let bytes = startup(
                version,
                &[
                    (b"user", b"app"),
                    (b"database", b"shop"),
                    (b"options", b"-c search_path=_pq_.x"),
                ],
            );
            let (forward, negotiation) = cap(&parsed(&bytes)).unwrap();
            assert_eq!(forward, bytes);
            assert_eq!(negotiation, None);
        }
    }

    #[test]
    fn a_newer_version_is_capped_at_3_2() {
        let bytes = startup(ProtocolVersion::new(3, 99), &[(b"user", b"app")]);
        let (forward, negotiation) = cap(&parsed(&bytes)).unwrap();
        assert_eq!(
            forward,
            startup(ProtocolVersion::V3_2, &[(b"user", b"app")])
        );
        let negotiation = negotiation.unwrap();

        // A server that speaks 3.2 says nothing, so pgsnare announces it.
        let mut announced = Vec::new();
        negotiation.announce(&mut announced).unwrap();
        assert_eq!(negotiated(&announced), (ProtocolVersion::V3_2, Vec::new()));
    }

    #[test]
    fn protocol_options_are_removed_and_reported_in_order() {
        let bytes = startup(
            ProtocolVersion::V3_0,
            &[
                (b"_pq_.first", b"1"),
                (b"user", b"app"),
                (b"_pq_.second", b"on"),
                (b"database", b"shop"),
                (b"_pq_.first", b"2"),
            ],
        );
        let (forward, negotiation) = cap(&parsed(&bytes)).unwrap();
        assert_eq!(
            forward,
            startup(
                ProtocolVersion::V3_0,
                &[(b"user", b"app"), (b"database", b"shop")]
            )
        );
        let negotiation = negotiation.unwrap();

        // The version the client asked for stands, since 3.0 needs no cap.
        let mut announced = Vec::new();
        negotiation.announce(&mut announced).unwrap();
        assert_eq!(
            negotiated(&announced),
            (
                ProtocolVersion::V3_0,
                vec![
                    b"_pq_.first".to_vec(),
                    b"_pq_.second".to_vec(),
                    b"_pq_.first".to_vec()
                ]
            )
        );
    }

    #[test]
    fn the_answer_of_the_server_is_merged_with_what_was_removed() {
        let bytes = startup(
            ProtocolVersion::new(3, 7),
            &[(b"user", b"app"), (b"_pq_.removed", b"x")],
        );
        let (_, negotiation) = cap(&parsed(&bytes)).unwrap();
        let negotiation = negotiation.unwrap();

        // An older server answers 3.2 with 3.0, and may name options of
        // its own.
        let mut theirs = Vec::new();
        encode::negotiate_protocol_version(ProtocolVersion::V3_0, &[b"_pq_.theirs"], &mut theirs)
            .unwrap();
        let mut merged = Vec::new();
        negotiation
            .merge(server_frame(&theirs), &mut merged)
            .unwrap();
        assert_eq!(
            negotiated(&merged),
            (
                ProtocolVersion::V3_0,
                vec![b"_pq_.removed".to_vec(), b"_pq_.theirs".to_vec()]
            )
        );

        // A frame that is not what its type byte says is refused.
        let malformed = [b'v', 0, 0, 0, 6, 0, 0];
        assert!(
            negotiation
                .merge(server_frame(&malformed), &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn identity_follows_the_rules_of_the_server() {
        let bytes = startup(
            ProtocolVersion::V3_0,
            &[
                (b"user", b"first"),
                (b"application_name", b"psql"),
                (b"user", b"app"),
            ],
        );
        let identity = Identity::of(&parsed(&bytes));
        assert_eq!(identity.db_user.as_deref(), Some("app"));
        // Without a database the server uses the user name.
        assert_eq!(identity.database.as_deref(), Some("app"));
        assert_eq!(identity.application_name.as_deref(), Some("psql"));

        let bytes = startup(ProtocolVersion::V3_0, &[(b"database", b"shop")]);
        let identity = Identity::of(&parsed(&bytes));
        assert_eq!(identity.db_user, None);
        assert_eq!(identity.database.as_deref(), Some("shop"));
        assert_eq!(identity.application_name, None);

        // A name is cut, and bytes that are not text are replaced.
        let long = [b'u'; 1000];
        let bytes = startup(
            ProtocolVersion::V3_0,
            &[(b"user", &long), (b"database", b"\xff")],
        );
        let identity = Identity::of(&parsed(&bytes));
        assert_eq!(
            identity.db_user.unwrap().chars().count(),
            MAX_NAME_BYTES + 1
        );
        assert_eq!(identity.database.as_deref(), Some("\u{fffd}"));
    }

    fn error_fields(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        ErrorResponse::from_frame(server_frame(bytes))
            .unwrap()
            .fields()
            .iter()
            .map(|field| (field.code(), field.value().to_vec()))
            .collect()
    }

    #[test]
    fn the_errors_pgsnare_writes_are_the_ones_postgresql_sends() {
        let mut out = Vec::new();
        admin_shutdown(&mut out).unwrap();
        assert_eq!(
            error_fields(&out),
            [
                (b'S', b"FATAL".to_vec()),
                (b'V', b"FATAL".to_vec()),
                (b'C', b"57P01".to_vec()),
                (
                    b'M',
                    b"terminating connection due to administrator command".to_vec()
                ),
            ]
        );

        let mut out = Vec::new();
        cannot_connect_now(&mut out).unwrap();
        let fields = error_fields(&out);
        assert_eq!(fields[2], (b'C', b"57P03".to_vec()));
        assert_eq!(
            fields[3],
            (
                b'M',
                b"the database system is not accepting connections".to_vec()
            )
        );
    }

    #[test]
    fn a_client_without_encryption_is_refused_in_the_words_of_the_server() {
        let message_of = |parameters: &[(&[u8], &[u8])], ip: &str| {
            let bytes = startup(ProtocolVersion::V3_0, parameters);
            let mut out = Vec::new();
            encryption_required(&parsed(&bytes), ip.parse().unwrap(), &mut out).unwrap();
            let fields = error_fields(&out);
            assert_eq!(fields[0], (b'S', b"FATAL".to_vec()));
            assert_eq!(fields[2], (b'C', b"28000".to_vec()));
            String::from_utf8(fields[3].1.clone()).unwrap()
        };

        assert_eq!(
            message_of(&[(b"user", b"app"), (b"database", b"shop")], "192.0.2.10"),
            "no pg_hba.conf entry for host \"192.0.2.10\", user \"app\", database \"shop\", \
             no encryption"
        );
        assert_eq!(
            message_of(&[(b"user", b"app")], "2001:db8::7"),
            "no pg_hba.conf entry for host \"2001:db8::7\", user \"app\", database \"app\", \
             no encryption"
        );
        assert_eq!(
            message_of(
                &[(b"user", b"standby"), (b"replication", b"TRUE")],
                "192.0.2.10"
            ),
            "no pg_hba.conf entry for replication connection from host \"192.0.2.10\", \
             user \"standby\", no encryption"
        );
        // A logical replication connection is reported like an ordinary one.
        assert_eq!(
            message_of(
                &[
                    (b"user", b"sub"),
                    (b"database", b"shop"),
                    (b"replication", b"database")
                ],
                "192.0.2.10"
            ),
            "no pg_hba.conf entry for host \"192.0.2.10\", user \"sub\", database \"shop\", \
             no encryption"
        );
    }

    #[test]
    fn mechanisms_with_channel_binding_are_removed_and_the_rest_kept_in_order() {
        let offer = |mechanisms: &[&[u8]]| {
            let mut bytes = Vec::new();
            encode::authentication_sasl(mechanisms, &mut bytes).unwrap();
            bytes
        };
        let rewritten = |bytes: &[u8]| {
            let Authentication::Sasl(mechanisms) =
                Authentication::from_frame(server_frame(bytes)).unwrap()
            else {
                panic!("expected AuthenticationSASL");
            };
            without_channel_binding(mechanisms).unwrap()
        };

        // What a server with TLS offers.
        let both = offer(&[b"SCRAM-SHA-256-PLUS", b"SCRAM-SHA-256"]);
        assert_eq!(rewritten(&both), Some(offer(&[b"SCRAM-SHA-256"])));

        // What a server without TLS offers is not touched.
        let plain = offer(&[b"SCRAM-SHA-256"]);
        assert_eq!(rewritten(&plain), None);

        let mixed = offer(&[
            b"OAUTHBEARER",
            b"SCRAM-SHA-512-PLUS",
            b"SCRAM-SHA-256",
            b"SCRAM-SHA-256-PLUS",
        ]);
        assert_eq!(
            rewritten(&mixed),
            Some(offer(&[b"OAUTHBEARER", b"SCRAM-SHA-256"]))
        );

        // Nothing is left: the client is shown an empty offer and gives up.
        let only = offer(&[b"SCRAM-SHA-256-PLUS"]);
        assert_eq!(rewritten(&only), Some(offer(&[])));

        assert!(binds_channel(b"SCRAM-SHA-256-PLUS"));
        assert!(!binds_channel(b"SCRAM-SHA-256"));
        assert!(!binds_channel(b"PLUS"));
    }
}
