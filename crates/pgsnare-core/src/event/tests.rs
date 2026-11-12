// SPDX-License-Identifier: Apache-2.0

//! Serialisation tests for the event schema.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{Value, json};

use crate::policy::Action;

use super::*;

fn origin() -> SessionOrigin {
    SessionOrigin::new(
        SessionId::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        49_152,
        true,
    )
}

fn labels() -> Labels {
    Labels::from([
        ("POD_NAMESPACE".to_owned(), "databases".to_owned()),
        ("POD_NAME".to_owned(), "pgsnare-0".to_owned()),
    ])
}

fn seal(body: EventBody) -> Event {
    body.seal(
        EventId::from_u128(0xfeed_face_0000_0000_0000_0000_0000_0001),
        Timestamp::from_unix_micros(1_794_416_791_123_456).unwrap(),
        labels(),
    )
}

/// A token hit with every field set.
fn token_hit() -> Event {
    let mut body = EventBody::new(EventKind::TokenHit, &origin());
    body.token_id = Some(TokenId::new("users-admin-backup").unwrap());
    body.action_taken = ActionSet::of(&[Action::Alert, Action::Kill]);
    body.hit_count = 3;
    body.direction = Some(Direction::FromServer);
    body.message_type = Some(Cow::Borrowed("DataRow"));
    body.db_user = Some("app".to_owned());
    body.database = Some("shop".to_owned());
    body.application_name = Some("psql".to_owned());
    body.query = Some(Query::fingerprint(
        "9f86d081884c7d65".to_owned(),
        Some("SELECT * FROM users WHERE id = $1".to_owned()),
    ));
    body.rows_so_far = Some(41);
    body.session_flagged = true;
    seal(body)
}

/// Every field name of the schema, in the order it is written.
const FIELDS: [&str; 21] = [
    // Identity
    "schema_version",
    "event_id",
    "timestamp",
    "labels",
    "kind",
    "session_id",
    // What fired
    "token_id",
    "rule_id",
    "action_taken",
    "hit_count",
    "direction",
    "message_type",
    // Who
    "client_ip",
    "client_port",
    "db_user",
    "database",
    "application_name",
    "tls",
    // Context
    "query",
    "rows_so_far",
    "session_flagged",
];

#[test]
fn a_token_hit_serialises_to_the_documented_json() {
    let json = serde_json::to_value(token_hit()).unwrap();
    assert_eq!(
        json,
        json!({
            "schema_version": 1,
            "event_id": "feedface000000000000000000000001",
            "timestamp": "2026-11-11T17:06:31.123456Z",
            "labels": {"POD_NAME": "pgsnare-0", "POD_NAMESPACE": "databases"},
            "kind": "token_hit",
            "session_id": "0123456789abcdef0123456789abcdef",
            "token_id": "users-admin-backup",
            "rule_id": null,
            "action_taken": ["alert", "kill"],
            "hit_count": 3,
            "direction": "from_server",
            "message_type": "DataRow",
            "client_ip": "192.0.2.10",
            "client_port": 49152,
            "db_user": "app",
            "database": "shop",
            "application_name": "psql",
            "tls": true,
            "query": {
                "known": true,
                "redaction": "fingerprint",
                "text": null,
                "fingerprint": "9f86d081884c7d65",
                "normalized": "SELECT * FROM users WHERE id = $1"
            },
            "rows_so_far": 41,
            "session_flagged": true
        })
    );
}

#[test]
fn the_json_text_is_stable_byte_for_byte() {
    // The order of the fields and of the labels never changes, so the same
    // event always gives the same bytes. A signature over the body relies
    // on that.
    let expected = concat!(
        r#"{"schema_version":1,"#,
        r#""event_id":"feedface000000000000000000000001","#,
        r#""timestamp":"2026-11-11T17:06:31.123456Z","#,
        r#""labels":{"POD_NAME":"pgsnare-0","POD_NAMESPACE":"databases"},"#,
        r#""kind":"token_hit","#,
        r#""session_id":"0123456789abcdef0123456789abcdef","#,
        r#""token_id":"users-admin-backup","#,
        r#""rule_id":null,"#,
        r#""action_taken":["alert","kill"],"#,
        r#""hit_count":3,"#,
        r#""direction":"from_server","#,
        r#""message_type":"DataRow","#,
        r#""client_ip":"192.0.2.10","#,
        r#""client_port":49152,"#,
        r#""db_user":"app","#,
        r#""database":"shop","#,
        r#""application_name":"psql","#,
        r#""tls":true,"#,
        r#""query":{"known":true,"redaction":"fingerprint","text":null,"#,
        r#""fingerprint":"9f86d081884c7d65","#,
        r#""normalized":"SELECT * FROM users WHERE id = $1"},"#,
        r#""rows_so_far":41,"#,
        r#""session_flagged":true}"#,
    );
    assert_eq!(serde_json::to_string(&token_hit()).unwrap(), expected);
    assert_eq!(
        serde_json::to_string(&token_hit().clone()).unwrap(),
        expected
    );
}

#[test]
fn every_field_is_always_present_and_in_order() {
    // The fullest event and the emptiest one have the same fields.
    let empty = seal(EventBody::new(EventKind::InspectionBypassed, &origin()));
    for event in [token_hit(), empty] {
        let text = serde_json::to_string(&event).unwrap();
        let mut position = 0;
        for field in FIELDS {
            let needle = format!("\"{field}\":");
            let found = text[position..]
                .find(&needle)
                .unwrap_or_else(|| panic!("field {field} is missing or out of order in {text}"));
            position += found + needle.len();
        }
        let Value::Object(object) = serde_json::to_value(&event).unwrap() else {
            panic!("an event is a JSON object");
        };
        assert_eq!(object.len(), FIELDS.len());
    }
}

#[test]
fn a_new_body_has_nothing_set_but_its_origin() {
    let json =
        serde_json::to_value(seal(EventBody::new(EventKind::SessionActivity, &origin()))).unwrap();
    assert_eq!(
        json,
        json!({
            "schema_version": 1,
            "event_id": "feedface000000000000000000000001",
            "timestamp": "2026-11-11T17:06:31.123456Z",
            "labels": {"POD_NAME": "pgsnare-0", "POD_NAMESPACE": "databases"},
            "kind": "session_activity",
            "session_id": "0123456789abcdef0123456789abcdef",
            "token_id": null,
            "rule_id": null,
            "action_taken": [],
            "hit_count": 1,
            "direction": null,
            "message_type": null,
            "client_ip": "192.0.2.10",
            "client_port": 49152,
            "db_user": null,
            "database": null,
            "application_name": null,
            "tls": true,
            "query": null,
            "rows_so_far": null,
            "session_flagged": false
        })
    );
}

#[test]
fn every_kind_has_its_name() {
    let kinds = [
        (EventKind::TokenHit, "token_hit"),
        (EventKind::RuleHit, "rule_hit"),
        (EventKind::ParseFailure, "parse_failure"),
        (EventKind::SessionActivity, "session_activity"),
        (EventKind::InspectionBypassed, "inspection_bypassed"),
    ];
    for (kind, name) in kinds {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(name));
        assert_eq!(
            serde_json::from_value::<EventKind>(json!(name)).unwrap(),
            kind
        );

        let event = seal(EventBody::new(kind, &origin()));
        assert_eq!(serde_json::to_value(&event).unwrap()["kind"], json!(name));
    }
    assert!(serde_json::from_value::<EventKind>(json!("something_else")).is_err());
}

#[test]
fn a_rule_hit_names_the_rule() {
    let mut body = EventBody::new(EventKind::RuleHit, &origin());
    body.rule_id = Some(RuleId::new("catalog_enumeration").unwrap());
    body.action_taken = ActionSet::ALERT;
    body.direction = Some(Direction::FromClient);
    body.message_type = Some(Cow::Borrowed("Query"));
    body.query = Some(Query::full("SELECT * FROM pg_catalog.pg_tables".to_owned()));

    let json = serde_json::to_value(seal(body)).unwrap();
    assert_eq!(json["kind"], json!("rule_hit"));
    assert_eq!(json["rule_id"], json!("catalog_enumeration"));
    assert_eq!(json["token_id"], Value::Null);
    assert_eq!(json["direction"], json!("from_client"));
    assert_eq!(
        json["query"],
        json!({
            "known": true,
            "redaction": "full",
            "text": "SELECT * FROM pg_catalog.pg_tables",
            "fingerprint": null,
            "normalized": null
        })
    );
}

#[test]
fn each_query_form_has_its_json() {
    let cases = [
        (
            Query::unknown(QueryRedaction::Fingerprint),
            json!({"known": false, "redaction": "fingerprint", "text": null,
                   "fingerprint": null, "normalized": null}),
        ),
        (
            Query::withheld(),
            json!({"known": true, "redaction": "none", "text": null,
                   "fingerprint": null, "normalized": null}),
        ),
        (
            Query::fingerprint("abc123".to_owned(), None),
            json!({"known": true, "redaction": "fingerprint", "text": null,
                   "fingerprint": "abc123", "normalized": null}),
        ),
        (
            Query::full("SELECT 1".to_owned()),
            json!({"known": true, "redaction": "full", "text": "SELECT 1",
                   "fingerprint": null, "normalized": null}),
        ),
    ];
    for (query, expected) in cases {
        assert_eq!(serde_json::to_value(&query).unwrap(), expected);
        assert_eq!(serde_json::from_value::<Query>(expected).unwrap(), query);
    }
}

#[test]
fn an_ipv6_client_is_written_in_the_usual_form() {
    let origin = SessionOrigin::new(
        SessionId::from_u128(1),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
        5432,
        false,
    );
    let json = serde_json::to_value(seal(EventBody::new(EventKind::TokenHit, &origin))).unwrap();
    assert_eq!(json["client_ip"], json!("2001:db8::10"));
    assert_eq!(json["client_port"], json!(5432));
    assert_eq!(json["tls"], json!(false));
}

#[test]
fn text_from_the_network_is_escaped_not_trusted() {
    let mut body = EventBody::new(EventKind::TokenHit, &origin());
    body.db_user = Some("line one\nline two\t\"quoted\" \u{1}".to_owned());
    body.application_name = Some("</script>\u{2028}".to_owned());
    let text = serde_json::to_string(&seal(body)).unwrap();

    // One line, whatever the content, so a JSON-lines sink cannot be made
    // to emit a second record.
    assert!(!text.contains('\n'));
    assert!(text.contains(r#""db_user":"line one\nline two\t\"quoted\" \u0001""#));

    let back: Event = serde_json::from_str(&text).unwrap();
    assert_eq!(
        back.body.db_user.as_deref(),
        Some("line one\nline two\t\"quoted\" \u{1}")
    );
}

#[test]
fn an_event_round_trips_through_json() {
    let empty = seal(EventBody::new(EventKind::ParseFailure, &origin()));
    for event in [token_hit(), empty] {
        let text = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&text).unwrap();
        assert_eq!(back, event);
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }
}

#[test]
fn a_reader_ignores_fields_it_does_not_know() {
    // A later schema may add fields. An older reader must cope.
    let mut json = serde_json::to_value(token_hit()).unwrap();
    json["added_later"] = json!({"anything": [1, 2, 3]});
    json["query"]["added_later"] = json!(true);
    let back: Event = serde_json::from_value(json).unwrap();
    assert_eq!(back, token_hit());
}

#[test]
fn a_reader_rejects_malformed_events() {
    let good = serde_json::to_value(token_hit()).unwrap();

    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("session_id");
    assert!(serde_json::from_value::<Event>(missing).is_err());

    for (field, bad) in [
        ("event_id", json!("not-an-id")),
        ("timestamp", json!("yesterday")),
        ("kind", json!("unknown_kind")),
        ("client_ip", json!("not-an-address")),
        ("client_port", json!(70_000)),
        ("action_taken", json!(["alert", "alert"])),
        ("token_id", json!("has a space")),
        ("direction", json!("sideways")),
        ("hit_count", json!(-1)),
    ] {
        let mut broken = good.clone();
        broken[field] = bad;
        assert!(serde_json::from_value::<Event>(broken).is_err(), "{field}");
    }
}

#[test]
fn sealing_adds_the_version_identifier_time_and_labels() {
    let body = EventBody::new(EventKind::TokenHit, &origin());
    let event = body
        .clone()
        .seal(EventId::from_u128(9), Timestamp::UNIX_EPOCH, Labels::new());
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 1);
    assert_eq!(event.event_id, EventId::from_u128(9));
    assert_eq!(event.timestamp, Timestamp::UNIX_EPOCH);
    assert!(event.labels.is_empty());
    assert_eq!(event.body, body);

    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["labels"], json!({}));
    assert_eq!(json["timestamp"], json!("1970-01-01T00:00:00.000000Z"));
}

#[test]
fn every_text_field_from_the_network_can_be_redacted_in_one_pass() {
    let mut event = token_hit();
    event.body.query = Some(Query {
        known: true,
        redaction: QueryRedaction::Full,
        text: Some("SELECT 'secret-token-value'".to_owned()),
        fingerprint: Some("f00d".to_owned()),
        normalized: Some("SELECT 'secret-token-value' -- normalised".to_owned()),
    });
    event.body.db_user = Some("secret-token-value".to_owned());
    event.body.database = Some("db-secret-token-value".to_owned());
    event.body.application_name = Some("app secret-token-value".to_owned());

    let mut visited = 0;
    event.body.for_each_text_mut(|text| {
        visited += 1;
        *text = text.replace("secret-token-value", "[redacted]");
    });
    assert_eq!(visited, 5);

    let text = serde_json::to_string(&event).unwrap();
    assert!(!text.contains("secret-token-value"), "{text}");
    assert_eq!(event.body.db_user.as_deref(), Some("[redacted]"));
    // Identifiers and fingerprints are not text from the network.
    assert_eq!(event.body.token_id.unwrap().as_str(), "users-admin-backup");
    assert_eq!(
        event.body.query.unwrap().fingerprint.as_deref(),
        Some("f00d")
    );

    // Nothing is visited when nothing is set.
    let mut empty = EventBody::new(EventKind::TokenHit, &origin());
    let mut visited = 0;
    empty.for_each_text_mut(|_| visited += 1);
    assert_eq!(visited, 0);
}

#[test]
fn a_message_type_survives_a_round_trip_as_owned_text() {
    let event = token_hit();
    let back: Event = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
    assert_eq!(back.body.message_type.as_deref(), Some("DataRow"));
    assert!(matches!(back.body.message_type, Some(Cow::Owned(_))));
}
