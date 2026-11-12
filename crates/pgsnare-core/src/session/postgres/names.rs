// SPDX-License-Identifier: Apache-2.0

//! The names of the messages, for events.
//!
//! An event names a message by one of these fixed texts and never by
//! anything taken from the network.

use pgsnare_proto::{backend, frontend};

use crate::session::Direction;

/// The name of the message with this type byte, as the protocol
/// documentation spells it. `None` for a type byte PostgreSQL does not
/// define.
///
/// Several messages of the login share one type byte. They are named by
/// what they have in common.
pub(super) const fn message_name(direction: Direction, tag: u8) -> Option<&'static str> {
    match direction {
        Direction::FromClient => match tag {
            frontend::tag::BIND => Some("Bind"),
            frontend::tag::CLOSE => Some("Close"),
            frontend::tag::COPY_DATA => Some("CopyData"),
            frontend::tag::COPY_DONE => Some("CopyDone"),
            frontend::tag::COPY_FAIL => Some("CopyFail"),
            frontend::tag::DESCRIBE => Some("Describe"),
            frontend::tag::EXECUTE => Some("Execute"),
            frontend::tag::FLUSH => Some("Flush"),
            frontend::tag::FUNCTION_CALL => Some("FunctionCall"),
            frontend::tag::PARSE => Some("Parse"),
            frontend::tag::AUTHENTICATION_RESPONSE => Some("AuthenticationResponse"),
            frontend::tag::QUERY => Some("Query"),
            frontend::tag::SYNC => Some("Sync"),
            frontend::tag::TERMINATE => Some("Terminate"),
            _ => None,
        },
        Direction::FromServer => match tag {
            backend::tag::AUTHENTICATION => Some("Authentication"),
            backend::tag::BACKEND_KEY_DATA => Some("BackendKeyData"),
            backend::tag::BIND_COMPLETE => Some("BindComplete"),
            backend::tag::CLOSE_COMPLETE => Some("CloseComplete"),
            backend::tag::COMMAND_COMPLETE => Some("CommandComplete"),
            backend::tag::COPY_BOTH_RESPONSE => Some("CopyBothResponse"),
            backend::tag::COPY_DATA => Some("CopyData"),
            backend::tag::COPY_DONE => Some("CopyDone"),
            backend::tag::COPY_IN_RESPONSE => Some("CopyInResponse"),
            backend::tag::COPY_OUT_RESPONSE => Some("CopyOutResponse"),
            backend::tag::DATA_ROW => Some("DataRow"),
            backend::tag::EMPTY_QUERY_RESPONSE => Some("EmptyQueryResponse"),
            backend::tag::ERROR_RESPONSE => Some("ErrorResponse"),
            backend::tag::FUNCTION_CALL_RESPONSE => Some("FunctionCallResponse"),
            backend::tag::NEGOTIATE_PROTOCOL_VERSION => Some("NegotiateProtocolVersion"),
            backend::tag::NO_DATA => Some("NoData"),
            backend::tag::NOTICE_RESPONSE => Some("NoticeResponse"),
            backend::tag::NOTIFICATION_RESPONSE => Some("NotificationResponse"),
            backend::tag::PARAMETER_DESCRIPTION => Some("ParameterDescription"),
            backend::tag::PARAMETER_STATUS => Some("ParameterStatus"),
            backend::tag::PARSE_COMPLETE => Some("ParseComplete"),
            backend::tag::PORTAL_SUSPENDED => Some("PortalSuspended"),
            backend::tag::READY_FOR_QUERY => Some("ReadyForQuery"),
            backend::tag::ROW_DESCRIPTION => Some("RowDescription"),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_byte_names_different_messages_in_the_two_directions() {
        assert_eq!(message_name(Direction::FromClient, b'D'), Some("Describe"));
        assert_eq!(message_name(Direction::FromServer, b'D'), Some("DataRow"));
        assert_eq!(message_name(Direction::FromClient, b'd'), Some("CopyData"));
        assert_eq!(message_name(Direction::FromServer, b'd'), Some("CopyData"));
        assert_eq!(message_name(Direction::FromClient, b'Z'), None);
        assert_eq!(message_name(Direction::FromServer, 0), None);
    }
}
