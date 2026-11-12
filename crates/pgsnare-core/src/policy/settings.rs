// SPDX-License-Identifier: Apache-2.0

//! Settings that shape inspection and the responses.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// What happens to a session when inspecting it fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OnError {
    /// End the session. This is the default.
    #[default]
    FailClosed,
    /// Keep relaying the session without inspecting it, and report that with
    /// an `inspection_bypassed` event. This must be chosen explicitly.
    FailOpen,
}

/// How much of a statement an event shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QueryRedaction {
    /// The statement text. Bind parameters are still left out.
    Full,
    /// A fingerprint of the statement, and its normalised form when the SQL
    /// parser is available. This is the default.
    #[default]
    Fingerprint,
    /// Nothing.
    None,
}

/// Limits of inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Inspection {
    /// What happens to a session when inspecting it fails.
    pub on_error: OnError,
    /// A message up to this many bytes is scanned whole before any byte of
    /// it is forwarded. A larger one is scanned as a stream.
    pub max_buffered_frame: usize,
}

impl Inspection {
    /// The default for [`Inspection::max_buffered_frame`]: 1 MiB.
    pub const DEFAULT_MAX_BUFFERED_FRAME: usize = 1024 * 1024;

    /// The smallest accepted [`Inspection::max_buffered_frame`]: 1 KiB.
    pub const MIN_MAX_BUFFERED_FRAME: usize = 1024;

    /// The largest accepted [`Inspection::max_buffered_frame`]: 1 GiB, about
    /// the largest message PostgreSQL itself accepts.
    pub const MAX_MAX_BUFFERED_FRAME: usize = 1024 * 1024 * 1024;

    /// Inspection settings from their parts.
    #[must_use]
    pub const fn new(on_error: OnError, max_buffered_frame: usize) -> Self {
        Self {
            on_error,
            max_buffered_frame,
        }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: a buffer limit outside 1 KiB to 1 GiB.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.max_buffered_frame < Self::MIN_MAX_BUFFERED_FRAME
            || self.max_buffered_frame > Self::MAX_MAX_BUFFERED_FRAME
        {
            return Err("max_buffered_frame must be between 1KiB and 1GiB");
        }
        Ok(())
    }
}

impl Default for Inspection {
    fn default() -> Self {
        Self::new(OnError::default(), Self::DEFAULT_MAX_BUFFERED_FRAME)
    }
}

/// A five-character SQLSTATE code, such as `57P01`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SqlState([u8; 5]);

/// The text is not a SQLSTATE code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSqlState;

const SQLSTATE_EXPECTING: &str =
    "a SQLSTATE code: five characters, each a digit or an upper-case ASCII letter";

impl fmt::Display for InvalidSqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SQLSTATE_EXPECTING)
    }
}

impl core::error::Error for InvalidSqlState {}

impl SqlState {
    /// `57P01`, `admin_shutdown`: what PostgreSQL reports when an
    /// administrator ends a session.
    pub const ADMIN_SHUTDOWN: Self = Self(*b"57P01");

    /// The code as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The constructor admits ASCII digits and letters only, so this
        // cannot fail. The fallback keeps the function free of panics.
        core::str::from_utf8(&self.0).unwrap_or("XX000")
    }

    /// The code as the five bytes that go on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 5] {
        &self.0
    }
}

impl FromStr for SqlState {
    type Err = InvalidSqlState;

    fn from_str(text: &str) -> Result<Self, InvalidSqlState> {
        let code: [u8; 5] = text.as_bytes().try_into().map_err(|_| InvalidSqlState)?;
        if code
            .iter()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        {
            Ok(Self(code))
        } else {
            Err(InvalidSqlState)
        }
    }
}

impl fmt::Display for SqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SqlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SqlState({})", self.as_str())
    }
}

impl Serialize for SqlState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

struct SqlStateVisitor;

impl de::Visitor<'_> for SqlStateVisitor {
    type Value = SqlState;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SQLSTATE_EXPECTING)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<SqlState, E> {
        text.parse()
            .map_err(|_| E::invalid_value(de::Unexpected::Other("other text"), &self))
    }
}

impl<'de> Deserialize<'de> for SqlState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(SqlStateVisitor)
    }
}

/// The error a killed session receives.
///
/// The defaults make it look like an administrator ended the session, which
/// is what the database itself would report.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KillSettings {
    /// The SQLSTATE code of the error.
    pub sqlstate: SqlState,
    /// The message of the error.
    pub message: String,
}

impl KillSettings {
    /// The default message, the one PostgreSQL uses with `57P01`.
    pub const DEFAULT_MESSAGE: &'static str = "terminating connection due to administrator command";

    /// The longest accepted message, in bytes.
    pub const MAX_MESSAGE_BYTES: usize = 512;

    /// Kill settings from their parts.
    #[must_use]
    pub const fn new(sqlstate: SqlState, message: String) -> Self {
        Self { sqlstate, message }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the message: it is empty, too long, or
    /// contains something other than printable ASCII.
    ///
    /// Printable ASCII reads the same in every client encoding, so the
    /// message needs no conversion. It also excludes the NUL byte, which
    /// ends a message on the wire, and line breaks, which would let the
    /// message forge a second line of output.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.message.is_empty() {
            return Err("message must not be empty");
        }
        if self.message.len() > Self::MAX_MESSAGE_BYTES {
            return Err("message must be at most 512 bytes");
        }
        if !self
            .message
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        {
            return Err("message must be printable ASCII");
        }
        Ok(())
    }
}

impl Default for KillSettings {
    fn default() -> Self {
        Self::new(SqlState::ADMIN_SHUTDOWN, Self::DEFAULT_MESSAGE.to_owned())
    }
}

/// How a tarpitted session is slowed down, and where that stops.
///
/// A tarpitted session keeps a real database connection busy, so it is
/// bounded in time and in number. Past either bound the session is killed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TarpitSettings {
    /// The shortest delay before a flush to the client.
    pub delay_min: Duration,
    /// The longest delay before a flush to the client. The actual delay is
    /// drawn at random between the two.
    pub delay_max: Duration,
    /// How long a session may stay tarpitted.
    pub max_duration: Duration,
    /// How many sessions may be tarpitted at once.
    pub max_sessions: u32,
    /// An optional cap on the bytes sent to the client per second.
    pub max_bytes_per_second: Option<u64>,
}

impl TarpitSettings {
    /// The longest accepted delay and duration: one day.
    pub const MAX_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

    /// Tarpit settings from their parts.
    #[must_use]
    pub const fn new(
        delay_min: Duration,
        delay_max: Duration,
        max_duration: Duration,
        max_sessions: u32,
        max_bytes_per_second: Option<u64>,
    ) -> Self {
        Self {
            delay_min,
            delay_max,
            max_duration,
            max_sessions,
            max_bytes_per_second,
        }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: a delay range that is empty, zero or longer
    /// than `max_duration`, a duration of zero or of more than a day, no
    /// sessions allowed, or a rate cap of zero.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.delay_min > self.delay_max {
            return Err("the shortest delay must not exceed the longest delay");
        }
        if self.delay_max.is_zero() {
            return Err("the longest delay must be greater than zero");
        }
        if self.max_duration.is_zero() || self.max_duration > Self::MAX_DURATION {
            return Err("max_duration must be greater than zero and at most one day");
        }
        if self.delay_max > self.max_duration {
            return Err("the longest delay must not exceed max_duration");
        }
        if self.max_sessions == 0 {
            return Err("max_sessions must be at least 1");
        }
        if self.max_bytes_per_second == Some(0) {
            return Err("max_bytes_per_second must be greater than zero");
        }
        Ok(())
    }
}

impl Default for TarpitSettings {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(2),
            Duration::from_secs(30),
            Duration::from_secs(10 * 60),
            50,
            None,
        )
    }
}

/// How many generated rows the `fake_data` response adds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FakeDataSettings {
    /// The number of rows added to a result.
    pub rows: u32,
}

impl FakeDataSettings {
    /// The largest accepted number of rows.
    pub const MAX_ROWS: u32 = 100_000;

    /// Fake-data settings from their parts.
    #[must_use]
    pub const fn new(rows: u32) -> Self {
        Self { rows }
    }

    /// Checks the values.
    ///
    /// # Errors
    ///
    /// Returns what is wrong: a row count of zero or above
    /// [`FakeDataSettings::MAX_ROWS`].
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.rows == 0 || self.rows > Self::MAX_ROWS {
            return Err("rows must be between 1 and 100000");
        }
        Ok(())
    }
}

impl Default for FakeDataSettings {
    fn default() -> Self {
        Self::new(500)
    }
}

/// The settings of every response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ActionSettings {
    /// The error a killed session receives.
    pub kill: KillSettings,
    /// How a tarpitted session is slowed down.
    pub tarpit: TarpitSettings,
    /// How many rows `fake_data` adds.
    pub fake_data: FakeDataSettings,
}

impl ActionSettings {
    /// Action settings from their parts.
    #[must_use]
    pub const fn new(
        kill: KillSettings,
        tarpit: TarpitSettings,
        fake_data: FakeDataSettings,
    ) -> Self {
        Self {
            kill,
            tarpit,
            fake_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_safe_ones() {
        assert_eq!(OnError::default(), OnError::FailClosed);
        assert_eq!(QueryRedaction::default(), QueryRedaction::Fingerprint);

        let inspection = Inspection::default();
        assert_eq!(inspection.on_error, OnError::FailClosed);
        assert_eq!(inspection.max_buffered_frame, 1024 * 1024);
        assert_eq!(inspection.validate(), Ok(()));

        let actions = ActionSettings::default();
        assert_eq!(actions.kill.sqlstate.as_str(), "57P01");
        assert_eq!(actions.kill.message, KillSettings::DEFAULT_MESSAGE);
        assert_eq!(actions.kill.validate(), Ok(()));
        assert_eq!(actions.tarpit.validate(), Ok(()));
        assert_eq!(actions.fake_data.validate(), Ok(()));
    }

    #[test]
    fn enumerations_use_snake_case_in_json() {
        assert_eq!(
            serde_json::to_string(&OnError::FailClosed).unwrap(),
            "\"fail_closed\""
        );
        assert_eq!(
            serde_json::to_string(&OnError::FailOpen).unwrap(),
            "\"fail_open\""
        );
        assert_eq!(
            serde_json::to_string(&QueryRedaction::Full).unwrap(),
            "\"full\""
        );
        assert_eq!(
            serde_json::to_string(&QueryRedaction::Fingerprint).unwrap(),
            "\"fingerprint\""
        );
        assert_eq!(
            serde_json::to_string(&QueryRedaction::None).unwrap(),
            "\"none\""
        );
        assert!(serde_json::from_str::<OnError>("\"open\"").is_err());
    }

    #[test]
    fn the_buffer_limit_is_bounded() {
        let with = |bytes| Inspection::new(OnError::FailClosed, bytes).validate();
        assert!(with(0).is_err());
        assert!(with(1023).is_err());
        assert_eq!(with(1024), Ok(()));
        assert_eq!(with(1024 * 1024 * 1024), Ok(()));
        assert!(with(1024 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn sqlstate_codes_are_five_digits_or_capitals() {
        for text in ["57P01", "00000", "XX000", "42P01", "ZZZZZ"] {
            let code: SqlState = text.parse().unwrap();
            assert_eq!(code.as_str(), text);
            assert_eq!(code.as_bytes(), text.as_bytes());
            assert_eq!(code.to_string(), text);
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(serde_json::from_str::<SqlState>(&json).unwrap(), code);
        }
        for text in [
            "",
            "57P0",
            "57P011",
            "57p01",
            "57 01",
            "57-01",
            "57P0\u{e9}",
            "\0\0\0\0\0",
        ] {
            assert_eq!(text.parse::<SqlState>(), Err(InvalidSqlState), "{text:?}");
        }
        assert_eq!(format!("{:?}", SqlState::ADMIN_SHUTDOWN), "SqlState(57P01)");
        assert!(serde_json::from_str::<SqlState>("57014").is_err());
    }

    #[test]
    fn a_kill_message_must_be_a_single_printable_line() {
        let with = |message: &str| {
            KillSettings::new(SqlState::ADMIN_SHUTDOWN, message.to_owned()).validate()
        };
        assert_eq!(with("terminating connection"), Ok(()));
        assert_eq!(with(&"x".repeat(512)), Ok(()));
        assert!(with("").is_err());
        assert!(with(&"x".repeat(513)).is_err());
        assert!(with("two\nlines").is_err());
        assert!(with("nul\0byte").is_err());
        assert!(with("tab\there").is_err());
        assert!(with("caf\u{e9}").is_err());
    }

    #[test]
    fn tarpit_settings_must_be_bounded_and_consistent() {
        let seconds = Duration::from_secs;
        let base = TarpitSettings::default();
        assert_eq!(base.validate(), Ok(()));

        let fixed = TarpitSettings::new(seconds(5), seconds(5), seconds(60), 1, Some(1));
        assert_eq!(fixed.validate(), Ok(()));

        let cases = [
            TarpitSettings::new(seconds(31), seconds(30), seconds(600), 50, None),
            TarpitSettings::new(seconds(0), seconds(0), seconds(600), 50, None),
            TarpitSettings::new(seconds(2), seconds(30), seconds(0), 50, None),
            TarpitSettings::new(seconds(2), seconds(30), seconds(86_401), 50, None),
            TarpitSettings::new(seconds(2), seconds(700), seconds(600), 50, None),
            TarpitSettings::new(seconds(2), seconds(30), seconds(600), 0, None),
            TarpitSettings::new(seconds(2), seconds(30), seconds(600), 50, Some(0)),
        ];
        for case in cases {
            assert!(case.validate().is_err(), "{case:?}");
        }
    }

    #[test]
    fn fake_data_rows_are_bounded() {
        assert!(FakeDataSettings::new(0).validate().is_err());
        assert_eq!(FakeDataSettings::new(1).validate(), Ok(()));
        assert_eq!(FakeDataSettings::new(100_000).validate(), Ok(()));
        assert!(FakeDataSettings::new(100_001).validate().is_err());
    }
}
