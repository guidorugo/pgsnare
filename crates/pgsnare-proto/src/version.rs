// SPDX-License-Identifier: Apache-2.0

//! The protocol version number.

use core::fmt;

/// A protocol version as it appears on the wire: the major version in the
/// upper 16 bits and the minor version in the lower 16 bits.
///
/// Versions order by major version first, then by minor version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    /// Protocol 3.0, spoken by every supported PostgreSQL version.
    pub const V3_0: Self = Self::new(3, 0);

    /// Protocol 3.2, introduced by PostgreSQL 18. It differs from 3.0 in the
    /// length of the cancel key.
    pub const V3_2: Self = Self::new(3, 2);

    /// Builds a version from its major and minor parts.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        let [a, b] = major.to_be_bytes();
        let [c, d] = minor.to_be_bytes();
        Self(u32::from_be_bytes([a, b, c, d]))
    }

    /// Interprets a 32-bit wire value as a version.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// The 32-bit wire value of this version.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// The major version.
    #[must_use]
    pub const fn major(self) -> u16 {
        let [a, b, _, _] = self.0.to_be_bytes();
        u16::from_be_bytes([a, b])
    }

    /// The minor version.
    #[must_use]
    pub const fn minor(self) -> u16 {
        let [_, _, c, d] = self.0.to_be_bytes();
        u16::from_be_bytes([c, d])
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major(), self.minor())
    }
}

impl fmt::Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProtocolVersion({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_match_postgresql() {
        assert_eq!(ProtocolVersion::V3_0.to_u32(), 196_608);
        assert_eq!(ProtocolVersion::V3_2.to_u32(), 196_610);
        assert_eq!(ProtocolVersion::new(1234, 5679).to_u32(), 80_877_103);
    }

    #[test]
    fn parts_round_trip() {
        let version = ProtocolVersion::from_u32(0x0003_0002);
        assert_eq!(version.major(), 3);
        assert_eq!(version.minor(), 2);
        assert_eq!(version, ProtocolVersion::V3_2);
        let extreme = ProtocolVersion::new(u16::MAX, u16::MAX);
        assert_eq!(extreme.to_u32(), u32::MAX);
        assert_eq!(extreme.major(), u16::MAX);
        assert_eq!(extreme.minor(), u16::MAX);
    }

    #[test]
    fn orders_by_major_then_minor() {
        assert!(ProtocolVersion::V3_0 < ProtocolVersion::V3_2);
        assert!(ProtocolVersion::new(3, 9999) < ProtocolVersion::new(4, 0));
        assert!(ProtocolVersion::new(2, 0) < ProtocolVersion::V3_0);
    }

    #[test]
    fn formats_as_major_dot_minor() {
        assert_eq!(ProtocolVersion::V3_2.to_string(), "3.2");
        assert_eq!(
            format!("{:?}", ProtocolVersion::V3_0),
            "ProtocolVersion(3.0)"
        );
    }
}
