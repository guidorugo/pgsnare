// SPDX-License-Identifier: Apache-2.0

//! Address ranges.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A range of IP addresses, written as an address and a prefix length, such
/// as `192.0.2.0/24` or `2001:db8::/32`.
///
/// The prefix length is required, and the bits after the prefix must be
/// zero. `192.0.2.5/24` is therefore rejected instead of being read as the
/// whole `/24`, which is probably not what its author meant.
///
/// An IPv4 client that reaches a dual-stack listener shows up as an
/// IPv4-mapped IPv6 address. [`IpCidr::contains`] treats such an address as
/// the IPv4 address it stands for, so an IPv4 range matches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

/// The text is not an address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCidr;

const EXPECTING: &str = "an address range such as 192.0.2.0/24 or 2001:db8::/32, \
                         with a prefix length and no bits set after the prefix";

impl fmt::Display for InvalidCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTING)
    }
}

impl core::error::Error for InvalidCidr {}

/// The mask for an IPv4 prefix. A prefix of 0 gives 0.
fn mask_v4(prefix_len: u8) -> u32 {
    let host_bits = 32u8.saturating_sub(prefix_len);
    u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0)
}

/// The mask for an IPv6 prefix. A prefix of 0 gives 0.
fn mask_v6(prefix_len: u8) -> u128 {
    let host_bits = 128u8.saturating_sub(prefix_len);
    u128::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0)
}

/// An IPv4-mapped IPv6 address as the IPv4 address it stands for.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

impl IpCidr {
    /// A range from its network address and prefix length.
    ///
    /// Returns `None` if the prefix is longer than the address, or if a bit
    /// after the prefix is set.
    ///
    /// A range of IPv4-mapped IPv6 addresses becomes the IPv4 range it
    /// stands for, because that is how [`IpCidr::contains`] sees the
    /// addresses in it.
    #[must_use]
    pub fn new(network: IpAddr, prefix_len: u8) -> Option<Self> {
        if let IpAddr::V6(v6) = network
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            // The 96 leading bits of a mapped address are fixed, so a
            // shorter prefix would leave some of them after the prefix.
            let prefix_len = prefix_len.checked_sub(96)?;
            return Self::new(IpAddr::V4(v4), prefix_len);
        }
        let aligned = match network {
            IpAddr::V4(v4) => prefix_len <= 32 && u32::from(v4) & !mask_v4(prefix_len) == 0,
            IpAddr::V6(v6) => prefix_len <= 128 && u128::from(v6) & !mask_v6(prefix_len) == 0,
        };
        aligned.then_some(Self {
            network,
            prefix_len,
        })
    }

    /// The first address of the range.
    #[must_use]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The number of leading bits every address in the range shares.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether the address lies in the range.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, canonical(address)) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                u32::from(address) & mask_v4(self.prefix_len) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                u128::from(address) & mask_v6(self.prefix_len) == u128::from(network)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for IpCidr {
    type Err = InvalidCidr;

    fn from_str(text: &str) -> Result<Self, InvalidCidr> {
        let (address, prefix) = text.split_once('/').ok_or(InvalidCidr)?;
        // Plain digits only: `u8::from_str` alone would accept a leading
        // plus sign and leading zeros.
        let plain_number = !prefix.is_empty()
            && prefix.len() <= 3
            && prefix.bytes().all(|byte| byte.is_ascii_digit())
            && (prefix == "0" || !prefix.starts_with('0'));
        if !plain_number {
            return Err(InvalidCidr);
        }
        let prefix_len: u8 = prefix.parse().map_err(|_| InvalidCidr)?;
        let network = if address.contains(':') {
            IpAddr::V6(Ipv6Addr::from_str(address).map_err(|_| InvalidCidr)?)
        } else {
            IpAddr::V4(Ipv4Addr::from_str(address).map_err(|_| InvalidCidr)?)
        };
        Self::new(network, prefix_len).ok_or(InvalidCidr)
    }
}

impl Serialize for IpCidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct CidrVisitor;

impl de::Visitor<'_> for CidrVisitor {
    type Value = IpCidr;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(EXPECTING)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<IpCidr, E> {
        text.parse()
            .map_err(|_| E::invalid_value(de::Unexpected::Other("other text"), &self))
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(CidrVisitor)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn cidr(text: &str) -> IpCidr {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn ranges_are_parsed_and_printed() {
        for text in [
            "192.0.2.0/24",
            "192.0.2.5/32",
            "198.51.100.0/22",
            "0.0.0.0/0",
            "2001:db8::/32",
            "2001:db8::1/128",
            "::/0",
        ] {
            assert_eq!(cidr(text).to_string(), text);
        }
        assert_eq!(cidr("192.0.2.0/24").prefix_len(), 24);
        assert_eq!(cidr("192.0.2.0/24").network(), ip("192.0.2.0"));
    }

    #[test]
    fn malformed_ranges_are_rejected() {
        for text in [
            "",
            "192.0.2.5",      // no prefix length
            "192.0.2.5/",     // empty prefix length
            "192.0.2.5/24",   // bits set after the prefix
            "192.0.2.0/33",   // prefix too long
            "192.0.2.0/+24",  // a sign
            "192.0.2.0/024x", // not a number
            "192.0.2.0/0024", // too many digits
            "192.0.2.0/024",  // a leading zero
            "192.0.2.0/00",   // a leading zero
            "192.0.2/24",     // not an address
            "192.0.2.0/24/8", // two prefixes
            " 192.0.2.0/24",  // leading space
            "2001:db8::1/64", // bits set after the prefix
            "2001:db8::/129", // prefix too long
            "example.com/24", // a host name
            "/24",
        ] {
            assert_eq!(text.parse::<IpCidr>(), Err(InvalidCidr), "{text:?}");
        }
    }

    #[test]
    fn a_range_contains_its_addresses_and_no_others() {
        let range = cidr("198.51.100.0/24");
        assert!(range.contains(ip("198.51.100.0")));
        assert!(range.contains(ip("198.51.100.77")));
        assert!(range.contains(ip("198.51.100.255")));
        assert!(!range.contains(ip("198.51.101.0")));
        assert!(!range.contains(ip("198.51.99.255")));
        assert!(!range.contains(ip("2001:db8::1")));

        let single = cidr("192.0.2.5/32");
        assert!(single.contains(ip("192.0.2.5")));
        assert!(!single.contains(ip("192.0.2.4")));
        assert!(!single.contains(ip("192.0.2.6")));

        let v6 = cidr("2001:db8:aa00::/40");
        assert!(v6.contains(ip("2001:db8:aa00::1")));
        assert!(v6.contains(ip("2001:db8:aaff:ffff::1")));
        assert!(!v6.contains(ip("2001:db8:ab00::1")));
        assert!(!v6.contains(ip("192.0.2.5")));

        assert!(cidr("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(!cidr("0.0.0.0/0").contains(ip("2001:db8::1")));
        assert!(cidr("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn an_ipv4_mapped_address_counts_as_ipv4() {
        let range = cidr("192.0.2.0/24");
        assert!(range.contains(ip("::ffff:192.0.2.5")));
        assert!(!range.contains(ip("::ffff:198.51.100.5")));
        // And it does not count as IPv6.
        assert!(!cidr("::/0").contains(ip("::ffff:192.0.2.5")));
    }

    #[test]
    fn a_range_of_ipv4_mapped_addresses_becomes_the_ipv4_range() {
        assert_eq!(cidr("::ffff:192.0.2.0/120"), cidr("192.0.2.0/24"));
        assert_eq!(cidr("::ffff:0:0/96"), cidr("0.0.0.0/0"));
        assert!(cidr("::ffff:192.0.2.0/120").contains(ip("192.0.2.9")));
        assert!(cidr("::ffff:192.0.2.0/120").contains(ip("::ffff:192.0.2.9")));
        // A shorter prefix cannot cover the fixed part of a mapped address.
        assert_eq!("::ffff:0:0/95".parse::<IpCidr>(), Err(InvalidCidr));
        assert_eq!("::ffff:192.0.2.5/120".parse::<IpCidr>(), Err(InvalidCidr));
    }

    #[test]
    fn json_uses_the_text_form() {
        let range = cidr("192.0.2.0/24");
        let json = serde_json::to_string(&range).unwrap();
        assert_eq!(json, "\"192.0.2.0/24\"");
        assert_eq!(serde_json::from_str::<IpCidr>(&json).unwrap(), range);
        assert!(serde_json::from_str::<IpCidr>("\"192.0.2.5\"").is_err());
        assert!(serde_json::from_str::<IpCidr>("24").is_err());
    }

    proptest! {
        #[test]
        fn an_ipv4_range_contains_exactly_the_addresses_with_its_prefix(
            address in any::<u32>(),
            probe in any::<u32>(),
            prefix_len in 0u8..=32,
        ) {
            let shift = 32 - u32::from(prefix_len);
            let network = if shift == 32 { 0 } else { (address >> shift) << shift };
            let range = IpCidr::new(IpAddr::V4(Ipv4Addr::from(network)), prefix_len).unwrap();
            let same_prefix = if shift == 32 { true } else { probe >> shift == network >> shift };
            prop_assert_eq!(range.contains(IpAddr::V4(Ipv4Addr::from(probe))), same_prefix);
            prop_assert!(range.contains(IpAddr::V4(Ipv4Addr::from(network))));
            prop_assert_eq!(range.to_string().parse::<IpCidr>(), Ok(range));
        }

        #[test]
        fn an_ipv6_range_contains_exactly_the_addresses_with_its_prefix(
            address in any::<u128>(),
            probe in any::<u128>(),
            prefix_len in 0u8..=128,
        ) {
            let shift = 128 - u32::from(prefix_len);
            let network = if shift == 128 { 0 } else { (address >> shift) << shift };
            let network_address = Ipv6Addr::from(network);
            let probe_address = Ipv6Addr::from(probe);
            // Mapped addresses are covered by a test of their own.
            prop_assume!(probe_address.to_ipv4_mapped().is_none());
            let range = IpCidr::new(IpAddr::V6(network_address), prefix_len).unwrap();
            let same_prefix = if shift == 128 { true } else { probe >> shift == network >> shift };
            prop_assert_eq!(range.contains(IpAddr::V6(probe_address)), same_prefix);
            prop_assert_eq!(range.to_string().parse::<IpCidr>(), Ok(range));
        }

        #[test]
        fn parsing_never_panics(text in "\\PC{0,48}") {
            let _ = text.parse::<IpCidr>();
        }
    }
}
