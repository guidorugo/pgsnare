// SPDX-License-Identifier: Apache-2.0

//! Where the randomness of a bait value comes from.

use core::fmt;

use super::error::BaitError;

/// A source of random bytes.
///
/// This crate asks nothing of the operating system, so the randomness of a
/// bait value is handed in by the caller, like the identifier of an event.
/// The runtime hands in the secure random generator of the operating
/// system. A test hands in a fixed sequence, which is the only way to make
/// a generator predictable.
///
/// # What an implementation must do
///
/// - Fill the whole buffer, or return an error. A buffer that is partly
///   filled, or filled with something weaker than was asked for, must never
///   be reported as a success: the generators build honeytokens from these
///   bytes and have no way to tell.
/// - Return without waiting. A generator runs on the data path of a
///   session.
pub trait Entropy {
    /// Fills `dest` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the source cannot fill the whole buffer.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError>;
}

impl<E: Entropy + ?Sized> Entropy for &mut E {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        (**self).fill(dest)
    }
}

impl<E: Entropy + ?Sized> Entropy for Box<E> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        (**self).fill(dest)
    }
}

/// A source of randomness could not fill a buffer.
///
/// The error may carry the error number the operating system gave, and
/// nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EntropyError {
    os_error: Option<i32>,
}

impl EntropyError {
    /// A failure with no further detail.
    #[must_use]
    pub const fn new() -> Self {
        Self { os_error: None }
    }

    /// A failure the operating system reported with this error number.
    #[must_use]
    pub const fn from_os_error(number: i32) -> Self {
        Self {
            os_error: Some(number),
        }
    }

    /// The error number of the operating system, if it gave one.
    #[must_use]
    pub const fn os_error(&self) -> Option<i32> {
        self.os_error
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the source of randomness failed")?;
        if let Some(number) = self.os_error {
            write!(f, " (operating system error {number})")?;
        }
        Ok(())
    }
}

impl core::error::Error for EntropyError {}

/// How many bytes are asked of the source at a time.
const POOL_BYTES: usize = 64;

/// How many bytes in a row may be thrown away while looking for one that
/// can be used.
///
/// A byte is thrown away when using it would make some outcomes more likely
/// than others. With a sound source that happens to fewer than half of the
/// bytes, so this many in a row happen once in 2^128 draws at most. A
/// source that keeps doing it is broken, and the generator stops instead of
/// asking for ever.
const MAX_DISCARDED: u32 = 128;

/// Takes random values from an [`Entropy`] in the shapes the generators
/// need.
///
/// It asks the source for [`POOL_BYTES`] bytes at a time and hands every
/// byte out once.
pub(super) struct Draw<'e> {
    entropy: &'e mut dyn Entropy,
    pool: [u8; POOL_BYTES],
    /// The position of the next unused byte of `pool`. Past its end, the
    /// pool is empty.
    next: usize,
}

impl<'e> Draw<'e> {
    pub(super) fn new(entropy: &'e mut dyn Entropy) -> Self {
        Self {
            entropy,
            pool: [0; POOL_BYTES],
            next: POOL_BYTES,
        }
    }

    /// One random byte.
    pub(super) fn byte(&mut self) -> Result<u8, BaitError> {
        if self.next >= POOL_BYTES {
            // On an error the pool stays empty, so that bytes of a failed
            // read can never be handed out.
            self.entropy.fill(&mut self.pool)?;
            self.next = 0;
        }
        let byte = self.pool.get(self.next).copied().ok_or(BaitError::Defect)?;
        self.next = self.next.saturating_add(1);
        Ok(byte)
    }

    /// `N` random bytes.
    pub(super) fn bytes<const N: usize>(&mut self) -> Result<[u8; N], BaitError> {
        let mut bytes = [0u8; N];
        for byte in &mut bytes {
            *byte = self.byte()?;
        }
        Ok(bytes)
    }

    /// A random number from 0 up to, and not including, `bound`. Every
    /// number is equally likely.
    ///
    /// A byte has 256 values. Unless `bound` divides 256, taking the
    /// remainder of a byte would favour the low numbers, so the bytes above
    /// the last whole multiple of `bound` are thrown away.
    pub(super) fn below(&mut self, bound: u8) -> Result<u8, BaitError> {
        let bound = u16::from(bound);
        let surplus = 256u16.checked_rem(bound).ok_or(BaitError::Defect)?;
        let usable = 256u16.checked_sub(surplus).ok_or(BaitError::Defect)?;
        for _ in 0..MAX_DISCARDED {
            let byte = u16::from(self.byte()?);
            if byte < usable {
                let number = byte.checked_rem(bound).ok_or(BaitError::Defect)?;
                return u8::try_from(number).map_err(|_| BaitError::Defect);
            }
        }
        Err(BaitError::UnusableEntropy)
    }

    /// One entry of `list`, every one equally likely.
    pub(super) fn pick<'l, T: ?Sized>(&mut self, list: &'l [&'l T]) -> Result<&'l T, BaitError> {
        let bound = u8::try_from(list.len()).map_err(|_| BaitError::Defect)?;
        let index = self.below(bound)?;
        list.get(usize::from(index))
            .copied()
            .ok_or(BaitError::Defect)
    }

    /// Appends `count` random characters of an alphabet of 32 to `out`.
    /// Each carries five random bits.
    pub(super) fn append_base32(
        &mut self,
        alphabet: &[u8; 32],
        count: usize,
        out: &mut String,
    ) -> Result<(), BaitError> {
        for _ in 0..count {
            // 32 divides 256, so the low five bits of a byte are uniform.
            let index = usize::from(self.byte()? & 0x1f);
            let symbol = alphabet.get(index).copied().ok_or(BaitError::Defect)?;
            out.push(char::from(symbol));
        }
        Ok(())
    }

    /// Appends `count` random decimal digits to `out`.
    pub(super) fn append_digits(
        &mut self,
        count: usize,
        out: &mut Vec<u8>,
    ) -> Result<(), BaitError> {
        for _ in 0..count {
            out.push(self.below(10)?);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod testing {
    //! Sources of randomness for tests.

    use super::{Entropy, EntropyError};

    /// A long sequence of bytes that looks random and is the same in every
    /// run: the SplitMix64 generator. It is here to make tests repeatable
    /// and is not a secure generator.
    pub(crate) struct Sequence {
        state: u64,
        buffered: [u8; 8],
        used: usize,
    }

    impl Sequence {
        pub(crate) fn new(seed: u64) -> Self {
            Self {
                state: seed,
                buffered: [0; 8],
                used: 8,
            }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl Entropy for Sequence {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            for byte in dest {
                if self.used == 8 {
                    self.buffered = self.next_u64().to_le_bytes();
                    self.used = 0;
                }
                *byte = self.buffered[self.used];
                self.used += 1;
            }
            Ok(())
        }
    }

    /// Every byte is the same.
    pub(crate) struct Constant(pub(crate) u8);

    impl Entropy for Constant {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.fill(self.0);
            Ok(())
        }
    }

    /// A source that always fails, and scribbles on the buffer first, as a
    /// failed read may.
    pub(crate) struct Failing;

    impl Entropy for Failing {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            dest.fill(0x41);
            Err(EntropyError::from_os_error(5))
        }
    }

    /// The given bytes, and then failure.
    pub(crate) struct Script {
        bytes: Vec<u8>,
        used: usize,
    }

    impl Script {
        pub(crate) fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: bytes.into(),
                used: 0,
            }
        }
    }

    impl Entropy for Script {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
            let Some(bytes) = self.bytes.get(self.used..self.used + dest.len()) else {
                return Err(EntropyError::new());
            };
            dest.copy_from_slice(bytes);
            self.used += dest.len();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Constant, Failing, Script, Sequence};
    use super::*;

    #[test]
    fn every_byte_of_the_source_is_handed_out_once_and_in_order() {
        let bytes: Vec<u8> = (0..=255).collect();
        let mut source = Script::new(bytes.clone());
        let mut draw = Draw::new(&mut source);
        let mut seen = Vec::new();
        for _ in 0..(POOL_BYTES * 4) {
            seen.push(draw.byte().unwrap());
        }
        assert_eq!(seen, bytes);
        // The source has nothing left, and that is an error, not a repeat.
        assert_eq!(draw.byte(), Err(BaitError::Entropy(EntropyError::new())));
    }

    #[test]
    fn a_failed_read_hands_out_nothing() {
        let mut source = Failing;
        let mut draw = Draw::new(&mut source);
        let failed = BaitError::Entropy(EntropyError::from_os_error(5));
        assert_eq!(draw.byte(), Err(failed));
        // The bytes the failed read left in the buffer are not used later.
        assert_eq!(draw.byte(), Err(failed));
        assert_eq!(draw.bytes::<4>(), Err(failed));
        assert_eq!(draw.below(10), Err(failed));
    }

    #[test]
    fn several_bytes_are_taken_across_refills() {
        let mut source = Sequence::new(1);
        let mut draw = Draw::new(&mut source);
        let a: [u8; 48] = draw.bytes().unwrap();
        let b: [u8; 48] = draw.bytes().unwrap();
        assert_ne!(a, b);

        // The same as reading the source directly.
        let mut direct = [0u8; 128];
        Sequence::new(1).fill(&mut direct).unwrap();
        assert_eq!(a, direct[..48]);
        assert_eq!(b, direct[48..96]);
    }

    #[test]
    fn a_number_below_a_bound_is_never_the_bound_or_more() {
        let mut source = Sequence::new(2);
        let mut draw = Draw::new(&mut source);
        for bound in 1..=u8::MAX {
            for _ in 0..50 {
                assert!(draw.below(bound).unwrap() < bound, "{bound}");
            }
        }
    }

    #[test]
    fn every_number_below_a_bound_is_equally_likely() {
        // Every byte value once: after throwing away the surplus, each
        // number must come up exactly as often as every other.
        for bound in [1u8, 2, 3, 7, 8, 10, 32, 33, 100, 128, 255] {
            let mut counts = vec![0u32; usize::from(bound)];
            let surplus = 256 % u16::from(bound);
            let usable = 256 - surplus;
            for byte in 0..=255u8 {
                let mut source = Script::new(vec![byte; POOL_BYTES]);
                let mut draw = Draw::new(&mut source);
                match draw.below(bound) {
                    Ok(number) => counts[usize::from(number)] += 1,
                    // Nothing but this byte was on offer.
                    Err(BaitError::Entropy(_)) => assert!(u16::from(byte) >= usable),
                    other => panic!("unexpected {other:?}"),
                }
            }
            let expected = u32::from(usable / u16::from(bound));
            assert!(
                counts.iter().all(|count| *count == expected),
                "bound {bound}: {counts:?}"
            );
        }
    }

    #[test]
    fn a_source_that_only_gives_surplus_bytes_ends_in_an_error() {
        // 255 is above the last whole multiple of 10, which is 250.
        let mut source = Constant(0xff);
        let mut draw = Draw::new(&mut source);
        assert_eq!(draw.below(10), Err(BaitError::UnusableEntropy));
        // 0xff is usable where the bound divides 256.
        assert_eq!(draw.below(16), Ok(15));
    }

    #[test]
    fn a_bound_of_zero_is_a_defect_and_not_a_panic() {
        let mut source = Sequence::new(3);
        let mut draw = Draw::new(&mut source);
        assert_eq!(draw.below(0), Err(BaitError::Defect));
        let empty: [&str; 0] = [];
        assert_eq!(draw.pick(&empty), Err(BaitError::Defect));
    }

    #[test]
    fn picking_reaches_every_entry() {
        let list = ["a", "b", "c", "d", "e"];
        let mut source = Sequence::new(4);
        let mut draw = Draw::new(&mut source);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            seen.insert(draw.pick(&list).unwrap());
        }
        assert_eq!(seen.len(), list.len());
    }

    #[test]
    fn base32_characters_and_digits_come_from_their_alphabets() {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut source = Sequence::new(5);
        let mut draw = Draw::new(&mut source);

        let mut text = String::from(">");
        draw.append_base32(alphabet, 500, &mut text).unwrap();
        assert_eq!(text.len(), 501);
        assert!(text[1..].bytes().all(|byte| alphabet.contains(&byte)));
        // All 32 characters turn up in 500 draws.
        let distinct: std::collections::BTreeSet<u8> = text[1..].bytes().collect();
        assert_eq!(distinct.len(), 32);

        let mut digits = vec![7u8];
        draw.append_digits(500, &mut digits).unwrap();
        assert_eq!(digits.len(), 501);
        assert!(digits.iter().all(|digit| *digit <= 9));
        let distinct: std::collections::BTreeSet<u8> = digits[1..].iter().copied().collect();
        assert_eq!(distinct.len(), 10);
    }

    #[test]
    fn the_error_shows_the_number_of_the_operating_system_and_nothing_else() {
        assert_eq!(
            EntropyError::new().to_string(),
            "the source of randomness failed"
        );
        assert_eq!(EntropyError::new().os_error(), None);
        assert_eq!(EntropyError::default(), EntropyError::new());
        let error = EntropyError::from_os_error(11);
        assert_eq!(error.os_error(), Some(11));
        assert_eq!(
            error.to_string(),
            "the source of randomness failed (operating system error 11)"
        );
    }

    #[test]
    fn a_borrowed_or_boxed_source_is_a_source() {
        fn take(mut entropy: impl Entropy) -> [u8; 4] {
            let mut bytes = [0u8; 4];
            entropy.fill(&mut bytes).unwrap();
            bytes
        }
        let mut source = Constant(9);
        assert_eq!(take(&mut source), [9; 4]);
        let boxed: Box<dyn Entropy> = Box::new(Constant(7));
        assert_eq!(take(boxed), [7; 4]);
    }
}
