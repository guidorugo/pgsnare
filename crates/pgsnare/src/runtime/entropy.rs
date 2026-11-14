// SPDX-License-Identifier: Apache-2.0

//! The secure random generator of the operating system, for the bait
//! `pgsnare token generate` prints and the jitter and bait of the
//! responses to a hit.

use pgsnare_core::bait::{Entropy, EntropyError};

/// The secure random generator of the operating system.
///
/// This is the source of randomness of every value the command prints. It
/// asks the operating system for every byte, through the `getrandom`
/// crate, and keeps no generator of its own. When the operating system
/// cannot give random bytes, [`Entropy::fill`] returns the error, and
/// nothing weaker is used in their place.
///
/// # Waiting
///
/// On Linux the operating system makes a caller wait only while its
/// generator has not been seeded, early in the start of the machine.
/// [`OsEntropy::new`] reads once, so that wait, if there is one, happens
/// when the source is made. After that a read does not wait: the source
/// asks for 256 bytes at a time at most, which the system call always
/// returns at once and in full.
#[derive(Clone, Copy, Debug)]
pub struct OsEntropy(());

impl OsEntropy {
    /// The most bytes asked of the operating system in one call.
    const CHUNK: usize = 256;

    /// Makes the source, and reads from it once to see that it works.
    ///
    /// # Errors
    ///
    /// Returns the error of the operating system if it cannot give random
    /// bytes.
    pub fn new() -> Result<Self, EntropyError> {
        let mut source = Self(());
        source.fill(&mut [0u8; 1])?;
        Ok(source)
    }
}

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in dest.chunks_mut(Self::CHUNK) {
            getrandom::fill(chunk).map_err(|error| match error.raw_os_error() {
                Some(number) => EntropyError::from_os_error(number),
                None => EntropyError::new(),
            })?;
        }
        Ok(())
    }
}
