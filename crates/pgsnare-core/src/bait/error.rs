// SPDX-License-Identifier: Apache-2.0

//! Why a bait value could not be generated.

use core::fmt;

use super::entropy::EntropyError;

/// Why a bait value could not be generated.
///
/// A generator returns a complete, well-formed value or one of these. It
/// never returns a value with less randomness than its kind promises.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BaitError {
    /// The source of randomness failed.
    Entropy(EntropyError),
    /// The source of randomness kept returning bytes that could only be
    /// used by making some values more likely than others. A sound source
    /// does not do that, so the generator gave up instead of asking for
    /// ever.
    UnusableEntropy,
    /// A generator produced something that breaks its own rules. This
    /// points at a defect in this crate, not at the caller.
    Defect,
}

impl fmt::Display for BaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(error) => write!(f, "{error}"),
            Self::UnusableEntropy => {
                f.write_str("the source of randomness does not return usable bytes")
            }
            Self::Defect => f.write_str("a bait generator broke its own rules"),
        }
    }
}

impl core::error::Error for BaitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Entropy(error) => Some(error),
            Self::UnusableEntropy | Self::Defect => None,
        }
    }
}

impl From<EntropyError> for BaitError {
    fn from(error: EntropyError) -> Self {
        Self::Entropy(error)
    }
}

#[cfg(test)]
mod tests {
    use core::error::Error;

    use super::*;

    #[test]
    fn every_error_has_a_fixed_message() {
        assert_eq!(
            BaitError::from(EntropyError::from_os_error(11)).to_string(),
            "the source of randomness failed (operating system error 11)"
        );
        assert_eq!(
            BaitError::UnusableEntropy.to_string(),
            "the source of randomness does not return usable bytes"
        );
        assert_eq!(
            BaitError::Defect.to_string(),
            "a bait generator broke its own rules"
        );
    }

    #[test]
    fn a_failed_source_is_the_cause() {
        assert!(BaitError::from(EntropyError::new()).source().is_some());
        assert!(BaitError::UnusableEntropy.source().is_none());
        assert!(BaitError::Defect.source().is_none());
    }
}
