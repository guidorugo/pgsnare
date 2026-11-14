// SPDX-License-Identifier: Apache-2.0

//! The hash behind the fingerprint of a statement.

use pgsnare_core::event::StatementDigest;

/// SHA-256, from the cryptographic library that TLS already uses.
///
/// This is what turns a statement into its fingerprint when an event shows
/// statements in the `fingerprint` mode: see
/// [`Query::from_statement`](pgsnare_core::event::Query::from_statement),
/// which also says what a fingerprint tells a reader of events.
///
/// ```
/// use pgsnare::redact::Sha256;
/// use pgsnare_core::event::Query;
/// use pgsnare_core::policy::QueryRedaction;
///
/// let query = Query::from_statement(b"SELECT 1", QueryRedaction::Fingerprint, &Sha256);
/// assert_eq!(
///     query.fingerprint.as_deref(),
///     Some("e004ebd5b5532a4b85984a62f8ad48a81aa3460c1ca07701f386135d72cdecf5")
/// );
/// assert_eq!(query.text, None);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sha256;

impl StatementDigest for Sha256 {
    fn digest(&self, statement: &[u8]) -> [u8; 32] {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, statement);
        let mut bytes = [0u8; 32];
        // SHA-256 gives 32 bytes. Should a library ever give another
        // number, the fingerprint is made of what fits.
        for (to, from) in bytes.iter_mut().zip(digest.as_ref()) {
            *to = *from;
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use pgsnare_core::event::Query;
    use pgsnare_core::policy::QueryRedaction;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn it_is_sha256() {
        // The test vectors of FIPS 180-2 for one block and for two.
        assert_eq!(
            hex(&Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&Sha256.digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&Sha256.digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_fingerprint_is_the_hash_of_the_statement_text() {
        let statement = b"SELECT * FROM users WHERE id = $1";
        let query = Query::from_statement(statement, QueryRedaction::Fingerprint, &Sha256);
        assert_eq!(
            query.fingerprint.as_deref(),
            Some(hex(&Sha256.digest(statement)).as_str())
        );
        // One more space is another statement.
        let other = Query::from_statement(
            b"SELECT  * FROM users WHERE id = $1",
            QueryRedaction::Fingerprint,
            &Sha256,
        );
        assert_ne!(other.fingerprint, query.fingerprint);
    }
}
