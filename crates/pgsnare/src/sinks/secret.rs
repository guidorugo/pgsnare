// SPDX-License-Identifier: Apache-2.0

//! Reading what a sink must keep to itself: a signing key, and a URL that
//! is a secret.
//!
//! A configuration never holds such a thing. It names an environment
//! variable or a file, and this module reads from there, once, when the
//! sink is built.
//!
//! - The bytes that were read are wiped when they are dropped.
//! - An error names the variable or the file and says what is wrong with
//!   it. It never contains anything that was read.
//! - A file is read up to [`MAX_SECRET_BYTES`] and no further.
//! - One line break at the end of a file is not part of the secret. Tools
//!   that write a secret to a file tend to add one, and a receiver that
//!   was given the secret without it could verify nothing.
//!
//! Whether a file is closed to other users is not checked here. `pgsnare
//! run` checks that for every file that holds a secret before it reads the
//! first of them, with the rule and the override it has for private keys.
//!
//! The value of an environment variable stays in the environment of the
//! process for as long as it runs. A file can be closed again.

use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::config::{EnvVarName, SecretRef};

/// The most bytes a secret may have.
pub const MAX_SECRET_BYTES: usize = 4096;

/// Reads the secret a configuration names.
///
/// # Errors
///
/// Returns what is wrong, with the name of the variable or of the file and
/// nothing of their content.
pub(crate) fn read(reference: &SecretRef) -> Result<Zeroizing<Vec<u8>>, String> {
    match reference {
        SecretRef::Env(variable) => from_env(variable),
        SecretRef::File(file) => from_file(file),
    }
}

/// The value of an environment variable.
pub(crate) fn from_env(variable: &EnvVarName) -> Result<Zeroizing<Vec<u8>>, String> {
    let Some(value) = std::env::var_os(variable.as_str()) else {
        return Err(format!("the environment variable {variable} is not set"));
    };
    let value = Zeroizing::new(value.into_vec());
    if value.is_empty() {
        return Err(format!("the environment variable {variable} is empty"));
    }
    if value.len() > MAX_SECRET_BYTES {
        return Err(format!(
            "the value of the environment variable {variable} is longer than {MAX_SECRET_BYTES} bytes"
        ));
    }
    Ok(value)
}

/// The content of a file, without one line break at its end.
pub(crate) fn from_file(file: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let failed = |problem: &str| format!("{}: {problem}", file.display());
    let opened = File::open(file)
        .map_err(|error| failed(&format!("cannot read the file: {}", error.kind())))?;

    // One byte more than the limit is enough to know the file is too
    // large. The buffer never grows, so no copy of the secret is left
    // behind in memory that was given back.
    let mut content = Zeroizing::new(vec![0u8; MAX_SECRET_BYTES.saturating_add(1)]);
    let mut filled = 0;
    let mut reader = opened.take(u64::try_from(content.len()).unwrap_or(u64::MAX));
    loop {
        let room = content.get_mut(filled..).unwrap_or_default();
        if room.is_empty() {
            break;
        }
        match reader.read(room) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(failed(&format!("cannot read the file: {}", error.kind()))),
        }
    }
    if filled > MAX_SECRET_BYTES {
        return Err(failed(&format!(
            "the file is larger than {MAX_SECRET_BYTES} bytes"
        )));
    }
    content.truncate(filled);
    if content.last() == Some(&b'\n') {
        content.pop();
        if content.last() == Some(&b'\r') {
            content.pop();
        }
    }
    if content.is_empty() {
        return Err(failed("the file is empty"));
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-secret-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_gives_its_content_without_the_line_break_at_its_end() {
        let dir = TempDir::new();
        let read = |name: &str, content: &[u8]| {
            from_file(&dir.file(name, content)).map(|secret| secret.to_vec())
        };
        assert_eq!(
            read("plain", b"0123456789abcdef"),
            Ok(b"0123456789abcdef".to_vec())
        );
        assert_eq!(
            read("unix", b"0123456789abcdef\n"),
            Ok(b"0123456789abcdef".to_vec())
        );
        assert_eq!(
            read("dos", b"0123456789abcdef\r\n"),
            Ok(b"0123456789abcdef".to_vec())
        );
        // Only one line break goes, and nothing else does.
        assert_eq!(read("two", b"key\n\n"), Ok(b"key\n".to_vec()));
        assert_eq!(read("spaces", b" key \n"), Ok(b" key ".to_vec()));
        assert_eq!(read("binary", &[0, 255, 10, 13]), Ok(vec![0, 255, 10, 13]));
        // A key of exactly the largest size is taken.
        let largest = vec![b'k'; MAX_SECRET_BYTES];
        assert_eq!(read("largest", &largest), Ok(largest));
    }

    #[test]
    fn a_file_that_cannot_be_used_is_named_and_not_shown() {
        let dir = TempDir::new();
        let missing = dir.0.join("missing");
        let error = from_file(&missing).unwrap_err();
        assert_eq!(
            error,
            format!(
                "{}: cannot read the file: entity not found",
                missing.display()
            )
        );

        for content in [&b""[..], b"\n", b"\r\n"] {
            let file = dir.file("empty", content);
            assert_eq!(
                from_file(&file).unwrap_err(),
                format!("{}: the file is empty", file.display())
            );
        }

        let secret = vec![b'S'; MAX_SECRET_BYTES + 1];
        let file = dir.file("large", &secret);
        let error = from_file(&file).unwrap_err();
        assert_eq!(
            error,
            format!("{}: the file is larger than 4096 bytes", file.display())
        );
        assert!(!error.contains("SSSS"), "{error}");

        // A directory is not a file.
        assert!(
            from_file(&dir.0)
                .unwrap_err()
                .contains("cannot read the file")
        );
    }

    #[test]
    fn an_environment_variable_that_is_not_set_is_named() {
        let variable: EnvVarName = "PGSNARE_TEST_SECRET_THAT_IS_NOT_SET".parse().unwrap();
        assert_eq!(
            from_env(&variable).unwrap_err(),
            "the environment variable PGSNARE_TEST_SECRET_THAT_IS_NOT_SET is not set"
        );
        assert_eq!(
            read(&SecretRef::Env(variable)).unwrap_err(),
            "the environment variable PGSNARE_TEST_SECRET_THAT_IS_NOT_SET is not set"
        );
    }

    #[test]
    fn an_environment_variable_gives_its_value() {
        // A variable every process has. A test cannot set one: that takes
        // unsafe code, which this crate forbids. The variables a sink is
        // given are covered by the tests that start the pgsnare process.
        let Some(path) = std::env::var_os("PATH") else {
            return;
        };
        let variable: EnvVarName = "PATH".parse().unwrap();
        match from_env(&variable) {
            Ok(value) => assert_eq!(*value, path.into_vec()),
            Err(error) => assert!(error.contains("PATH"), "{error}"),
        }
    }
}
