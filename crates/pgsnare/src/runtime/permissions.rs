// SPDX-License-Identifier: Apache-2.0

//! Refusing files that other users can read.
//!
//! A private key, a token file and the configuration file hold what must
//! stay secret, so pgsnare does not start when one of them is open to
//! other users. The rule is the one PostgreSQL applies to its own private
//! key:
//!
//! - the file is a regular file, or a link to one
//! - it is owned by the user pgsnare runs as, or by root
//! - owned by that user, nobody else may do anything with it: mode `0600`
//!   or less
//! - owned by root, the group may read it and nobody else may do anything
//!   with it: mode `0640` or less
//!
//! The second form is what lets a file be shared with a service through a
//! group, which is how a container platform mounts a secret for a process
//! that does not run as root.

use std::fmt;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// What is wrong with the access rights of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// The file could not be examined.
    Unreadable(io::ErrorKind),
    /// It is not a regular file.
    NotAFile,
    /// It belongs to a user other than the one pgsnare runs as and root.
    WrongOwner,
    /// It belongs to the user pgsnare runs as and the group or others have
    /// access.
    OpenToOthers,
    /// It belongs to root and the group can do more than read it, or
    /// others have access.
    OpenToOthersAsRoot,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(kind) => write!(f, "the file cannot be examined: {kind}"),
            Self::NotAFile => f.write_str("this is not a regular file"),
            Self::WrongOwner => {
                f.write_str("the file must be owned by the user pgsnare runs as, or by root")
            }
            Self::OpenToOthers => f.write_str(
                "the file is open to the group or to others; it is owned by the user pgsnare \
                 runs as, so its mode must be 0600 or less",
            ),
            Self::OpenToOthersAsRoot => f.write_str(
                "the file is open to others, or the group can do more than read it; it is \
                 owned by root, so its mode must be 0640 or less",
            ),
        }
    }
}

/// A file whose access rights are not acceptable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The file.
    pub file: PathBuf,
    /// What is wrong with it.
    pub problem: Problem,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file.display(), self.problem)
    }
}

impl std::error::Error for Refused {}

/// The user this process runs as.
#[must_use]
pub fn effective_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Applies the rule to an owner and a mode.
const fn judge(owner: u32, mode: u32, user: u32) -> Result<(), Problem> {
    if owner == user {
        // Nobody else: no bit for the group, none for others.
        if mode & 0o077 != 0 {
            return Err(Problem::OpenToOthers);
        }
        return Ok(());
    }
    if owner == 0 {
        // The group may read. It may not write or execute, and others may
        // do nothing.
        if mode & 0o037 != 0 {
            return Err(Problem::OpenToOthersAsRoot);
        }
        return Ok(());
    }
    Err(Problem::WrongOwner)
}

/// Checks one file for `user`, the user the process runs as.
///
/// A symbolic link is followed: what counts is the file it leads to.
///
/// # Errors
///
/// Returns what is wrong with the file.
pub fn check_as(file: &Path, user: u32) -> Result<(), Problem> {
    let metadata = std::fs::metadata(file).map_err(|error| Problem::Unreadable(error.kind()))?;
    if !metadata.is_file() {
        return Err(Problem::NotAFile);
    }
    judge(metadata.uid(), metadata.mode() & 0o7777, user)
}

/// Checks every file for the user this process runs as and returns the
/// ones that are refused, in the order given.
#[must_use]
pub fn check_all<'a>(files: impl IntoIterator<Item = &'a Path>) -> Vec<Refused> {
    let user = effective_user();
    files
        .into_iter()
        .filter_map(|file| {
            check_as(file, user).err().map(|problem| Refused {
                file: file.to_path_buf(),
                problem,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn a_file_of_the_user_must_be_closed_to_everybody_else() {
        let user = 1000;
        for mode in [0o600, 0o400, 0o200, 0o000, 0o700] {
            assert_eq!(judge(user, mode, user), Ok(()), "{mode:o}");
        }
        for mode in [
            0o640, 0o660, 0o604, 0o644, 0o610, 0o601, 0o602, 0o620, 0o777,
        ] {
            assert_eq!(
                judge(user, mode, user),
                Err(Problem::OpenToOthers),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn a_file_of_root_may_be_read_by_the_group() {
        let user = 1000;
        for mode in [0o640, 0o600, 0o440, 0o400, 0o040, 0o000, 0o740] {
            assert_eq!(judge(0, mode, user), Ok(()), "{mode:o}");
        }
        for mode in [0o660, 0o650, 0o644, 0o641, 0o642, 0o604, 0o664, 0o777] {
            assert_eq!(
                judge(0, mode, user),
                Err(Problem::OpenToOthersAsRoot),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn root_itself_is_held_to_the_stricter_rule() {
        // When pgsnare runs as root, a file of root is its own file.
        assert_eq!(judge(0, 0o600, 0), Ok(()));
        assert_eq!(judge(0, 0o640, 0), Err(Problem::OpenToOthers));
    }

    #[test]
    fn a_file_of_anybody_else_is_refused_whatever_its_mode() {
        for mode in [0o600, 0o400, 0o000, 0o644] {
            assert_eq!(
                judge(1001, mode, 1000),
                Err(Problem::WrongOwner),
                "{mode:o}"
            );
        }
    }

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-permissions-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, "content").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn files_on_disk_are_judged_by_their_owner_and_mode() {
        let dir = TempDir::new();
        let user = effective_user();
        let closed = dir.file("closed.key", 0o600);
        let group = dir.file("group.key", 0o640);
        let world = dir.file("world.key", 0o644);

        assert_eq!(check_as(&closed, user), Ok(()));
        assert_eq!(check_as(&group, user), Err(Problem::OpenToOthers));
        assert_eq!(check_as(&world, user), Err(Problem::OpenToOthers));
        // The same files, seen by a process that runs as somebody else.
        if user != 0 {
            assert_eq!(check_as(&closed, user + 1), Err(Problem::WrongOwner));
        }

        assert_eq!(check_as(&dir.0, user), Err(Problem::NotAFile));
        assert_eq!(
            check_as(&dir.0.join("missing.key"), user),
            Err(Problem::Unreadable(io::ErrorKind::NotFound))
        );

        // A link is judged by what it leads to, as a mounted secret is.
        let link = dir.0.join("link.key");
        std::os::unix::fs::symlink(&closed, &link).unwrap();
        assert_eq!(check_as(&link, user), Ok(()));
        let link = dir.0.join("open-link.key");
        std::os::unix::fs::symlink(&world, &link).unwrap();
        assert_eq!(check_as(&link, user), Err(Problem::OpenToOthers));

        let refused = check_all([closed.as_path(), world.as_path(), group.as_path()]);
        assert_eq!(
            refused
                .iter()
                .map(|refused| refused.file.as_path())
                .collect::<Vec<_>>(),
            [world.as_path(), group.as_path()]
        );
        assert!(refused[0].to_string().ends_with(
            "world.key: the file is open to the group or to others; it is owned by the user \
             pgsnare runs as, so its mode must be 0600 or less"
        ));
    }
}
