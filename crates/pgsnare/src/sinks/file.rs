// SPDX-License-Identifier: Apache-2.0

//! The `file` sink: events appended to a file, one JSON object per line.
//!
//! # The file
//!
//! - **It is created closed to other users**, with mode `0600`. A file
//!   that is there already is written to only if it is closed enough: it
//!   belongs to the user pgsnare runs as, its mode gives the group no
//!   write and others nothing, and it has one name, no hard link beside
//!   it. Reading by the group is a normal arrangement: a log collector in
//!   the same group, as the `0640` of a `logrotate` `create`. Any other
//!   file is refused, and no event is written to it.
//! - **A symbolic link is never followed.** If the last part of the path
//!   is a link, the file is not opened: an event is not written to wherever
//!   somebody pointed a link. The directories on the way are the
//!   operator's to protect.
//! - **Only a regular file is written to**, not a pipe or a device that
//!   stands where the file should be.
//! - **Each event is appended**, whatever else writes to the file.
//!
//! # When the file is rotated
//!
//! Before each event the sink looks at what the path leads to.
//!
//! - **Renamed or removed**, as `logrotate` does by default: the next
//!   event goes to a new file at the path, which the sink creates if
//!   whatever rotated the file has not done so. Nothing has to tell
//!   pgsnare, and nothing is written to the old file once it has been
//!   moved away.
//! - **Emptied in place**, as `logrotate` does with `copytruncate`: the
//!   sink goes on writing at the new end of the file.
//!
//! # When a write fails
//!
//! The event is tried again later, like any delivery that failed. If only
//! a part of a line reached the file, as on a disk that filled up, the
//! next write starts with a line break, so that the broken line stays one
//! line and does not run into the event after it.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use pgsnare_core::event::Event;
use pgsnare_core::extension::{EventSink, SinkError, SinkFuture};
use rustix::fs::{Access, OFlags};

use super::lines::{LineOutput, Lines, json_line};

/// Why the file of a sink could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    /// The last part of the path is a symbolic link.
    SymbolicLink,
    /// The path leads to something that is not a regular file.
    NotAFile,
    /// The file could not be opened or created.
    Open(io::ErrorKind),
    /// The file belongs to another user than the one pgsnare runs as.
    OtherOwner,
    /// The mode of the file gives the group a write, or anything to others.
    OpenToOthers,
    /// The file has more than one name.
    Linked,
}

impl FileError {
    const fn text(self) -> &'static str {
        match self {
            Self::SymbolicLink => {
                "the path is a symbolic link, and events are not written through one"
            }
            Self::NotAFile => "the path does not lead to a regular file",
            Self::Open(_) => "the file cannot be opened",
            Self::OtherOwner => {
                "the file belongs to another user, and events are not written to it"
            }
            Self::OpenToOthers => {
                "the file can be read or written by others than its owner, and events are not \
                 written to it"
            }
            Self::Linked => "the file has more than one name, and events are not written to it",
        }
    }
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(kind) => write!(f, "{}: {kind}", self.text()),
            _ => f.write_str(self.text()),
        }
    }
}

impl std::error::Error for FileError {}

/// The file as it is open now.
struct Opened {
    file: File,
    device: u64,
    inode: u64,
}

/// Why a file with this mode, this owner and this number of names is not
/// written to by a process of the user `user`, or `None` when it is closed
/// enough to be written to.
const fn refusal(mode: u32, owner: u32, names: u64, user: u32) -> Option<FileError> {
    if owner != user {
        return Some(FileError::OtherOwner);
    }
    // The group may read the file: a collector in the same group, as the
    // 0640 of a logrotate create. A write for the group and anything for
    // others are not.
    if mode & 0o027 != 0 {
        return Some(FileError::OpenToOthers);
    }
    if names != 1 {
        return Some(FileError::Linked);
    }
    None
}

/// Opens the file at `path` for appending. With `create`, a file that is
/// not there is created, closed to other users. A file that is there and
/// is not closed enough is refused.
fn open(path: &Path, create: bool) -> Result<Opened, FileError> {
    // Not through a link, and without waiting for the other end of a pipe
    // that may stand where the file should be. Without these flags the
    // file is not opened at all.
    let flags = OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let flags =
        i32::try_from(flags.bits()).map_err(|_| FileError::Open(io::ErrorKind::Unsupported))?;
    let file = OpenOptions::new()
        .append(true)
        .create(create)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| {
            // The system says "too many levels of symbolic links" when the
            // last part of the path is one and may not be followed.
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                FileError::SymbolicLink
            } else {
                FileError::Open(error.kind())
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| FileError::Open(error.kind()))?;
    if !metadata.is_file() {
        return Err(FileError::NotAFile);
    }
    let user = rustix::process::geteuid().as_raw();
    if let Some(refused) = refusal(metadata.mode(), metadata.uid(), metadata.nlink(), user) {
        return Err(refused);
    }
    Ok(Opened {
        file,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

/// The file of a sink, and what the sink remembers about it.
struct EventsFile {
    path: PathBuf,
    opened: Option<Opened>,
    /// Whether the last write left a part of a line behind.
    torn: bool,
}

impl EventsFile {
    /// Opens the file for appending, and creates it when it is not there.
    fn open(&self) -> Result<Opened, FileError> {
        open(&self.path, true)
    }

    /// Whether the path still leads to the file that is open.
    fn is_current(&self, opened: &Opened) -> bool {
        // The path itself is looked at, not what a link there may lead to.
        std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.is_file() && metadata.dev() == opened.device && metadata.ino() == opened.inode
        })
    }
}

impl LineOutput for EventsFile {
    fn write_line(&mut self, line: &[u8]) -> Result<(), SinkError> {
        if self
            .opened
            .as_ref()
            .is_some_and(|opened| !self.is_current(opened))
        {
            // Rotated: what is open is no longer what the path leads to.
            self.opened = None;
            self.torn = false;
        }
        let mut opened = match self.opened.take() {
            Some(opened) => opened,
            None => self
                .open()
                .map_err(|error| SinkError::retryable(error.text()))?,
        };

        // A line that was cut short is ended first, so that it stays one
        // line.
        if self.torn {
            if write_all(&mut opened.file, b"\n").is_err() {
                return Err(SinkError::retryable(WRITE_FAILED));
            }
            self.torn = false;
        }
        match write_all(&mut opened.file, line) {
            Ok(()) => {
                self.opened = Some(opened);
                Ok(())
            }
            Err(written) => {
                // Whatever reached the file is the beginning of a line that
                // will never be finished. The file is opened anew for the
                // next attempt.
                self.torn = written > 0;
                Err(SinkError::retryable(WRITE_FAILED))
            }
        }
    }
}

/// What the sink says when a write fails.
const WRITE_FAILED: &str = "the file could not be written to";

/// Writes all of `bytes`. When that fails, says how many of them were
/// written before it did.
fn write_all(file: &mut File, bytes: &[u8]) -> Result<(), usize> {
    let mut written = 0;
    while let Some(rest) = bytes.get(written..).filter(|rest| !rest.is_empty()) {
        match file.write(rest) {
            Ok(0) => return Err(written),
            Ok(count) => written = written.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(written),
        }
    }
    Ok(())
}

/// Appends each event to a file as one line of JSON.
///
/// See the [module documentation](self) for how the file is opened and
/// what happens when it is rotated.
pub struct FileSink {
    name: String,
    path: PathBuf,
    lines: Lines<EventsFile>,
}

impl FileSink {
    /// A sink that appends to the file at `path`, which is opened now, and
    /// created if it is not there.
    ///
    /// `name` is what logs and metrics call the sink.
    ///
    /// # Errors
    ///
    /// Returns why the file cannot be opened. A sink whose file cannot be
    /// written to is better refused when the proxy starts than found out
    /// with the first event.
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Result<Self, FileError> {
        let name = name.into();
        let mut file = EventsFile {
            path: path.into(),
            opened: None,
            torn: false,
        };
        file.opened = Some(file.open()?);
        Ok(Self {
            name,
            path: file.path.clone(),
            lines: Lines::new(file),
        })
    }

    /// Whether a sink could be built for the file at `path`, found out
    /// without creating the file and without writing to it.
    ///
    /// A file that is there is opened the way [`FileSink::new`] opens it,
    /// and closed again. For a file that is not there, the directory it
    /// would be created in must be there, and this process must be allowed
    /// to create a file in it.
    ///
    /// # Errors
    ///
    /// Returns why `new` would fail. A file that is not there can still
    /// fail to be created for a reason that cannot be seen from here, such
    /// as a disk that is full.
    pub fn check(path: &Path) -> Result<(), FileError> {
        match open(path, false) {
            Ok(_) => Ok(()),
            Err(FileError::Open(io::ErrorKind::NotFound)) => {
                let directory = match path.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => parent,
                    _ => Path::new("."),
                };
                let failed = |error: io::Error| FileError::Open(error.kind());
                if !std::fs::metadata(directory).map_err(failed)?.is_dir() {
                    return Err(FileError::Open(io::ErrorKind::NotADirectory));
                }
                rustix::fs::access(directory, Access::WRITE_OK | Access::EXEC_OK)
                    .map_err(|error| failed(io::Error::from(error)))?;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The file events are appended to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for FileSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSink")
            .field("name", &self.name)
            .field("path", &self.path)
            .finish()
    }
}

impl EventSink for FileSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn deliver<'a>(&'a self, event: &'a Event) -> SinkFuture<'a> {
        Box::pin(async move { self.lines.write(json_line(event)?).await })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::super::lines::tests::event;
    use super::*;

    /// A directory that is removed again when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "pgsnare-file-sink-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }

    /// The users of the events in a file, one for each line.
    fn users(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| {
                let event: Event = serde_json::from_str(line).unwrap();
                event.body.db_user.unwrap()
            })
            .collect()
    }

    #[tokio::test]
    async fn events_are_appended_one_line_each_to_a_file_closed_to_others() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        let sink = FileSink::new("file-0", &path).unwrap();
        assert_eq!(sink.name(), "file-0");
        assert_eq!(sink.path(), path);

        // The file is there from the start, and only its owner may use it.
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        assert_eq!(mode(&path), 0o600);

        sink.deliver(&event("first")).await.unwrap();
        sink.deliver(&event("two\nlines")).await.unwrap();
        assert_eq!(users(&path), ["first", "two\nlines"]);
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.iter().filter(|byte| **byte == b'\n').count(), 2);
        assert_eq!(content.last(), Some(&b'\n'));
    }

    #[tokio::test]
    async fn a_file_that_is_there_and_closed_to_others_is_appended_to() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        std::fs::write(&path, "an earlier line\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("app")).await.unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("an earlier line\n{"), "{content}");
        assert_eq!(content.lines().count(), 2);
        assert_eq!(mode(&path), 0o600);
    }

    #[tokio::test]
    async fn a_file_that_its_group_may_read_is_written_to() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        std::fs::write(&path, "an earlier line\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(FileSink::check(&path), Ok(()));

        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("app")).await.unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("an earlier line\n{"), "{content}");
        assert_eq!(content.lines().count(), 2);
        assert_eq!(mode(&path), 0o640);
    }

    #[tokio::test]
    async fn a_file_that_is_open_to_others_is_not_written_to() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        for open in [0o660, 0o644, 0o620, 0o604, 0o602, 0o666] {
            std::fs::write(&path, "an earlier line\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(open)).unwrap();
            assert_eq!(
                FileSink::new("file-0", &path).err(),
                Some(FileError::OpenToOthers),
                "{open:o}"
            );
            assert_eq!(FileSink::check(&path), Err(FileError::OpenToOthers));
            // Nothing was written, and nothing about the file was changed.
            assert_eq!(std::fs::read(&path).unwrap(), b"an earlier line\n");
            assert_eq!(mode(&path), open);
        }

        // A file that is opened to others while the sink runs: the sink
        // notices when it opens the file anew, after a rotation.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("first")).await.unwrap();
        std::fs::rename(&path, dir.0.join("events.jsonl.1")).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(sink.deliver(&event("second")).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }

    #[tokio::test]
    async fn a_file_with_a_second_name_is_not_written_to() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let other_name = dir.0.join("another-name");
        std::fs::hard_link(&path, &other_name).unwrap();
        assert_eq!(
            FileSink::new("file-0", &path).err(),
            Some(FileError::Linked)
        );
        assert_eq!(FileSink::check(&path), Err(FileError::Linked));
        assert_eq!(std::fs::read(&other_name).unwrap(), b"");

        // With the other name gone, the file is the sink's alone.
        std::fs::remove_file(&other_name).unwrap();
        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("app")).await.unwrap();
        assert_eq!(users(&path), ["app"]);
    }

    #[test]
    fn only_a_file_of_the_user_that_gives_the_group_no_write_and_others_nothing_is_taken() {
        assert_eq!(refusal(0o100_600, 1000, 1, 1000), None);
        assert_eq!(refusal(0o100_400, 0, 1, 0), None);
        // The group may read it: a log collector in the same group.
        // Execute, too: the only group bit that is refused is the write.
        assert_eq!(refusal(0o100_640, 1000, 1, 1000), None);
        assert_eq!(refusal(0o100_610, 1000, 1, 1000), None);
        // The file of another user, also for a process that may write to
        // any file.
        assert_eq!(
            refusal(0o100_600, 1001, 1, 1000),
            Some(FileError::OtherOwner)
        );
        assert_eq!(refusal(0o100_600, 1000, 1, 0), Some(FileError::OtherOwner));
        for bit in [0o020, 0o004, 0o002, 0o001] {
            assert_eq!(
                refusal(0o100_600 | bit, 1000, 1, 1000),
                Some(FileError::OpenToOthers),
                "{bit:o}"
            );
        }
        assert_eq!(refusal(0o100_600, 1000, 2, 1000), Some(FileError::Linked));
        assert_eq!(refusal(0o100_600, 1000, 0, 1000), Some(FileError::Linked));
        for refused in [
            FileError::OtherOwner,
            FileError::OpenToOthers,
            FileError::Linked,
        ] {
            assert!(
                refused
                    .to_string()
                    .ends_with("events are not written to it"),
                "{refused}"
            );
        }
    }

    #[tokio::test]
    async fn a_symbolic_link_is_not_written_through() {
        let dir = TempDir::new();
        let elsewhere = dir.0.join("elsewhere");
        std::fs::write(&elsewhere, "not for events\n").unwrap();
        let link = dir.0.join("events.jsonl");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        // Not when the sink is built.
        assert_eq!(
            FileSink::new("file-0", &link).err(),
            Some(FileError::SymbolicLink)
        );
        // Not through a link to nowhere, which would create a file there.
        let dangling = dir.0.join("dangling");
        std::os::unix::fs::symlink(dir.0.join("created-by-the-sink"), &dangling).unwrap();
        assert_eq!(
            FileSink::new("file-0", &dangling).err(),
            Some(FileError::SymbolicLink)
        );
        assert!(!dir.0.join("created-by-the-sink").exists());

        // And not when a link takes the place of the file later.
        let path = dir.0.join("real.jsonl");
        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("before")).await.unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        let error = sink.deliver(&event("after")).await.unwrap_err();
        assert!(error.is_retryable());
        assert_eq!(
            error.message(),
            "the path is a symbolic link, and events are not written through one"
        );
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            "not for events\n"
        );

        // Once the link is gone the sink writes again, to a file of its
        // own.
        std::fs::remove_file(&path).unwrap();
        sink.deliver(&event("again")).await.unwrap();
        assert_eq!(users(&path), ["again"]);
        assert_eq!(mode(&path), 0o600);
    }

    #[tokio::test]
    async fn what_is_not_a_regular_file_is_not_written_to() {
        let dir = TempDir::new();
        assert_eq!(
            FileSink::new("file-0", &dir.0).err(),
            Some(FileError::Open(io::ErrorKind::IsADirectory))
        );
        let missing = dir.0.join("no-such-directory").join("events.jsonl");
        assert_eq!(
            FileSink::new("file-0", &missing).err(),
            Some(FileError::Open(io::ErrorKind::NotFound))
        );
        assert_eq!(
            FileError::Open(io::ErrorKind::NotFound).to_string(),
            "the file cannot be opened: entity not found"
        );
        // A device is not a file.
        assert_eq!(
            FileSink::new("file-0", "/dev/null").err(),
            Some(FileError::NotAFile)
        );
    }

    #[tokio::test]
    async fn a_file_that_was_moved_away_is_followed_by_a_new_one() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        let rotated = dir.0.join("events.jsonl.1");
        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("one")).await.unwrap();

        // Renamed, as a rotation does it, with nothing in its place.
        std::fs::rename(&path, &rotated).unwrap();
        sink.deliver(&event("two")).await.unwrap();
        assert_eq!(users(&rotated), ["one"]);
        assert_eq!(users(&path), ["two"]);
        assert_eq!(mode(&path), 0o600);

        // Renamed, with a new file already in its place, closed to others
        // as the sink would have made it.
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        sink.deliver(&event("three")).await.unwrap();
        assert_eq!(users(&rotated), ["two"]);
        assert_eq!(users(&path), ["three"]);
        assert_eq!(mode(&path), 0o600);

        // Removed.
        std::fs::remove_file(&path).unwrap();
        sink.deliver(&event("four")).await.unwrap();
        assert_eq!(users(&path), ["four"]);
    }

    #[tokio::test]
    async fn a_file_that_was_emptied_is_written_to_from_its_new_end() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("one")).await.unwrap();
        sink.deliver(&event("two")).await.unwrap();

        // Emptied in place, as a rotation that copies and truncates does
        // it.
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        sink.deliver(&event("three")).await.unwrap();
        assert_eq!(users(&path), ["three"]);
    }

    #[test]
    fn a_line_that_was_cut_short_does_not_run_into_the_next_event() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        let mut file = EventsFile {
            path: path.clone(),
            opened: None,
            torn: false,
        };
        file.write_line(b"{\"complete\":1}\n").unwrap();
        // A write that got only a part of its line onto the disk: what the
        // sink then remembers.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"cut\":")
            .unwrap();
        file.torn = true;

        file.write_line(b"{\"complete\":2}\n").unwrap();
        assert!(!file.torn);
        file.write_line(b"{\"complete\":3}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"complete\":1}\n{\"cut\":\n{\"complete\":2}\n{\"complete\":3}\n"
        );
    }

    #[test]
    fn nothing_about_the_sink_needs_more_than_its_name_and_its_path() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        let sink = FileSink::new("file-2", &path).unwrap();
        assert_eq!(
            format!("{sink:?}"),
            format!("FileSink {{ name: \"file-2\", path: {path:?} }}")
        );
    }

    #[test]
    fn a_check_says_what_building_the_sink_would_say_and_creates_nothing() {
        let dir = TempDir::new();

        // A file that is not there, in a directory that is: the sink could
        // be built, and the file is still not there.
        let path = dir.0.join("events.jsonl");
        assert_eq!(FileSink::check(&path), Ok(()));
        assert!(!path.exists());

        // A directory that is not there.
        let missing = dir.0.join("missing").join("events.jsonl");
        let not_found = Some(FileError::Open(io::ErrorKind::NotFound));
        assert_eq!(FileSink::check(&missing).err(), not_found);
        assert_eq!(FileSink::new("file-0", &missing).err(), not_found);

        // A symbolic link, whether it leads to a file or to nothing.
        let target = dir.0.join("elsewhere");
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(FileSink::check(&link), Err(FileError::SymbolicLink));
        assert!(!target.exists());
        std::fs::write(&target, b"").unwrap();
        assert_eq!(FileSink::check(&link), Err(FileError::SymbolicLink));
        assert_eq!(std::fs::read(&target).unwrap(), b"");

        // What is not a regular file is refused as building the sink
        // refuses it.
        assert!(FileSink::check(&dir.0).is_err());
        assert_eq!(
            FileSink::check(&dir.0).err(),
            FileSink::new("file-0", &dir.0).err()
        );

        // A file that is there keeps its content and its mode, and a mode
        // that lets others in is refused, as the sink refuses it.
        let open = dir.0.join("open.jsonl");
        std::fs::write(&open, b"{}\n").unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(FileSink::check(&open), Err(FileError::OpenToOthers));
        assert_eq!(
            FileSink::new("file-0", &open).err(),
            Some(FileError::OpenToOthers)
        );
        assert_eq!(std::fs::read(&open).unwrap(), b"{}\n");
        assert_eq!(mode(&open), 0o644);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(FileSink::check(&open), Ok(()));

        // A directory in which nothing can be created: the check and the
        // sink agree, whoever runs the test.
        let closed = dir.0.join("closed");
        std::fs::create_dir(&closed).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o500)).unwrap();
        let inside = closed.join("events.jsonl");
        let checked = FileSink::check(&inside).err();
        let built = FileSink::new("file-0", &inside).err();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(checked, built);
    }
}
