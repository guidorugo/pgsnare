// SPDX-License-Identifier: Apache-2.0

//! The `file` sink: events appended to a file, one JSON object per line.
//!
//! # The file
//!
//! - **It is created closed to other users**, with mode `0600`. A file
//!   that is there already keeps the mode it has. When that mode lets
//!   others than the owner read or write it, the sink says so in the log.
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
use rustix::fs::OFlags;

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
}

impl FileError {
    const fn text(self) -> &'static str {
        match self {
            Self::SymbolicLink => {
                "the path is a symbolic link, and events are not written through one"
            }
            Self::NotAFile => "the path does not lead to a regular file",
            Self::Open(_) => "the file cannot be opened",
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

/// The file of a sink, and what the sink remembers about it.
struct EventsFile {
    name: String,
    path: PathBuf,
    opened: Option<Opened>,
    /// Whether the last write left a part of a line behind.
    torn: bool,
}

impl EventsFile {
    /// Opens the file for appending, and creates it when it is not there.
    fn open(&self) -> Result<Opened, FileError> {
        // Not through a link, and without waiting for the other end of a
        // pipe that may stand where the file should be.
        let flags = OFlags::NOFOLLOW | OFlags::NONBLOCK;
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(i32::try_from(flags.bits()).unwrap_or(0))
            .open(&self.path)
            .map_err(|error| {
                // The system says "too many levels of symbolic links" when
                // the last part of the path is one and may not be followed.
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
        if metadata.mode() & 0o077 != 0 {
            tracing::warn!(
                sink = %self.name,
                file = %self.path.display(),
                "the file events are written to can be read or written by others than its \
                 owner"
            );
        }
        Ok(Opened {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
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
            name: name.clone(),
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
    async fn a_file_that_is_there_is_appended_to_and_keeps_its_mode() {
        let dir = TempDir::new();
        let path = dir.0.join("events.jsonl");
        std::fs::write(&path, "an earlier line\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let sink = FileSink::new("file-0", &path).unwrap();
        sink.deliver(&event("app")).await.unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("an earlier line\n{"), "{content}");
        assert_eq!(content.lines().count(), 2);
        assert_eq!(mode(&path), 0o640);
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

        // Renamed, with a new file already in its place.
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        sink.deliver(&event("three")).await.unwrap();
        assert_eq!(users(&rotated), ["two"]);
        assert_eq!(users(&path), ["three"]);
        assert_eq!(mode(&path), 0o640);

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
            name: "file-0".to_owned(),
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
}
