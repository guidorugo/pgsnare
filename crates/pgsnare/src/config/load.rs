// SPDX-License-Identifier: Apache-2.0

//! Loading a configuration from disk, with its token files.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use super::error::ConfigError;
use super::{Config, Sink, TokenFile};

/// The largest configuration or token file that is read: 16 MiB.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// A configuration read from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Loaded {
    /// The configuration, with the tokens of every token file added to
    /// `tokens`, and every relative path made absolute against the directory
    /// of the main file.
    pub config: Config,
    /// Every file that was read: the main file first, then the token files
    /// in the order they were read. A reload watches these.
    pub files: Vec<PathBuf>,
}

impl Loaded {
    /// The files that hold secrets, each once: every file that was read,
    /// which is the configuration file and the token files, the private
    /// key of every listener, and the files a webhook sink reads its
    /// signing key and its URL from.
    ///
    /// These are the files whose access rights must keep other users out.
    /// `pgsnare run` checks them before it starts and `pgsnare config
    /// check` reports on them, and both take the list from here, so that
    /// the two can never disagree about which files count.
    #[must_use]
    pub fn secret_files(&self) -> Vec<&Path> {
        let keys = self
            .config
            .listeners
            .iter()
            .filter_map(|listener| listener.client_tls.key.as_deref());
        let sinks = self.config.events.sinks.iter().flat_map(Sink::secret_files);
        unique(
            self.files
                .iter()
                .map(PathBuf::as_path)
                .chain(keys)
                .chain(sinks),
        )
    }
}

/// The files in the order given, each once.
fn unique<'a>(files: impl Iterator<Item = &'a Path>) -> Vec<&'a Path> {
    let mut seen: Vec<&Path> = Vec::new();
    for file in files {
        if !seen.contains(&file) {
            seen.push(file);
        }
    }
    seen
}

/// Why a configuration could not be loaded.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError {
    /// A file could not be read.
    Read {
        /// The file.
        file: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// A file is larger than [`MAX_FILE_BYTES`].
    TooLarge {
        /// The file.
        file: PathBuf,
    },
    /// A file is not valid UTF-8.
    NotUtf8 {
        /// The file.
        file: PathBuf,
    },
    /// An entry of `token_files` could not be used.
    TokenFiles {
        /// The entry, with a relative path already made absolute.
        pattern: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The directory of a `token_files` pattern could not be listed.
    ListDirectory {
        /// The directory.
        directory: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
    /// The configuration is not valid.
    Invalid(ConfigError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { file, source } => {
                write!(f, "{}: cannot read the file: {source}", file.display())
            }
            Self::TooLarge { file } => {
                write!(f, "{}: the file is larger than 16MiB", file.display())
            }
            Self::NotUtf8 { file } => {
                write!(f, "{}: the file is not valid UTF-8", file.display())
            }
            Self::TokenFiles { pattern, reason } => {
                write!(f, "token_files entry {}: {reason}", pattern.display())
            }
            Self::ListDirectory { directory, source } => {
                write!(
                    f,
                    "{}: cannot list the directory: {source}",
                    directory.display()
                )
            }
            Self::Invalid(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } | Self::ListDirectory { source, .. } => Some(source),
            Self::Invalid(error) => Some(error),
            Self::TooLarge { .. } | Self::NotUtf8 { .. } | Self::TokenFiles { .. } => None,
        }
    }
}

impl From<ConfigError> for LoadError {
    fn from(error: ConfigError) -> Self {
        Self::Invalid(error)
    }
}

/// Reads a configuration file and the token files it names, and checks the
/// result completely.
///
/// A relative path in the configuration is taken relative to the directory
/// of `path`.
///
/// An entry of `token_files` that matches no file is an error. A typing
/// mistake there would otherwise load no tokens and detect nothing, without
/// a word.
///
/// # Errors
///
/// Returns the first file that cannot be read, or everything that is wrong
/// with what was read. Apart from file names, the error contains no text
/// from the files.
pub fn load(path: &Path) -> Result<Loaded, LoadError> {
    let text = read(path)?;
    let mut config = Config::parse(&text, Some(path))?;

    let base = path.parent().unwrap_or_else(|| Path::new(""));
    config.for_each_path_mut(&mut |entry| {
        // An empty path stays empty, so that validation can report it.
        if entry.is_relative() && !entry.as_os_str().is_empty() {
            *entry = base.join(&*entry);
        }
    });

    let mut files = vec![path.to_path_buf()];
    for pattern in &config.token_files {
        if pattern.as_os_str().is_empty() {
            continue;
        }
        for file in expand(pattern)? {
            if files.contains(&file) {
                return Err(LoadError::TokenFiles {
                    pattern: pattern.clone(),
                    reason: "this file is named more than once, or is the configuration file itself",
                });
            }
            let text = read(&file)?;
            let parsed = TokenFile::parse(&text, &file)?;
            config.tokens.extend(parsed.tokens);
            files.push(file);
        }
    }

    config.validate().map_err(|error| {
        // Problems that are not about a token of a token file are about the
        // main file.
        LoadError::Invalid(error.in_file(path))
    })?;
    Ok(Loaded { config, files })
}

/// Reads a file as text, up to [`MAX_FILE_BYTES`].
fn read(path: &Path) -> Result<String, LoadError> {
    let failed = |source| LoadError::Read {
        file: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(failed)?;
    let mut bytes = Vec::new();
    // One byte more than the limit is enough to know the file is too large.
    file.take(MAX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(LoadError::TooLarge {
            file: path.to_path_buf(),
        });
    }
    String::from_utf8(bytes).map_err(|_| LoadError::NotUtf8 {
        file: path.to_path_buf(),
    })
}

/// The files an entry of `token_files` stands for, in name order.
fn expand(pattern: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let unusable = |reason| LoadError::TokenFiles {
        pattern: pattern.to_path_buf(),
        reason,
    };
    let has_wildcard = |text: &std::ffi::OsStr| {
        text.as_encoded_bytes()
            .iter()
            .any(|byte| matches!(byte, b'*' | b'?'))
    };

    let directory = pattern.parent().unwrap_or_else(|| Path::new(""));
    if has_wildcard(directory.as_os_str()) {
        return Err(unusable(
            "wildcards are only supported in the file name, not in the directory",
        ));
    }
    let Some(name) = pattern.file_name() else {
        return Err(unusable("this is not the name of a file"));
    };

    if !has_wildcard(name) {
        // `metadata` follows symbolic links, as Kubernetes uses them for
        // mounted secrets.
        return match std::fs::metadata(pattern) {
            Ok(metadata) if metadata.is_file() => Ok(vec![pattern.to_path_buf()]),
            Ok(_) => Err(unusable("this is not a file")),
            Err(source) => Err(LoadError::Read {
                file: pattern.to_path_buf(),
                source,
            }),
        };
    }

    let Some(name) = name.to_str() else {
        return Err(unusable("the file name pattern is not valid UTF-8"));
    };
    let name: Vec<char> = name.chars().collect();
    let list_failed = |source| LoadError::ListDirectory {
        directory: directory.to_path_buf(),
        source,
    };
    let listing = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };

    let mut matches = Vec::new();
    for entry in std::fs::read_dir(listing).map_err(list_failed)? {
        let entry = entry.map_err(list_failed)?;
        let file_name = entry.file_name();
        let Some(candidate) = file_name.to_str() else {
            continue;
        };
        // Hidden entries never match. Kubernetes keeps the real files of a
        // mounted secret in hidden directories next to the links to them.
        if candidate.starts_with('.') {
            continue;
        }
        let candidate_chars: Vec<char> = candidate.chars().collect();
        if !wildcard_match(&name, &candidate_chars) {
            continue;
        }
        let path = directory.join(candidate);
        if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file()) {
            matches.push(path);
        }
    }
    if matches.is_empty() {
        return Err(unusable(
            "no file matches; a pattern that matches nothing would load no tokens",
        ));
    }
    matches.sort();
    Ok(matches)
}

/// Whether `name` matches `pattern`, where `*` stands for any run of
/// characters, including none, and `?` for exactly one.
fn wildcard_match(pattern: &[char], name: &[char]) -> bool {
    let mut pattern_at = 0usize;
    let mut name_at = 0usize;
    // The position after the last `*` seen, and how much of the name that
    // star has been tried against so far.
    let mut retry: Option<(usize, usize)> = None;

    while let Some(&character) = name.get(name_at) {
        match pattern.get(pattern_at) {
            Some('*') => {
                pattern_at = pattern_at.saturating_add(1);
                retry = Some((pattern_at, name_at));
            }
            Some(&expected) if expected == '?' || expected == character => {
                pattern_at = pattern_at.saturating_add(1);
                name_at = name_at.saturating_add(1);
            }
            _ => match retry {
                // Let the last star swallow one more character and try again.
                Some((after_star, tried)) => {
                    let tried = tried.saturating_add(1);
                    retry = Some((after_star, tried));
                    pattern_at = after_star;
                    name_at = tried;
                }
                None => return false,
            },
        }
    }
    pattern
        .get(pattern_at..)
        .is_some_and(|rest| rest.iter().all(|character| *character == '*'))
}

#[cfg(test)]
mod tests;
