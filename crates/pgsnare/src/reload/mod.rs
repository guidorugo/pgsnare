// SPDX-License-Identifier: Apache-2.0

//! Reloading the policy: on a signal, and when a watched file changes.
//!
//! [`SharedPolicy`] is the source the sessions read the policy from. A
//! [`Reloader`] reads the configuration again, checks the access rights of
//! the files that hold secrets, builds the new snapshot with its matcher,
//! and only then puts it in place, with one swap of a pointer. A session
//! that reads the policy gets the old snapshot or the new one, never a
//! moment without one and never a mixture. A message keeps the snapshot it
//! started with; a COPY or a message that arrives in chunks keeps the
//! matcher it started with until it ends (see the scanner of the session
//! logic).
//!
//! A reload that fails leaves the snapshot in force as it is, logs a fixed
//! line with the file and the reason (a position and a fixed text, never
//! a value that was read) and counts the failure in
//! `pgsnare_reload_failures_total`.
//!
//! # What a reload changes
//!
//! The policy only: tokens, exemptions, responses and their settings,
//! inspection limits and query redaction. What the log and the events must
//! not show grows with the new tokens before the new snapshot is in force.
//! Listeners, TLS, sinks, the admin and metrics listeners and the grace
//! period need a restart. A reload that would change them applies the rest
//! and logs, once for that reload, that those settings keep their old
//! values.
//!
//! A session keeps what it learnt under the old policy: a session flagged
//! before a reload stays flagged, and the hit counts of its tokens go on.
//!
//! # Watching the files
//!
//! [`Watch`] notes the state of every file that was read, of the directory
//! of each of them, and of the directory of each token-file pattern. A
//! directory is watched as well as the file in it, so that a file replaced
//! by a rename, or by the swap of a symbolic link to the directory of its
//! data, is seen. It is read by polling: [`WATCH_INTERVAL`] apart, and a
//! change is acted on once nothing has changed for one more interval, so
//! that a file is not read while it is being written.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use pgsnare_core::policy::{PolicySnapshot, PolicySource};

use crate::config::{self, Config, Loaded};
use crate::redact::{Redaction, Redactor, RedactorBuilder};
use crate::runtime::{Status, permissions};
use crate::sinks;

/// How far apart the watched files are looked at.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// The policy in force, which a reload replaces as a whole.
#[derive(Debug)]
pub struct SharedPolicy {
    current: RwLock<Arc<PolicySnapshot>>,
}

impl SharedPolicy {
    /// A source that starts with `snapshot`.
    #[must_use]
    pub fn new(snapshot: PolicySnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Puts `snapshot` in force. The lock is held for the swap of a
    /// pointer and nothing else.
    pub fn replace(&self, snapshot: PolicySnapshot) {
        let snapshot = Arc::new(snapshot);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = snapshot;
    }
}

impl PolicySource for SharedPolicy {
    fn snapshot(&self) -> Arc<PolicySnapshot> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// What makes the redactor: the tokens of a configuration, and what the
/// sinks that run must keep to themselves.
pub fn redactor_of(config: &Config, sinks_of: &config::Events) -> RedactorBuilder {
    let mut builder = Redactor::builder();
    for token in &config.tokens {
        builder = builder.token(
            token.id.as_str(),
            token.values.iter().map(config::TokenValue::expose),
            token.case_insensitive,
        );
    }
    sinks::check_config(sinks_of, builder).redactor
}

/// Why a reload did not take place.
#[derive(Debug)]
pub struct ReloadError {
    /// The file at fault.
    pub file: PathBuf,
    /// Why, in fixed words with positions, never a value that was read.
    pub reason: String,
}

/// The configuration the proxy started with.
#[derive(Debug)]
pub struct Started {
    /// The configuration file.
    pub path: PathBuf,
    /// Whether files that hold secrets may be open to other users.
    pub allow_insecure_file_permissions: bool,
    /// What was read from it.
    pub config: Config,
    /// The files to watch, from [`watched`].
    pub files: Vec<PathBuf>,
    /// The generation of the snapshot built from it.
    pub generation: u64,
}

/// Reads the configuration again and puts the new policy in force.
pub struct Reloader {
    path: PathBuf,
    allow_insecure_file_permissions: bool,
    policy: Arc<SharedPolicy>,
    redaction: Redaction,
    status: Arc<Status>,
    /// The configuration of the settings that need a restart, as the
    /// proxy started with it.
    started: Config,
    generation: AtomicU64,
    /// The files of the configuration in force, for the watch.
    files: Mutex<Vec<PathBuf>>,
    /// One reload at a time.
    busy: Mutex<()>,
}

impl core::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reloader")
            .field("path", &self.path)
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Reloader {
    /// A reloader for the configuration the proxy started with, whose
    /// snapshot is in force in `policy`.
    #[must_use]
    pub fn new(
        started: Started,
        policy: Arc<SharedPolicy>,
        redaction: Redaction,
        status: Arc<Status>,
    ) -> Self {
        Self {
            path: started.path,
            allow_insecure_file_permissions: started.allow_insecure_file_permissions,
            policy,
            redaction,
            status,
            started: started.config,
            generation: AtomicU64::new(started.generation),
            files: Mutex::new(started.files),
            busy: Mutex::new(()),
        }
    }

    /// The generation of the snapshot in force.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Reloads, and logs and counts the outcome. Blocks: call it off the
    /// threads that relay traffic.
    ///
    /// Returns the files a [`Watch`] should look at from now on, which
    /// are those of the configuration in force.
    pub fn reload(&self) -> Option<Vec<PathBuf>> {
        let _one = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        match self.try_reload() {
            Ok(loaded) => {
                let config = &loaded.config;
                if restart_needed(&self.started, config) {
                    tracing::warn!(
                        "the configuration changes listeners, TLS, sinks, the admin or metrics \
                         listener or the grace period: these keep their values until pgsnare \
                         is restarted, and the rest is in force"
                    );
                }
                tracing::info!(
                    generation = self.generation(),
                    tokens = config.tokens.len(),
                    "the policy was reloaded"
                );
                let files = watched(&loaded);
                files.clone_into(&mut self.files.lock().unwrap_or_else(PoisonError::into_inner));
                Some(files)
            }
            Err(error) => {
                self.status.reload_failed();
                tracing::error!(
                    file = %error.file.display(),
                    reason = %error.reason,
                    "the configuration could not be reloaded, and the policy in force stays as it is"
                );
                None
            }
        }
    }

    /// Watches the files of the configuration in force on a thread of its
    /// own, and reloads when they change, until `stop` is set.
    ///
    /// # Errors
    ///
    /// Fails when the thread cannot be started.
    pub fn watch(self: Arc<Self>, stop: Arc<AtomicBool>) -> std::io::Result<()> {
        let files = self
            .files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut watch = Watch::new(&files);
        let mut generation = self.generation();
        std::thread::Builder::new()
            .name("pgsnare-watch".to_owned())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(WATCH_INTERVAL);
                    if watch.poll() {
                        tracing::info!("a file of the configuration changed: reloading the policy");
                        self.reload();
                    }
                    // A reload, from here or from a signal, can change the
                    // files.
                    if self.generation() != generation {
                        generation = self.generation();
                        let files = self
                            .files
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .clone();
                        watch = Watch::new(&files);
                    }
                }
            })
            .map(drop)
    }

    fn try_reload(&self) -> Result<Loaded, ReloadError> {
        let main = |reason: String| ReloadError {
            file: self.path.clone(),
            reason,
        };
        let loaded = config::load(&self.path).map_err(|error| main(error.to_string()))?;
        let refused = permissions::check_all(loaded.secret_files());
        if let Some(first) = refused.first() {
            if !self.allow_insecure_file_permissions {
                return Err(ReloadError {
                    file: first.file.clone(),
                    reason: first.problem.to_string(),
                });
            }
            for file in &refused {
                tracing::warn!(
                    file = %file.file.display(),
                    problem = %file.problem,
                    "reloading although a file that holds secrets is not protected, because \
                     --allow-insecure-file-permissions was given"
                );
            }
        }
        let generation = self.generation().saturating_add(1);
        let snapshot = loaded
            .config
            .policy(generation)
            .map_err(|error| main(error.to_string()))?;
        let redactor = redactor_of(&loaded.config, &self.started.events)
            .build()
            .map_err(|error| main(error.to_string()))?;
        // What must not be shown is known before a session can find it.
        self.redaction.replace(redactor);
        self.policy.replace(snapshot);
        self.generation.store(generation, Ordering::Relaxed);
        Ok(loaded)
    }
}

/// Whether `new` differs from `started` in a setting that needs a restart.
fn restart_needed(started: &Config, new: &Config) -> bool {
    started.listeners != new.listeners
        || started.events != new.events
        || started.admin != new.admin
        || started.metrics != new.metrics
        || started.shutdown != new.shutdown
}

/// The paths a [`Watch`] looks at for a configuration: every file that was
/// read, and the directory of each token-file pattern.
#[must_use]
pub fn watched(loaded: &Loaded) -> Vec<PathBuf> {
    let mut paths = loaded.files.clone();
    for pattern in &loaded.config.token_files {
        if let Some(directory) = pattern.parent() {
            paths.push(directory.to_path_buf());
        }
    }
    paths
}

/// What a watch knows of one path: its kind, size, time of change and
/// identity, following symbolic links. `None` for a path that cannot be
/// read.
type State = Option<(u64, Option<SystemTime>, u64, u64)>;

fn state(path: &Path) -> State {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::metadata(path).ok()?;
    Some((
        metadata.len(),
        metadata.modified().ok(),
        metadata.ino(),
        metadata.dev(),
    ))
}

/// The most paths a watch looks at.
const MAX_WATCHED: usize = 4096;

/// Polls the files of the configuration for a change.
#[derive(Debug)]
pub struct Watch {
    /// Each path with its directory.
    paths: Vec<PathBuf>,
    last: Vec<State>,
    /// A change was seen, and is acted on once things are still.
    pending: bool,
}

impl Watch {
    /// A watch of `files` and of their directories, from their state now.
    #[must_use]
    pub fn new(files: &[PathBuf]) -> Self {
        let mut paths = Vec::new();
        for file in files.iter().take(MAX_WATCHED / 2) {
            paths.push(file.clone());
            if let Some(directory) = file.parent() {
                paths.push(directory.to_path_buf());
            }
        }
        paths.sort();
        paths.dedup();
        let last = paths.iter().map(|path| state(path)).collect();
        Self {
            paths,
            last,
            pending: false,
        }
    }

    /// Looks again. Returns true when a reload is due: something changed
    /// one interval ago, and nothing since.
    pub fn poll(&mut self) -> bool {
        let now: Vec<State> = self.paths.iter().map(|path| state(path)).collect();
        if now != self.last {
            self.last = now;
            self.pending = true;
            return false;
        }
        let due = self.pending;
        self.pending = false;
        due
    }
}

#[cfg(test)]
mod tests;
