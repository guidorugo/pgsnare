// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pgsnare_core::policy::{PolicySource as _, TokenId};

use super::{Reloader, SharedPolicy, Watch};
use crate::config;
use crate::redact::Redaction;
use crate::runtime::Status;

const FIRST: &str = "VALUE-ONE-7Q2M-XK4T";
const SECOND: &str = "VALUE-TWO-9D1B-CANARY";

/// A directory of its own under the temporary directory, removed at the
/// end of the test.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pgsnare-reload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn configuration(tokens: &[(&str, &str)], listen: &str) -> String {
    let mut text = format!(
        "listeners:\n  - name: main\n    listen: {listen}\n    upstream: 127.0.0.1:5432\n    \
         client_tls: {{ mode: disable }}\n    upstream_tls: {{ mode: disable }}\nevents:\n  sinks: [{{ type: stdout }}]\ntokens:\n"
    );
    for (id, value) in tokens {
        text.push_str(&format!("  - {{ id: {id}, values: [\"{value}\"] }}\n"));
    }
    text
}

struct Setup {
    reloader: Reloader,
    policy: Arc<SharedPolicy>,
    status: Arc<Status>,
    redaction: Redaction,
}

fn setup(path: &Path) -> Setup {
    let loaded = config::load(path).unwrap();
    let policy = Arc::new(SharedPolicy::new(loaded.config.policy(1).unwrap()));
    let status = Arc::new(Status::new());
    let redaction = Redaction::default();
    let reloader = Reloader::new(
        super::Started {
            path: path.to_path_buf(),
            allow_insecure_file_permissions: false,
            files: super::watched(&loaded),
            config: loaded.config,
            generation: 1,
        },
        Arc::clone(&policy),
        redaction.clone(),
        Arc::clone(&status),
    );
    Setup {
        reloader,
        policy,
        status,
        redaction,
    }
}

fn finds(policy: &SharedPolicy, value: &str) -> bool {
    policy
        .snapshot()
        .matcher()
        .scan(value.as_bytes())
        .next()
        .is_some()
}

#[test]
fn a_reload_puts_a_new_token_in_force_with_a_new_generation() {
    let scratch = Scratch::new();
    let path = scratch.write(
        "pgsnare.yaml",
        &configuration(&[("first", FIRST)], "127.0.0.1:6432"),
    );
    let setup = setup(&path);
    assert!(!finds(&setup.policy, SECOND));
    assert!(setup.redaction.label(SECOND).contains(SECOND));

    scratch.write(
        "pgsnare.yaml",
        &configuration(&[("first", FIRST), ("second", SECOND)], "127.0.0.1:6432"),
    );
    let files = setup.reloader.reload().unwrap();
    assert_eq!(files, [path]);
    let snapshot = setup.policy.snapshot();
    assert_eq!(snapshot.generation(), 2);
    assert!(snapshot.token(&TokenId::new("second").unwrap()).is_some());
    assert!(finds(&setup.policy, SECOND));
    // The log and the events cannot show the new value either.
    assert!(!setup.redaction.label(SECOND).contains(SECOND));
    assert_eq!(setup.status.counters().reload_failures, 0);
}

#[test]
fn a_reload_that_fails_keeps_the_policy_in_force_and_is_counted() {
    let scratch = Scratch::new();
    let path = scratch.write(
        "pgsnare.yaml",
        &configuration(&[("first", FIRST)], "127.0.0.1:6432"),
    );
    let setup = setup(&path);

    // Not a configuration at all, then a token without a value, then a
    // file other users can read.
    let broken = [
        "listeners: [".to_owned(),
        configuration(&[("first", "")], "127.0.0.1:6432"),
        configuration(&[("first", FIRST), ("second", SECOND)], "127.0.0.1:6432"),
    ];
    for (round, text) in broken.iter().enumerate() {
        scratch.write("pgsnare.yaml", text);
        if round == 2 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(setup.reloader.reload().is_none());
        let snapshot = setup.policy.snapshot();
        assert_eq!(snapshot.generation(), 1);
        assert!(finds(&setup.policy, FIRST));
        assert!(!finds(&setup.policy, SECOND));
        assert_eq!(
            setup.status.counters().reload_failures,
            u64::try_from(round).unwrap() + 1
        );
    }
}

#[test]
fn a_reload_keeps_the_listeners_it_started_with() {
    let scratch = Scratch::new();
    let path = scratch.write(
        "pgsnare.yaml",
        &configuration(&[("first", FIRST)], "127.0.0.1:6432"),
    );
    let setup = setup(&path);
    scratch.write(
        "pgsnare.yaml",
        &configuration(&[("second", SECOND)], "127.0.0.1:7432"),
    );
    // The policy changes; the listener is the runtime's and stays.
    assert!(setup.reloader.reload().is_some());
    assert!(finds(&setup.policy, SECOND));
    assert!(super::restart_needed(
        &config::load(&path).unwrap().config,
        &setup.reloader.started
    ));
}

#[test]
fn a_watch_sees_a_file_replaced_by_the_swap_of_a_symbolic_link() {
    // The layout a mounted volume of a container orchestrator uses: the
    // file is a link through `..data`, which is a link to a directory of
    // the current data, swapped by a rename.
    let scratch = Scratch::new();
    scratch.write("..2026_01/pgsnare.yaml", "first");
    symlink("..2026_01", scratch.0.join("..data")).unwrap();
    symlink("..data/pgsnare.yaml", scratch.0.join("pgsnare.yaml")).unwrap();
    let mut watch = Watch::new(&[scratch.0.join("pgsnare.yaml")]);
    assert!(!watch.poll());

    scratch.write("..2026_02/pgsnare.yaml", "second");
    symlink("..2026_02", scratch.0.join("..data_tmp")).unwrap();
    fs::rename(scratch.0.join("..data_tmp"), scratch.0.join("..data")).unwrap();

    // Seen at once, acted on once it has been still for one look.
    assert!(!watch.poll());
    assert!(watch.poll());
    assert!(!watch.poll());
}

#[test]
fn a_watch_waits_while_a_file_keeps_changing() {
    let scratch = Scratch::new();
    let path = scratch.write("pgsnare.yaml", "a");
    let mut watch = Watch::new(std::slice::from_ref(&path));
    for content in ["ab", "abc", "abcd"] {
        scratch.write("pgsnare.yaml", content);
        assert!(!watch.poll());
    }
    assert!(watch.poll());
}
