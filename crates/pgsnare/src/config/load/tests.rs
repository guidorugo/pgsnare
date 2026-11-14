// SPDX-License-Identifier: Apache-2.0

//! Tests of loading a configuration from disk.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use proptest::prelude::*;

use super::*;

/// A directory that is removed again when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "pgsnare-config-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, text: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MAIN: &str = "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: require, cert: certs/server.crt, key: /etc/pgsnare/server.key }
    upstream_tls: { mode: verify-full }
events:
  sinks:
    - { type: stdout }
    - { type: file, path: events.jsonl }
";

fn token_file(id: &str, value: &str) -> String {
    format!("tokens:\n  - id: {id}\n    values: [\"{value}\"]\n")
}

fn chars(text: &str) -> Vec<char> {
    text.chars().collect()
}

fn matches(pattern: &str, name: &str) -> bool {
    wildcard_match(&chars(pattern), &chars(name))
}

#[test]
fn the_shipped_example_loads_with_its_token_file() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/config/pgsnare.yaml");
    if !cfg!(feature = "rules") {
        // The example turns SQL rules on, which this build does not have.
        let LoadError::Invalid(error) = load(&example).unwrap_err() else {
            panic!("expected an invalid configuration");
        };
        assert_eq!(error.problems().len(), 1, "{error}");
        assert!(
            error
                .to_string()
                .contains("this build of pgsnare has no SQL rules"),
            "{error}"
        );
        return;
    }
    let loaded = load(&example).unwrap();

    let ids: Vec<&str> = loaded
        .config
        .tokens
        .iter()
        .map(|token| token.id.as_str())
        .collect();
    assert_eq!(
        ids,
        ["users-admin-backup", "api-key-reporting", "card-test-0002"]
    );

    assert_eq!(loaded.files.len(), 2);
    assert_eq!(loaded.files[0], example);
    assert!(loaded.files[1].ends_with("examples/config/tokens/example.yaml"));

    // A token knows where it was defined.
    assert_eq!(
        loaded.config.tokens[0].origin.file.as_deref(),
        Some(example.as_path())
    );
    assert_eq!(
        loaded.config.tokens[2].origin.file.as_deref(),
        Some(loaded.files[1].as_path())
    );
    assert_eq!(loaded.config.tokens[2].origin.index, 1);

    loaded.config.policy(1).unwrap();
}

#[test]
fn relative_paths_are_taken_from_the_directory_of_the_file() {
    let dir = TempDir::new();
    let main = dir.write("conf/pgsnare.yaml", MAIN);
    let loaded = load(&main).unwrap();

    let listener = &loaded.config.listeners[0];
    assert_eq!(
        listener.client_tls.cert.as_deref(),
        Some(dir.path("conf/certs/server.crt").as_path())
    );
    // An absolute path stays as it is.
    assert_eq!(
        listener.client_tls.key.as_deref(),
        Some(Path::new("/etc/pgsnare/server.key"))
    );
    assert!(
        matches!(&loaded.config.events.sinks[1], crate::config::Sink::File(file) if file.path == dir.path("conf/events.jsonl"))
    );
    assert_eq!(loaded.files, [main]);
}

#[test]
fn token_files_are_found_by_name_and_by_pattern() {
    let dir = TempDir::new();
    dir.write("tokens/b.yaml", token_file("from-b", "value-from-file-b"));
    dir.write("tokens/a.yaml", token_file("from-a", "value-from-file-a"));
    dir.write("tokens/notes.txt", "not a token file");
    dir.write("tokens/.hidden.yaml", "not: valid");
    dir.write("extra.yaml", token_file("extra", "value-from-extra"));
    let main = dir.write(
        "pgsnare.yaml",
        format!(
            "{MAIN}token_files: [\"tokens/*.yaml\", extra.yaml]\ntokens:\n  - id: inline\n    values: [\"value-from-main-file\"]\n"
        ),
    );

    let loaded = load(&main).unwrap();
    let ids: Vec<&str> = loaded
        .config
        .tokens
        .iter()
        .map(|token| token.id.as_str())
        .collect();
    // The main file first, then each entry in order, a pattern in name order.
    assert_eq!(ids, ["inline", "from-a", "from-b", "extra"]);
    assert_eq!(
        loaded.files,
        [
            main,
            dir.path("tokens/a.yaml"),
            dir.path("tokens/b.yaml"),
            dir.path("extra.yaml")
        ]
    );
}

#[cfg(unix)]
#[test]
fn a_mounted_kubernetes_secret_is_read_through_its_links() {
    // A Secret volume holds the files in a hidden, timestamped directory,
    // reached through a hidden link, with one visible link per key.
    let dir = TempDir::new();
    dir.write(
        "tokens/..2026_11_11_17_06_31.123/tokens.yaml",
        token_file("from-secret", "value-from-secret"),
    );
    std::os::unix::fs::symlink("..2026_11_11_17_06_31.123", dir.path("tokens/..data")).unwrap();
    std::os::unix::fs::symlink("..data/tokens.yaml", dir.path("tokens/tokens.yaml")).unwrap();
    let main = dir.write(
        "pgsnare.yaml",
        format!("{MAIN}token_files: [\"tokens/*.yaml\"]\n"),
    );

    let loaded = load(&main).unwrap();
    let ids: Vec<&str> = loaded
        .config
        .tokens
        .iter()
        .map(|token| token.id.as_str())
        .collect();
    assert_eq!(ids, ["from-secret"]);
    // Only the visible link is read, and only once.
    assert_eq!(loaded.files, [main, dir.path("tokens/tokens.yaml")]);
}

#[test]
fn a_pattern_that_matches_nothing_is_an_error() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.path("tokens")).unwrap();
    let main = dir.write(
        "pgsnare.yaml",
        format!("{MAIN}token_files: [\"tokens/*.yaml\"]\n"),
    );
    let error = load(&main).unwrap_err();
    assert!(matches!(error, LoadError::TokenFiles { .. }), "{error:?}");
    assert!(
        error
            .to_string()
            .ends_with("no file matches; a pattern that matches nothing would load no tokens")
    );

    let main = dir.write(
        "missing.yaml",
        format!("{MAIN}token_files: [nowhere.yaml]\n"),
    );
    let error = load(&main).unwrap_err();
    assert!(matches!(error, LoadError::Read { .. }), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("nowhere.yaml: cannot read the file")
    );

    let main = dir.write(
        "nodir.yaml",
        format!("{MAIN}token_files: [\"absent/*.yaml\"]\n"),
    );
    let error = load(&main).unwrap_err();
    assert!(
        matches!(error, LoadError::ListDirectory { .. }),
        "{error:?}"
    );

    let main = dir.write("isdir.yaml", format!("{MAIN}token_files: [tokens]\n"));
    let error = load(&main).unwrap_err();
    assert!(error.to_string().ends_with("this is not a file"), "{error}");

    let main = dir.write(
        "wild.yaml",
        format!("{MAIN}token_files: [\"*/tokens.yaml\"]\n"),
    );
    let error = load(&main).unwrap_err();
    assert!(
        error
            .to_string()
            .ends_with("wildcards are only supported in the file name, not in the directory")
    );
}

#[test]
fn a_file_is_not_read_twice() {
    let dir = TempDir::new();
    dir.write("tokens/a.yaml", token_file("from-a", "value-from-file-a"));
    let main = dir.write(
        "pgsnare.yaml",
        format!("{MAIN}token_files: [\"tokens/*.yaml\", tokens/a.yaml]\n"),
    );
    let error = load(&main).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("this file is named more than once"),
        "{error}"
    );
}

#[test]
fn problems_name_the_file_they_are_in() {
    let dir = TempDir::new();
    let a = dir.write("tokens/a.yaml", token_file("shared", "value-from-file-a"));
    let b = dir.write(
        "tokens/b.yaml",
        "tokens:\n  - id: shared\n    values: [\"value-from-file-a\", \"short\"]\n",
    );
    let main = dir.write(
        "pgsnare.yaml",
        format!("{MAIN}token_files: [\"tokens/*.yaml\"]\nshutdown: {{ grace_period: 2h }}\n"),
    );

    let LoadError::Invalid(error) = load(&main).unwrap_err() else {
        panic!("expected an invalid configuration");
    };
    let lines: Vec<String> = error.problems().iter().map(ToString::to_string).collect();
    assert_eq!(
        lines,
        [
            format!(
                "{}: tokens[0].values[1]: a value must be at least 12 bytes long",
                b.display()
            ),
            format!(
                "{}: tokens[0].id: this id is already used (see tokens[0].id in {})",
                b.display(),
                a.display()
            ),
            format!(
                "{}: tokens[0].values[0]: this value is already used (see tokens[0].values[0] in {})",
                b.display(),
                a.display()
            ),
            format!(
                "{}: shutdown.grace_period: must be at most 1h",
                main.display()
            ),
        ]
    );
}

#[test]
fn a_syntax_error_names_its_file_and_position() {
    let dir = TempDir::new();
    let broken = dir.write(
        "tokens/broken.yaml",
        "tokens:\n  - id: t\n    valuess: []\n",
    );
    let main = dir.write(
        "pgsnare.yaml",
        format!("{MAIN}token_files: [tokens/broken.yaml]\n"),
    );
    let error = load(&main).unwrap_err().to_string();
    assert!(
        error.starts_with(&format!("{}: line 3, column ", broken.display())),
        "{error}"
    );
    assert!(error.contains("unknown field"), "{error}");

    let main = dir.write("bad.yaml", "listeners: [\n");
    let error = load(&main).unwrap_err().to_string();
    assert!(
        error.starts_with(&format!("{}: ", main.display())),
        "{error}"
    );
}

#[test]
fn unreadable_input_is_reported_without_its_content() {
    let dir = TempDir::new();

    let error = load(&dir.path("absent.yaml")).unwrap_err();
    assert!(matches!(error, LoadError::Read { .. }), "{error:?}");
    assert!(std::error::Error::source(&error).is_some());

    let binary = dir.write(
        "binary.yaml",
        [0xff, 0xfe, b's', b'e', b'c', b'r', b'e', b't'],
    );
    let error = load(&binary).unwrap_err();
    assert!(matches!(error, LoadError::NotUtf8 { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!("{}: the file is not valid UTF-8", binary.display())
    );

    let error = load(&dir.0).unwrap_err();
    assert!(matches!(error, LoadError::Read { .. }), "{error:?}");
}

#[test]
fn a_file_larger_than_the_limit_is_refused() {
    let dir = TempDir::new();
    let limit = usize::try_from(MAX_FILE_BYTES).unwrap();

    // A comment that pads the file to exactly the limit is still read.
    let mut text = String::from(MAIN);
    text.push('#');
    text.push_str(&"x".repeat(limit - text.len()));
    assert_eq!(text.len(), limit);
    let at_limit = dir.write("at-limit.yaml", &text);
    assert!(load(&at_limit).is_ok());

    text.push('x');
    let over = dir.write("over.yaml", &text);
    let error = load(&over).unwrap_err();
    assert!(matches!(error, LoadError::TooLarge { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!("{}: the file is larger than 16MiB", over.display())
    );
}

#[test]
fn a_token_value_in_a_broken_token_file_does_not_reach_the_error() {
    const VALUE: &str = "Zq7honeytokenValue9xK";
    let dir = TempDir::new();
    for (name, text) in [
        ("list.yaml", format!("- {VALUE}\n")),
        ("scalar.yaml", format!("{VALUE}\n")),
        ("key.yaml", format!("tokens:\n  - id: t\n    {VALUE}: 1\n")),
        (
            "string.yaml",
            format!("tokens:\n  - id: t\n    values: {VALUE}\n"),
        ),
        (
            "short.yaml",
            "tokens:\n  - id: t\n    values: [\"Zq7short\"]\n".to_owned(),
        ),
        (
            "dup.yaml",
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\", \"{VALUE}\"]\n"),
        ),
        (
            "cut.yaml",
            format!("tokens:\n  - id: t\n    values: [\"{VALUE}\n"),
        ),
    ] {
        dir.write(&format!("tokens/{name}"), text);
        let main = dir.write(
            "pgsnare.yaml",
            format!("{MAIN}token_files: [tokens/{name}]\n"),
        );
        let error = load(&main).unwrap_err();
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("Zq7"), "{name}: {shown}");
    }
}

#[test]
fn files_are_listed_once_and_in_order() {
    let (a, b) = (Path::new("/a"), Path::new("/b"));
    assert_eq!(unique([a, b, a, b, a].into_iter()), [a, b]);
    assert!(unique(std::iter::empty()).is_empty());
}

#[test]
fn the_files_that_hold_secrets_are_what_was_read_and_every_private_key() {
    let dir = TempDir::new();
    let main = dir.write(
        "pgsnare.yaml",
        "\
listeners:
  - name: first
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: { mode: require, cert: certs/server.crt, key: certs/server.key }
    upstream_tls: { mode: verify-full, ca: certs/root.crt }
  - name: second
    listen: 0.0.0.0:5433
    upstream: db.example.com:5432
    client_tls: { mode: prefer, cert: certs/server.crt, key: certs/server.key }
    upstream_tls: { mode: disable }
  - name: third
    listen: 0.0.0.0:5434
    upstream: db.example.com:5432
    client_tls: { mode: require, cert: certs/other.crt, key: /etc/pgsnare/other.key }
    upstream_tls: { mode: disable }
  - name: plain
    listen: 0.0.0.0:5435
    upstream: db.example.com:5432
    client_tls: { mode: disable }
    upstream_tls: { mode: disable }
token_files: [\"tokens/*.yaml\"]
events:
  sinks:
    - { type: stdout }
    - { type: file, path: events.jsonl }
    - { type: webhook, url_file: hook-url, hmac_secret_file: hook-secret }
",
    );
    let first = dir.write("tokens/a.yaml", token_file("a", "first-value-0001"));
    let second = dir.write("tokens/b.yaml", token_file("b", "second-value-0002"));

    let loaded = load(&main).unwrap();
    assert_eq!(
        loaded.secret_files(),
        [
            // What was read, in the order it was read.
            main.as_path(),
            first.as_path(),
            second.as_path(),
            // The key of every listener that has one, each once. A key that
            // two listeners share is one file.
            dir.path("certs/server.key").as_path(),
            Path::new("/etc/pgsnare/other.key"),
            // What a webhook reads its signing key and its URL from.
            dir.path("hook-secret").as_path(),
            dir.path("hook-url").as_path(),
        ]
    );
    // Certificates and authorities are public, and the file of a file sink
    // is written by pgsnare and holds nothing that is read.
    let listed = loaded.secret_files();
    for other in ["certs/server.crt", "certs/root.crt", "events.jsonl"] {
        assert!(!listed.contains(&dir.path(other).as_path()), "{other}");
    }
}

#[test]
fn a_value_that_contains_a_value_of_another_file_names_both_files() {
    let dir = TempDir::new();
    let main = dir.write(
        "pgsnare.yaml",
        format!(
            "{MAIN}token_files: [tokens.yaml]\n{}",
            token_file("short", "alpha-0001-zulu")
        ),
    );
    let tokens = dir.write(
        "tokens.yaml",
        token_file("long", "prefix-alpha-0001-zulu-suffix"),
    );
    let LoadError::Invalid(error) = load(&main).unwrap_err() else {
        panic!("expected an invalid configuration");
    };
    assert_eq!(
        error.to_string(),
        format!(
            "{}: tokens[0].values[0]: this value contains another value, so data that matches \
             it would set off both (see tokens[0].values[0] in {})",
            tokens.display(),
            main.display()
        )
    );
    assert!(!error.to_string().contains("alpha"), "{error}");
}

#[test]
fn wildcards_match_as_a_shell_would() {
    for (pattern, name) in [
        ("*.yaml", "tokens.yaml"),
        ("*.yaml", ".yaml"),
        ("*", "anything"),
        ("*", ""),
        ("", ""),
        ("tokens.yaml", "tokens.yaml"),
        ("tokens-?.yaml", "tokens-1.yaml"),
        ("t*s.y?ml", "tokens.yaml"),
        ("*a*b*c*", "xxaxxbxxcxx"),
        ("a*a*a", "aaaa"),
        ("**", "x"),
        ("*.y*", "a.yaml.yaml"),
        ("?", "\u{e9}"),
    ] {
        assert!(matches(pattern, name), "{pattern:?} should match {name:?}");
    }
    for (pattern, name) in [
        ("*.yaml", "tokens.yml"),
        ("*.yaml", "tokens.yaml.bak"),
        ("tokens.yaml", "tokens.yam"),
        ("tokens.yaml", "tokens.yamll"),
        ("tokens-?.yaml", "tokens-.yaml"),
        ("tokens-?.yaml", "tokens-10.yaml"),
        ("", "x"),
        ("?", ""),
        ("a*a*a", "aa"),
        ("*a*b*c*", "xxaxxcxxbxx"),
    ] {
        assert!(
            !matches(pattern, name),
            "{pattern:?} should not match {name:?}"
        );
    }
}

/// The obvious recursive definition, to compare against.
fn slow_match(pattern: &[char], name: &[char]) -> bool {
    match (pattern.split_first(), name.split_first()) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(('*', rest)), _) => {
            slow_match(rest, name)
                || name
                    .split_first()
                    .is_some_and(|(_, tail)| slow_match(pattern, tail))
        }
        (Some(_), None) => false,
        (Some((expected, rest)), Some((character, tail))) => {
            (*expected == '?' || expected == character) && slow_match(rest, tail)
        }
    }
}

proptest! {
    #[test]
    fn the_wildcard_matcher_agrees_with_its_definition(
        pattern in "[ab*?]{0,8}",
        name in "[ab]{0,10}",
    ) {
        prop_assert_eq!(matches(&pattern, &name), slow_match(&chars(&pattern), &chars(&name)));
    }

    #[test]
    fn a_pattern_without_wildcards_matches_only_itself(a in "[a-c.]{0,6}", b in "[a-c.]{0,6}") {
        prop_assert_eq!(matches(&a, &b), a == b);
    }
}
