// SPDX-License-Identifier: Apache-2.0

//! A stand-in for the `bindgen` crate, for the one build script that asks
//! for it.
//!
//! The SQL parser of the optional rules, `pg_query`, writes the Rust
//! declarations of its C interface while it is built, and uses `bindgen`
//! for that. `bindgen` reads C through libclang, and the way `pg_query`
//! asks for it, it loads libclang at run time through `libloading`.
//! pgsnare accepts no crate that loads code at run time anywhere in its
//! dependency tree, build tools included.
//!
//! The C interface of one version of `pg_query` does not change, so its
//! declarations do not either. This crate holds them, made once, and hands
//! them out through the three calls the build script of `pg_query` makes:
//! [`Builder::header`], [`Builder::generate`] and
//! [`Bindings::write_to_file`]. The workspace, and each fuzz crate that
//! builds the parser, puts it in the place of `bindgen` with
//! `[patch.crates-io]`. The build then needs neither `bindgen` nor
//! libclang, and nothing here is `unsafe`: the declarations are text to
//! this crate.
//!
//! # What keeps wrong declarations out
//!
//! - **The headers are checked.** [`Builder::generate`] reads the three
//!   header files the declarations were made from and compares a
//!   fingerprint of them with the one recorded here. After an update of
//!   `pg_query` that changes its C interface, the build stops with an
//!   error instead of going on with declarations of the old one. The
//!   fingerprint is there to notice a change, not to stop an attacker: the
//!   content of the `pg_query` crate is pinned by its checksum in
//!   `Cargo.lock`.
//! - **The target is checked.** The declarations use C's `char`, `int`,
//!   `unsigned`, `size_t`, `bool`, integers of a fixed width, pointers,
//!   and structures of these, and they name the C types rather than a size.
//!   They were made on 64-bit Linux on x86-64; 64-bit Linux on ARM lays all
//!   of these out the same way. Any other target is refused.
//!
//! # Making the declarations again
//!
//! When `pg_query` is updated and the build stops here:
//!
//! 1. Run the real `bindgen` 0.66.1 (the version `pg_query` asks for) on
//!    `libpg_query/pg_query.h` of the new `pg_query` crate, with its
//!    default settings and
//!    `--allowlist-file '.*/pg_query\.h' --allowlist-file '.*/postgres_deparse\.h' --allowlist-file '.*/pg_query_scan_tokens\.h'`.
//! 2. Put the output into `bindings/`, under the comment at the top of the
//!    file that is there, and point the constant `DECLARATIONS` at it.
//! 3. Set [`FINGERPRINT`] to the value the error message names, and
//!    [`PG_QUERY_VERSION`] to the new version.
//! 4. Run the tests of the rules: they call the parser through these
//!    declarations.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The version of `pg_query` the declarations belong to.
pub const PG_QUERY_VERSION: &str = "18.1.0";

/// The header files the declarations were made from, in the order their
/// fingerprint is taken. The first is the one the build script names; the
/// others are next to it.
const HEADERS: [&str; 3] = ["pg_query.h", "postgres_deparse.h", "pg_query_scan_tokens.h"];

/// The fingerprint of the three header files as `pg_query`
/// [`PG_QUERY_VERSION`] ships them.
pub const FINGERPRINT: u64 = 0xc7ce8158037ab00;

/// The declarations.
const DECLARATIONS: &str = include_str!("../bindings/pg_query-18.1.0.bindings");

/// Why no declarations are handed out.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindgenError {
    /// No header file was named.
    NoHeader,
    /// The header file is not `pg_query.h`: this crate knows no other.
    NotPgQuery,
    /// A header file could not be read.
    UnreadableHeader(io::ErrorKind),
    /// The header files are not the ones the declarations were made from.
    ChangedHeaders {
        /// The fingerprint of the header files that were found.
        found: u64,
    },
    /// The declarations were not made for this target.
    UnsupportedTarget,
    /// The target is not known, because this is not running in a build
    /// script.
    UnknownTarget,
}

impl fmt::Display for BindgenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeader => f.write_str("no header file was named"),
            Self::NotPgQuery => {
                f.write_str("this stand-in for bindgen only knows pg_query.h of the pg_query crate")
            }
            Self::UnreadableHeader(kind) => write!(f, "a header file could not be read: {kind}"),
            Self::ChangedHeaders { found } => write!(
                f,
                "the header files of pg_query are not those of version {PG_QUERY_VERSION}, which \
                 the declarations in the stand-in for bindgen were made from (fingerprint \
                 {found:#018x}, expected {FINGERPRINT:#018x}); make the declarations again as \
                 the documentation of that crate says"
            ),
            Self::UnsupportedTarget => f.write_str(
                "the declarations in the stand-in for bindgen were made for 64-bit Linux on \
                 x86-64 and ARM; for another target, build without the rules feature",
            ),
            Self::UnknownTarget => {
                f.write_str("the stand-in for bindgen only works in a build script")
            }
        }
    }
}

impl Error for BindgenError {}

/// The target a build is for, as cargo tells a build script.
#[derive(Clone, Copy, Debug)]
struct Target<'a> {
    os: &'a str,
    arch: &'a str,
    pointer_width: &'a str,
    endian: &'a str,
}

impl Target<'_> {
    fn is_supported(&self) -> bool {
        self.os == "linux"
            && matches!(self.arch, "x86_64" | "aarch64")
            && self.pointer_width == "64"
            && self.endian == "little"
    }
}

/// Collects what [`Builder::generate`] needs: the header file.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    header: Option<PathBuf>,
}

/// Starts a [`Builder`], as `bindgen::builder()` does.
#[must_use]
pub fn builder() -> Builder {
    Builder::default()
}

impl Builder {
    /// Names the header file. It must be `pg_query.h`, with the headers it
    /// includes next to it.
    #[must_use]
    pub fn header<T: Into<String>>(mut self, header: T) -> Self {
        self.header = Some(PathBuf::from(header.into()));
        self
    }

    /// Checks the header files and the target, and returns the
    /// declarations.
    ///
    /// # Errors
    ///
    /// Returns why the declarations do not fit: see [`BindgenError`].
    pub fn generate(self) -> Result<Bindings, BindgenError> {
        let cfg = |name: &str| std::env::var(name).map_err(|_| BindgenError::UnknownTarget);
        let (os, arch) = (cfg("CARGO_CFG_TARGET_OS")?, cfg("CARGO_CFG_TARGET_ARCH")?);
        let pointer_width = cfg("CARGO_CFG_TARGET_POINTER_WIDTH")?;
        let endian = cfg("CARGO_CFG_TARGET_ENDIAN")?;
        self.generate_for(&Target {
            os: &os,
            arch: &arch,
            pointer_width: &pointer_width,
            endian: &endian,
        })
    }

    fn generate_for(self, target: &Target<'_>) -> Result<Bindings, BindgenError> {
        let header = self.header.ok_or(BindgenError::NoHeader)?;
        if !target.is_supported() {
            return Err(BindgenError::UnsupportedTarget);
        }
        if header.file_name().and_then(|name| name.to_str()) != HEADERS.first().copied() {
            return Err(BindgenError::NotPgQuery);
        }
        let directory = header.parent().unwrap_or_else(|| Path::new("."));
        let found =
            fingerprint(directory).map_err(|error| BindgenError::UnreadableHeader(error.kind()))?;
        if found != FINGERPRINT {
            return Err(BindgenError::ChangedHeaders { found });
        }
        Ok(Bindings { text: DECLARATIONS })
    }
}

/// The declarations, checked and ready to be written.
#[derive(Clone, Debug)]
pub struct Bindings {
    text: &'static str,
}

impl Bindings {
    /// Writes the declarations to a file.
    ///
    /// # Errors
    ///
    /// Returns the error of the operating system when the file cannot be
    /// written.
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        fs::write(path, self.text)
    }
}

impl fmt::Display for Bindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

/// The fingerprint of the header files in `directory`: FNV-1a over the
/// length and the content of each, in the order of [`HEADERS`].
fn fingerprint(directory: &Path) -> io::Result<u64> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    for name in HEADERS {
        let content = fs::read(directory.join(name))?;
        feed(&(content.len() as u64).to_le_bytes());
        feed(&content);
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX: Target<'static> = Target {
        os: "linux",
        arch: "x86_64",
        pointer_width: "64",
        endian: "little",
    };

    /// A directory of its own with the three header files, each holding
    /// what `content` gives for its name.
    fn headers(test: &str, content: impl Fn(&str) -> Vec<u8>) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("pgsnare-bindgen-{}-{test}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        for name in HEADERS {
            fs::write(directory.join(name), content(name)).unwrap();
        }
        directory
    }

    fn generate(directory: &Path, target: &Target<'_>) -> Result<Bindings, BindgenError> {
        builder()
            .header(directory.join("pg_query.h").to_str().unwrap())
            .generate_for(target)
    }

    #[test]
    fn headers_other_than_the_recorded_ones_are_refused() {
        let directory = headers("changed", |name| name.as_bytes().to_vec());
        let found = fingerprint(&directory).unwrap();
        assert_ne!(found, FINGERPRINT);
        assert_eq!(
            generate(&directory, &LINUX).unwrap_err(),
            BindgenError::ChangedHeaders { found }
        );
        let message = BindgenError::ChangedHeaders { found }.to_string();
        assert!(message.contains(&format!("{found:#018x}")), "{message}");
        assert!(message.contains(PG_QUERY_VERSION), "{message}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn the_fingerprint_follows_every_byte_of_every_header() {
        let base = headers("base", |_| b"int f(void);\n".to_vec());
        let same = headers("same", |_| b"int f(void);\n".to_vec());
        assert_eq!(fingerprint(&base).unwrap(), fingerprint(&same).unwrap());
        for changed in HEADERS {
            let other = headers("other", |name| {
                if name == changed {
                    b"int g(void);\n".to_vec()
                } else {
                    b"int f(void);\n".to_vec()
                }
            });
            assert_ne!(
                fingerprint(&base).unwrap(),
                fingerprint(&other).unwrap(),
                "{changed}"
            );
        }
        // Bytes that move from one file to the next are a change too.
        let moved = headers("moved", |name| match name {
            "pg_query.h" => b"int f(void);\nint".to_vec(),
            "postgres_deparse.h" => b" f(void);\n".to_vec(),
            _ => b"int f(void);\n".to_vec(),
        });
        assert_ne!(fingerprint(&base).unwrap(), fingerprint(&moved).unwrap());
        for directory in [base, same, moved] {
            fs::remove_dir_all(directory).unwrap();
        }
        fs::remove_dir_all(
            std::env::temp_dir().join(format!("pgsnare-bindgen-{}-other", std::process::id())),
        )
        .unwrap();
    }

    #[test]
    fn a_missing_or_foreign_header_is_refused() {
        assert_eq!(
            builder().generate_for(&LINUX).unwrap_err(),
            BindgenError::NoHeader
        );
        let directory = headers("foreign", |_| Vec::new());
        fs::write(directory.join("other.h"), b"").unwrap();
        assert_eq!(
            builder()
                .header(directory.join("other.h").to_str().unwrap())
                .generate_for(&LINUX)
                .unwrap_err(),
            BindgenError::NotPgQuery
        );
        fs::remove_file(directory.join("postgres_deparse.h")).unwrap();
        assert_eq!(
            generate(&directory, &LINUX).unwrap_err(),
            BindgenError::UnreadableHeader(io::ErrorKind::NotFound)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn only_the_targets_the_declarations_fit_are_accepted() {
        let arm = Target {
            arch: "aarch64",
            ..LINUX
        };
        assert!(LINUX.is_supported() && arm.is_supported());
        for other in [
            Target {
                os: "windows",
                ..LINUX
            },
            Target { os: "macos", ..arm },
            Target {
                arch: "x86",
                pointer_width: "32",
                ..LINUX
            },
            Target {
                pointer_width: "32",
                ..LINUX
            },
            Target {
                arch: "riscv64",
                ..LINUX
            },
            Target {
                endian: "big",
                ..LINUX
            },
        ] {
            assert!(!other.is_supported(), "{other:?}");
            // The target is judged before any file is read.
            assert_eq!(
                builder()
                    .header("/nonexistent/pg_query.h")
                    .generate_for(&other)
                    .unwrap_err(),
                BindgenError::UnsupportedTarget
            );
        }
        // Outside a build script the target is not known.
        if std::env::var_os("CARGO_CFG_TARGET_OS").is_none() {
            assert_eq!(
                builder().header("pg_query.h").generate().unwrap_err(),
                BindgenError::UnknownTarget
            );
        }
    }

    #[test]
    fn the_declarations_are_the_generated_ones() {
        assert!(DECLARATIONS.contains("pub fn pg_query_parse_protobuf_opts"));
        assert!(DECLARATIONS.contains("pub struct PgQueryError"));
        // Nothing of the C library of the machine they were made on.
        assert!(!DECLARATIONS.contains("pthread") && !DECLARATIONS.contains("pub fn select"));
        let bindings = Bindings { text: DECLARATIONS };
        assert_eq!(bindings.to_string(), DECLARATIONS);
        let file = std::env::temp_dir().join(format!("pgsnare-bindgen-{}.rs", std::process::id()));
        bindings.write_to_file(&file).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), DECLARATIONS);
        fs::remove_file(file).unwrap();
    }
}
