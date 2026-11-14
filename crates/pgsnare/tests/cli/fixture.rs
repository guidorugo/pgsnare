// SPDX-License-Identifier: Apache-2.0

//! Configurations on disk for the commands that read one.
//!
//! The commands look at the access rights of files, and git keeps none but
//! the right to execute. So every test writes its files into a directory
//! of its own, with the rights it means them to have. The name of that
//! directory differs from run to run, and is replaced by `<dir>` before
//! output is compared.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// A directory that is removed again when the test ends.
pub struct Fixture(PathBuf);

impl Fixture {
    pub fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "pgsnare-cli-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// The path of a file in the directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// The path of a file in the directory, as text for a command line.
    pub fn arg(&self, name: &str) -> String {
        self.path(name).to_str().unwrap().to_owned()
    }

    /// Writes a file that only its owner can read and write.
    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        self.write_with_mode(name, content, 0o600)
    }

    /// Writes a file with these access rights.
    pub fn write_with_mode(&self, name: &str, content: &str, mode: u32) -> PathBuf {
        let path = self.path(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Writes a certificate authority to `ca.crt`, and a certificate it
    /// signed with its key to `server.crt` and `server.key`. They exist for
    /// this test only.
    pub fn certificates(&self) {
        let mut authority = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        authority.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        authority.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        authority
            .distinguished_name
            .push(rcgen::DnType::CommonName, "pgsnare cli tests");
        let issuer =
            rcgen::CertifiedIssuer::self_signed(authority, rcgen::KeyPair::generate().unwrap())
                .unwrap();

        let mut server = rcgen::CertificateParams::new(vec!["db.example.com".to_owned()]).unwrap();
        server.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = server.signed_by(&key, &issuer).unwrap();

        self.write_with_mode("ca.crt", &issuer.pem(), 0o644);
        self.write_with_mode("server.crt", &certificate.pem(), 0o644);
        self.write("server.key", &key.serialize_pem());
    }

    /// `text` with the name of the directory replaced by `<dir>`.
    pub fn normalise(&self, text: &str) -> String {
        text.replace(self.0.to_str().unwrap(), "<dir>")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A configuration that is valid and has no warning, for the files that
/// [`Fixture::certificates`] writes. `more` is added at its end.
pub fn valid(more: &str) -> String {
    format!(
        "\
listeners:
  - name: main
    listen: 0.0.0.0:5432
    upstream: db.example.com:5432
    client_tls: {{ mode: require, cert: server.crt, key: server.key }}
    upstream_tls: {{ mode: verify-full, ca: ca.crt }}
  - name: local
    listen: 127.0.0.1:6432
    upstream: unix:/var/run/postgresql/.s.PGSQL.5432
    client_tls: {{ mode: disable }}
    upstream_tls: {{ mode: disable }}
events:
  sinks:
    - type: stdout
{more}"
    )
}

/// A token file with one token.
pub fn token_file(id: &str, value: &str) -> String {
    format!("tokens:\n  - id: {id}\n    values: [\"{value}\"]\n")
}
