// SPDX-License-Identifier: Apache-2.0

//! TLS on both legs.
//!
//! pgsnare ends TLS on the client leg and starts it again on the backend
//! leg, because it has to read the traffic in between. This module turns
//! the TLS settings of a listener into what the runtime needs for both:
//! a [`ClientLeg`] and a [`BackendLeg`].
//!
//! # What holds on both legs
//!
//! - **TLS 1.2 is the floor.** Nothing older is ever negotiated, and a
//!   listener can raise the floor to TLS 1.3.
//! - **No resumption.** Every connection runs a full handshake, as it does
//!   against PostgreSQL itself.
//! - **The protocol's ALPN name is offered and accepted.** A client that
//!   names other protocols and not this one is refused, as PostgreSQL 17
//!   and 18 refuse it. PostgreSQL 15 and 16 ignore the extension and
//!   accept such a client, so in front of them pgsnare is the stricter of
//!   the two.
//!
//! # The backend leg
//!
//! With `verify-full` the certificate of the database is checked against
//! the configured authorities, or the system's store, and against the name
//! of the database. With `prefer` and `require` the certificate is not
//! checked at all. That takes one of those two modes, which an operator has
//! to write down, and [`BackendLeg::verifies`] lets the runtime say so in
//! its log when it starts.
//!
//! # Logging
//!
//! A failed handshake is described by [`describe`], which gives a fixed
//! text. The text of the error itself is not logged, because it can repeat
//! what the other side sent, such as the names in its certificate.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use pgsnare_core::session::TlsPolicy;
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
    SignatureScheme, SupportedProtocolVersion,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::{ClientTls, ClientTlsMode, Endpoint, TlsVersion, UpstreamTls, UpstreamTlsMode};

/// The cryptography behind TLS: `aws-lc-rs`, the provider rustls uses by
/// default.
///
/// It is created once and named explicitly wherever a configuration is
/// built, so that nothing depends on a default some other part of the
/// process may have installed.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider())))
}

/// TLS 1.3 and nothing else.
static ONLY_TLS13: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

/// Both versions rustls implements. It implements nothing below TLS 1.2,
/// so that is the floor whatever a peer offers.
static FROM_TLS12: [&SupportedProtocolVersion; 2] =
    [&rustls::version::TLS13, &rustls::version::TLS12];

/// The protocol versions for a floor.
fn versions(floor: TlsVersion) -> &'static [&'static SupportedProtocolVersion] {
    match floor {
        TlsVersion::Tls13 => &ONLY_TLS13,
        _ => &FROM_TLS12,
    }
}

/// Why the TLS settings of a listener could not be used.
///
/// The message names files and says what is wrong. It never contains
/// anything read from a key or a certificate.
#[derive(Debug)]
#[non_exhaustive]
pub enum TlsError {
    /// A file could not be read.
    Read {
        /// The file.
        file: PathBuf,
        /// What went wrong.
        kind: io::ErrorKind,
    },
    /// A file is not valid PEM.
    NotPem {
        /// The file.
        file: PathBuf,
    },
    /// A file holds no certificate.
    NoCertificate {
        /// The file.
        file: PathBuf,
    },
    /// A file holds no private key.
    NoPrivateKey {
        /// The file.
        file: PathBuf,
    },
    /// The certificate and the private key do not belong together, or the
    /// key is of a kind that is not supported.
    KeyMismatch {
        /// The certificate file.
        cert: PathBuf,
        /// The key file.
        key: PathBuf,
    },
    /// The system's certificate store holds no usable certificate.
    NoSystemRoots,
    /// The name to verify the certificate of the database against is not a
    /// host name or an address.
    ServerName,
    /// TLS is configured, and a setting it needs is missing. A checked
    /// configuration never gives this.
    Incomplete(&'static str),
    /// The TLS library refused the settings.
    Rejected(&'static str),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { file, kind } => {
                write!(f, "{}: cannot read the file: {kind}", file.display())
            }
            Self::NotPem { file } => write!(f, "{}: the file is not valid PEM", file.display()),
            Self::NoCertificate { file } => {
                write!(f, "{}: the file holds no certificate", file.display())
            }
            Self::NoPrivateKey { file } => {
                write!(f, "{}: the file holds no private key", file.display())
            }
            Self::KeyMismatch { cert, key } => write!(
                f,
                "the private key in {} cannot be used with the certificate in {}",
                key.display(),
                cert.display()
            ),
            Self::NoSystemRoots => f.write_str(
                "the system's certificate store holds no usable certificate; set upstream_tls.ca",
            ),
            Self::ServerName => {
                f.write_str("the name of the database is not a host name or an address")
            }
            Self::Incomplete(what) => write!(f, "TLS is configured without {what}"),
            Self::Rejected(what) => write!(f, "the TLS settings were refused: {what}"),
        }
    }
}

impl std::error::Error for TlsError {}

fn pem_error(file: &Path, error: rustls::pki_types::pem::Error) -> TlsError {
    match error {
        rustls::pki_types::pem::Error::Io(error) => TlsError::Read {
            file: file.to_path_buf(),
            kind: error.kind(),
        },
        // What the parser says about the content is not repeated: the file
        // may be a private key.
        _ => TlsError::NotPem {
            file: file.to_path_buf(),
        },
    }
}

/// Reads every certificate of a PEM file. There must be at least one.
fn read_certificates(file: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = CertificateDer::pem_file_iter(file)
        .map_err(|error| pem_error(file, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| pem_error(file, error))?;
    if certificates.is_empty() {
        return Err(TlsError::NoCertificate {
            file: file.to_path_buf(),
        });
    }
    Ok(certificates)
}

/// Reads the private key of a PEM file.
fn read_private_key(file: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(file).map_err(|error| match error {
        rustls::pki_types::pem::Error::NoItemsFound => TlsError::NoPrivateKey {
            file: file.to_path_buf(),
        },
        other => pem_error(file, other),
    })
}

/// TLS on the client leg of one listener, between applications and pgsnare.
#[derive(Clone)]
pub struct ClientLeg {
    policy: TlsPolicy,
    acceptor: Option<TlsAcceptor>,
    /// The certificate pgsnare presents to clients, encoded.
    leaf: Option<CertificateDer<'static>>,
}

impl ClientLeg {
    /// A client leg without TLS.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            policy: TlsPolicy::Disabled,
            acceptor: None,
            leaf: None,
        }
    }

    /// Reads the certificate and the key a listener is configured with.
    ///
    /// `alpn` is the name of the protocol in the ALPN extension, if it has
    /// one.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the files or the settings.
    pub fn from_config(config: &ClientTls, alpn: Option<&[u8]>) -> Result<Self, TlsError> {
        let policy = match config.mode {
            ClientTlsMode::Disable => return Ok(Self::disabled()),
            ClientTlsMode::Prefer => TlsPolicy::Optional,
            _ => TlsPolicy::Required,
        };
        let cert_file = config
            .cert
            .as_deref()
            .ok_or(TlsError::Incomplete("a certificate"))?;
        let key_file = config
            .key
            .as_deref()
            .ok_or(TlsError::Incomplete("a private key"))?;
        let chain = read_certificates(cert_file)?;
        let key = read_private_key(key_file)?;
        let leaf = chain.first().cloned();

        let mut server = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(versions(config.min_version))
            .map_err(|_| TlsError::Rejected("no cipher suite for the protocol versions"))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|_| TlsError::KeyMismatch {
                cert: cert_file.to_path_buf(),
                key: key_file.to_path_buf(),
            })?;
        server.alpn_protocols = alpn.map(<[u8]>::to_vec).into_iter().collect();
        // A full handshake every time, as against the database itself.
        server.session_storage = Arc::new(NoServerSessionStorage {});
        server.send_tls13_tickets = 0;

        Ok(Self {
            policy,
            acceptor: Some(TlsAcceptor::from(Arc::new(server))),
            leaf,
        })
    }

    /// Whether clients may or must use TLS.
    #[must_use]
    pub const fn policy(&self) -> TlsPolicy {
        self.policy
    }

    /// What runs the handshake with a client. `None` without TLS.
    #[must_use]
    pub const fn acceptor(&self) -> Option<&TlsAcceptor> {
        self.acceptor.as_ref()
    }

    /// The certificate pgsnare presents to clients, in its encoded form.
    #[must_use]
    pub fn certificate(&self) -> Option<&[u8]> {
        self.leaf.as_deref()
    }
}

impl fmt::Debug for ClientLeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientLeg")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// When the backend leg uses TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendTlsUse {
    /// Never.
    Never,
    /// When the database offers it. Plaintext otherwise.
    IfOffered,
    /// Always. A database that does not offer it is not used.
    Always,
}

/// TLS on the backend leg of one listener, between pgsnare and the
/// database.
#[derive(Clone)]
pub struct BackendLeg {
    usage: BackendTlsUse,
    verifies: bool,
    connector: Option<TlsConnector>,
    server_name: Option<ServerName<'static>>,
}

impl BackendLeg {
    /// A backend leg without TLS.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            usage: BackendTlsUse::Never,
            verifies: false,
            connector: None,
            server_name: None,
        }
    }

    /// Reads what a listener is configured with for the connection to
    /// `upstream`.
    ///
    /// `alpn` is the name of the protocol in the ALPN extension, if it has
    /// one.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the files or the settings.
    pub fn from_config(
        config: &UpstreamTls,
        upstream: &Endpoint,
        alpn: Option<&[u8]>,
    ) -> Result<Self, TlsError> {
        let usage = match config.mode {
            UpstreamTlsMode::Disable => return Ok(Self::disabled()),
            UpstreamTlsMode::Prefer => BackendTlsUse::IfOffered,
            _ => BackendTlsUse::Always,
        };
        let verifies = config.mode.verifies();

        let name = match (&config.server_name, upstream) {
            (Some(name), _) => name.as_str().to_owned(),
            (None, Endpoint::Tcp { host, .. }) => host.as_str().to_owned(),
            (None, _) => return Err(TlsError::Incomplete("a host to connect to")),
        };
        let server_name = ServerName::try_from(name).map_err(|_| TlsError::ServerName)?;

        let builder = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(versions(config.min_version))
            .map_err(|_| TlsError::Rejected("no cipher suite for the protocol versions"))?;
        let mut client = if verifies {
            builder
                .with_root_certificates(roots(config.ca.as_deref())?)
                .with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate {
                    provider: provider(),
                }))
                .with_no_client_auth()
        };
        client.alpn_protocols = alpn.map(<[u8]>::to_vec).into_iter().collect();
        client.resumption = Resumption::disabled();

        Ok(Self {
            usage,
            verifies,
            connector: Some(TlsConnector::from(Arc::new(client))),
            server_name: Some(server_name),
        })
    }

    /// When the backend leg uses TLS.
    #[must_use]
    pub const fn usage(&self) -> BackendTlsUse {
        self.usage
    }

    /// Whether the certificate of the database is verified. `false` also
    /// when TLS is not used at all.
    #[must_use]
    pub const fn verifies(&self) -> bool {
        self.verifies
    }

    /// What runs the handshake with the database. `None` without TLS.
    #[must_use]
    pub const fn connector(&self) -> Option<&TlsConnector> {
        self.connector.as_ref()
    }

    /// The name the certificate of the database must carry, which is also
    /// the name sent to it in the handshake.
    #[must_use]
    pub const fn server_name(&self) -> Option<&ServerName<'static>> {
        self.server_name.as_ref()
    }
}

impl fmt::Debug for BackendLeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendLeg")
            .field("usage", &self.usage)
            .field("verifies", &self.verifies)
            .finish_non_exhaustive()
    }
}

/// The authorities a certificate of the database may be signed by: the
/// ones in `ca`, or the system's store.
fn roots(ca: Option<&Path>) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    match ca {
        Some(file) => {
            for certificate in read_certificates(file)? {
                store
                    .add(certificate)
                    .map_err(|_| TlsError::NoCertificate {
                        file: file.to_path_buf(),
                    })?;
            }
        }
        None => {
            // Certificates the store cannot use are skipped, as every TLS
            // client does. An empty store would trust nobody.
            let found = rustls_native_certs::load_native_certs();
            store.add_parsable_certificates(found.certs);
            if store.is_empty() {
                return Err(TlsError::NoSystemRoots);
            }
        }
    }
    Ok(store)
}

/// Accepts whatever certificate the database presents: the modes `prefer`
/// and `require`, which encrypt and do not authenticate.
///
/// The signature of the handshake is still checked, so the peer does hold
/// the key of the certificate it presented. Whose certificate that is
/// remains unknown.
#[derive(Debug)]
struct AnyCertificate {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Says what went wrong in a handshake, in a fixed text.
///
/// The text of the error is never used, because parts of it can come from
/// the other side.
#[must_use]
pub fn describe(error: &io::Error) -> &'static str {
    let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return match error.kind() {
            io::ErrorKind::UnexpectedEof => "the connection was closed during the handshake",
            io::ErrorKind::TimedOut => "the handshake took too long",
            _ => "the connection failed during the handshake",
        };
    };
    match tls {
        rustls::Error::InvalidCertificate(reason) => match reason {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "the certificate has expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "the certificate is not valid yet"
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "the certificate is not valid for the name of the database"
            }
            CertificateError::UnknownIssuer => {
                "the certificate is not signed by a trusted authority"
            }
            CertificateError::BadSignature => "the certificate has a bad signature",
            CertificateError::Revoked => "the certificate has been revoked",
            _ => "the certificate was not accepted",
        },
        rustls::Error::NoApplicationProtocol => "the peer does not speak the expected protocol",
        rustls::Error::PeerIncompatible(_) => {
            "the peer supports no protocol version or cipher that is acceptable"
        }
        rustls::Error::AlertReceived(_) => "the peer refused the handshake",
        rustls::Error::InvalidMessage(_)
        | rustls::Error::InappropriateMessage { .. }
        | rustls::Error::InappropriateHandshakeMessage { .. }
        | rustls::Error::PeerMisbehaved(_) => "the peer did not send a valid handshake",
        _ => "the handshake failed",
    }
}
