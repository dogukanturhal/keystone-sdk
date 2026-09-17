// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL connection establishment with libpq-compatible TLS.
//!
//! Every database connection the SDK and `keystonectl` open goes through
//! [`connect`]. Before this module existed both call sites passed
//! [`tokio_postgres::NoTls`] literally, which meant the Rust side could not
//! speak TLS *at all* — not "defaulted to plaintext", but had no code path
//! that would ever negotiate a session. Against a CloudNativePG cluster,
//! which serves TLS and presents a cert signed by a per-cluster CA, that
//! surfaced as `error performing TLS handshake` with no setting that could
//! fix it. The Go operator has always dialled `verify-full` by default
//! (`internal/postgres/pool.go`), so the two halves of the same SDK
//! disagreed about whether the wire was encrypted.
//!
//! # sslmode
//!
//! The libpq ladder is implemented in full, including the distinction that
//! is easiest to get wrong: **`require` encrypts but does not authenticate**.
//! It stops a passive eavesdropper and nothing else — an attacker who can
//! answer for the server's address presents any self-signed cert and the
//! handshake succeeds. Only `verify-ca` and `verify-full` check the chain.
//!
//! | mode          | encrypted | chain checked | hostname checked |
//! |---------------|-----------|---------------|------------------|
//! | `disable`     | no        | –             | –                |
//! | `allow`       | if server insists | no    | no               |
//! | `prefer`      | if server offers  | no    | no               |
//! | `require`     | yes       | no            | no               |
//! | `verify-ca`   | yes       | yes           | no               |
//! | `verify-full` | yes       | yes           | yes              |
//!
//! The default when a DSN names no `sslmode` is **`verify-full`**, not
//! libpq's `prefer`. This deliberately diverges from libpq: `prefer` falls
//! back to cleartext against a server that declines TLS, so a
//! man-in-the-middle strips encryption merely by answering "no". Matching
//! the operator's default instead means the secure mode is the one you get
//! by saying nothing, and the weaker modes are reachable only by asking for
//! them by name.
//!
//! `sslrootcert` selects the trust anchors for `verify-ca`/`verify-full`: a
//! path to a PEM bundle, or the literal `system` to use the platform trust
//! store. Omitted, the platform trust store is used. For a CloudNativePG
//! cluster the bundle is the `ca.crt` key of the cluster's CA Secret.
//!
//! `allow` has no tokio-postgres equivalent — it asks for plaintext first
//! and upgrades only if refused. It is accepted and treated as `prefer`,
//! which negotiates in the opposite order but admits exactly the same set
//! of outcomes, and prefers the encrypted one.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::task::JoinHandle;
use tokio_postgres::{Client, Config, NoTls};

/// The libpq `sslmode` ladder. See the module docs for the guarantees each
/// rung actually provides — in particular that `Require` does not
/// authenticate the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    /// Never use TLS.
    Disable,
    /// Use TLS only if the server refuses a plaintext connection. Accepted
    /// for libpq compatibility; negotiated as [`SslMode::Prefer`].
    Allow,
    /// Use TLS if the server offers it, without verifying the certificate.
    Prefer,
    /// Require TLS, without verifying the certificate.
    Require,
    /// Require TLS and verify the certificate chain, but not the hostname.
    VerifyCa,
    /// Require TLS and verify both the certificate chain and the hostname.
    #[default]
    VerifyFull,
}

impl SslMode {
    /// Parses a libpq `sslmode` keyword.
    pub fn parse(s: &str) -> Result<Self, ConnectError> {
        match s {
            "disable" => Ok(Self::Disable),
            "allow" => Ok(Self::Allow),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            other => Err(ConnectError::InvalidSslMode(other.to_string())),
        }
    }

    /// The libpq keyword for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Allow => "allow",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }

    /// Whether a session on this mode is guaranteed to be encrypted.
    pub fn encrypts(self) -> bool {
        !matches!(self, Self::Disable | Self::Allow | Self::Prefer)
    }

    /// Whether the server's certificate chain is checked against a trust
    /// anchor.
    pub fn verifies_chain(self) -> bool {
        matches!(self, Self::VerifyCa | Self::VerifyFull)
    }

    /// How tokio-postgres should negotiate. `verify-ca`/`verify-full` map to
    /// `Require` because the extra checking happens in the certificate
    /// verifier, not in the startup negotiation.
    fn negotiation(self) -> tokio_postgres::config::SslMode {
        use tokio_postgres::config::SslMode as Neg;
        match self {
            Self::Disable => Neg::Disable,
            Self::Allow | Self::Prefer => Neg::Prefer,
            Self::Require | Self::VerifyCa | Self::VerifyFull => Neg::Require,
        }
    }
}

/// Errors raised while establishing a connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// `sslmode` named something outside the libpq ladder.
    #[error(
        "invalid sslmode {0:?}: expected disable, allow, prefer, require, verify-ca or verify-full"
    )]
    InvalidSslMode(String),
    /// The `sslrootcert` file could not be read.
    #[error("sslrootcert {path}: {source}")]
    RootCertRead {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The `sslrootcert` file held no usable certificates.
    #[error("sslrootcert {0}: no certificates found in PEM bundle")]
    RootCertEmpty(String),
    /// The platform trust store could not be loaded.
    #[error("loading platform root certificates: {0}")]
    PlatformRoots(String),
    /// The DSN was not parseable as a PostgreSQL connection string.
    #[error("connection string: {0}")]
    Dsn(String),
    /// Building the TLS client configuration failed.
    #[error("tls configuration: {0}")]
    Tls(#[from] rustls::Error),
    /// The connection itself failed.
    #[error(transparent)]
    Db(#[from] tokio_postgres::Error),
}

/// A DSN with the TLS parameters lifted out of it.
///
/// `dsn` has `sslmode` and `sslrootcert` removed, because tokio-postgres
/// rejects `verify-ca`/`verify-full` outright and does not know
/// `sslrootcert` at all. The mode is reapplied through
/// [`Config::ssl_mode`] after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsParams {
    /// The DSN stripped of `sslmode` and `sslrootcert`.
    pub dsn: String,
    /// The requested mode, defaulting to [`SslMode::VerifyFull`].
    pub mode: SslMode,
    /// The `sslrootcert` value, if the DSN carried one.
    pub root_cert: Option<String>,
}

/// Lifts `sslmode` and `sslrootcert` out of a DSN.
///
/// Handles both syntaxes libpq accepts: the URL form
/// (`postgres://user@host/db?sslmode=require`) and the keyword/value form
/// (`host=db user=u sslmode=require`). Parameters that are kept are
/// preserved as their original substrings rather than re-serialised, so no
/// quoting or percent-encoding is disturbed on the way through.
pub fn split_tls_params(dsn: &str) -> Result<TlsParams, ConnectError> {
    if is_url_form(dsn) {
        split_url(dsn)
    } else {
        split_keyword_value(dsn)
    }
}

fn is_url_form(dsn: &str) -> bool {
    let lower = dsn.trim_start().to_ascii_lowercase();
    lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("postgres:")
        || lower.starts_with("postgresql:")
}

fn split_url(dsn: &str) -> Result<TlsParams, ConnectError> {
    let (base, query) = match dsn.split_once('?') {
        Some((b, q)) => (b, q),
        None => {
            return Ok(TlsParams {
                dsn: dsn.to_string(),
                mode: SslMode::default(),
                root_cert: None,
            })
        }
    };

    let mut mode = None;
    let mut root_cert = None;
    let mut kept: Vec<&str> = Vec::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        match percent_decode(raw_key).as_str() {
            "sslmode" => mode = Some(SslMode::parse(&percent_decode(raw_value))?),
            "sslrootcert" => root_cert = Some(percent_decode(raw_value)),
            _ => kept.push(pair),
        }
    }

    let rebuilt = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };

    Ok(TlsParams {
        dsn: rebuilt,
        mode: mode.unwrap_or_default(),
        root_cert,
    })
}

/// Percent-decodes a URL query component. Also maps `+` to a space, which
/// is what libpq's URI parser does for query values.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    // Not a valid escape — keep the '%' verbatim, as libpq
                    // does rather than failing the whole DSN.
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits the keyword/value form, honouring libpq's quoting: values may be
/// single-quoted to contain spaces, and a backslash escapes the next
/// character inside or outside quotes.
fn split_keyword_value(dsn: &str) -> Result<TlsParams, ConnectError> {
    let mut mode = None;
    let mut root_cert = None;
    let mut kept: Vec<String> = Vec::new();

    for (raw, key, value) in tokenize_keyword_value(dsn) {
        match key.as_str() {
            "sslmode" => mode = Some(SslMode::parse(&value)?),
            "sslrootcert" => root_cert = Some(value),
            _ => kept.push(raw),
        }
    }

    Ok(TlsParams {
        dsn: kept.join(" "),
        mode: mode.unwrap_or_default(),
        root_cert,
    })
}

/// Yields `(original_token, key, unquoted_value)` for each `key=value` in a
/// keyword/value DSN. The original token is returned verbatim so callers
/// can rebuild a DSN without re-quoting anything.
fn tokenize_keyword_value(dsn: &str) -> Vec<(String, String, String)> {
    let chars: Vec<char> = dsn.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let start = i;

        // Key runs to '=' or whitespace.
        let mut key = String::new();
        while i < chars.len() && chars[i] != '=' && !chars[i].is_whitespace() {
            key.push(chars[i]);
            i += 1;
        }
        // libpq tolerates whitespace around '='.
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            // A bare word with no '='. Keep it so the DSN survives round
            // trip and let tokio-postgres report it.
            out.push((chars[start..i].iter().collect(), key, String::new()));
            continue;
        }
        i += 1; // consume '='
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }

        let mut value = String::new();
        if i < chars.len() && chars[i] == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                value.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                i += 1; // closing quote
            }
        } else {
            while i < chars.len() && !chars[i].is_whitespace() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                value.push(chars[i]);
                i += 1;
            }
        }

        out.push((chars[start..i].iter().collect(), key, value));
    }

    out
}

/// A certificate verifier that checks the chain but tolerates a name
/// mismatch — libpq's `verify-ca`.
///
/// rustls has no "chain but not name" mode, so this delegates every check
/// to the real Web PKI verifier and then forgives exactly one class of
/// rejection: the certificate not being valid for the requested name.
/// Every other failure — untrusted issuer, expiry, bad signature, revoked —
/// still rejects. That is precisely what `verify-ca` means: the server
/// proved it holds a key certified by an anchor we trust, but we did not
/// insist the address we dialled is one of the names on the certificate.
#[derive(Debug)]
struct ChainOnlyVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForName)) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
                ..
            })) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A verifier that accepts any certificate — libpq's `require`/`prefer`.
///
/// This is not a weakened `verify-full`; it is the mode's actual definition.
/// libpq's `require` promises encryption only, and callers that want the
/// server authenticated are expected to say `verify-full`. Naming the type
/// after what it does keeps that from reading like an oversight at the call
/// site.
#[derive(Debug)]
struct EncryptOnlyVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for EncryptOnlyVerifier {
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
        rustls::crypto::verify_tls12_signature(
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
        rustls::crypto::verify_tls13_signature(
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

/// Loads the trust anchors named by `sslrootcert`, or the platform trust
/// store when it is absent or set to the literal `system`.
fn root_store(root_cert: Option<&str>) -> Result<RootCertStore, ConnectError> {
    let mut store = RootCertStore::empty();

    match root_cert {
        Some(path) if path != "system" => {
            let pem = std::fs::read(path).map_err(|source| ConnectError::RootCertRead {
                path: path.to_string(),
                source,
            })?;
            let mut cursor = std::io::Cursor::new(pem);
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert = cert.map_err(|source| ConnectError::RootCertRead {
                    path: path.to_string(),
                    source,
                })?;
                store
                    .add(cert)
                    .map_err(|e| ConnectError::PlatformRoots(e.to_string()))?;
                added += 1;
            }
            if added == 0 {
                return Err(ConnectError::RootCertEmpty(path.to_string()));
            }
        }
        _ => {
            let loaded = rustls_native_certs::load_native_certs();
            if loaded.certs.is_empty() {
                let why = loaded
                    .errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(ConnectError::PlatformRoots(if why.is_empty() {
                    "trust store is empty".to_string()
                } else {
                    why
                }));
            }
            for cert in loaded.certs {
                // A platform store may carry a cert rustls will not accept;
                // skipping it is right, because failing the whole
                // connection over one unrelated anchor is not.
                let _ = store.add(cert);
            }
        }
    }

    Ok(store)
}

/// Builds the rustls client configuration for a mode.
///
/// Returns `None` for [`SslMode::Disable`], where there is no TLS stack to
/// build.
fn client_config(
    mode: SslMode,
    root_cert: Option<&str>,
) -> Result<Option<rustls::ClientConfig>, ConnectError> {
    if mode == SslMode::Disable {
        return Ok(None);
    }

    // Pin the provider explicitly. rustls 0.23 otherwise reads a
    // process-global default that a *different* crate in the binary may
    // have installed — or not installed, in which case building a config
    // panics rather than returning an error.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;

    let verifier: Arc<dyn ServerCertVerifier> = if mode.verifies_chain() {
        let store = Arc::new(root_store(root_cert)?);
        let webpki = WebPkiServerVerifier::builder_with_provider(store, provider.clone())
            .build()
            .map_err(|e| ConnectError::Tls(rustls::Error::General(e.to_string())))?;
        match mode {
            SslMode::VerifyCa => Arc::new(ChainOnlyVerifier { inner: webpki }),
            _ => webpki,
        }
    } else {
        Arc::new(EncryptOnlyVerifier { provider })
    };

    Ok(Some(
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    ))
}

/// Opens a connection to `dsn`, negotiating TLS per its `sslmode`.
///
/// Returns the client together with the [`JoinHandle`] of the spawned
/// connection driver. Dropping the client ends the driver, so a caller that
/// wants to be sure the socket is closed can drop the client and then await
/// the handle.
///
/// The default when `dsn` names no `sslmode` is `verify-full` — see the
/// module docs for why this diverges from libpq.
pub async fn connect(dsn: &str) -> Result<(Client, JoinHandle<()>), ConnectError> {
    let params = split_tls_params(dsn)?;
    let mut config: Config = params
        .dsn
        .parse()
        .map_err(|e: tokio_postgres::Error| ConnectError::Dsn(e.to_string()))?;
    config.ssl_mode(params.mode.negotiation());

    match client_config(params.mode, params.root_cert.as_deref())? {
        None => {
            let (client, connection) = config.connect(NoTls).await?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, driver))
        }
        Some(tls) => {
            let (client, connection) = config
                .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                .await?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((client, driver))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_verify_full_when_dsn_is_silent() {
        // The whole point of the module: saying nothing must not mean
        // cleartext.
        let p = split_tls_params("postgres://u@h/db").unwrap();
        assert_eq!(p.mode, SslMode::VerifyFull);
        assert!(p.mode.encrypts());
        assert!(p.mode.verifies_chain());

        let p = split_tls_params("host=h user=u dbname=db").unwrap();
        assert_eq!(p.mode, SslMode::VerifyFull);
    }

    #[test]
    fn url_form_lifts_and_strips_tls_params() {
        let p =
            split_tls_params("postgres://u:p@h:5432/db?sslmode=verify-ca&sslrootcert=/tmp/ca.crt")
                .unwrap();
        assert_eq!(p.mode, SslMode::VerifyCa);
        assert_eq!(p.root_cert.as_deref(), Some("/tmp/ca.crt"));
        // Both must be gone: tokio-postgres rejects `verify-ca` outright and
        // has never heard of `sslrootcert`.
        assert_eq!(p.dsn, "postgres://u:p@h:5432/db");
    }

    #[test]
    fn url_form_preserves_unrelated_params_verbatim() {
        let p = split_tls_params(
            "postgres://u@h/db?application_name=keystonectl&sslmode=require&connect_timeout=5",
        )
        .unwrap();
        assert_eq!(p.mode, SslMode::Require);
        assert_eq!(
            p.dsn,
            "postgres://u@h/db?application_name=keystonectl&connect_timeout=5"
        );
    }

    #[test]
    fn url_form_percent_decodes_values() {
        let p = split_tls_params("postgres://u@h/db?sslrootcert=%2Fetc%2Fssl%2Fca%20bundle.pem")
            .unwrap();
        assert_eq!(p.root_cert.as_deref(), Some("/etc/ssl/ca bundle.pem"));
    }

    #[test]
    fn keyword_form_lifts_and_strips_tls_params() {
        let p = split_tls_params("host=db.internal user=u sslmode=verify-full sslrootcert=/ca.pem")
            .unwrap();
        assert_eq!(p.mode, SslMode::VerifyFull);
        assert_eq!(p.root_cert.as_deref(), Some("/ca.pem"));
        assert_eq!(p.dsn, "host=db.internal user=u");
    }

    #[test]
    fn keyword_form_honours_quoted_values() {
        let p = split_tls_params("host=h password='a b c' sslmode=require").unwrap();
        assert_eq!(p.mode, SslMode::Require);
        // The kept token is the *original* text, so the quoting that made
        // the space legal is still there.
        assert_eq!(p.dsn, "host=h password='a b c'");
    }

    #[test]
    fn keyword_form_honours_escaped_quote() {
        let p = split_tls_params(r"host=h password='a\'b' sslmode=disable").unwrap();
        assert_eq!(p.mode, SslMode::Disable);
        assert_eq!(p.dsn, r"host=h password='a\'b'");
    }

    #[test]
    fn rejects_unknown_sslmode() {
        let err = split_tls_params("postgres://h/db?sslmode=verify_full").unwrap_err();
        // Loud, not a silent downgrade to cleartext.
        assert!(matches!(err, ConnectError::InvalidSslMode(m) if m == "verify_full"));
    }

    #[test]
    fn allow_is_accepted_and_treated_as_prefer() {
        let p = split_tls_params("postgres://h/db?sslmode=allow").unwrap();
        assert_eq!(p.mode, SslMode::Allow);
        assert_eq!(
            p.mode.negotiation(),
            tokio_postgres::config::SslMode::Prefer
        );
    }

    #[test]
    fn negotiation_maps_verify_modes_to_require() {
        use tokio_postgres::config::SslMode as Neg;
        assert_eq!(SslMode::Disable.negotiation(), Neg::Disable);
        assert_eq!(SslMode::Prefer.negotiation(), Neg::Prefer);
        assert_eq!(SslMode::Require.negotiation(), Neg::Require);
        // Verification happens in the certificate verifier; the startup
        // negotiation is identical to `require`.
        assert_eq!(SslMode::VerifyCa.negotiation(), Neg::Require);
        assert_eq!(SslMode::VerifyFull.negotiation(), Neg::Require);
    }

    #[test]
    fn guarantees_are_reported_per_mode() {
        // `require` encrypts but does not authenticate — the distinction
        // this table exists to keep honest.
        assert!(SslMode::Require.encrypts());
        assert!(!SslMode::Require.verifies_chain());
        assert!(!SslMode::Prefer.encrypts());
        assert!(SslMode::VerifyCa.verifies_chain());
        assert!(SslMode::VerifyFull.verifies_chain());
        assert!(!SslMode::Disable.encrypts());
    }

    #[test]
    fn round_trips_every_mode_keyword() {
        for m in [
            SslMode::Disable,
            SslMode::Allow,
            SslMode::Prefer,
            SslMode::Require,
            SslMode::VerifyCa,
            SslMode::VerifyFull,
        ] {
            assert_eq!(SslMode::parse(m.as_str()).unwrap(), m);
        }
    }

    #[test]
    fn disable_builds_no_tls_stack() {
        assert!(client_config(SslMode::Disable, None).unwrap().is_none());
    }

    #[test]
    fn encrypt_only_modes_need_no_trust_store() {
        // Must not touch the platform trust store — `require` has to work
        // on a host with no CA bundle at all.
        assert!(client_config(SslMode::Require, None).unwrap().is_some());
        assert!(client_config(SslMode::Prefer, None).unwrap().is_some());
    }

    #[test]
    fn missing_root_cert_file_is_an_error() {
        let err = client_config(SslMode::VerifyFull, Some("/nonexistent/ca.pem")).unwrap_err();
        assert!(matches!(err, ConnectError::RootCertRead { .. }));
    }

    #[test]
    fn empty_root_cert_file_is_an_error() {
        let dir = std::env::temp_dir().join("keystone-pgconn-empty-ca");
        std::fs::write(&dir, b"not a certificate\n").unwrap();
        let err = client_config(SslMode::VerifyCa, Some(dir.to_str().unwrap())).unwrap_err();
        std::fs::remove_file(&dir).ok();
        assert!(matches!(err, ConnectError::RootCertEmpty(_)));
    }

    #[tokio::test]
    async fn connect_reports_bad_sslmode_without_dialling() {
        // 127.0.0.1:1 would refuse instantly, but the mode is rejected
        // first, so the error is the parse error and not a connection error.
        let err = connect("postgres://u@127.0.0.1:1/db?sslmode=bogus")
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectError::InvalidSslMode(_)));
    }
}
