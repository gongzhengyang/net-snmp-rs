//! SNMP over TLS — the secure transport channel (`snmpTLSTCPDomain`).
//!
//! Counterpart of `transports/snmpTLSTCPDomain.c` and the TLS portion of
//! `snmpTLSBaseDomain.c`. This layers [`tokio_rustls`] (rustls with the `ring`
//! crypto provider) over a TCP stream and reuses the BER message framing of
//! [`StreamTransport`](crate::transport::StreamTransport), so SNMP messages of
//! any version flow over an encrypted, optionally mutually-authenticated
//! channel.
//!
//! # Scope
//!
//! This implements the **secure transport channel**: certificate-based server
//! (and optional client) authentication plus confidentiality/integrity from
//! TLS 1.2/1.3. The full RFC 6353 **Transport Security Model** (TSM) — the
//! `securityModel = transportSecurityModel(4)` message processing and the
//! `tlstmCertToTSN` certificate→securityName mapping table — is *not* modelled;
//! community or USM messages are simply carried over the TLS channel.
//!
//! Only compiled when the `tls` feature is enabled (on by default).

use crate::error::{Error, Result};
use crate::transport::StreamTransport;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A TLS client transport: a [`StreamTransport`] over a client-side TLS stream.
pub type TlsClientTransport = StreamTransport<tokio_rustls::client::TlsStream<TcpStream>>;
/// A TLS server transport: a [`StreamTransport`] over a server-side TLS stream.
pub type TlsServerTransport = StreamTransport<tokio_rustls::server::TlsStream<TcpStream>>;

/// Construct the `ring`-backed rustls crypto provider.
fn provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
}

/// Parse one or more PEM-encoded certificates.
fn certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = pem;
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut cursor).collect();
    let certs = certs.map_err(Error::Io)?;
    if certs.is_empty() {
        return Err(Error::Security("no certificates found in PEM".into()));
    }
    Ok(certs)
}

/// Parse the first PEM-encoded private key (PKCS#8, PKCS#1 or SEC1).
fn key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = pem;
    rustls_pemfile::private_key(&mut cursor)
        .map_err(Error::Io)?
        .ok_or_else(|| Error::Security("no private key found in PEM".into()))
}

/// A reusable TLS client factory: a rustls connector plus the expected server
/// name used to validate the peer certificate.
#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsClient {
    /// Build a client that trusts the certificate authority (or self-signed
    /// peer certificate) in `ca_pem`, validating the peer against `server_name`.
    ///
    /// `server_name` must match a name in the peer certificate (its CN/SAN).
    pub fn from_root_ca_pem(server_name: &str, ca_pem: &[u8]) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in certs_from_pem(ca_pem)? {
            roots
                .add(cert)
                .map_err(|e| Error::Security(format!("invalid CA certificate: {e}")))?;
        }
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Security(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::Security(format!("invalid server name: {e}")))?;
        Ok(TlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    /// Build a client from an already-constructed rustls [`ClientConfig`].
    pub fn from_config(config: Arc<ClientConfig>, server_name: &str) -> Result<Self> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::Security(format!("invalid server name: {e}")))?;
        Ok(TlsClient {
            connector: TlsConnector::from(config),
            server_name,
        })
    }

    /// Build a client that trusts `ca_pem`, validates the peer against
    /// `server_name`, and additionally presents a client certificate
    /// (`client_cert_pem` chain + `client_key_pem`) for mutual TLS.
    ///
    /// This is the `(D)TLS-TM` client side of RFC 6353: the server may use the
    /// client certificate to derive a `securityName` via the
    /// `tlstmCertToTSN` table (see [`crate::v3::tsm`]).
    pub fn with_client_cert(
        server_name: &str,
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
    ) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in certs_from_pem(ca_pem)? {
            roots
                .add(cert)
                .map_err(|e| Error::Security(format!("invalid CA certificate: {e}")))?;
        }
        let client_certs = certs_from_pem(client_cert_pem)?;
        let client_key = key_from_pem(client_key_pem)?;
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Security(e.to_string()))?
            .with_root_certificates(roots)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| Error::Security(format!("invalid client certificate/key: {e}")))?;
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| Error::Security(format!("invalid server name: {e}")))?;
        Ok(TlsClient {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    /// Open a TCP connection to `peer` and complete the TLS handshake.
    pub async fn connect(&self, peer: &str) -> Result<TlsClientTransport> {
        let tcp = TcpStream::connect(peer).await?;
        tcp.set_nodelay(true).ok();
        let addr = tcp.peer_addr().ok();
        let stream = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| Error::Security(format!("TLS handshake failed: {e}")))?;
        Ok(StreamTransport::new(stream, addr))
    }
}

/// A TLS listener that accepts inbound SNMP-over-TLS connections.
pub struct TlsServer {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsServer {
    /// Build a rustls [`ServerConfig`] presenting `cert_pem` (a chain) with the
    /// private key `key_pem`, without requiring client certificates.
    pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>> {
        let certs = certs_from_pem(cert_pem)?;
        let key = key_from_pem(key_pem)?;
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Security(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::Security(format!("invalid server certificate/key: {e}")))?;
        Ok(Arc::new(config))
    }

    /// Build a rustls [`ServerConfig`] presenting `cert_pem` (a chain) with the
    /// private key `key_pem`, and **require** a client certificate verified
    /// against `client_ca_pem` (mutual TLS).
    ///
    /// This is the `(D)TLS-TM` server side of RFC 6353: the presented client
    /// certificate identifies the peer and is mapped to a `securityName` via
    /// the `tlstmCertToTSN` table (see [`crate::v3::tsm`]). A client that does
    /// not present a trusted certificate is rejected at the TLS layer.
    pub fn server_config_with_client_auth(
        cert_pem: &[u8],
        key_pem: &[u8],
        client_ca_pem: &[u8],
    ) -> Result<Arc<ServerConfig>> {
        let certs = certs_from_pem(cert_pem)?;
        let key = key_from_pem(key_pem)?;
        let mut client_roots = RootCertStore::empty();
        for cert in certs_from_pem(client_ca_pem)? {
            client_roots
                .add(cert)
                .map_err(|e| Error::Security(format!("invalid client CA certificate: {e}")))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| Error::Security(format!("client cert verifier build failed: {e}")))?;
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Security(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| Error::Security(format!("invalid server certificate/key: {e}")))?;
        Ok(Arc::new(config))
    }

    /// Bind a TLS listener on `local` using the given server configuration.
    pub async fn bind(local: &str, config: Arc<ServerConfig>) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(local).await?;
        Ok(TlsServer {
            listener,
            acceptor: TlsAcceptor::from(config),
        })
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept the next connection and complete the TLS handshake, returning a
    /// framed transport and the peer address.
    pub async fn accept(&self) -> Result<(TlsServerTransport, std::net::SocketAddr)> {
        let (tcp, peer) = self.listener.accept().await?;
        tcp.set_nodelay(true).ok();
        let stream = self
            .acceptor
            .accept(tcp)
            .await
            .map_err(|e| Error::Security(format!("TLS handshake failed: {e}")))?;
        Ok((StreamTransport::new(stream, Some(peer)), peer))
    }
}
