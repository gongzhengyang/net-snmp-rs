//! SNMP over DTLS — the `snmpDTLSUDPDomain` transport (RFC 6340).
//!
//! Counterpart of `transports/snmpDTLSUDPDomain.c`. DTLS carries SNMP over a
//! datagram channel with the same confidentiality/integrity guarantees TLS
//! gives the TCP domain, but preserving the datagram semantics of UDP.
//!
//! # Current status: stub
//!
//! A real DTLS implementation requires a DTLS-capable crate that is **not**
//! currently in the dependency tree (`tokio-rustls` does not expose DTLS in
//! its stable releases; DTLS support lives in `webrtc-dtls` or the experimental
//! rustls DTLS branch). This crate forbids adding new dependencies, so this
//! module ships a **stub**: the [`Transport`] surface is present and compiles
//! so callers and future wiring can reference the types, but every send/receive
//! returns [`Error::Protocol`] documenting that DTLS is not yet implemented.
//!
//! When a DTLS crate is added to the workspace, replace the bodies of
//! [`DtlsTransport::send`]/[`DtlsTransport::receive`] (and the [`DtlsServer`]
//! accept path) with the real handshake. The rest of the stack — BER framing,
//! session, TSM message processing — already handles per-datagram messages, so
//! no other plumbing changes are required.

use crate::error::{Error, Result};
use crate::transport::Transport;
use bytes::Bytes;

/// The URI-style scheme prefix identifying the DTLS-over-UDP domain.
pub const DTLS_SCHEME: &str = "dtls:";
/// The alternate `udp+dtls:` scheme prefix used by some tooling.
pub const UDP_DTLS_SCHEME: &str = "udp+dtls:";

/// Strip a `dtls:` / `udp+dtls:` prefix from `s`, returning the bare host:port
/// when the input names the DTLS domain and `None` otherwise.
///
/// Mirrors the address-prefix handling the C agent applies for
/// `snmpDTLSUDPDomain`. Trailing whitespace is trimmed.
///
/// ```
/// # use netsnmp::dtls::parse_dtls_addr;
/// assert_eq!(parse_dtls_addr("dtls:127.0.0.1:161"), Some("127.0.0.1:161".to_string()));
/// assert_eq!(parse_dtls_addr("udp+dtls:127.0.0.1:161"), Some("127.0.0.1:161".to_string()));
/// assert_eq!(parse_dtls_addr("127.0.0.1:161"), None);
/// ```
pub fn parse_dtls_addr(s: &str) -> Option<String> {
    let trimmed = s.trim();
    for prefix in [DTLS_SCHEME, UDP_DTLS_SCHEME] {
        if trimmed
            .to_ascii_lowercase()
            .strip_prefix(prefix)
            .is_some()
        {
            // Re-slice the original (case-preserving) string past the prefix.
            let stripped = &trimmed[prefix.len()..];
            return Some(stripped.trim().to_string());
        }
    }
    None
}

/// A connected DTLS client transport (`snmpDTLSUDPDomain`).
///
/// This is a **stub**: DTLS requires a DTLS implementation not currently in the
/// dependency tree, so [`Transport::send`] and [`Transport::receive`] always
/// return [`Error::Protocol`]. The type exists so higher layers can reference
/// the domain and a future DTLS crate can fill in the handshake without
/// touching call sites.
#[derive(Debug)]
pub struct DtlsTransport {
    /// The configured peer address (kept for diagnostics).
    pub peer: String,
}

impl DtlsTransport {
    /// "Connect" to `peer`. No socket is opened and no handshake is performed:
    /// DTLS is not yet implemented (see the module docs).
    pub async fn connect(peer: &str) -> Result<Self> {
        Ok(DtlsTransport {
            peer: peer.to_string(),
        })
    }
}

impl Transport for DtlsTransport {
    async fn send(&self, _data: &[u8]) -> Result<()> {
        Err(Error::Protocol(
            "DTLS not yet implemented; use TLS or UDP".into(),
        ))
    }

    async fn receive(&self) -> Result<Bytes> {
        Err(Error::Protocol(
            "DTLS not yet implemented; use TLS or UDP".into(),
        ))
    }
}

/// A DTLS server listener (`snmpDTLSUDPDomain` server side).
///
/// This is a **stub**: DTLS requires a DTLS implementation not currently in the
/// dependency tree, so [`DtlsServer::accept`] always returns
/// [`Error::Protocol`]. The type exists so a future DTLS crate can fill in the
/// handshake.
#[derive(Debug)]
pub struct DtlsServer {
    /// The configured bind address (kept for diagnostics).
    pub local: String,
}

impl DtlsServer {
    /// "Bind" to `local`. No socket is opened: DTLS is not yet implemented.
    pub async fn bind(local: &str) -> Result<Self> {
        Ok(DtlsServer {
            local: local.to_string(),
        })
    }

    /// Accept the next inbound DTLS connection. Always fails: DTLS is not yet
    /// implemented (see the module docs).
    pub async fn accept(&self) -> Result<(DtlsTransport, std::net::SocketAddr)> {
        Err(Error::Protocol(
            "DTLS not yet implemented; use TLS or UDP".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dtls_addr_strips_prefix() {
        assert_eq!(
            parse_dtls_addr("dtls:127.0.0.1:161"),
            Some("127.0.0.1:161".to_string())
        );
        assert_eq!(
            parse_dtls_addr("udp+dtls:127.0.0.1:161"),
            Some("127.0.0.1:161".to_string())
        );
    }

    #[test]
    fn parse_dtls_addr_uppercase_prefix_matches() {
        assert_eq!(
            parse_dtls_addr("DTLS:127.0.0.1:1161"),
            Some("127.0.0.1:1161".to_string())
        );
    }

    #[test]
    fn parse_dtls_addr_non_dtls_is_none() {
        assert_eq!(parse_dtls_addr("127.0.0.1:161"), None);
        assert_eq!(parse_dtls_addr("udp:127.0.0.1:161"), None);
        assert_eq!(parse_dtls_addr("tcp:127.0.0.1:161"), None);
    }

    #[tokio::test]
    async fn stub_transport_send_returns_protocol_error() {
        let t = DtlsTransport::connect("127.0.0.1:1161").await.unwrap();
        let err = t.send(&[0u8; 4]).await.unwrap_err();
        assert!(matches!(err, Error::Protocol(msg) if msg.contains("DTLS")));
    }

    #[tokio::test]
    async fn stub_transport_receive_returns_protocol_error() {
        let t = DtlsTransport::connect("127.0.0.1:1161").await.unwrap();
        let err = t.receive().await.unwrap_err();
        assert!(matches!(err, Error::Protocol(msg) if msg.contains("DTLS")));
    }

    #[tokio::test]
    async fn stub_server_accept_returns_protocol_error() {
        let s = DtlsServer::bind("127.0.0.1:0").await.unwrap();
        let err = s.accept().await.unwrap_err();
        assert!(matches!(err, Error::Protocol(msg) if msg.contains("DTLS")));
    }
}
