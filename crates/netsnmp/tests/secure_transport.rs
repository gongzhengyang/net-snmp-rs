//! End-to-end tests for the connection-oriented transports: plaintext TCP
//! (`snmpTCPDomain`) and TLS (`snmpTLSTCPDomain` secure channel).
//!
//! Each test stands up a minimal responder that decodes the request message and
//! answers with a fixed value, then drives it with a high-level [`Session`] over
//! the transport under test, all on the loopback interface.

use netsnmp::message::Message;
use netsnmp::pdu::{Pdu, PduType, VarBind};
use netsnmp::transport::{TcpServer, Transport};
use netsnmp::value::Value;
use netsnmp::{Oid, Session, SessionConfig};

const REPLY: &[u8] = b"hello-secure";

/// Decode one request and reply, echoing each requested OID with `REPLY`.
fn build_reply(raw: &[u8]) -> netsnmp::Result<Vec<u8>> {
    let msg = Message::decode(raw)?;
    let mut resp = Pdu::new(PduType::Response, msg.pdu.request_id);
    for vb in &msg.pdu.variables {
        resp.variables.push(VarBind::new(
            vb.oid.clone(),
            Value::OctetString(REPLY.to_vec()),
        ));
    }
    Message::new(msg.version, msg.community.clone(), resp).encode()
}

fn config() -> SessionConfig {
    SessionConfig {
        timeout: std::time::Duration::from_secs(5),
        retries: 0,
        ..SessionConfig::default()
    }
}

#[tokio::test]
async fn tcp_get_roundtrip() {
    let server = TcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (transport, _peer) = server.accept().await.unwrap();
        let raw = transport.receive().await.unwrap();
        let reply = build_reply(&raw).unwrap();
        transport.send(&reply).await.unwrap();
    });

    let session = Session::open_tcp(&addr.to_string(), config())
        .await
        .unwrap();
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(REPLY.to_vec()));

    server_task.await.unwrap();
}

#[tokio::test]
async fn tcp_multiple_requests_on_one_connection() {
    let server = TcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    // Answer three back-to-back requests on the same stream to exercise framing.
    let server_task = tokio::spawn(async move {
        let (transport, _peer) = server.accept().await.unwrap();
        for _ in 0..3 {
            let raw = transport.receive().await.unwrap();
            let reply = build_reply(&raw).unwrap();
            transport.send(&reply).await.unwrap();
        }
    });

    let session = Session::open_tcp(&addr.to_string(), config())
        .await
        .unwrap();
    let oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    for _ in 0..3 {
        let value = session.get_one(&oid).await.unwrap();
        assert_eq!(value, Value::OctetString(REPLY.to_vec()));
    }

    server_task.await.unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_get_roundtrip() {
    use netsnmp::tls::{TlsClient, TlsServer};

    // Self-signed certificate for "localhost".
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    let server_config = TlsServer::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
    let server = TlsServer::bind("127.0.0.1:0", server_config).await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (transport, _peer) = server.accept().await.unwrap();
        let raw = transport.receive().await.unwrap();
        let reply = build_reply(&raw).unwrap();
        transport.send(&reply).await.unwrap();
    });

    // The client trusts the self-signed cert as its CA and validates "localhost".
    let client = TlsClient::from_root_ca_pem("localhost", cert_pem.as_bytes()).unwrap();
    // Connect using the literal hostname so SNI/cert validation matches the SAN.
    let peer = format!("localhost:{}", addr.port());
    let session = Session::open_tls(&client, &peer, config()).await.unwrap();
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(REPLY.to_vec()));

    server_task.await.unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_rejects_untrusted_certificate() {
    use netsnmp::tls::{TlsClient, TlsServer};

    let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server_config = TlsServer::server_config(
        server_cert.cert.pem().as_bytes(),
        server_cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let server = TlsServer::bind("127.0.0.1:0", server_config).await.unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        // The handshake will fail; just attempt to accept so the client proceeds.
        let _ = server.accept().await;
    });

    // Client trusts a *different* self-signed cert, so validation must fail.
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let client = TlsClient::from_root_ca_pem("localhost", other.cert.pem().as_bytes()).unwrap();
    let peer = format!("localhost:{}", addr.port());
    let result = Session::open_tls(&client, &peer, config()).await;
    assert!(result.is_err(), "handshake with untrusted cert must fail");
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn mtls_config_builds_without_error() {
    // Smoke test: the mTLS server/client constructors accept valid PEM and
    // produce usable configs (no live handshake here).
    use netsnmp::tls::{TlsClient, TlsServer};

    // Exercise the constructors with a self-signed cert used as both the
    // server identity and the client CA/identity.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let server_config = TlsServer::server_config_with_client_auth(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        cert_pem.as_bytes(),
    );
    assert!(
        server_config.is_ok(),
        "server_config_with_client_auth should build"
    );

    let client = TlsClient::with_client_cert(
        "localhost",
        cert_pem.as_bytes(),
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
    );
    assert!(client.is_ok(), "with_client_cert should build");
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn mtls_loopback_handshake_succeeds() {
    // Full mutual-TLS loopback: a CA signs both the server and client certs;
    // the server requires a client cert and the client presents one.
    use netsnmp::tls::{TlsClient, TlsServer};
    use rcgen::{CertificateParams, IsCa, KeyPair, BasicConstraints};

    // 1. A self-signed CA.
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // 2. Server cert signed by the CA.
    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let server_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    // 3. Client cert signed by the CA.
    let client_key = KeyPair::generate().unwrap();
    let client_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
    let client_pem = client_cert.pem();
    let client_key_pem = client_key.serialize_pem();

    // 4. Server requires a client cert verified against the CA.
    let server_config = TlsServer::server_config_with_client_auth(
        server_pem.as_bytes(),
        server_key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .unwrap();
    let server = TlsServer::bind("127.0.0.1:0", server_config).await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (transport, _peer) = server.accept().await.unwrap();
        let raw = transport.receive().await.unwrap();
        let reply = build_reply(&raw).unwrap();
        transport.send(&reply).await.unwrap();
    });

    // 5. Client trusts the CA and presents its own cert.
    let client = TlsClient::with_client_cert(
        "localhost",
        ca_pem.as_bytes(),
        client_pem.as_bytes(),
        client_key_pem.as_bytes(),
    )
    .unwrap();
    let peer = format!("localhost:{}", addr.port());
    let session = Session::open_tls(&client, &peer, config()).await.unwrap();
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(REPLY.to_vec()));

    server_task.await.unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn mtls_rejects_client_without_cert() {
    // Server requires a client cert; a client that does not present one must
    // fail the handshake.
    use netsnmp::tls::{TlsClient, TlsServer};
    use rcgen::{CertificateParams, IsCa, KeyPair, BasicConstraints};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let server_key = KeyPair::generate().unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
    let server_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    let server_config = TlsServer::server_config_with_client_auth(
        server_pem.as_bytes(),
        server_key_pem.as_bytes(),
        ca_pem.as_bytes(),
    )
    .unwrap();
    let server = TlsServer::bind("127.0.0.1:0", server_config).await.unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        // The accept will fail; just attempt it so the client can proceed.
        let _ = server.accept().await;
    });

    // Client trusts the CA but does NOT present a client cert. Under TLS 1.3
    // the client-side handshake may complete before the server's client-cert
    // rejection arrives, so the failure surfaces on the first read/write rather
    // than on connect. Drive a full request and assert it never succeeds.
    let client = TlsClient::from_root_ca_pem("localhost", ca_pem.as_bytes()).unwrap();
    let peer = format!("localhost:{}", addr.port());
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let result = Session::open_tls(&client, &peer, config()).await;
    let failed = match result {
        Err(_) => true,
        Ok(session) => session.get_one(&oid).await.is_err(),
    };
    assert!(
        failed,
        "a client without a cert must not complete an exchange under mTLS"
    );
}
