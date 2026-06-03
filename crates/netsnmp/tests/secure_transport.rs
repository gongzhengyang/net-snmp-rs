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
