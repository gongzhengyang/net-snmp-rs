//! End-to-end tests for the shared UDP socket multiplexer
//! (`snmpUDPsharedDomain` equivalent).
//!
//! A minimal community-based responder is spun up on a real loopback UDP socket
//! and driven through a [`Session`] built on [`UdpSharedTransport`], proving the
//! request-id routing end-to-end: responses are dispatched to the correct handle
//! despite being read from a single shared socket, and two concurrent sessions
//! over the same [`UdpShared`] each receive their own responses.

use std::sync::Arc;
use std::time::Duration;

use netsnmp::message::{Message, Version};
use netsnmp::pdu::{Pdu, PduType, VarBind};
use netsnmp::udp_shared::{UdpShared, UdpSharedTransport};
use netsnmp::value::Value;
use netsnmp::{Oid, Session, SessionConfig, Transport};
use tokio::net::UdpSocket;

/// Spawn a community responder that answers each GetRequest with a fixed
/// OctetString value for `sysDescr.0`. Returns its bound address.
async fn spawn_responder(reply: &'static [u8]) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let Ok(req) = Message::decode(&buf[..n]) else {
                continue;
            };
            let mut resp = Pdu::new(PduType::Response, req.pdu.request_id);
            resp.variables = req
                .pdu
                .variables
                .iter()
                .map(|vb| VarBind::new(vb.oid.clone(), Value::OctetString(reply.to_vec())))
                .collect();
            if let Ok(bytes) = Message::new(Version::V2c, b"public".to_vec(), resp).encode() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    addr
}

/// A `Session` GET over a shared UDP socket resolves the value the responder
/// returns, proving send→receive pairing through the multiplexer.
#[tokio::test]
async fn session_get_over_shared_socket() {
    let addr = spawn_responder(b"shared-ok").await;
    let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();
    let peer: std::net::SocketAddr = addr.parse().unwrap();
    let transport = UdpSharedTransport::new(shared, peer);
    let session = Session::with_transport(transport, SessionConfig::default());

    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"shared-ok".to_vec()));
}

/// Two sessions sharing one [`UdpShared`] socket GET concurrently against two
/// distinct responders and each receive the correct value. This is the
/// acceptance criterion from Task 5.34: responses routed by request-id across a
/// shared socket.
#[tokio::test]
async fn two_sessions_concurrent_over_one_shared_socket() {
    let addr_a = spawn_responder(b"agent-A").await;
    let addr_b = spawn_responder(b"agent-B").await;
    let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();

    let peer_a: std::net::SocketAddr = addr_a.parse().unwrap();
    let peer_b: std::net::SocketAddr = addr_b.parse().unwrap();
    let sa = Session::with_transport(
        UdpSharedTransport::new(Arc::clone(&shared), peer_a),
        SessionConfig::default(),
    );
    let sb = Session::with_transport(
        UdpSharedTransport::new(Arc::clone(&shared), peer_b),
        SessionConfig::default(),
    );

    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let (va, vb) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(3), sa.get_one(&oid)),
        tokio::time::timeout(Duration::from_secs(3), sb.get_one(&oid)),
    );
    assert_eq!(
        va.expect("A timed out").unwrap(),
        Value::OctetString(b"agent-A".to_vec())
    );
    assert_eq!(
        vb.expect("B timed out").unwrap(),
        Value::OctetString(b"agent-B".to_vec())
    );
}

/// The `Transport` trait works directly (without a `Session`): a raw send of an
/// encoded GetRequest is paired with the raw response bytes by request-id.
#[tokio::test]
async fn transport_send_receive_direct() {
    let addr = spawn_responder(b"raw-transport").await;
    let shared = UdpShared::bind("127.0.0.1:0").await.unwrap();
    let peer: std::net::SocketAddr = addr.parse().unwrap();
    let transport = UdpSharedTransport::new(shared, peer);

    let pdu = Pdu::new(PduType::Get, 0x7a).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
    let req = Message::new(Version::V2c, b"public".to_vec(), pdu)
        .encode()
        .unwrap();
    transport.send(&req).await.unwrap();
    let raw = tokio::time::timeout(Duration::from_secs(3), transport.receive())
        .await
        .expect("receive timed out")
        .unwrap();
    let resp = Message::decode(&raw).unwrap();
    assert_eq!(resp.pdu.request_id, 0x7a);
    assert_eq!(
        resp.pdu.variables[0].value,
        Value::OctetString(b"raw-transport".to_vec())
    );
}
