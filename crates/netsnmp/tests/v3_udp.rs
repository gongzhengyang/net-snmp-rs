//! End-to-end SNMPv3/USM test over a real UDP loopback socket.
//!
//! A minimal authoritative engine is spun up on tokio: it answers the RFC 3414
//! discovery probe with a Report carrying its engineID/boots/time, then accepts
//! authenticated + encrypted requests and replies in kind. The client side is
//! the real [`V3Session`], so this exercises discovery, time-sync, HMAC
//! verification, and AES-128-CFB privacy across the async transport.

use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::pdu::{Pdu, PduType, VarBind};
use netsnmp::session::V3Session;
use netsnmp::usm::{AuthProtocol, PrivProtocol, UsmUser};
use netsnmp::v3::{self, EngineParams};
use netsnmp::value::Value;
use tokio::net::UdpSocket;

const ENGINE_ID: &[u8] = &[0x80, 0x00, 0x1f, 0x88, 0x80, 0x12, 0x34, 0x56, 0x78, 0x9a];

/// Spawn an authoritative USM engine; returns its bound address.
async fn spawn_engine(user: UsmUser) -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let engine = EngineParams {
        engine_id: ENGINE_ID.to_vec(),
        engine_boots: 1,
        engine_time: 1000,
    };

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let raw = &buf[..n];

            // Discovery probe: no engine id, no auth -> reply with a Report.
            let probe = v3::parse(raw, None).ok();
            let is_discovery = probe
                .as_ref()
                .map(|m| m.usm.engine_id.is_empty())
                .unwrap_or(false);

            let reply = if is_discovery {
                let msg = probe.unwrap();
                // Report with usmStatsUnknownEngineIDs and our authoritative engine.
                let report = Pdu {
                    pdu_type: PduType::Report,
                    request_id: msg.scoped.pdu.request_id,
                    error_status: 0,
                    error_index: 0,
                    variables: vec![VarBind::new(
                        "1.3.6.1.6.3.15.1.1.4.0".parse::<Oid>().unwrap(),
                        Value::Counter32(1),
                    )],
                    v1_trap: None,
                };
                let noauth = UsmUser::noauth("");
                v3::build_request(msg.header.msg_id, &noauth, &engine, &[], report)
            } else {
                // An authenticated/encrypted request: verify, decrypt, echo back.
                match v3::parse(raw, Some(&user)) {
                    Ok(msg) => {
                        let req = &msg.scoped.pdu;
                        let mut resp = Pdu::new(PduType::Response, req.request_id);
                        resp.variables = req
                            .variables
                            .iter()
                            .map(|vb| {
                                VarBind::new(
                                    vb.oid.clone(),
                                    Value::OctetString(b"v3-udp-ok".to_vec()),
                                )
                            })
                            .collect();
                        v3::build_request(msg.header.msg_id, &user, &engine, &[], resp)
                    }
                    Err(_) => continue,
                }
            };

            if let Ok(bytes) = reply {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });

    addr
}

#[tokio::test]
async fn v3_authpriv_over_udp_with_discovery() {
    let user = UsmUser::auth_priv(
        "udpuser",
        AuthProtocol::HmacSha1,
        "authpassword",
        PrivProtocol::AesCfb128,
        "privpassword",
    );
    let addr = spawn_engine(user.clone()).await;

    let mut session = V3Session::open_udp(&addr, user, Duration::from_secs(2), 2)
        .await
        .unwrap();

    // Discovery must have learned the authoritative engine id.
    assert_eq!(session.engine().engine_id, ENGINE_ID);

    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"v3-udp-ok".to_vec()));
}

#[tokio::test]
async fn v3_authnopriv_over_udp() {
    let user = UsmUser::auth("udpuser2", AuthProtocol::HmacSha256, "authpassword");
    let addr = spawn_engine(user.clone()).await;

    let mut session = V3Session::open_udp(&addr, user, Duration::from_secs(2), 2)
        .await
        .unwrap();
    assert_eq!(session.engine().engine_id, ENGINE_ID);

    let oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"v3-udp-ok".to_vec()));
}
