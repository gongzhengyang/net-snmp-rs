//! End-to-end SNMPv3/USM integration test: a real [`V3Session`] client performs
//! engine discovery, then authenticated (and encrypted) GET/SET/walk requests
//! against a real [`Agent`] over a UDP loopback socket. This exercises the full
//! authoritative-engine path: discovery Report, user lookup, HMAC verification,
//! AES decryption, time-window check, and authenticated/encrypted responses.

use std::sync::Arc;
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::session::V3Session;
use netsnmp::usm::{AuthProtocol, PrivProtocol, UsmUser};
use netsnmp::value::Value;
use netsnmp_agent::{Agent, AgentConfig, Registry, ScalarHandler};

/// Spawn a v3-capable agent serving a couple of scalars; return its address.
async fn spawn_v3_agent(user: UsmUser) -> String {
    let mut reg = Registry::new();
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"v3 integration agent".to_vec()),
    )));
    reg.register(Arc::new(
        ScalarHandler::new(
            "1.3.6.1.2.1.1.5".parse().unwrap(),
            Value::OctetString(b"host-v3".to_vec()),
        )
        .writable(),
    ));

    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        users: vec![user],
        ..AgentConfig::default()
    };
    let agent = Agent::new(reg, config);
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    addr
}

async fn open(addr: &str, user: UsmUser) -> V3Session {
    V3Session::open_udp(addr, user, Duration::from_secs(2), 2)
        .await
        .expect("discovery + session open")
}

#[tokio::test]
async fn v3_auth_no_priv_get_over_udp() {
    let user = UsmUser::auth("alice", AuthProtocol::HmacSha1, "authpassword");
    let addr = spawn_v3_agent(user.clone()).await;
    let mut session = open(&addr, user).await;

    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"v3 integration agent".to_vec()));
}

#[tokio::test]
async fn v3_auth_priv_get_and_set_over_udp() {
    let user = UsmUser::auth_priv(
        "bob",
        AuthProtocol::HmacSha256,
        "authpassword",
        PrivProtocol::AesCfb128,
        "privpassword",
    );
    let addr = spawn_v3_agent(user.clone()).await;
    let mut session = open(&addr, user).await;

    let sys_name: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
    session
        .set(vec![VarBind::new(
            sys_name.clone(),
            Value::OctetString(b"renamed-v3".to_vec()),
        )])
        .await
        .unwrap();

    let value = session.get_one(&sys_name).await.unwrap();
    assert_eq!(value, Value::OctetString(b"renamed-v3".to_vec()));
}

#[tokio::test]
async fn v3_wrong_password_times_out() {
    // Agent knows the real password; client uses the wrong one. The agent drops
    // the request (bad HMAC), so the client never gets a reply and times out.
    let real = UsmUser::auth("carol", AuthProtocol::HmacSha1, "correct");
    let addr = spawn_v3_agent(real).await;
    let imposter = UsmUser::auth("carol", AuthProtocol::HmacSha1, "incorrect");
    // Discovery is noAuth and succeeds; the authenticated GET is what fails.
    let mut session = open(&addr, imposter).await;
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let err = session.get_one(&oid).await.unwrap_err();
    assert!(
        matches!(err, netsnmp::Error::Timeout),
        "expected timeout, got {err:?}"
    );
}
