//! End-to-end integration test: a real `netsnmp` client talking to a real
//! `netsnmp-agent` over a UDP loopback socket. This exercises the full async
//! stack — BER encode/decode, message framing, tokio transport, session
//! retry logic, and the agent registry — exactly as the C `snmpget`/`snmpwalk`
//! would against `snmpd`.

use std::sync::Arc;
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::session::{Session, SessionConfig};
use netsnmp::value::Value;
use netsnmp_agent::{Agent, AgentConfig, MapHandler, Registry, ScalarHandler};

/// Spawn an agent on an ephemeral loopback port and return its bound address.
async fn spawn_agent() -> String {
    let mut reg = Registry::new();
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"integration agent".to_vec()),
    )));
    reg.register(Arc::new(
        ScalarHandler::new(
            "1.3.6.1.2.1.1.5".parse().unwrap(),
            Value::OctetString(b"host-a".to_vec()),
        )
        .writable(),
    ));
    let if_descr: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
    reg.register(Arc::new(
        MapHandler::new(if_descr.clone())
            .with(if_descr.child(1), Value::OctetString(b"lo".to_vec()))
            .with(if_descr.child(2), Value::OctetString(b"eth0".to_vec())),
    ));

    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: b"public".to_vec(),
        ..AgentConfig::default()
    };
    let agent = Agent::new(reg, config);
    // Bind first so the OS assigns the ephemeral port before we hand out the addr.
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    addr
}

async fn client(addr: &str) -> Session {
    Session::open_udp(
        addr,
        SessionConfig {
            timeout: Duration::from_secs(2),
            retries: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn get_scalar_over_udp() {
    let addr = spawn_agent().await;
    let session = client(&addr).await;
    let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    let value = session.get_one(&oid).await.unwrap();
    assert_eq!(value, Value::OctetString(b"integration agent".to_vec()));
}

#[tokio::test]
async fn walk_interface_table_over_udp() {
    let addr = spawn_agent().await;
    let session = client(&addr).await;
    let root: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
    let results = session.walk(&root).await.unwrap();
    let descrs: Vec<Value> = results.into_iter().map(|vb| vb.value).collect();
    assert_eq!(
        descrs,
        vec![
            Value::OctetString(b"lo".to_vec()),
            Value::OctetString(b"eth0".to_vec()),
        ]
    );
}

#[tokio::test]
async fn set_then_get_roundtrip_over_udp() {
    let addr = spawn_agent().await;
    let session = client(&addr).await;
    let sys_name: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();

    session
        .set(vec![netsnmp::pdu::VarBind::new(
            sys_name.clone(),
            Value::OctetString(b"renamed".to_vec()),
        )])
        .await
        .unwrap();

    let value = session.get_one(&sys_name).await.unwrap();
    assert_eq!(value, Value::OctetString(b"renamed".to_vec()));
}
