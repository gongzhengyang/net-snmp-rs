//! End-to-end notification integration tests: real `snmptrap`-style senders
//! ([`Session`] / [`V3Session`]) deliver traps and informs over a UDP loopback
//! to a real [`TrapReceiver`] (`snmptrapd`'s core), exercising community v2c and
//! SNMPv3/USM (auth+priv), plus the confirmed-inform acknowledgement path.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netsnmp::message::Version;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::session::{Session, SessionConfig, V3Session};
use netsnmp::usm::{AuthProtocol, PrivProtocol, UsmUser};
use netsnmp::v3::EngineParams;
use netsnmp::value::Value;
use netsnmp_agent::{NotifyVersion, ReceivedNotification, TrapReceiver, TrapReceiverConfig};

type Collected = Arc<Mutex<Vec<ReceivedNotification>>>;

/// Spawn a trap receiver bound to an ephemeral loopback port. Returns the bound
/// address and a shared buffer that accumulates received notifications.
async fn spawn_receiver(users: Vec<UsmUser>) -> (String, Collected) {
    let config = TrapReceiverConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: Some(b"public".to_vec()),
        users,
        ..TrapReceiverConfig::default()
    };
    let receiver = TrapReceiver::new(config);
    let socket = receiver.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();

    let collected: Collected = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    tokio::spawn(async move {
        let _ = receiver
            .serve_on(socket, move |note, _peer| {
                sink.lock().unwrap().push(note.clone());
            })
            .await;
    });
    (addr, collected)
}

/// Poll the shared buffer until it holds at least `n` notifications or a short
/// timeout elapses (traps are fire-and-forget, so we must wait for delivery).
async fn wait_for(collected: &Collected, n: usize) -> Vec<ReceivedNotification> {
    for _ in 0..200 {
        if collected.lock().unwrap().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    collected.lock().unwrap().clone()
}

fn cold_start() -> Oid {
    "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
}

#[tokio::test]
async fn v2c_trap_is_received() {
    let (addr, collected) = spawn_receiver(Vec::new()).await;
    let config = SessionConfig {
        version: Version::V2c,
        community: b"public".to_vec(),
        ..SessionConfig::default()
    };
    let session = Session::open_udp(&addr, config).await.unwrap();
    let extra = vec![VarBind::new(
        "1.3.6.1.2.1.1.5.0".parse().unwrap(),
        Value::OctetString(b"sensor-1".to_vec()),
    )];
    session.send_trap(4242, &cold_start(), extra).await.unwrap();

    let got = wait_for(&collected, 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, NotifyVersion::Community);
    assert!(!got[0].confirmed);
    assert_eq!(got[0].notification.sys_uptime, 4242);
    assert_eq!(got[0].notification.trap_oid, cold_start());
    assert_eq!(got[0].notification.varbinds.len(), 1);
}

#[tokio::test]
async fn v2c_inform_is_acknowledged() {
    let (addr, collected) = spawn_receiver(Vec::new()).await;
    let config = SessionConfig {
        version: Version::V2c,
        community: b"public".to_vec(),
        timeout: Duration::from_secs(2),
        ..SessionConfig::default()
    };
    let session = Session::open_udp(&addr, config).await.unwrap();
    // send_inform awaits the acknowledgement before returning.
    let resp = session
        .send_inform(100, &cold_start(), Vec::new())
        .await
        .unwrap();
    assert_eq!(resp.pdu_type, netsnmp::PduType::Response);

    let got = collected.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert!(got[0].confirmed);
}

#[tokio::test]
async fn v3_auth_priv_trap_is_received() {
    let user = UsmUser::auth_priv(
        "notifier",
        AuthProtocol::HmacSha256,
        "authpassword",
        PrivProtocol::AesCfb128,
        "privpassword",
    );
    let (addr, collected) = spawn_receiver(vec![user.clone()]).await;

    // A notification originator is its own authoritative engine: no discovery.
    let engine = EngineParams {
        engine_id: vec![0x80, 0, 0x1f, 0x88, 0x04, b'r', b's', b'n', b't'],
        engine_boots: 1,
        engine_time: 0,
    };
    let mut session = V3Session::open_udp_notifier(&addr, user, engine, Duration::from_secs(2), 2)
        .await
        .unwrap();
    session
        .send_trap(7777, &cold_start(), Vec::new())
        .await
        .unwrap();

    let got = wait_for(&collected, 1).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, NotifyVersion::V3);
    assert_eq!(got[0].security_name.as_deref(), Some("notifier"));
    assert_eq!(got[0].notification.sys_uptime, 7777);
}

#[tokio::test]
async fn v3_auth_inform_is_acknowledged() {
    let user = UsmUser::auth("informer", AuthProtocol::HmacSha1, "authpassword");
    let (addr, collected) = spawn_receiver(vec![user.clone()]).await;

    // Confirmed inform: the receiver is authoritative, so discovery happens.
    let mut session = V3Session::open_udp(&addr, user, Duration::from_secs(2), 2)
        .await
        .unwrap();
    let extra = vec![VarBind::new(
        "1.3.6.1.2.1.1.6.0".parse().unwrap(),
        Value::OctetString(b"rack-7".to_vec()),
    )];
    session
        .send_inform(1234, &cold_start(), extra)
        .await
        .unwrap();

    let got = collected.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].version, NotifyVersion::V3);
    assert!(got[0].confirmed);
    assert_eq!(got[0].notification.varbinds.len(), 1);
}
