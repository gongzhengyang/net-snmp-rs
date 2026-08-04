//! End-to-end tests for the notification originator (Task 5.12): an
//! [`Agent`] configured with `trap2sink 127.0.0.1 public` delivers a startup
//! `coldStart` to an in-process [`TrapReceiver`], and `Agent::send_notification`
//! routes a custom trap to the same receiver.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netsnmp::config::parse_str;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::value::Value;
use netsnmp::v3::EngineParams;
use netsnmp_agent::{
    Agent, AgentConfig, NotifyConfig, NotificationOriginator, ReceivedNotification, Registry,
    TrapReceiver, TrapReceiverConfig,
};

type Collected = Arc<Mutex<Vec<ReceivedNotification>>>;

/// Spawn an in-process trap receiver on an ephemeral loopback port.
async fn spawn_receiver() -> (String, Collected) {
    let config = TrapReceiverConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: Some(b"public".to_vec()),
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

/// Build a [`NotificationOriginator`] from `trap2sink HOST COMM` directives,
/// aimed at `addr`.
fn originator_for(addr: &str) -> Arc<NotificationOriginator> {
    let dirs = parse_str(&format!("trap2sink {addr} public\n"));
    let config = NotifyConfig::from_config_directives(&dirs);
    let engine = EngineParams {
        engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', b'n', b't'],
        engine_boots: 1,
        engine_time: 0,
    };
    NotificationOriginator::new(config, engine, Instant::now())
}

/// Poll the shared buffer until it holds at least `n` notifications or a short
/// timeout elapses (traps are fire-and-forget).
async fn wait_for(collected: &Collected, n: usize) -> Vec<ReceivedNotification> {
    for _ in 0..300 {
        if collected.lock().unwrap().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    collected.lock().unwrap().clone()
}

fn cold_start_oid() -> Oid {
    "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_startup_emits_cold_start_to_receiver() {
    let (addr, collected) = spawn_receiver().await;
    let originator = originator_for(&addr);

    let mut reg = Registry::new();
    // A minimal scalar so the registry is non-empty.
    reg.register(Arc::new(netsnmp_agent::ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"notify-test-agent".to_vec()),
    )));
    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: b"public".to_vec(),
        ..AgentConfig::default()
    }
    .with_notify(originator);
    let agent = Arc::new(Agent::new(reg, config));

    // Bind + emit coldStart + serve in the background.
    let socket = agent.bind().await.unwrap();
    agent.emit_startup_cold_start();
    tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });

    let got = wait_for(&collected, 1).await;
    assert_eq!(got.len(), 1, "expected one coldStart trap, got {got:?}");
    assert_eq!(got[0].notification.trap_oid, cold_start_oid());
    // sysUpTime should be small (agent just started).
    assert!(got[0].notification.sys_uptime < 600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_send_notification_routes_custom_trap() {
    let (addr, collected) = spawn_receiver().await;
    let originator = originator_for(&addr);

    let mut reg = Registry::new();
    reg.register(Arc::new(netsnmp_agent::ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"notify-test-agent".to_vec()),
    )));
    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: b"public".to_vec(),
        ..AgentConfig::default()
    }
    .with_notify(originator);
    let agent = Arc::new(Agent::new(reg, config));

    // Serve the agent in the background.
    let socket = agent.bind().await.unwrap();
    let serve_agent = Arc::clone(&agent);
    tokio::spawn(async move {
        let _ = serve_agent.serve_on(socket).await;
    });

    // Give the listener a moment to be ready, then send a custom notification
    // via the agent's own send_notification (it opens an outbound socket to
    // the receiver; it does not need the agent's listener).
    tokio::time::sleep(Duration::from_millis(50)).await;
    let custom_oid: Oid = "1.3.6.1.4.1.8072.2.3.1".parse().unwrap();
    let extra = vec![VarBind::new(
        "1.3.6.1.2.1.1.5.0".parse().unwrap(),
        Value::OctetString(b"host-x".to_vec()),
    )];
    agent.send_notification(&custom_oid, extra).await.unwrap();

    let got = wait_for(&collected, 1).await;
    assert_eq!(got.len(), 1, "expected one custom trap, got {got:?}");
    assert_eq!(got[0].notification.trap_oid, custom_oid);
    assert_eq!(got[0].notification.varbinds.len(), 1);
    assert_eq!(
        got[0].notification.varbinds[0].value,
        Value::OctetString(b"host-x".to_vec())
    );
}
