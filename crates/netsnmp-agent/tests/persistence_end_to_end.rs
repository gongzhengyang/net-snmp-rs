//! End-to-end persistence integration test: SET a writable scalar against a
//! running agent, flush the persistence layer, then start a *new* agent
//! pointing at the same persistent directory and confirm the SET value is
//! restored on a GET. This mirrors the Task 5.11 acceptance criterion:
//!
//! > SET `sysContact.0 = X` -> restart agent -> GET `sysContact.0` still X.

use std::sync::Arc;
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::session::{Session, SessionConfig};
use netsnmp::value::Value;
use netsnmp_agent::{
    Agent, AgentConfig, Persistence, Registry, ScalarHandler, ScalarPersistable,
};

/// The `sysContact` root OID (`1.3.6.1.2.1.1.4`, instance `.0`).
const SYS_CONTACT: &str = "1.3.6.1.2.1.1.4";

/// Build a registry whose `sysContact` scalar is both writable and persisted
/// under the given `Persistence`. Returns the registry together with a clone
/// of the scalar handler so the test can inspect its value directly.
fn registry_with_persisted_contact(
    persistence: &Arc<Persistence>,
) -> (Registry, Arc<ScalarHandler>) {
    let mut reg = Registry::new();
    let contact: Oid = SYS_CONTACT.parse().unwrap();
    let handler = Arc::new(
        ScalarHandler::new(contact, Value::OctetString(b"initial".to_vec())).writable(),
    );
    persistence.register(ScalarPersistable::new("sysContact", Arc::clone(&handler)));
    reg.register(Arc::clone(&handler) as Arc<dyn netsnmp_agent::MibHandler>);
    (reg, handler)
}

/// Bind an agent on an ephemeral loopback port, returning its bound address
/// together with a join handle for the serve task.
async fn spawn_agent(
    persistence: Arc<Persistence>,
) -> (String, tokio::task::JoinHandle<()>) {
    let (reg, _handler) = registry_with_persisted_contact(&persistence);
    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: b"public".to_vec(),
        persistence: Some(persistence),
        ..AgentConfig::default()
    };
    let agent = Arc::new(Agent::new(reg, config));
    // Restore any previously persisted state before serving.
    agent.load_persistent().unwrap();
    let socket = agent.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let _ = agent.serve_on(socket).await;
    });
    (addr, handle)
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
async fn set_then_save_then_restart_restores_value() {
    let dir = std::env::temp_dir().join(format!(
        "netsnmp-persist-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // Fresh persistent directory: nothing to restore yet.
    let persistence = Arc::new(Persistence::new(&dir));
    let (addr, handle) = spawn_agent(Arc::clone(&persistence)).await;
    let session = client(&addr).await;

    let oid: Oid = format!("{SYS_CONTACT}.0").parse().unwrap();
    // GET initially returns the seeded default.
    let initial = session.get_one(&oid).await.unwrap();
    assert_eq!(initial, Value::OctetString(b"initial".to_vec()));

    // SET sysContact.0 = "ops desk".
    session
        .set(vec![VarBind::new(
            oid.clone(),
            Value::OctetString(b"ops desk".to_vec()),
        )])
        .await
        .unwrap();

    // Flush to disk (the on-shutdown save the binary would perform).
    persistence.save().unwrap();

    // Stop the first agent.
    handle.abort();

    // Simulate a restart: a brand-new Persistence + agent pointing at the same
    // dir. load_persistent() must replay the saved sysContact value.
    let persistence2 = Arc::new(Persistence::new(&dir));
    let (addr2, handle2) = spawn_agent(Arc::clone(&persistence2)).await;
    let session2 = client(&addr2).await;

    let restored = session2.get_one(&oid).await.unwrap();
    assert_eq!(restored, Value::OctetString(b"ops desk".to_vec()));

    handle2.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn save_persistent_noop_without_persistence() {
    // An agent with no persistence layer: save_persistent is a no-op success.
    let mut reg = Registry::new();
    reg.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse().unwrap(),
        Value::OctetString(b"x".to_vec()),
    )));
    let agent = Agent::new(reg, AgentConfig::default());
    assert!(agent.save_persistent().is_ok());
    assert!(agent.load_persistent().is_ok());
}
