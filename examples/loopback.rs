//! End-to-end in one process: build a custom agent, serve it on an ephemeral
//! UDP port in a background task, then drive it with the client `Session` API.
//!
//! This is the best starting point for "how do I use this library?" — it shows
//! the full request/response loop (GET, GETNEXT/WALK, SET) without needing any
//! external agent or network setup.
//!
//! Run:
//! ```text
//! cargo run -p netsnmp-examples --example loopback
//! ```

use std::sync::Arc;

use futures::TryStreamExt;
use netsnmp::{Oid, Session, SessionConfig, VarBind, Value};
use netsnmp_agent::{Agent, AgentConfig, MapHandler, Registry, ScalarHandler};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    // ---- 1. Build the agent's MIB tree out of handlers -------------------
    let sys_name_root: Oid = "1.3.6.1.2.1.1.5".parse()?; // sysName
    let if_descr_root: Oid = "1.3.6.1.2.1.2.2.1.2".parse()?; // ifDescr column

    let mut registry = Registry::new();
    // A read-only scalar at sysDescr.0.
    registry.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.2.1.1.1".parse()?,
        Value::OctetString(b"net-snmp-rs loopback example".to_vec()),
    )));
    // A *writable* scalar at sysName.0 so we can demonstrate SET.
    registry.register(Arc::new(
        ScalarHandler::new(sys_name_root.clone(), Value::OctetString(b"unset".to_vec())).writable(),
    ));
    // A tiny two-row "table" (ifDescr.1 / ifDescr.2) backed by an in-memory map.
    registry.register(Arc::new(
        MapHandler::new(if_descr_root.clone())
            .with(if_descr_root.child(1), Value::OctetString(b"lo".to_vec()))
            .with(if_descr_root.child(2), Value::OctetString(b"eth0".to_vec())),
    ));

    // ---- 2. Bind to an ephemeral port and serve in the background --------
    let config = AgentConfig {
        bind_addr: "127.0.0.1:0".to_string(), // :0 => OS picks a free port
        ..AgentConfig::default()
    };
    let agent = Agent::new(registry, config);
    let socket = agent.bind().await?;
    let agent_addr = socket.local_addr()?;
    info!("agent listening on {agent_addr}");
    tokio::spawn(async move {
        // serve_on only returns on error; ignore it on shutdown.
        let _ = agent.serve_on(socket).await;
    });

    // ---- 3. Talk to it with the client Session API -----------------------
    let session = Session::open_udp(&agent_addr.to_string(), SessionConfig::default()).await?;

    let sys_descr: Oid = "1.3.6.1.2.1.1.1.0".parse()?;
    info!("GET  sysDescr.0 = {}", session.get_one(&sys_descr).await?);

    // Stream the subtree so each binding is printed as it arrives (memory is
    // bounded to one varbind regardless of table size).
    info!("WALK ifDescr (streaming):");
    let mut walk = std::pin::pin!(session.walk_stream(&if_descr_root));
    while let Some(vb) = walk.try_next().await? {
        info!("       {} = {}", vb.oid, vb.value);
    }

    let sys_name: Oid = sys_name_root.child(0);
    session
        .set(vec![VarBind::new(
            sys_name.clone(),
            Value::OctetString(b"renamed-by-set".to_vec()),
        )])
        .await?;
    info!("SET  sysName.0, read back = {}", session.get_one(&sys_name).await?);

    Ok(())
}
