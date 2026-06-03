//! Build and run a standalone SNMP agent (the building blocks behind `snmpd`).
//!
//! It installs the live system-data MIB modules (mibII system group, IF-MIB,
//! a HOST-RESOURCES subset) plus a custom read-only object under a private
//! enterprise OID, then serves community v2c requests forever.
//!
//! Run, then query from another shell:
//! ```text
//! cargo run -p netsnmp-examples --example agent -- 127.0.0.1:11611
//! snmpwalk -c public 127.0.0.1:11611 system
//! snmpget  -c public 127.0.0.1:11611 1.3.6.1.4.1.8072.9999.1.0
//! ```

use std::sync::Arc;

use netsnmp::Value;
use netsnmp_agent::{
    Agent, AgentConfig, Registry, ScalarHandler, SystemMibConfig, register_system_mibs,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:11611".to_string());

    let mut registry = Registry::new();

    // Live OS data: sysDescr/sysName/sysUpTime, ifTable from /proc/net/dev, etc.
    register_system_mibs(&mut registry, &SystemMibConfig::default());

    // Add your own object under a private enterprise arc (1.3.6.1.4.1.8072.9999).
    registry.register(Arc::new(ScalarHandler::new(
        "1.3.6.1.4.1.8072.9999.1".parse()?,
        Value::OctetString(b"hello from a custom MIB handler".to_vec()),
    )));

    let config = AgentConfig {
        bind_addr: bind_addr.clone(),
        community: b"public".to_vec(),
        ..AgentConfig::default()
    };

    info!("agent serving on {bind_addr} (community: public). Ctrl-C to stop.");
    Agent::new(registry, config).serve_forever().await?;
    Ok(())
}
