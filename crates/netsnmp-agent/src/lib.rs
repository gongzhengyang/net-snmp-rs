//! # netsnmp-agent — SNMP agent framework
//!
//! A pure-Rust reimplementation of the core of Net-SNMP's agent libraries
//! (`agent/`, `libnetsnmpagent`). It builds on the [`netsnmp`] core crate and
//! provides:
//!
//! | Module        | C counterpart                              |
//! |---------------|--------------------------------------------|
//! | [`handler`]   | `agent/agent_handler.c`, `helpers/`        |
//! | [`scalar`]    | `helpers/scalar.c`, `instance.c`, tables   |
//! | [`registry`]  | `agent/agent_registry.c`, `snmp_agent.c`   |
//! | [`agent`]     | `agent/snmpd.c` (the daemon run-loop)      |
//! | [`trap`]      | `apps/snmptrapd*.c` (notification receiver)|
//! | [`mibgroup`]  | `agent/mibgroup/` (live system-data MIBs)  |
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use netsnmp_agent::{Agent, AgentConfig, Registry, ScalarHandler};
//! use netsnmp::value::Value;
//!
//! # async fn run() -> Result<(), netsnmp::Error> {
//! let mut registry = Registry::new();
//! registry.register(Arc::new(ScalarHandler::new(
//!     "1.3.6.1.2.1.1.1".parse().unwrap(),
//!     Value::OctetString(b"my agent".to_vec()),
//! )));
//! let agent = Agent::new(registry, AgentConfig::default());
//! agent.serve_forever().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod agent;
pub mod handler;
pub mod mibgroup;
pub mod registry;
pub mod scalar;
pub mod trap;

pub use agent::{Agent, AgentConfig};
pub use handler::{MibHandler, Mode, Reading};
pub use mibgroup::{SystemMibConfig, register_system_mibs};
pub use registry::Registry;
pub use scalar::{FnHandler, MapHandler, ScalarHandler};
pub use trap::{
    NotifyVersion, ReceivedNotification, TrapDisposition, TrapReceiver, TrapReceiverConfig,
};
