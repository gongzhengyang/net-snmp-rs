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
//! | [`row`]       | RFC 2579 RowStatus textual convention      |
//! | [`helpers`]   | `agent/helpers/` (table, watcher, ...)     |
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
pub mod callback;
pub mod handler;
pub mod hardware;
pub mod helpers;
pub mod mibgroup;
pub mod notify;
pub mod persist;
pub mod proxy;
pub mod registry;
pub mod row;
pub mod scalar;
pub mod trap;
pub mod vacm;

pub use agent::{Agent, AgentConfig};
pub use callback::CallbackBus;
pub use handler::{MibHandler, Mode, Reading, SetPhase};
pub use hardware::{
    CpuAccess, FsType, FsysAccess, HardwareLayer, HwmonSensorAccess, MemInfo, MemoryAccess,
    SensorAccess, SensorReading, StaticSensorAccess, SwapInfo, SysCpuAccess, SysFsysAccess,
    SysMemoryAccess,
};
pub use helpers::{
    CacheHandler, ColumnMeta, ReadOnly, Row, TableDataSet, TableHandler, Watcher, read_only,
};
pub use mibgroup::{
    ExecRegistry, FileCheckRegistry, FrameworkMibConfig, LogMatchRegistry, PassHandler,
    ProcCheckRegistry, SnmpCounter, SnmpCounters, SysOrTable, UcdMibConfig, UsmStats,
    extend_handler, parse_exec_directives, register_framework_mibs, register_host_mibs,
    register_mib2_mibs, register_system_mibs, register_system_mibs_with_persistables,
    register_ucd_mibs, register_vacm_mibs, SystemMibConfig, ucd_handler, ucd_handler_with,
};
pub use notify::{
    NotifyConfig, NotifyEntry, NotifyType, NotificationOriginator, TargetAddr, TargetParams,
    COLD_START_OID, WARM_START_OID,
};
pub use persist::{
    EngineBootsPersistable, Persistable, Persistence, ScalarPersistable, default_persistent_dir,
    load_engine_boots, save_engine_boots,
};
pub use proxy::{ProxyForwarder, V3Config, register_proxy_mibs};
pub use registry::{Registry, SecurityContext};
pub use row::RowStatus;
pub use scalar::{FnHandler, MapHandler, ScalarHandler};
pub use trap::{
    FileSink, ForwardSink, HandleRule, HandleSink, NotificationLog, NotifyVersion,
    ReceivedNotification, StdoutSink, TrapDisposition, TrapReceiver, TrapReceiverConfig, TrapSink,
    notiflog_handler, register_notiflog_mibs,
};
pub use vacm::{
    AccessView, ContextMatch, Vacm, VacmAccess, VacmGroup, VacmView, ViewTreeFamilyType,
};
