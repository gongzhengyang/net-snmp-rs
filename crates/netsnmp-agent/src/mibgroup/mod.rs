//! Live system-data MIB modules.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/` tree. Where the in-memory
//! [`ScalarHandler`](crate::scalar::ScalarHandler) and
//! [`MapHandler`](crate::scalar::MapHandler) serve static values, these modules
//! plug real operating-system data into the agent via
//! [`FnHandler`](crate::scalar::FnHandler):
//!
//! | Module        | Group     | C counterpart                |
//! |---------------|-----------|------------------------------|
//! | [`system`]    | mibII     | `mibgroup/mibII/system_mib.c`|
//! | [`interfaces`]| IF-MIB    | `mibgroup/if-mib/`           |
//! | [`host`]      | HOST-RES  | `mibgroup/host/`             |
//!
//! The host/interface data is gathered by a shared, cross-platform
//! [`collector::HostCollector`] (built on the `sysinfo` crate), so the same
//! handlers work on Linux, macOS and Windows.
//!
//! Use [`register_system_mibs`] to install all of them at once.

pub mod collector;
pub mod host;
pub mod interfaces;
pub mod snmp_framework;
pub mod snmp_mpd;
pub mod system;
pub mod sysor;
pub mod ucd;
pub mod usm_stats;

// Convenience re-exports so callers can write `mibgroup::SysOrTable` etc.
pub use snmp_framework::{EngineSnapshot, EngineSnapshotProvider};
pub use snmp_mpd::SnmpMpdStats;
pub use sysor::SysOrTable;
pub use usm_stats::UsmStats;

use crate::registry::Registry;
use std::sync::Arc;
use std::time::Instant;

/// Options for the live MIB modules.
#[derive(Clone, Debug)]
pub struct SystemMibConfig {
    /// Seed value for the writable `sysContact.0`.
    pub contact: String,
    /// Seed value for the writable `sysLocation.0`.
    pub location: String,
    /// Agent start instant, used to compute `sysUpTime.0`.
    pub start: Instant,
}

impl Default for SystemMibConfig {
    fn default() -> Self {
        SystemMibConfig {
            contact: "Me <me@example.org>".to_string(),
            location: "Unknown".to_string(),
            start: Instant::now(),
        }
    }
}

/// Register all live system-data MIB modules into `registry`: the mibII system
/// group, the IF-MIB (`ifTable` + `ifXTable`), and the HOST-RESOURCES system,
/// storage, device/processor and software-run tables.
///
/// All host/interface handlers share one [`collector::HostCollector`] so the
/// underlying system is sampled at most once per refresh interval, even during
/// a full walk.
pub fn register_system_mibs(registry: &mut Registry, config: &SystemMibConfig) {
    let collector = collector::HostCollector::new();

    for handler in system::system_handlers(&config.contact, &config.location, config.start) {
        registry.register(handler);
    }

    registry.register(interfaces::if_number_handler(collector.clone()));
    registry.register(interfaces::if_table_handler(collector.clone()));
    registry.register(interfaces::if_xtable_handler(collector.clone()));

    registry.register(host::hr_system_handler(collector.clone()));
    registry.register(host::hr_storage_handler(collector.clone()));
    registry.register(host::hr_device_handler(collector.clone()));
    registry.register(host::hr_swrun_handler(collector.clone()));
    registry.register(host::hr_swrun_perf_handler(collector.clone()));

    // UCD-SNMP-MIB: load averages, memory, per-filesystem usage, CPU summary.
    registry.register(ucd::ucd_handler(collector));
}

/// Configuration for the SNMP framework/engine MIB modules.
///
/// These values mirror the authoritative engine state held inside
/// [`Agent`](crate::Agent). Because that state is private to the agent, the
/// binary constructs a snapshot here at registration time and supplies a closure
/// so the framework scalars (`snmpEngineTime`) stay live.
#[derive(Clone, Debug)]
pub struct FrameworkMibConfig {
    /// The authoritative `snmpEngineID` advertised to SNMPv3 peers.
    pub engine_id: Vec<u8>,
    /// The authoritative `snmpEngineBoots` counter (>= 1).
    pub engine_boots: u32,
    /// The agent start instant, used to derive `snmpEngineTime` and each
    /// `sysORUpTime` value.
    pub boot_time: Instant,
}

/// Register the SNMP framework/engine MIB modules into `registry`:
///
/// * SNMP-FRAMEWORK-MIB `snmpEngine` group (`snmpEngineID`/`Boots`/`Time`/
///   `MaxMessageSize`).
/// * SNMP-USER-BASED-SM-MIB `usmStats` (six USM error counters).
/// * SNMP-MPD-MIB `snmpMPDStats` (two dispatch counters).
/// * SNMPv2-MIB `sysORTable` (the supplied `sysor` table).
///
/// `usm_stats` is shared so the agent's v3 path can increment the same counters
/// that this handler reports. Likewise `sysor` is shared so subsystems can call
/// [`sysor::SysOrTable::register`] against the same table the handler walks.
pub fn register_framework_mibs(
    registry: &mut Registry,
    fw: &FrameworkMibConfig,
    sysor: &Arc<sysor::SysOrTable>,
    usm_stats: &Arc<usm_stats::UsmStats>,
) {
    // The engine snapshot is rebuilt on each read so snmpEngineTime advances.
    let engine_id = fw.engine_id.clone();
    let engine_boots = fw.engine_boots;
    let boot_time = fw.boot_time;
    let provider: snmp_framework::EngineSnapshotProvider = Arc::new(move || {
        snmp_framework::EngineSnapshot {
            engine_id: engine_id.clone(),
            engine_boots,
            boot_time: Some(boot_time),
        }
    });
    for handler in snmp_framework::snmp_framework_handlers(provider) {
        registry.register(handler);
    }

    registry.register(usm_stats::usm_stats_handler(Arc::clone(usm_stats)));
    registry.register(snmp_mpd::snmp_mpd_handler());
    registry.register(sysor::sysor_handler(Arc::clone(sysor)));
}
