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
pub mod system;
pub mod ucd;

use crate::registry::Registry;
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
