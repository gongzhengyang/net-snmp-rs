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
//! | [`tcp`]       | TCP-MIB   | `mibgroup/mibII/tcp.c`       |
//! | [`udp`]       | UDP-MIB   | `mibgroup/mibII/udp.c`       |
//! | [`ip`]        | IP-MIB    | `mibgroup/mibII/ip.c`        |
//! | [`icmp`]      | ICMP-MIB  | `mibgroup/mibII/icmp.c`      |
//! | [`at`]        | at        | `mibgroup/mibII/at.c`        |
//! | [`route`]     | IP-FORWARD| `mibgroup/mibII/route_write.c`|
//! | [`snmp_mib`]  | SNMPv2    | `mibgroup/mibII/snmp_mib.c`  |
//! | [`set_serial`]| SNMPv2    | `mibgroup/mibII/setSerialNo.c`|
//!
//! The host/interface data is gathered by a shared, cross-platform
//! [`collector::HostCollector`] (built on the `sysinfo` crate), so the same
//! handlers work on Linux, macOS and Windows. The `tcp`/`udp`/`ip`/`icmp`/
//! `at`/`route` modules additionally parse Linux `/proc/net/*` and fall back to
//! empty tables / zero counters where `/proc` is unavailable.
//!
//! Use [`register_system_mibs`] to install the system/IF/HOST-RES modules, and
//! [`register_mib2_mibs`] to install the mibII core (TCP/UDP/IP/ICMP/at/route/
//! snmp/setSerialNo) modules.

pub mod at;
pub mod collector;
pub mod extend;
pub mod host;
pub mod icmp;
pub mod interfaces;
pub mod ip;
pub mod lm_sensors;
pub mod notify;
pub mod pass;
pub mod route;
pub mod set_serial;
pub mod snmp_framework;
pub mod snmp_mib;
pub mod snmp_mpd;
pub mod system;
pub mod sysor;
pub mod tcp;
pub mod ucd;
pub mod udp;
pub mod usm_stats;
pub mod vacm;

// Convenience re-exports so callers can write `mibgroup::SysOrTable` etc.
pub use extend::extend_handler;
pub use notify::{notify_handlers, register_notify_mibs};
pub use pass::PassHandler;
pub use snmp_framework::{EngineSnapshot, EngineSnapshotProvider};
pub use snmp_mib::{SnmpCounter, SnmpCounters, snmp_mib_handlers};
pub use snmp_mpd::SnmpMpdStats;
pub use sysor::SysOrTable;
pub use ucd::{
    ExecRegistry, FileCheckRegistry, LogMatchRegistry, ProcCheckRegistry, UcdMibConfig,
    parse_exec_directives, ucd_handler, ucd_handler_with,
};
pub use usm_stats::UsmStats;
pub use vacm::{register_vacm_mibs, vacm_handlers};

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
    register_system_mibs_inner(registry, config, false).1;
}

/// Like [`register_system_mibs`] but also returns the writable system scalar
/// handlers (`sysContact`, `sysName`, `sysLocation`) so callers (e.g. `snmpd`)
/// can attach them to a [`Persistence`](crate::Persistence) layer. Returns
/// `(handlers_already_registered, writable_scalars)`.
pub fn register_system_mibs_with_persistables(
    registry: &mut Registry,
    config: &SystemMibConfig,
) -> Vec<Arc<crate::scalar::ScalarHandler>> {
    register_system_mibs_inner(registry, config, true).0
}

fn register_system_mibs_inner(
    registry: &mut Registry,
    config: &SystemMibConfig,
    return_writable: bool,
) -> (Vec<Arc<crate::scalar::ScalarHandler>>, ()) {
    let collector = collector::HostCollector::new();

    let (system_handlers, writable) = if return_writable {
        system::system_handlers_with_persistables(
            &config.contact,
            &config.location,
            config.start,
        )
    } else {
        (
            system::system_handlers(&config.contact, &config.location, config.start),
            Vec::new(),
        )
    };
    for handler in system_handlers {
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
    (writable, ())
}

/// Register the extended UCD-SNMP-MIB groups that are **not** installed by
/// [`register_system_mibs`]: the NET-SNMP-EXTEND-MIB `nsExtendOutput1Table`
/// (when an [`ExecRegistry`] is supplied) and any [`pass::PassHandler`]s
/// passed in `passes`.
///
/// This does **not** re-register the `1.3.6.1.4.1.2021` subtree (that is already
/// served by the basic `ucd_handler` installed by [`register_system_mibs`]).
/// To expose `exec` entries under the legacy `extTable` as well, build the UCD
/// handler yourself with [`ucd::ucd_handler_with`] and register it instead of
/// relying on [`register_system_mibs`] (the two are mutually exclusive at the
/// `2021` root).
///
/// `collector` is accepted for symmetry with [`register_system_mibs`] and for
/// future groups (e.g. `prTable` is driven by the process list); it is unused
/// when no proc-check registry is supplied.
pub fn register_ucd_mibs(
    registry: &mut Registry,
    collector: Arc<collector::HostCollector>,
    exec: Option<Arc<ucd::ExecRegistry>>,
    passes: Vec<Arc<pass::PassHandler>>,
) {
    let _ = &collector; // reserved for future prTable/file wiring.
    if let Some(exec) = exec {
        registry.register(extend::extend_handler(exec));
    }
    for handler in passes {
        registry.register(handler);
    }
}

/// Register the additional HOST-RESOURCES-MIB tables and LM-SENSORS-MIB that
/// are **not** installed by [`register_system_mibs`].
///
/// This adds:
/// * `hrPrinterTable` (always empty — no printers enumerated),
/// * `hrDiskStorageTable` (Linux `/sys/block`),
/// * `hrPartitionTable` (Linux `/proc/partitions`),
/// * `hrNetworkTable` (per-interface `ifIndex`),
/// * `hrSWInstalledTable` (empty by default),
/// * a writable `hrSWRunTable` (`hrSWRunStatus` SET `invalid(4)` signals the
///   process),
/// * the LM-SENSORS-MIB tables (`lmTempSensorsTable` / `lmFanSensorsTable` /
///   `lmVoltSensorsTable`) when a [`HardwareLayer`](crate::hardware::HardwareLayer)
///   is supplied.
///
/// `collector` is the same shared collector used by [`register_system_mibs`];
/// pass `hw = None` to skip the LM-SENSORS tables (e.g. on a host without
/// sensors). This function does **not** re-register the basic `hrSystem` /
/// `hrStorage` / `hrDevice` / `hrSWRunPerf` handlers — those stay owned by
/// [`register_system_mibs`]. The writable `hrSWRun` handler installed here
/// supersedes the read-only one for `hrSWRunStatus` SETs; both serve the same
/// subtree, so GETs continue to work via whichever handler the registry
/// resolves first.
pub fn register_host_mibs(
    registry: &mut Registry,
    collector: Arc<collector::HostCollector>,
    hw: Option<Arc<crate::hardware::HardwareLayer>>,
) {
    // Extra HOST-RESOURCES tables (Task 5.22).
    registry.register(host::hr_printer_handler());
    registry.register(host::hr_disk_storage_handler());
    registry.register(host::hr_partition_handler());
    registry.register(host::hr_network_handler(collector.clone()));

    // Writable hrSWRun handler (hrSWRunStatus SET invalid(4) -> signal).
    registry.register(Arc::new(host::HrSWRunHandler::new(collector.clone())));

    registry.register(host::hr_sw_installed_handler());

    // LM-SENSORS-MIB (Task 5.24), when a hardware layer is available.
    if let Some(hw) = hw {
        registry.register(lm_sensors::lm_sensors_handler(hw.sensors.clone()));
    }
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

/// Register the mibII core MIB modules into `registry`: the `tcp`, `udp`,
/// `ip`, `icmp`, `at`, `route`, `snmp` and `setSerialNo` groups.
///
/// This is the counterpart of `register_system_mibs` for the protocol/stack
/// objects. It does **not** touch the system/IF/HOST-RES modules registered by
/// [`register_system_mibs`]; call both to install the full mibII tree.
///
/// `snmp_counters` optionally supplies a shared [`SnmpCounters`] so the agent's
/// dispatcher can increment the `snmp` group counters as it processes packets.
/// When `None`, a private counter set (starting at zero) is created — the
/// objects are still walkable, they just never advance.
///
/// `setSerialNo` is registered read-write (RFC 1907 `TestAndIncr`); its backing
/// `AtomicI32` is private to the handler. Use
/// [`set_serial::set_serial_no_handler_with`] directly to share the counter
/// with the registry's commit path.
pub fn register_mib2_mibs(registry: &mut Registry, snmp_counters: Option<Arc<SnmpCounters>>) {
    for handler in tcp::tcp_handlers() {
        registry.register(handler);
    }
    for handler in udp::udp_handlers() {
        registry.register(handler);
    }
    for handler in ip::ip_handlers() {
        registry.register(handler);
    }
    for handler in icmp::icmp_handlers() {
        registry.register(handler);
    }
    registry.register(at::at_handler());
    registry.register(route::route_handler());
    let counters = snmp_counters.unwrap_or_else(SnmpCounters::new);
    for handler in snmp_mib::snmp_mib_handlers(counters) {
        registry.register(handler);
    }
    registry.register(set_serial::set_serial_no_handler());
}
