//! Cross-platform host-metrics collector backing the HOST-RESOURCES-MIB and
//! IF-MIB modules.
//!
//! Where the C agent reads `/proc` and `/sys` directly (Linux only), this uses
//! the [`sysinfo`] crate, which works on Linux, macOS and Windows. A single
//! [`HostCollector`] is shared (via `Arc`) by every live MIB handler. It owns
//! the mutable `sysinfo` state behind a `Mutex` and hands out an immutable,
//! owned [`Snapshot`] that the cell-builders read without touching the OS.
//!
//! Refreshes are throttled: gathering CPU/memory/disk/network/process data does
//! a fair amount of syscalls, so we refresh at most once per
//! [`REFRESH_INTERVAL`]. Repeated GETNEXTs during a single walk therefore reuse
//! one snapshot instead of re-reading the system for every column. The interval
//! also gives CPU-usage figures a sampling window (sysinfo computes usage from
//! the delta between two refreshes).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sysinfo::{Disks, Networks, ProcessStatus, ProcessesToUpdate, RefreshKind, System, Users};

use super::interfaces::{IfStat, Interface};

/// Minimum delay between two underlying `sysinfo` refreshes.
const REFRESH_INTERVAL: Duration = Duration::from_millis(1500);

/// hrSWRunStatus values (HOST-RESOURCES-MIB).
const RUN_RUNNING: i64 = 1;
const RUN_RUNNABLE: i64 = 2;
const RUN_NOT_RUNNABLE: i64 = 3;
const RUN_INVALID: i64 = 4;

/// A single CPU/core sample.
#[derive(Clone, Debug)]
pub struct CpuSample {
    /// Human-readable core name (e.g. `cpu0`).
    pub name: String,
    /// Instantaneous load as a whole-number percentage (0..=100).
    pub usage_pct: i64,
    /// Reported frequency in MHz (0 when unknown).
    pub freq_mhz: i64,
}

/// A single mounted filesystem / disk sample.
#[derive(Clone, Debug)]
pub struct DiskSample {
    /// Mount point, used as the storage description (e.g. `/`).
    pub mount: String,
    /// Filesystem type (e.g. `ext4`), informational only.
    pub fs: String,
    /// Total capacity in bytes.
    pub total: u64,
    /// Available capacity in bytes.
    pub available: u64,
}

/// A single process sample (HOST-RESOURCES software-run tables).
#[derive(Clone, Debug)]
pub struct ProcSample {
    /// Process id, used as the table row index.
    pub pid: u32,
    /// Short process name.
    pub name: String,
    /// Executable path (may be empty when unreadable).
    pub path: String,
    /// Resident memory in kilobytes.
    pub mem_kb: i64,
    /// CPU usage as a whole-number percentage.
    pub cpu_pct: i64,
    /// `hrSWRunStatus` value.
    pub status: i64,
}

/// An immutable, owned point-in-time view of the host. Built at most once per
/// [`REFRESH_INTERVAL`] and shared via `Arc`.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// System uptime in seconds.
    pub uptime_secs: u64,
    /// Number of running processes.
    pub num_processes: i64,
    /// Number of logged-in users.
    pub num_users: i64,
    /// Total physical memory in bytes.
    pub mem_total: u64,
    /// Used physical memory in bytes.
    pub mem_used: u64,
    /// Free physical memory in bytes.
    pub mem_free: u64,
    /// Available physical memory in bytes.
    pub mem_available: u64,
    /// Total swap in bytes.
    pub swap_total: u64,
    /// Used swap in bytes.
    pub swap_used: u64,
    /// Free swap in bytes.
    pub swap_free: u64,
    /// Aggregate CPU load across all cores, as a whole-number percentage.
    pub cpu_global_pct: i64,
    /// System load averages over 1, 5 and 15 minutes (0 where unavailable).
    pub load_avg: (f64, f64, f64),
    /// Per-core CPU samples.
    pub cpus: Vec<CpuSample>,
    /// Mounted filesystems.
    pub disks: Vec<DiskSample>,
    /// Processes, sorted by pid.
    pub processes: Vec<ProcSample>,
    /// Network interfaces, sorted by `ifIndex`.
    pub interfaces: Vec<Interface>,
}

struct State {
    sys: System,
    networks: Networks,
    last: Option<Instant>,
    snapshot: Arc<Snapshot>,
}

/// Shared, throttled view over `sysinfo`. Cheap to clone (`Arc`).
pub struct HostCollector {
    state: Mutex<State>,
}

impl HostCollector {
    /// Create a collector and take an initial snapshot.
    pub fn new() -> Arc<Self> {
        let sys = System::new_with_specifics(RefreshKind::everything());
        let networks = Networks::new_with_refreshed_list();
        let mut state = State {
            sys,
            networks,
            last: None,
            snapshot: Arc::new(Snapshot::default()),
        };
        state.rebuild();
        Arc::new(HostCollector {
            state: Mutex::new(state),
        })
    }

    /// Return the current snapshot, refreshing the underlying sources first if
    /// the previous snapshot is older than [`REFRESH_INTERVAL`].
    pub fn snapshot(&self) -> Arc<Snapshot> {
        // Recover from a poisoned lock rather than panicking inside a handler.
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let stale = st
            .last
            .map(|t| t.elapsed() >= REFRESH_INTERVAL)
            .unwrap_or(true);
        if stale {
            st.refresh_sources();
            st.rebuild();
        }
        st.snapshot.clone()
    }
}

impl State {
    fn refresh_sources(&mut self) {
        self.sys.refresh_specifics(RefreshKind::everything());
        // Keep the persistent process list pruned of dead processes.
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        // Keep totals monotonic by refreshing the persistent Networks instance.
        self.networks.refresh(true);
    }

    fn rebuild(&mut self) {
        let load = System::load_average();
        let snap = Snapshot {
            uptime_secs: System::uptime(),
            num_processes: self.sys.processes().len() as i64,
            num_users: Users::new_with_refreshed_list().len() as i64,
            mem_total: self.sys.total_memory(),
            mem_used: self.sys.used_memory(),
            mem_free: self.sys.free_memory(),
            mem_available: self.sys.available_memory(),
            swap_total: self.sys.total_swap(),
            swap_used: self.sys.used_swap(),
            swap_free: self.sys.free_swap(),
            cpu_global_pct: self.sys.global_cpu_usage().round() as i64,
            load_avg: (load.one, load.five, load.fifteen),
            cpus: self.gather_cpus(),
            disks: gather_disks(),
            processes: self.gather_processes(),
            interfaces: self.gather_interfaces(),
        };
        self.snapshot = Arc::new(snap);
        self.last = Some(Instant::now());
    }

    fn gather_cpus(&self) -> Vec<CpuSample> {
        self.sys
            .cpus()
            .iter()
            .map(|c| CpuSample {
                name: c.name().to_string(),
                usage_pct: c.cpu_usage().round() as i64,
                freq_mhz: c.frequency() as i64,
            })
            .collect()
    }

    fn gather_processes(&self) -> Vec<ProcSample> {
        let mut procs: Vec<ProcSample> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| ProcSample {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().into_owned(),
                path: p
                    .exe()
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                mem_kb: (p.memory() / 1024) as i64,
                cpu_pct: p.cpu_usage().round() as i64,
                status: map_status(p.status()),
            })
            .collect();
        procs.sort_by_key(|p| p.pid);
        procs
    }

    fn gather_interfaces(&self) -> Vec<Interface> {
        // sysinfo exposes name + MAC + MTU + cumulative counters, but not
        // ifIndex / admin-oper status / link speed. We synthesize a stable
        // 1-based index by sorting on the interface name and assume listed
        // interfaces are up.
        let mut named: Vec<(&String, &sysinfo::NetworkData)> = self.networks.iter().collect();
        named.sort_by(|a, b| a.0.cmp(b.0));
        named
            .into_iter()
            .enumerate()
            .map(|(i, (name, data))| {
                let index = (i + 1) as u32;
                let is_loopback = name == "lo" || name.starts_with("lo");
                Interface {
                    index,
                    // 24 = softwareLoopback, 6 = ethernetCsmacd.
                    if_type: if is_loopback { 24 } else { 6 },
                    mtu: data.mtu() as i64,
                    speed_bps: 0,
                    phys_address: mac_bytes(&data.mac_address().to_string()),
                    admin_up: true,
                    oper_up: true,
                    stat: IfStat {
                        name: name.clone(),
                        rx_bytes: data.total_received(),
                        rx_packets: data.total_packets_received(),
                        rx_errs: data.total_errors_on_received(),
                        rx_drop: 0,
                        tx_bytes: data.total_transmitted(),
                        tx_packets: data.total_packets_transmitted(),
                        tx_errs: data.total_errors_on_transmitted(),
                        tx_drop: 0,
                    },
                }
            })
            .collect()
    }
}

fn gather_disks() -> Vec<DiskSample> {
    // Disk capacities are absolute, so a freshly refreshed list is correct and
    // avoids tracking per-disk state across refreshes.
    let disks = Disks::new_with_refreshed_list();
    let mut out: Vec<DiskSample> = disks
        .iter()
        .map(|d| DiskSample {
            mount: d.mount_point().to_string_lossy().into_owned(),
            fs: d.file_system().to_string_lossy().into_owned(),
            total: d.total_space(),
            available: d.available_space(),
        })
        .collect();
    out.sort_by(|a, b| a.mount.cmp(&b.mount));
    out.dedup_by(|a, b| a.mount == b.mount);
    out
}

/// Parse a colon-separated MAC string into octets (empty on failure).
fn mac_bytes(s: &str) -> Vec<u8> {
    super::interfaces::parse_mac(s)
}

/// Map a sysinfo [`ProcessStatus`] to an `hrSWRunStatus` value.
fn map_status(status: ProcessStatus) -> i64 {
    match status {
        ProcessStatus::Run => RUN_RUNNING,
        ProcessStatus::Sleep | ProcessStatus::Idle | ProcessStatus::Parked | ProcessStatus::Waking => {
            RUN_RUNNABLE
        }
        ProcessStatus::Stop
        | ProcessStatus::Tracing
        | ProcessStatus::UninterruptibleDiskSleep
        | ProcessStatus::LockBlocked => RUN_NOT_RUNNABLE,
        ProcessStatus::Zombie | ProcessStatus::Dead => RUN_INVALID,
        _ => RUN_RUNNABLE,
    }
}
