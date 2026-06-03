//! UCD-SNMP-MIB (`1.3.6.1.4.1.2021`), backed by cross-platform [`sysinfo`] data.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/ucd-snmp/`. These are the objects
//! `snmpwalk`/monitoring tools most often poll on a net-snmp host:
//!
//! * `memory` group (`2021.4`): real/swap memory totals and free space (KB).
//! * `laTable` (`2021.10.1`): 1/5/15-minute load averages.
//! * `dskTable` (`2021.9.1`): per-filesystem capacity, usage and percent-full.
//! * `ssCpu` (`2021.11`): aggregate CPU user/system/idle percentages.

use std::collections::BTreeMap;
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use super::collector::{HostCollector, Snapshot};
use crate::scalar::FnHandler;

/// UCD-SNMP enterprise root: `1.3.6.1.4.1.2021`.
const UCD: [u32; 7] = [1, 3, 6, 1, 4, 1, 2021];

/// Bytes-to-kilobytes, clamped to the signed 32-bit range used by these
/// (historically 32-bit) UCD objects.
fn kib(bytes: u64) -> i64 {
    (bytes / 1024).min(i32::MAX as u64) as i64
}

/// `memory` group scalars (`2021.4.*`).
fn memory_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let m = Oid::new(UCD.to_vec()).child(4);
    let total_free = snap.mem_free + snap.swap_free;
    vec![
        (m.child(3).child(0), Value::Integer(kib(snap.swap_total))), // memTotalSwap
        (m.child(4).child(0), Value::Integer(kib(snap.swap_free))),  // memAvailSwap
        (m.child(5).child(0), Value::Integer(kib(snap.mem_total))),  // memTotalReal
        (m.child(6).child(0), Value::Integer(kib(snap.mem_available))), // memAvailReal
        (m.child(11).child(0), Value::Integer(kib(total_free))),     // memTotalFree
    ]
}

/// `laTable` rows (`2021.10.1.*`): 1/5/15-minute load averages.
fn la_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(10).child(1); // laEntry
    let rows = [
        (1u32, "Load-1", snap.load_avg.0),
        (2, "Load-5", snap.load_avg.1),
        (3, "Load-15", snap.load_avg.2),
    ];
    let mut cells = Vec::new();
    for (idx, name, load) in rows {
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // laIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(name.as_bytes().to_vec()),
        )); // laNames
        cells.push((
            entry.child(3).child(idx),
            Value::OctetString(format!("{load:.2}").into_bytes()),
        )); // laLoad (display string)
        cells.push((
            entry.child(5).child(idx),
            Value::Integer((load * 100.0) as i64),
        )); // laLoadInt
    }
    cells
}

/// `dskTable` rows (`2021.9.1.*`): one row per mounted filesystem.
fn dsk_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(9).child(1); // dskEntry
    let mut cells = Vec::new();
    for (i, disk) in snap.disks.iter().enumerate() {
        let idx = (i + 1) as u32;
        let used = disk.total.saturating_sub(disk.available);
        let percent = if disk.total > 0 {
            (used as u128 * 100 / disk.total as u128) as i64
        } else {
            0
        };
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // dskIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(disk.mount.clone().into_bytes()),
        )); // dskPath
        cells.push((
            entry.child(3).child(idx),
            Value::OctetString(disk.fs.clone().into_bytes()),
        )); // dskDevice
        cells.push((entry.child(6).child(idx), Value::Integer(kib(disk.total)))); // dskTotal
        cells.push((entry.child(7).child(idx), Value::Integer(kib(disk.available)))); // dskAvail
        cells.push((entry.child(8).child(idx), Value::Integer(kib(used)))); // dskUsed
        cells.push((entry.child(9).child(idx), Value::Integer(percent))); // dskPercent
    }
    cells
}

/// `ssCpu` aggregate percentages (`2021.11.*`).
fn ss_cpu_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let s = Oid::new(UCD.to_vec()).child(11);
    let busy = snap.cpu_global_pct.clamp(0, 100);
    vec![
        (s.child(9).child(0), Value::Integer(busy)),        // ssCpuUser (approx: all busy)
        (s.child(10).child(0), Value::Integer(0)),          // ssCpuSystem
        (s.child(11).child(0), Value::Integer(100 - busy)), // ssCpuIdle
    ]
}

/// Build all UCD-SNMP-MIB cells from a snapshot.
fn ucd_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for (oid, value) in memory_cells(snap)
        .into_iter()
        .chain(la_cells(snap))
        .chain(dsk_cells(snap))
        .chain(ss_cpu_cells(snap))
    {
        cells.insert(oid, value);
    }
    cells.into_iter().collect()
}

/// UCD-SNMP-MIB handler rooted at the enterprise subtree (`1.3.6.1.4.1.2021`).
pub fn ucd_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(UCD.to_vec());
    Arc::new(FnHandler::new(root, move || ucd_cells(&collector.snapshot())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mibgroup::collector::DiskSample;

    fn snap() -> Snapshot {
        Snapshot {
            mem_total: 16 * 1024 * 1024 * 1024,
            mem_available: 8 * 1024 * 1024 * 1024,
            mem_free: 4 * 1024 * 1024 * 1024,
            swap_total: 2 * 1024 * 1024 * 1024,
            swap_free: 1024 * 1024 * 1024,
            cpu_global_pct: 30,
            load_avg: (0.5, 1.25, 2.0),
            disks: vec![DiskSample {
                mount: "/".to_string(),
                fs: "ext4".to_string(),
                total: 100 * 1024 * 1024 * 1024,
                available: 25 * 1024 * 1024 * 1024,
            }],
            ..Snapshot::default()
        }
    }

    #[test]
    fn memory_reports_real_and_swap() {
        let cells = ucd_cells(&snap());
        let total_real = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.4.5.0")
            .map(|(_, v)| v.clone());
        assert_eq!(total_real, Some(Value::Integer(16 * 1024 * 1024)));
    }

    #[test]
    fn load_average_int_is_scaled() {
        let cells = ucd_cells(&snap());
        let la5 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.10.1.5.2")
            .map(|(_, v)| v.clone());
        assert_eq!(la5, Some(Value::Integer(125))); // 1.25 * 100
    }

    #[test]
    fn disk_percent_is_computed() {
        let cells = ucd_cells(&snap());
        // 75 GiB used of 100 GiB -> 75%.
        let pct = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.9.1.9.1")
            .map(|(_, v)| v.clone());
        assert_eq!(pct, Some(Value::Integer(75)));
    }

    #[test]
    fn ss_cpu_idle_complements_busy() {
        let cells = ucd_cells(&snap());
        let idle = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.11.11.0")
            .map(|(_, v)| v.clone());
        assert_eq!(idle, Some(Value::Integer(70)));
    }
}
