//! HOST-RESOURCES-MIB, backed by cross-platform [`sysinfo`] data.
//!
//! Counterpart of `agent/mibgroup/host/`. All values come from the shared
//! [`HostCollector`](super::collector::HostCollector), which works on Linux,
//! macOS and Windows.
//!
//! Objects exposed:
//! * `hrSystem` group (`25.1`): `hrSystemUptime`, `hrSystemDate`,
//!   `hrSystemNumUsers`, `hrSystemProcesses`, `hrSystemMaxProcesses`.
//! * `hrStorage` group (`25.2`): `hrMemorySize` and `hrStorageTable` rows for
//!   physical memory, swap and every mounted filesystem.
//! * `hrDevice` group (`25.3`): `hrDeviceTable` (processors + disks),
//!   `hrProcessorTable` (per-core load) and `hrFSTable` (per-filesystem).
//! * `hrSWRun` group (`25.4`): `hrSWRunTable` — one row per process.
//! * `hrSWRunPerf` group (`25.5`): `hrSWRunPerfTable` — per-process CPU/memory.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{Datelike, Local, Offset, Timelike};
use netsnmp::oid::Oid;
use netsnmp::value::Value;

use super::collector::{HostCollector, Snapshot};
use crate::scalar::FnHandler;

/// `host` group root: `1.3.6.1.2.1.25`.
const HOST: [u32; 7] = [1, 3, 6, 1, 2, 1, 25];

/// `hrStorageTypes` prefix: `1.3.6.1.2.1.25.2.1` (`.2` ram, `.3` virtual, `.4` fixed disk).
const HR_STORAGE_TYPE: [u32; 9] = [1, 3, 6, 1, 2, 1, 25, 2, 1];
/// `hrDeviceTypes` prefix: `1.3.6.1.2.1.25.3.1` (`.3` processor, `.5` disk).
const HR_DEVICE_TYPE: [u32; 9] = [1, 3, 6, 1, 2, 1, 25, 3, 1];
/// `hrFSTypes` prefix: `1.3.6.1.2.1.25.3.9` (`.1` = hrFSOther).
const HR_FS_TYPE: [u32; 9] = [1, 3, 6, 1, 2, 1, 25, 3, 9];

/// Encode the current local time as an SMIv2 `DateAndTime` (RFC 2579), the
/// 11-octet form including the timezone offset.
fn date_and_time_now() -> Vec<u8> {
    let now = Local::now();
    let year = now.year();
    let off_min = now.offset().fix().local_minus_utc() / 60;
    let (sign, off_h, off_m) = if off_min >= 0 {
        (b'+', off_min / 60, off_min % 60)
    } else {
        (b'-', (-off_min) / 60, (-off_min) % 60)
    };
    vec![
        (year >> 8) as u8,
        (year & 0xff) as u8,
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
        (now.nanosecond() / 100_000_000) as u8,
        sign,
        off_h as u8,
        off_m as u8,
    ]
}

/// Clamp a value into the signed 32-bit range used by SMIv2 `Integer32`.
fn clamp_i32(v: i64) -> i64 {
    v.clamp(0, i32::MAX as i64)
}

/// Choose a storage allocation unit (bytes) so that `total / units` fits in an
/// `Integer32`, starting from a typical 4 KiB block.
fn alloc_units_for(total: u64) -> i64 {
    let mut units: u64 = 4096;
    while total / units > i32::MAX as u64 {
        units = units.saturating_mul(2);
    }
    units as i64
}

/// One `hrStorageTable` row, expressed in allocation units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageRow {
    /// `hrStorageIndex`.
    pub index: u32,
    /// `hrStorageType` OID.
    pub type_oid: Oid,
    /// `hrStorageDescr`.
    pub descr: String,
    /// `hrStorageAllocationUnits` (bytes per unit).
    pub alloc_units: i64,
    /// `hrStorageSize` in allocation units.
    pub size: i64,
    /// `hrStorageUsed` in allocation units.
    pub used: i64,
}

/// Build the `hrStorageTable` cells from already-computed rows (pure/testable).
///
/// Cell OID layout: `hrStorageEntry(25.2.3.1).column(.C).index(.N)`.
pub fn storage_table_cells(rows: &[StorageRow]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(HOST.to_vec()).child(2).child(3).child(1);
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for row in rows {
        let idx = row.index;
        cells.insert(entry.child(1).child(idx), Value::Integer(idx as i64));
        cells.insert(entry.child(2).child(idx), Value::Oid(row.type_oid.clone()));
        cells.insert(
            entry.child(3).child(idx),
            Value::OctetString(row.descr.clone().into_bytes()),
        );
        cells.insert(entry.child(4).child(idx), Value::Integer(row.alloc_units));
        cells.insert(entry.child(5).child(idx), Value::Integer(row.size));
        cells.insert(entry.child(6).child(idx), Value::Integer(row.used));
    }
    cells.into_iter().collect()
}

/// Derive the storage rows (RAM, swap, fixed disks) from a snapshot.
fn storage_rows(snap: &Snapshot) -> Vec<StorageRow> {
    let ram_type = Oid::new(HR_STORAGE_TYPE.to_vec()).child(2);
    let vm_type = Oid::new(HR_STORAGE_TYPE.to_vec()).child(3);
    let disk_type = Oid::new(HR_STORAGE_TYPE.to_vec()).child(4);

    let mut rows = Vec::new();
    if snap.mem_total > 0 {
        rows.push(StorageRow {
            index: 1,
            type_oid: ram_type,
            descr: "Physical memory".to_string(),
            alloc_units: 1024,
            size: clamp_i32((snap.mem_total / 1024) as i64),
            used: clamp_i32((snap.mem_used / 1024) as i64),
        });
    }
    if snap.swap_total > 0 {
        rows.push(StorageRow {
            index: 3,
            type_oid: vm_type,
            descr: "Swap space".to_string(),
            alloc_units: 1024,
            size: clamp_i32((snap.swap_total / 1024) as i64),
            used: clamp_i32((snap.swap_used / 1024) as i64),
        });
    }
    for (i, disk) in snap.disks.iter().enumerate() {
        let units = alloc_units_for(disk.total);
        let used_bytes = disk.total.saturating_sub(disk.available);
        rows.push(StorageRow {
            index: 4 + i as u32,
            type_oid: disk_type.clone(),
            descr: if disk.fs.is_empty() {
                disk.mount.clone()
            } else {
                format!("{} ({})", disk.mount, disk.fs)
            },
            alloc_units: units,
            size: clamp_i32((disk.total / units as u64) as i64),
            used: clamp_i32((used_bytes / units as u64) as i64),
        });
    }
    rows
}

/// `hrSystem` group cells (`25.1.*`).
fn hr_system_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let base = Oid::new(HOST.to_vec()).child(1);
    let ticks = snap.uptime_secs.saturating_mul(100).min(u32::MAX as u64) as u32;
    vec![
        (base.child(1).child(0), Value::TimeTicks(ticks)), // hrSystemUptime
        (
            base.child(2).child(0),
            Value::OctetString(date_and_time_now()),
        ), // hrSystemDate
        (
            base.child(5).child(0),
            Value::Gauge32(clamp_i32(snap.num_users) as u32),
        ), // hrSystemNumUsers
        (
            base.child(6).child(0),
            Value::Gauge32(clamp_i32(snap.num_processes) as u32),
        ), // hrSystemProcesses
        (base.child(7).child(0), Value::Integer(0)), // hrSystemMaxProcesses (0 = no fixed max)
    ]
}

/// `hrStorage` group cells: `hrMemorySize` scalar + `hrStorageTable` (`25.2.*`).
fn hr_storage_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let mut cells = vec![(
        // hrMemorySize.0 in kilobytes.
        Oid::new(HOST.to_vec()).child(2).child(2).child(0),
        Value::Integer(clamp_i32((snap.mem_total / 1024) as i64)),
    )];
    cells.extend(storage_table_cells(&storage_rows(snap)));
    cells
}

/// `hrDevice` group cells: `hrDeviceTable` (processors + disks) and
/// `hrProcessorTable` (per-core load) under `25.3.*`.
fn hr_device_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let dev_entry = Oid::new(HOST.to_vec()).child(3).child(2).child(1); // hrDeviceEntry
    let proc_entry = Oid::new(HOST.to_vec()).child(3).child(3).child(1); // hrProcessorEntry
    let processor_type = Oid::new(HR_DEVICE_TYPE.to_vec()).child(3);
    let disk_type = Oid::new(HR_DEVICE_TYPE.to_vec()).child(5);
    let frw_id = Oid::new(vec![0, 0]); // hrProcessorFrwID = { 0 0 }

    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    let mut dev_index = 0u32;

    // Processors first, so their device index lines up with hrProcessorTable.
    for cpu in &snap.cpus {
        dev_index += 1;
        let descr = if cpu.freq_mhz > 0 {
            format!("{} @ {} MHz", cpu.name, cpu.freq_mhz)
        } else {
            cpu.name.clone()
        };
        cells.insert(dev_entry.child(1).child(dev_index), Value::Integer(dev_index as i64));
        cells.insert(dev_entry.child(2).child(dev_index), Value::Oid(processor_type.clone()));
        cells.insert(dev_entry.child(3).child(dev_index), Value::OctetString(descr.into_bytes()));
        cells.insert(dev_entry.child(5).child(dev_index), Value::Integer(2)); // running
        // hrProcessorTable row, indexed by the same device index.
        cells.insert(proc_entry.child(1).child(dev_index), Value::Oid(frw_id.clone()));
        cells.insert(
            proc_entry.child(2).child(dev_index),
            Value::Integer(clamp_i32(cpu.usage_pct)),
        );
    }

    // hrFSEntry = hrDevice(.3).hrFSTable(.8).hrFSEntry(.1).
    let fs_entry = Oid::new(HOST.to_vec()).child(3).child(8).child(1);
    let fs_other = Oid::new(HR_FS_TYPE.to_vec()).child(1); // hrFSOther

    for (i, disk) in snap.disks.iter().enumerate() {
        dev_index += 1;
        cells.insert(dev_entry.child(1).child(dev_index), Value::Integer(dev_index as i64));
        cells.insert(dev_entry.child(2).child(dev_index), Value::Oid(disk_type.clone()));
        cells.insert(
            dev_entry.child(3).child(dev_index),
            Value::OctetString(disk.mount.clone().into_bytes()),
        );
        cells.insert(dev_entry.child(5).child(dev_index), Value::Integer(2)); // running

        // hrFSTable row, indexed independently and linked back to hrStorageTable.
        let fs_idx = (i + 1) as u32;
        let storage_idx = 4 + i as i64; // matches storage_rows() disk indices
        cells.insert(fs_entry.child(1).child(fs_idx), Value::Integer(fs_idx as i64)); // hrFSIndex
        cells.insert(
            fs_entry.child(2).child(fs_idx),
            Value::OctetString(disk.mount.clone().into_bytes()),
        ); // hrFSMountPoint
        cells.insert(fs_entry.child(3).child(fs_idx), Value::OctetString(Vec::new())); // hrFSRemoteMountPoint
        cells.insert(fs_entry.child(4).child(fs_idx), Value::Oid(fs_other.clone())); // hrFSType
        cells.insert(fs_entry.child(5).child(fs_idx), Value::Integer(1)); // hrFSAccess = readWrite
        cells.insert(fs_entry.child(6).child(fs_idx), Value::Integer(2)); // hrFSBootable = false
        cells.insert(fs_entry.child(7).child(fs_idx), Value::Integer(storage_idx)); // hrFSStorageIndex
    }

    cells.into_iter().collect()
}

/// `hrSWRunTable` cells: one row per process (`25.4.2.*`).
fn hr_swrun_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let entry = Oid::new(HOST.to_vec()).child(4).child(2).child(1); // hrSWRunEntry
    let sw_id = Oid::new(vec![0, 0]);
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for p in &snap.processes {
        let idx = p.pid;
        cells.insert(entry.child(1).child(idx), Value::Integer(idx as i64)); // hrSWRunIndex
        cells.insert(
            entry.child(2).child(idx),
            Value::OctetString(p.name.clone().into_bytes()),
        ); // hrSWRunName
        cells.insert(entry.child(3).child(idx), Value::Oid(sw_id.clone())); // hrSWRunID
        cells.insert(
            entry.child(4).child(idx),
            Value::OctetString(p.path.clone().into_bytes()),
        ); // hrSWRunPath
        cells.insert(entry.child(5).child(idx), Value::OctetString(Vec::new())); // hrSWRunParameters
        cells.insert(entry.child(6).child(idx), Value::Integer(4)); // hrSWRunType = application
        cells.insert(entry.child(7).child(idx), Value::Integer(p.status)); // hrSWRunStatus
    }
    cells.into_iter().collect()
}

/// `hrSWRunPerfTable` cells: per-process CPU and memory (`25.5.1.*`).
fn hr_swrun_perf_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let entry = Oid::new(HOST.to_vec()).child(5).child(1).child(1); // hrSWRunPerfEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for p in &snap.processes {
        let idx = p.pid;
        cells.insert(entry.child(1).child(idx), Value::Integer(clamp_i32(p.cpu_pct))); // hrSWRunPerfCPU
        cells.insert(entry.child(2).child(idx), Value::Integer(clamp_i32(p.mem_kb))); // hrSWRunPerfMem
    }
    cells.into_iter().collect()
}

/// `hrSystem` handler (`25.1`).
pub fn hr_system_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(1);
    Arc::new(FnHandler::new(root, move || {
        hr_system_cells(&collector.snapshot())
    }))
}

/// `hrStorage` handler (`25.2`).
pub fn hr_storage_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(2);
    Arc::new(FnHandler::new(root, move || {
        hr_storage_cells(&collector.snapshot())
    }))
}

/// `hrDevice` handler (`25.3`).
pub fn hr_device_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(3);
    Arc::new(FnHandler::new(root, move || {
        hr_device_cells(&collector.snapshot())
    }))
}

/// `hrSWRun` handler (`25.4`).
pub fn hr_swrun_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(4);
    Arc::new(FnHandler::new(root, move || {
        hr_swrun_cells(&collector.snapshot())
    }))
}

/// `hrSWRunPerf` handler (`25.5`).
pub fn hr_swrun_perf_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(5);
    Arc::new(FnHandler::new(root, move || {
        hr_swrun_perf_cells(&collector.snapshot())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ram_swap_rows() -> Vec<StorageRow> {
        vec![
            StorageRow {
                index: 1,
                type_oid: "1.3.6.1.2.1.25.2.1.2".parse().unwrap(),
                descr: "Physical memory".to_string(),
                alloc_units: 1024,
                size: 16384000,
                used: 8192000,
            },
            StorageRow {
                index: 3,
                type_oid: "1.3.6.1.2.1.25.2.1.3".parse().unwrap(),
                descr: "Swap space".to_string(),
                alloc_units: 1024,
                size: 2048000,
                used: 1024000,
            },
        ]
    }

    #[test]
    fn builds_storage_table_cells() {
        let cells = storage_table_cells(&ram_swap_rows());
        // hrStorageSize.1 (RAM).
        let size_ram = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.2.3.1.5.1")
            .map(|(_, v)| v.clone());
        assert_eq!(size_ram, Some(Value::Integer(16384000)));
        // hrStorageUsed.1 (RAM).
        let used_ram = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.2.3.1.6.1")
            .map(|(_, v)| v.clone());
        assert_eq!(used_ram, Some(Value::Integer(8192000)));
        // hrStorageType.3 (swap) = hrStorageVirtualMemory.
        let type_swap = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.2.3.1.2.3")
            .map(|(_, v)| v.clone());
        assert_eq!(
            type_swap,
            Some(Value::Oid("1.3.6.1.2.1.25.2.1.3".parse().unwrap()))
        );
    }

    #[test]
    fn storage_rows_include_disks() {
        let snap = Snapshot {
            mem_total: 16 * 1024 * 1024 * 1024,
            mem_used: 8 * 1024 * 1024 * 1024,
            swap_total: 2 * 1024 * 1024 * 1024,
            swap_used: 1024 * 1024 * 1024,
            disks: vec![super::super::collector::DiskSample {
                mount: "/".to_string(),
                fs: "ext4".to_string(),
                total: 500 * 1024 * 1024 * 1024,
                available: 100 * 1024 * 1024 * 1024,
            }],
            ..Snapshot::default()
        };
        let rows = storage_rows(&snap);
        // RAM (1), swap (3), one disk (4).
        assert_eq!(rows.iter().map(|r| r.index).collect::<Vec<_>>(), vec![1, 3, 4]);
        let disk = rows.iter().find(|r| r.index == 4).unwrap();
        assert_eq!(disk.descr, "/ (ext4)");
        // size * alloc_units should reconstruct (approximately) the byte total.
        assert!(disk.size > 0 && disk.alloc_units >= 4096);
    }

    #[test]
    fn alloc_units_keep_size_in_i32() {
        // A 100 TiB volume must still fit hrStorageSize in Integer32.
        let total = 100u64 * 1024 * 1024 * 1024 * 1024;
        let units = alloc_units_for(total) as u64;
        assert!(total / units <= i32::MAX as u64);
    }

    #[test]
    fn system_cells_report_uptime_and_processes() {
        let snap = Snapshot {
            uptime_secs: 100,
            num_processes: 42,
            ..Snapshot::default()
        };
        let cells = hr_system_cells(&snap);
        let uptime = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.1.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(uptime, Some(Value::TimeTicks(10000)));
        let procs = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.1.6.0")
            .map(|(_, v)| v.clone());
        assert_eq!(procs, Some(Value::Gauge32(42)));
    }
}
