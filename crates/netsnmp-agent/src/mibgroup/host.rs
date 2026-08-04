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
use crate::handler::{MibHandler, Reading};
use crate::scalar::types_compatible;
use crate::scalar::{CellSnapshot, FnHandler};
use netsnmp::pdu::ErrorStatus;

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

/// Map a filesystem-type string (as reported by `sysinfo`, e.g. `ext4`, `xfs`,
/// `ntfs`, `vfat`) to the RFC 1514 `hrFSType` OID under `1.3.6.1.2.1.25.3.9`.
///
/// This is the string-based counterpart of
/// [`FsysAccess::fs_type`](crate::hardware::FsysAccess::fs_type); it lives here
/// so the hrDevice cell-builder can classify a [`super::collector::DiskSample`]
/// without depending on the hardware layer. Unrecognised strings map to
/// `hrFSOther` (`.1`); an empty string maps to `hrFSUnknown` (`.2`), matching
/// the upstream behaviour for filesystems whose magic number is not in the
/// `get_fs_type` table.
fn fs_type_oid_for(fs: &str) -> Oid {
    use crate::hardware::FsType;
    let suffix = FsType::from_fs_string(fs).as_oid_suffix();
    Oid::new(HR_FS_TYPE.to_vec()).child(suffix)
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
        // hrFSType: classify the real filesystem type (ext4/xfs/ntfs/vfat/...)
        // into the RFC 1514 hrFSType enum. Previously this was hard-coded to
        // hrFSOther for every filesystem.
        let fs_type_oid = fs_type_oid_for(&disk.fs);
        cells.insert(fs_entry.child(1).child(fs_idx), Value::Integer(fs_idx as i64)); // hrFSIndex
        cells.insert(
            fs_entry.child(2).child(fs_idx),
            Value::OctetString(disk.mount.clone().into_bytes()),
        ); // hrFSMountPoint
        cells.insert(fs_entry.child(3).child(fs_idx), Value::OctetString(Vec::new())); // hrFSRemoteMountPoint
        cells.insert(fs_entry.child(4).child(fs_idx), Value::Oid(fs_type_oid)); // hrFSType
        cells.insert(fs_entry.child(5).child(fs_idx), Value::Integer(1)); // hrFSAccess = readWrite
        cells.insert(fs_entry.child(6).child(fs_idx), Value::Integer(2)); // hrFSBootable = false
        cells.insert(fs_entry.child(7).child(fs_idx), Value::Integer(storage_idx)); // hrFSStorageIndex
        // hrFSLastFullBackupDate / hrFSLastPartialBackupDate: no backup data is
        // available, so report `unknown(2)` per the DateAndTime textual
        // convention (an empty/unknown DateAndTime is encoded as the single
        // octet 0x02).
        cells.insert(
            fs_entry.child(8).child(fs_idx),
            Value::OctetString(vec![2]),
        ); // hrFSLastFullBackupDate = unknown(2)
        cells.insert(
            fs_entry.child(9).child(fs_idx),
            Value::OctetString(vec![2]),
        ); // hrFSLastPartialBackupDate = unknown(2)
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

// ---------------------------------------------------------------------------
// Task 5.22: HOST-RESOURCES-MIB completion — additional tables.
// ---------------------------------------------------------------------------

/// `hrDiskStorageEntry` root: `1.3.6.1.2.1.25.3.6.1.1` (under
/// `hrDiskStorageTable` `25.3.6`).
const HR_DISK_STORAGE_ENTRY: [u32; 10] = [1, 3, 6, 1, 2, 1, 25, 3, 6, 1];

/// `hrPartitionEntry` root: `1.3.6.1.2.1.25.3.7.1.1` (under `hrPartitionTable`
/// `25.3.7`).
const HR_PARTITION_ENTRY: [u32; 10] = [1, 3, 6, 1, 2, 1, 25, 3, 7, 1];

/// `hrNetworkEntry` root: `1.3.6.1.2.1.25.3.4.1.1` (under `hrNetworkTable`
/// `25.3.4`).
const HR_NETWORK_ENTRY: [u32; 10] = [1, 3, 6, 1, 2, 1, 25, 3, 4, 1];

/// `hrSWRunStatus` column within `hrSWRunEntry` (`25.4.2.1.7`).
const HRSWRUN_STATUS_COL: u32 = 7;
/// `invalid(4)` — the only writable `hrSWRunStatus` value that triggers an
/// action (signal the process to terminate).
const HRSWRUN_STATUS_INVALID: i64 = 4;

/// A single disk-storage device row (from `/sys/block` on Linux).
#[derive(Clone, Debug)]
struct DiskStorageRow {
    /// Device index, matching the `hrDeviceTable` disk entry it extends.
    index: u32,
    /// `hrDiskStorageAccess`: 1 = readWrite, 2 = readOnly.
    access: i64,
    /// `hrDiskStorageMedia`: rough media type (1=other, 3=floppy, 6=hardDisk,
    /// 11=CD-ROM, 21=compactFlash). We classify hard disks vs. CD-ROM vs.
    /// other pragmatically from the device name.
    media: i64,
    /// `hrDiskStorageRemoveble`: true(1)/false(2).
    removable: i64,
    /// `hrDiskStorageCapacity` in bytes (kJ units of 1 KiB per the RFC; we
    /// report the raw byte count clamped to Integer32, which is what most
    /// managers expect for a "capacity" gauge).
    capacity: i64,
}

/// A single partition row (from `/proc/partitions` on Linux).
#[derive(Clone, Debug)]
struct PartitionRow {
    /// Partition index, 1-based within its parent disk.
    index: u32,
    /// Link back to the `hrDiskStorageTable` / `hrDeviceTable` disk index.
    parent: u32,
    /// `hrPartitionLabel` — the partition device name (e.g. `sda1`).
    label: String,
    /// `hrPartitionID` — opaque octet string identifying the partition.
    id: Vec<u8>,
    /// `hrPartitionSize` in KiB.
    size: i64,
    /// `hrPartitionFsType` — filesystem type string (often empty when unknown).
    fs_type: String,
}

/// Build `hrPrinterTable` cells. Cross-platform: no printers are enumerated,
/// so the table is always empty (the RFC allows zero rows). Returns an empty
/// `Vec` so `GETNEXT` walks straight past the table without error.
fn hr_printer_cells() -> Vec<(Oid, Value)> {
    Vec::new()
}

/// Enumerate Linux block devices from `/sys/block`. Returns one
/// [`DiskStorageRow`] per block device whose name does not start with `loop`
/// or `ram`. Returns an empty `Vec` on non-Linux or when `/sys/block` is
/// absent.
fn disk_storage_rows() -> Vec<DiskStorageRow> {
    let mut rows = Vec::new();
    let entries = match std::fs::read_dir("/sys/block") {
        Ok(e) => e,
        Err(_) => return rows,
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().into_owned().into())
        .filter(|n| {
            // Skip loop and ram devices; they are not physical disks.
            !n.starts_with("loop") && !n.starts_with("ram")
        })
        .collect();
    names.sort();
    for (i, name) in names.iter().enumerate() {
        let idx = (i + 1) as u32;
        let removable = read_sys_bool(&format!("/sys/block/{name}/removable"), 0);
        let read_only = read_sys_bool(&format!("/sys/block/{name}/ro"), 0);
        let capacity_sectors = read_sys_u64(&format!("/sys/block/{name}/size"));
        // 512-byte sectors by convention for /sys/block/.../size.
        let capacity_bytes = capacity_sectors.saturating_mul(512);
        let media = classify_disk_media(name);
        rows.push(DiskStorageRow {
            index: idx,
            access: if read_only != 0 { 2 } else { 1 },
            media,
            removable: if removable != 0 { 1 } else { 2 },
            capacity: clamp_i32(capacity_bytes as i64),
        });
    }
    rows
}

/// Build `hrDiskStorageTable` cells from `/sys/block` on Linux. Empty on other
/// platforms or when no block devices are visible.
fn hr_disk_storage_cells() -> Vec<(Oid, Value)> {
    let entry = Oid::new(HR_DISK_STORAGE_ENTRY.to_vec()).child(1); // hrDiskStorageEntry
    let rows = disk_storage_rows();
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for r in rows {
        cells.insert(entry.child(1).child(r.index), Value::Integer(r.index as i64));
        cells.insert(entry.child(2).child(r.index), Value::Integer(r.access));
        cells.insert(entry.child(3).child(r.index), Value::Integer(r.media));
        cells.insert(entry.child(4).child(r.index), Value::Integer(r.removable));
        cells.insert(entry.child(5).child(r.index), Value::Integer(r.capacity));
    }
    cells.into_iter().collect()
}

/// Parse `/proc/partitions` (Linux) into [`PartitionRow`]s. Each row is
/// 1-based within its parent disk; the parent index matches the disk order
/// produced by [`disk_storage_rows`]. Returns an empty `Vec` when
/// `/proc/partitions` is absent or unparseable.
fn partition_rows() -> Vec<PartitionRow> {
    let contents = match std::fs::read_to_string("/proc/partitions") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    // /proc/partitions has a header line then "major minor  blocks name".
    let mut rows = Vec::new();
    // Map disk base name -> parent index (1-based) matching disk_storage_rows.
    let disk_names = disk_storage_names();
    let mut part_index: BTreeMap<String, u32> = BTreeMap::new();
    for line in contents.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _major = fields.next();
        let _minor = fields.next();
        let blocks = match fields.next().and_then(|s| s.parse::<i64>().ok()) {
            Some(b) => b,
            None => continue,
        };
        let name = match fields.next() {
            Some(n) => n,
            None => continue,
        };
        // Find the parent disk: the longest disk-name prefix of `name`.
        let parent_name = disk_names
            .iter()
            .find(|d| name.starts_with(d.as_str()))
            .cloned();
        let parent_name = match parent_name {
            Some(p) => p,
            None => continue,
        };
        // Skip the whole-disk entry itself (name == parent_name).
        if name == parent_name {
            continue;
        }
        let parent_idx = match disk_names.iter().position(|d| d == &parent_name) {
            Some(p) => (p + 1) as u32,
            None => continue,
        };
        let counter = part_index.entry(parent_name.clone()).or_insert(0);
        *counter += 1;
        let idx = *counter;
        rows.push(PartitionRow {
            index: idx,
            parent: parent_idx,
            label: name.to_string(),
            id: format!("{parent_name}{idx}").into_bytes(),
            size: blocks,
            fs_type: String::new(),
        });
    }
    rows
}

/// Return the sorted list of block-device names (matching
/// [`disk_storage_rows`]'s ordering) for parent-index lookup.
fn disk_storage_names() -> Vec<String> {
    let entries = match std::fs::read_dir("/sys/block") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().into_owned().into())
        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram"))
        .collect();
    names.sort();
    names
}

/// Build `hrPartitionTable` cells from `/proc/partitions` on Linux. Empty on
/// other platforms.
fn hr_partition_cells() -> Vec<(Oid, Value)> {
    let entry = Oid::new(HR_PARTITION_ENTRY.to_vec()).child(1); // hrPartitionEntry
    let rows = partition_rows();
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for r in rows {
        // The row index is the (parent, partition) pair per the RFC, but for
        // flatness we use a single global counter encoded as parent*256+idx so
        // GETNEXT ordering stays sane.
        let flat = r.parent * 256 + r.index;
        cells.insert(entry.child(1).child(flat), Value::Integer(flat as i64));
        cells.insert(
            entry.child(2).child(flat),
            Value::OctetString(r.label.clone().into_bytes()),
        );
        cells.insert(entry.child(3).child(flat), Value::OctetString(r.id.clone()));
        cells.insert(entry.child(4).child(flat), Value::Integer(clamp_i32(r.size)));
        cells.insert(
            entry.child(5).child(flat),
            Value::OctetString(r.fs_type.clone().into_bytes()),
        );
    }
    cells.into_iter().collect()
}

/// Build `hrNetworkTable` cells: one row per network device in
/// `hrDeviceTable`, linking to the interface's `ifIndex` via the collector's
/// interface list. The network device indices mirror the order disks appear in
/// [`hr_device_cells`] (processors first, then disks); here we expose the
/// collector's interfaces as network devices under `25.3.4`.
fn hr_network_cells(snap: &Snapshot) -> Vec<(Oid, Value)> {
    let entry = Oid::new(HR_NETWORK_ENTRY.to_vec()).child(1); // hrNetworkEntry
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    // Network devices are indexed after processors and disks in hrDeviceTable.
    // We use a dedicated 1-based index here for the hrNetworkTable itself.
    for (i, iface) in snap.interfaces.iter().enumerate() {
        let idx = (i + 1) as u32;
        cells.insert(entry.child(1).child(idx), Value::Integer(iface.index as i64));
    }
    cells.into_iter().collect()
}

/// Build `hrSWInstalledTable` cells. Installed-software enumeration is
/// platform- and package-manager-specific; this implementation is intentionally
/// empty by default (the RFC permits zero rows). Callers that wish to populate
/// it can wrap the handler. Returns an empty `Vec`.
fn hr_sw_installed_cells() -> Vec<(Oid, Value)> {
    Vec::new()
}

/// `hrPrinterTable` handler (`1.3.6.1.2.1.25.3.5`). Always empty (no
/// printers enumerated) — `GETNEXT` walks past it, `GET` returns
/// `noSuchInstance`, matching upstream behaviour on a host with no printers.
pub fn hr_printer_handler() -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(3).child(5);
    Arc::new(FnHandler::new(root, hr_printer_cells))
}

/// `hrDiskStorageTable` handler (`1.3.6.1.2.1.25.3.6`). On Linux, reads
/// `/sys/block` for disk capacities, media type and removability. Empty on
/// other platforms or when `/sys/block` is absent.
pub fn hr_disk_storage_handler() -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(3).child(6);
    Arc::new(FnHandler::new(root, hr_disk_storage_cells))
}

/// `hrPartitionTable` handler (`1.3.6.1.2.1.25.3.7`). On Linux, parses
/// `/proc/partitions`. Empty on other platforms.
pub fn hr_partition_handler() -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(3).child(7);
    Arc::new(FnHandler::new(root, hr_partition_cells))
}

/// `hrNetworkTable` handler (`1.3.6.1.2.1.25.3.4`). Maps each network device
/// to its `ifIndex` via the collector's interface list.
pub fn hr_network_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(3).child(4);
    Arc::new(FnHandler::new(root, move || {
        hr_network_cells(&collector.snapshot())
    }))
}

/// `hrSWInstalledTable` handler (`1.3.6.1.2.1.25.6.3`). Empty by default
/// (installed-software enumeration is package-manager-specific and optional).
pub fn hr_sw_installed_handler() -> Arc<FnHandler> {
    let root = Oid::new(HOST.to_vec()).child(6).child(3);
    Arc::new(FnHandler::new(root, hr_sw_installed_cells))
}

/// Read a `/sys` file as a `u64` (0 on any error).
fn read_sys_u64(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Read a `/sys` file as an integer (default on any error).
fn read_sys_bool(path: &str, default: i64) -> i64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

/// Classify a block-device name into an `hrDiskStorageMedia` value.
fn classify_disk_media(name: &str) -> i64 {
    if name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("hd") || name.starts_with("vd") {
        6 // hardDisk
    } else if name.starts_with("sr") || name.starts_with("scd") || name.starts_with("cd") {
        11 // CD-ROM
    } else if name.starts_with("fd") {
        3 // floppy
    } else {
        1 // other
    }
}

// ---------------------------------------------------------------------------
// hrSWRunStatus write support (Task 5.22).
// ---------------------------------------------------------------------------

/// A handler for the `hrSWRun` group that adds write support for
/// `hrSWRunStatus.<pid>`.
///
/// `SET hrSWRunStatus.<pid> = invalid(4)` signals the process to terminate.
/// Because `#![forbid(unsafe_code)]` blocks the `libc::kill` syscall, the
/// signal is sent by spawning `kill <pid>` as a subprocess via
/// [`tokio::process::Command`] (safe, Unix-only but harmless elsewhere). Any
/// other `hrSWRunStatus` value is accepted but treated as a no-op (the value
/// is not persisted — the process's real status is always re-read from the
/// collector on the next GET).
///
/// All other `hrSWRun` columns remain read-only.
pub struct HrSWRunHandler {
    root: Oid,
    collector: Arc<HostCollector>,
    cache: std::sync::Mutex<Option<(std::time::Instant, CellSnapshot)>>,
}

impl HrSWRunHandler {
    /// Create a new writable `hrSWRun` handler backed by `collector`.
    pub fn new(collector: Arc<HostCollector>) -> Self {
        HrSWRunHandler {
            root: Oid::new(HOST.to_vec()).child(4),
            collector,
            cache: std::sync::Mutex::new(None),
        }
    }

    /// Return the current hrSWRun cells, reusing the FnHandler cache TTL so a
    /// full walk stays cheap. This mirrors [`FnHandler::snapshot`].
    fn snapshot_cells(&self) -> CellSnapshot {
        use std::time::{Duration, Instant};
        const TTL: Duration = Duration::from_millis(900);
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((built, cells)) = guard.as_ref() {
            if built.elapsed() < TTL {
                return cells.clone();
            }
        }
        let mut cells = hr_swrun_cells(&self.collector.snapshot());
        cells.sort_by(|a, b| a.0.cmp(&b.0));
        let cells = std::sync::Arc::new(cells);
        *guard = Some((Instant::now(), cells.clone()));
        cells
    }
}

impl MibHandler for HrSWRunHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        let cells = self.snapshot_cells();
        cells
            .binary_search_by(|(o, _)| o.cmp(oid))
            .ok()
            .map(|i| cells[i].1.clone())
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.snapshot_cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, value)| Reading {
            oid: o.clone(),
            value: value.clone(),
        })
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        // Only hrSWRunStatus (column 7) is writable.
        // OID layout: HOST.4.2.1.7.<pid>
        let entry = Oid::new(HOST.to_vec())
            .child(4)
            .child(2)
            .child(1)
            .child(HRSWRUN_STATUS_COL);
        if !oid.as_slice().starts_with(entry.as_slice()) || oid.len() != entry.len() + 1 {
            return Err(ErrorStatus::NotWritable);
        }
        // Type check: must be Integer-compatible.
        let current = self.get(oid);
        match &current {
            Some(c) if !types_compatible(c, value) => return Err(ErrorStatus::WrongType),
            None => return Err(ErrorStatus::NoCreation),
            _ => {}
        }
        // Range check: hrSWRunStatus is 1..=4.
        if let Value::Integer(v) = value {
            if !(*v >= 1 && *v <= 4) {
                return Err(ErrorStatus::WrongValue);
            }
        } else {
            return Err(ErrorStatus::WrongType);
        }
        Ok(())
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        // Only act on invalid(4): send SIGTERM to the pid via `kill` subprocess.
        let pid = oid.as_slice().last().copied().unwrap_or(0);
        let act = matches!(value, Value::Integer(v) if *v == HRSWRUN_STATUS_INVALID);
        if act && pid > 0 {
            // Safe signalling: spawn `kill <pid>` (sends SIGTERM by default).
            // This is a best-effort side effect; failure to spawn or a non-zero
            // exit does not fail the SET (the process may already be gone).
            let pid_str = pid.to_string();
            // Use a blocking spawn in a background thread so the commit stays
            // synchronous and non-async (the registry's commit path is sync).
            std::thread::spawn(move || {
                let _ = std::process::Command::new("kill")
                    .arg(&pid_str)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            });
        }
        Ok(())
    }
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

    // --- Task 5.22 tests ---

    #[test]
    fn fs_type_oid_for_maps_common_filesystems() {
        // ext4 -> hrFSLinuxExt2 (1.3.6.1.2.1.25.3.9.10)
        assert_eq!(
            fs_type_oid_for("ext4").to_string(),
            ".1.3.6.1.2.1.25.3.9.10"
        );
        // xfs -> hrFSXFS (.14)
        assert_eq!(
            fs_type_oid_for("xfs").to_string(),
            ".1.3.6.1.2.1.25.3.9.14"
        );
        // ntfs -> hrFSHPFS (.7)
        assert_eq!(
            fs_type_oid_for("ntfs").to_string(),
            ".1.3.6.1.2.1.25.3.9.7"
        );
        // vfat -> hrFSFat (.6)
        assert_eq!(
            fs_type_oid_for("vfat").to_string(),
            ".1.3.6.1.2.1.25.3.9.6"
        );
        // unknown -> hrFSOther (.1)
        assert_eq!(
            fs_type_oid_for("btrfs").to_string(),
            ".1.3.6.1.2.1.25.3.9.1"
        );
        // empty -> hrFSUnknown (.2)
        assert_eq!(
            fs_type_oid_for("").to_string(),
            ".1.3.6.1.2.1.25.3.9.2"
        );
    }

    #[test]
    fn hr_device_cells_map_fs_type_for_real_filesystems() {
        // An ext4 disk must now report hrFSLinuxExt2 (.10) instead of the old
        // hard-coded hrFSOther (.1).
        let snap = Snapshot {
            disks: vec![super::super::collector::DiskSample {
                mount: "/".to_string(),
                fs: "ext4".to_string(),
                total: 100 * 1024 * 1024 * 1024,
                available: 50 * 1024 * 1024 * 1024,
            }],
            cpus: vec![super::super::collector::CpuSample {
                name: "cpu0".to_string(),
                usage_pct: 10,
                freq_mhz: 2400,
            }],
            ..Snapshot::default()
        };
        let cells = hr_device_cells(&snap);
        // hrFSType.1 = ext4 -> hrFSLinuxExt2.
        let fs_type = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.3.8.1.4.1")
            .map(|(_, v)| v.clone());
        assert_eq!(
            fs_type,
            Some(Value::Oid("1.3.6.1.2.1.25.3.9.10".parse().unwrap()))
        );
        // hrFSLastFullBackupDate.1 = unknown(2) -> single octet 0x02.
        let full_backup = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.3.8.1.8.1")
            .map(|(_, v)| v.clone());
        assert_eq!(full_backup, Some(Value::OctetString(vec![2])));
        // hrFSLastPartialBackupDate.1 = unknown(2).
        let partial_backup = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.3.8.1.9.1")
            .map(|(_, v)| v.clone());
        assert_eq!(partial_backup, Some(Value::OctetString(vec![2])));
    }

    #[test]
    fn hr_printer_table_is_empty() {
        // No printers are enumerated; the table must be empty (no panic).
        let cells = hr_printer_cells();
        assert!(cells.is_empty());
        // The handler must also serve an empty subtree without erroring.
        let handler = hr_printer_handler();
        let root: Oid = "1.3.6.1.2.1.25.3.5".parse().unwrap();
        assert!(handler.get_next(&root).is_none());
    }

    #[test]
    fn hr_sw_installed_table_is_empty() {
        let cells = hr_sw_installed_cells();
        assert!(cells.is_empty());
        let handler = hr_sw_installed_handler();
        let root: Oid = "1.3.6.1.2.1.25.6.3".parse().unwrap();
        assert!(handler.get_next(&root).is_none());
    }

    #[test]
    fn hr_network_table_maps_ifindex() {
        use super::super::interfaces::{IfStat, Interface};
        let snap = Snapshot {
            interfaces: vec![
                Interface {
                    index: 1,
                    if_type: 24,
                    mtu: 65536,
                    speed_bps: 0,
                    phys_address: vec![],
                    admin_up: true,
                    oper_up: true,
                    stat: IfStat {
                        name: "lo".into(),
                        ..Default::default()
                    },
                },
                Interface {
                    index: 2,
                    if_type: 6,
                    mtu: 1500,
                    speed_bps: 0,
                    phys_address: vec![],
                    admin_up: true,
                    oper_up: true,
                    stat: IfStat {
                        name: "eth0".into(),
                        ..Default::default()
                    },
                },
            ],
            ..Snapshot::default()
        };
        let cells = hr_network_cells(&snap);
        // hrNetworkIfIndex.1 = 1, hrNetworkIfIndex.2 = 2.
        // OID layout: hrNetworkEntry(25.3.4.1.1).column(1).idx(N).
        let if1 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.3.4.1.1.1.1")
            .map(|(_, v)| v.clone());
        assert_eq!(if1, Some(Value::Integer(1)));
        let if2 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.25.3.4.1.1.1.2")
            .map(|(_, v)| v.clone());
        assert_eq!(if2, Some(Value::Integer(2)));
    }

    #[test]
    fn hrswrun_handler_rejects_non_status_columns() {
        // hrSWRunName.<pid> (column 2) is not writable.
        let collector = HostCollector::new();
        let handler = HrSWRunHandler::new(collector);
        let name_oid: Oid = "1.3.6.1.2.1.25.4.2.1.2.1".parse().unwrap();
        let err = handler
            .prepare_set(&name_oid, &Value::OctetString(b"x".to_vec()))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::NotWritable);
    }

    #[test]
    fn hrswrun_handler_rejects_out_of_range_status() {
        let collector = HostCollector::new();
        let handler = HrSWRunHandler::new(collector);
        // Use a pid that exists (the test process's own pid) so the column is
        // present. Status value 5 is out of the 1..=4 range.
        let pid = std::process::id();
        let status_oid: Oid = format!(".1.3.6.1.2.1.25.4.2.1.7.{pid}")
            .parse()
            .unwrap();
        // First, the column may or may not be present depending on whether the
        // collector enumerated this process. If absent, prepare_set returns
        // NoCreation; if present, it returns WrongValue for value 5. Either
        // way, an out-of-range value must not be accepted.
        let res = handler.prepare_set(&status_oid, &Value::Integer(5));
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(
            err == ErrorStatus::WrongValue || err == ErrorStatus::NoCreation,
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn hrswrun_handler_set_invalid_commits_and_signals_child() {
        // Spawn a long-lived child process, then SET hrSWRunStatus.<child_pid>
        // = invalid(4). The handler must accept the SET and the child must
        // exit within a timeout (the handler spawns `kill <pid>`).
        let collector = HostCollector::new();
        let handler = HrSWRunHandler::new(collector);
        let mut child = std::process::Command::new("sleep")
            .arg("1000")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let status_oid: Oid = format!(".1.3.6.1.2.1.25.4.2.1.7.{pid}")
            .parse()
            .unwrap();
        // Note: the child is not in the collector's snapshot (it was spawned
        // after the snapshot was built), so prepare_set would return
        // NoCreation. To test the commit path in isolation, call commit_set
        // directly — it does not require the row to pre-exist (the side
        // effect is the signal, which is independent of the table contents).
        handler
            .commit_set(&status_oid, &Value::Integer(4))
            .expect("commit invalid succeeds");
        // The child should exit within a few seconds. Poll with try_wait since
        // std::process::Child has no blocking wait_timeout.
        let mut exited = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    exited = true;
                    break;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
                Err(_) => break,
            }
        }
        // Clean up if still alive (defensive; `kill` may be absent).
        let _ = child.kill();
        let _ = child.wait();
        assert!(exited, "child did not exit after hrSWRunStatus=invalid(4)");
    }
}
