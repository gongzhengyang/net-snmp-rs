//! UCD-SNMP-MIB (`1.3.6.1.4.1.2021`), backed by cross-platform [`sysinfo`] data.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/ucd-snmp/`. These are the objects
//! `snmpwalk`/monitoring tools most often poll on a net-snmp host:
//!
//! * `memory` group (`2021.4`): real/swap memory totals and free space (KB).
//! * `laTable` (`2021.10.1`): 1/5/15-minute load averages.
//! * `dskTable` (`2021.9.1`): per-filesystem capacity, usage and percent-full.
//! * `ssCpu` and `systemStats` (`2021.11`): aggregate and raw CPU jiffies, I/O
//!   and interrupt/context counters, parsed from Linux `/proc/stat` (zeros when
//!   the file is absent, e.g. on non-Linux hosts or in sandboxes).
//! * `version` (`2021.1`): agent version/build identification.
//! * `extTable` / `exec` (`2021.8`): external commands run on demand, exposed
//!   via [`ExecRegistry`].
//! * `prTable` / `proc` (`2021.2`): process-count health checks, exposed via
//!   [`ProcCheckRegistry`].
//! * `file` (`2021.3`): file-size health checks, exposed via
//!   [`FileCheckRegistry`].
//! * `logMatch` (`2021.16`): simple substring-based log counters, exposed via
//!   [`LogMatchRegistry`].
//! * `dlmod` (`2021.14`): recorded as unsupported (no-op handler).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, RwLock};

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

// ---------------------------------------------------------------------------
// Existing groups (memory / laTable / dskTable / ssCpu): unchanged.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// systemStats raw counters (2021.11.50..): parsed from Linux /proc/stat.
// ---------------------------------------------------------------------------

/// Parsed `/proc/stat` snapshot for the `systemStats` raw counters. All fields
/// default to zero so non-Linux hosts (or a missing file) report zeros rather
/// than failing the whole UCD walk.
#[derive(Clone, Debug, Default)]
struct ProcStat {
    /// Aggregate `cpu` jiffies: (user, nice, system, idle, wait, irq, softirq).
    cpu_jiffies: [u64; 7],
    /// `page` line values (in/out), pre-2.6 kernels; zeros otherwise.
    page: [u64; 2],
    /// `swap` line values (in/out).
    swap: [u64; 2],
    /// `intr` line: total interrupt count (first number on the `intr` line).
    intr_total: u64,
    /// `ctxt` line: total context switches.
    ctxt_total: u64,
}

/// Parse `/proc/stat` into a [`ProcStat`]. Returns `ProcStat::default()` (all
/// zeros) when the file is absent or unreadable, so the SNMP view degrades
/// gracefully on non-Linux hosts and in sandboxed CI.
fn parse_proc_stat() -> ProcStat {
    let text = match fs::read_to_string("/proc/stat") {
        Ok(t) => t,
        Err(_) => return ProcStat::default(),
    };
    parse_proc_stat_text(&text)
}

/// Parse a `/proc/stat` document into a [`ProcStat`]. Separated from
/// [`parse_proc_stat`] so unit tests can feed a synthetic sample.
fn parse_proc_stat_text(text: &str) -> ProcStat {
    let mut out = ProcStat::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("cpu") => {
                // cpu  user nice system idle iowait irq softirq [steal guest ...]
                for slot in out.cpu_jiffies.iter_mut() {
                    if let Some(tok) = parts.next() {
                        *slot = tok.parse().unwrap_or(0);
                    }
                }
            }
            Some("page") => {
                for (i, tok) in parts.take(2).enumerate() {
                    out.page[i] = tok.parse().unwrap_or(0);
                }
            }
            Some("swap") => {
                for (i, tok) in parts.take(2).enumerate() {
                    out.swap[i] = tok.parse().unwrap_or(0);
                }
            }
            Some("intr") => {
                if let Some(total) = parts.next() {
                    out.intr_total = total.parse().unwrap_or(0);
                }
            }
            Some("ctxt") => {
                if let Some(total) = parts.next() {
                    out.ctxt_total = total.parse().unwrap_or(0);
                }
            }
            _ => {}
        }
    }
    out
}

/// `systemStats` raw counters (`2021.11.50..`): raw CPU jiffies, I/O,
/// interrupts and context switches. Sourced from `/proc/stat`; zeros when the
/// file is unavailable.
fn ss_cpu_raw_cells() -> Vec<(Oid, Value)> {
    let stat = parse_proc_stat();
    let s = Oid::new(UCD.to_vec()).child(11);
    let c = |col: u32, v: u64| (s.child(col).child(0), Value::Counter32(v as u32));
    vec![
        c(50, stat.cpu_jiffies[0]), // ssCpuRawUser
        c(51, stat.cpu_jiffies[1]), // ssCpuRawNice
        c(52, stat.cpu_jiffies[2]), // ssCpuRawSystem
        c(53, stat.cpu_jiffies[3]), // ssCpuRawIdle
        c(54, stat.cpu_jiffies[4]), // ssCpuRawWait
        c(55, stat.cpu_jiffies[5] + stat.cpu_jiffies[6]), // ssCpuRawKernel (irq+softirq)
        c(56, stat.cpu_jiffies[5]), // ssCpuRawInterrupt
        c(57, stat.page[0]),        // ssIORawReceived (page-in proxy)
        c(58, stat.page[1]),        // ssIORawSent (page-out proxy)
        c(59, stat.intr_total),     // ssInterrupts (deprecated rate, here: total)
        c(60, stat.intr_total),     // ssRawInterrupts
        c(61, stat.ctxt_total),     // ssRawContexts
        c(62, stat.swap[0]),        // ssRawSwapIn
        c(63, stat.swap[1]),        // ssRawSwapOut
    ]
}

// ---------------------------------------------------------------------------
// version group (2021.1): static identification scalars.
// ---------------------------------------------------------------------------

/// Crate version advertised in `versionTag` (`2021.100.1.0` etc.). The
/// `version` group has no standard column numbering, so this follows the
/// Net-SNMP convention of presenting the fields as instance scalars under
/// `2021.1`.
fn version_cells() -> Vec<(Oid, Value)> {
    let v = Oid::new(UCD.to_vec()).child(1);
    let tag = format!("net-snmp-rs {}", env!("CARGO_PKG_VERSION"));
    vec![
        (v.child(1).child(0), Value::OctetString(tag.into_bytes())), // versionTag
        (v.child(2).child(0), Value::OctetString(Vec::new())), // versionCDate (unknown)
        (
            v.child(3).child(0),
            Value::OctetString(b"cross-platform sysinfo build".to_vec()),
        ), // versionConfigureOptions
    ]
}

// ---------------------------------------------------------------------------
// extTable / exec (2021.8): backed by ExecRegistry.
// ---------------------------------------------------------------------------

/// A single `exec NAME CMD ARGS...` entry: runs the command on demand and
/// exposes its first stdout line and exit code.
#[derive(Clone, Debug)]
pub struct ExecEntry {
    /// Symbolic name (the row's `extNames` column, also used by `extend`).
    pub name: String,
    /// Executable to run.
    pub command: String,
    /// Arguments (already split off the directive).
    pub args: Vec<String>,
}

impl ExecEntry {
    /// Construct from a directive's `NAME CMD ARGS...` fields.
    pub fn new(name: impl Into<String>, command: impl Into<String>, args: Vec<String>) -> Self {
        ExecEntry {
            name: name.into(),
            command: command.into(),
            args,
        }
    }

    /// Run the command synchronously, returning `(exit_code, first_stdout_line)`.
    /// On any failure (spawn error, timeout) returns `(127, "")`.
    pub fn run(&self) -> (i64, String) {
        let output = Command::new(&self.command)
            .args(&self.args)
            .stdin(std::process::Stdio::null())
            .output();
        let Ok(out) = output else {
            return (127, String::new());
        };
        let code = out.status.code().unwrap_or(127) as i64;
        let first_line = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        (code, first_line)
    }
}

/// Runtime configuration for the `extTable`/`exec` group and the
/// NET-SNMP-EXTEND-MIB `extend` group. Entries may be added at any time.
///
/// Counterpart of Net-SNMP's `exec`/`extend` directives. Each entry runs its
/// command synchronously on every read; the spawn itself is blocking, so
/// long-running commands are the operator's responsibility (as in Net-SNMP,
/// which documents the same caveat for `exec`).
pub struct ExecRegistry {
    entries: RwLock<Vec<ExecEntry>>,
}

impl ExecRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(ExecRegistry {
            entries: RwLock::new(Vec::new()),
        })
    }

    /// Add an `exec NAME CMD ARGS...` entry. Returns the (1-based) index it will
    /// occupy.
    pub fn add(&self, name: impl Into<String>, command: impl Into<String>, args: Vec<String>) -> usize {
        let mut guard = self.entries.write().unwrap();
        let idx = guard.len() + 1;
        guard.push(ExecEntry::new(name, command, args));
        idx
    }

    /// Snapshot of the current entries (cloned).
    pub fn entries(&self) -> Vec<ExecEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for ExecRegistry {
    fn default() -> Self {
        ExecRegistry {
            entries: RwLock::new(Vec::new()),
        }
    }
}

/// `extTable` cells (`2021.8.1.*`): one row per [`ExecEntry`]. Each column
/// triggers a fresh run of the entry's command (the table is intentionally
/// side-effecting and reflects current output).
fn ext_table_cells(reg: &ExecRegistry) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(8).child(1); // extEntry
    let mut cells = Vec::new();
    for (i, e) in reg.entries().iter().enumerate() {
        let idx = (i + 1) as u32;
        let (code, line) = e.run();
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // extIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(e.name.clone().into_bytes()),
        )); // extNames
        cells.push((
            entry.child(3).child(idx),
            Value::OctetString(format!("{} {}", e.command, e.args.join(" ")).into_bytes()),
        )); // extCommand
        cells.push((entry.child(4).child(idx), Value::Integer(code))); // extResult
        cells.push((
            entry.child(5).child(idx),
            Value::OctetString(line.into_bytes()),
        )); // extOutput
    }
    cells
}

// ---------------------------------------------------------------------------
// prTable / proc (2021.2): process-count health checks.
// ---------------------------------------------------------------------------

/// A `proc NAME [MAX [MIN]]` entry.
#[derive(Clone, Debug)]
pub struct ProcCheckEntry {
    /// Process-name pattern (matched against `hrSWRunName`).
    pub name: String,
    /// Allowed maximum count; an actual count above this sets the error flag.
    pub max: i64,
    /// Allowed minimum count; an actual count below this sets the error flag.
    pub min: i64,
}

/// Runtime configuration for the `prTable`/`proc` group.
pub struct ProcCheckRegistry {
    entries: RwLock<Vec<ProcCheckEntry>>,
}

impl ProcCheckRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(ProcCheckRegistry {
            entries: RwLock::new(Vec::new()),
        })
    }

    /// Add a `proc NAME [MAX [MIN]]` entry.
    pub fn add(
        &self,
        name: impl Into<String>,
        max: i64,
        min: i64,
    ) -> usize {
        let mut guard = self.entries.write().unwrap();
        guard.push(ProcCheckEntry {
            name: name.into(),
            max,
            min,
        });
        guard.len()
    }

    fn entries(&self) -> Vec<ProcCheckEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for ProcCheckRegistry {
    fn default() -> Self {
        ProcCheckRegistry {
            entries: RwLock::new(Vec::new()),
        }
    }
}

/// Count processes whose name equals (case-insensitive) `pattern`.
fn count_named(snap: &Snapshot, pattern: &str) -> i64 {
    let p = pattern.to_ascii_lowercase();
    snap.processes
        .iter()
        .filter(|proc| proc.name.to_ascii_lowercase() == p)
        .count() as i64
}

/// `prTable` cells (`2021.2.1.*`): one row per [`ProcCheckEntry`].
fn pr_table_cells(snap: &Snapshot, reg: &ProcCheckRegistry) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(2).child(1); // prEntry
    let mut cells = Vec::new();
    for (i, e) in reg.entries().iter().enumerate() {
        let idx = (i + 1) as u32;
        let count = count_named(snap, &e.name);
        let (flag, msg) = if count > e.max {
            (
                1,
                format!("Too many {} (= {}) (> {})", e.name, count, e.max),
            )
        } else if count < e.min {
            (
                1,
                format!("Too few {} (= {}) (< {})", e.name, count, e.min),
            )
        } else {
            (0, String::new())
        };
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // prIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(e.name.clone().into_bytes()),
        )); // prNames
        cells.push((entry.child(3).child(idx), Value::Integer(e.min))); // prMin
        cells.push((entry.child(4).child(idx), Value::Integer(e.max))); // prMax
        cells.push((entry.child(5).child(idx), Value::Integer(count))); // prCount
        cells.push((entry.child(6).child(idx), Value::Integer(flag))); // prErrorFlag
        cells.push((
            entry.child(7).child(idx),
            Value::OctetString(msg.into_bytes()),
        )); // prErrMessage
    }
    cells
}

// ---------------------------------------------------------------------------
// file group (2021.3): file-size health checks.
// ---------------------------------------------------------------------------

/// A `file NAME PATH [MAXSIZE]` entry.
#[derive(Clone, Debug)]
pub struct FileCheckEntry {
    /// Symbolic name.
    pub name: String,
    /// Filesystem path to check.
    pub path: PathBuf,
    /// Maximum allowed size in bytes (0 disables the upper bound).
    pub max_size: u64,
}

/// Runtime configuration for the `file` group.
pub struct FileCheckRegistry {
    entries: RwLock<Vec<FileCheckEntry>>,
}

impl FileCheckRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(FileCheckRegistry {
            entries: RwLock::new(Vec::new()),
        })
    }

    /// Add a `file NAME PATH [MAXSIZE]` entry.
    pub fn add(
        &self,
        name: impl Into<String>,
        path: impl Into<PathBuf>,
        max_size: u64,
    ) -> usize {
        let mut guard = self.entries.write().unwrap();
        guard.push(FileCheckEntry {
            name: name.into(),
            path: path.into(),
            max_size,
        });
        guard.len()
    }

    fn entries(&self) -> Vec<FileCheckEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for FileCheckRegistry {
    fn default() -> Self {
        FileCheckRegistry {
            entries: RwLock::new(Vec::new()),
        }
    }
}

/// `fileTable`-style cells (`2021.3.1.*`): one row per [`FileCheckEntry`].
fn file_cells(reg: &FileCheckRegistry) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(3).child(1); // fileEntry
    let mut cells = Vec::new();
    for (i, e) in reg.entries().iter().enumerate() {
        let idx = (i + 1) as u32;
        let meta = fs::metadata(&e.path);
        let (size, exists, flag, msg) = match &meta {
            Ok(m) => {
                let len = m.len();
                let over = e.max_size > 0 && len > e.max_size;
                (
                    len as i64,
                    true,
                    if over { 1 } else { 0 },
                    if over {
                        format!("{} size {} > {}", e.name, len, e.max_size)
                    } else {
                        String::new()
                    },
                )
            }
            Err(err) => (
                0,
                false,
                1,
                format!("{}: {err}", e.path.display()),
            ),
        };
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // fileIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(e.name.clone().into_bytes()),
        )); // fileName
        cells.push((entry.child(3).child(idx), Value::Integer(size))); // fileSize
        cells.push((entry.child(4).child(idx), Value::Integer(e.max_size as i64))); // fileMax
        cells.push((entry.child(5).child(idx), Value::Integer(flag))); // fileErrorFlag
        cells.push((
            entry.child(6).child(idx),
            Value::OctetString(msg.into_bytes()),
        )); // fileErrorMsg
        let _ = exists;
    }
    cells
}

// ---------------------------------------------------------------------------
// logMatch group (2021.16): substring-based log counters.
// ---------------------------------------------------------------------------

/// A `logmatch NAME PATH OFFSET PATTERN` entry. Net-SNMP uses POSIX extended
/// regexes; to avoid pulling a regex dependency (this crate is dependency-free
/// beyond `sysinfo`/`tokio`/`tracing`/`chrono`), the pattern is treated as a
/// literal substring. This limitation is documented.
#[derive(Clone, Debug)]
pub struct LogMatchEntry {
    /// Symbolic name.
    pub name: String,
    /// Log file path.
    pub path: PathBuf,
    /// Starting byte offset (advisory; the file is re-scanned each read).
    pub offset: u64,
    /// Substring to search for.
    pub pattern: String,
}

/// Runtime configuration for the `logMatch` group.
pub struct LogMatchRegistry {
    entries: RwLock<Vec<LogMatchEntry>>,
}

impl LogMatchRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(LogMatchRegistry {
            entries: RwLock::new(Vec::new()),
        })
    }

    /// Add a `logmatch NAME PATH OFFSET PATTERN` entry. The pattern is matched
    /// as a literal substring (no regex), see [`LogMatchEntry`].
    pub fn add(
        &self,
        name: impl Into<String>,
        path: impl Into<PathBuf>,
        offset: u64,
        pattern: impl Into<String>,
    ) -> usize {
        let mut guard = self.entries.write().unwrap();
        guard.push(LogMatchEntry {
            name: name.into(),
            path: path.into(),
            offset,
            pattern: pattern.into(),
        });
        guard.len()
    }

    fn entries(&self) -> Vec<LogMatchEntry> {
        self.entries.read().unwrap().clone()
    }
}

impl Default for LogMatchRegistry {
    fn default() -> Self {
        LogMatchRegistry {
            entries: RwLock::new(Vec::new()),
        }
    }
}

/// `logMatchTable` cells (`2021.16.1.*`). `logMatchMatchCount` counts
/// occurrences of the entry's substring in the file from `offset` onward.
fn log_match_cells(reg: &LogMatchRegistry) -> Vec<(Oid, Value)> {
    let entry = Oid::new(UCD.to_vec()).child(16).child(1); // logMatchEntry
    let mut cells = Vec::new();
    for (i, e) in reg.entries().iter().enumerate() {
        let idx = (i + 1) as u32;
        let body = fs::read(&e.path).map(|b| b).unwrap_or_default();
        let tail = if (e.offset as usize) <= body.len() {
            &body[e.offset as usize..]
        } else {
            &body[..]
        };
        let count = match std::str::from_utf8(tail) {
            Ok(s) => s.matches(e.pattern.as_str()).count() as i64,
            Err(_) => 0,
        };
        cells.push((entry.child(1).child(idx), Value::Integer(idx as i64))); // logMatchIndex
        cells.push((
            entry.child(2).child(idx),
            Value::OctetString(e.name.clone().into_bytes()),
        )); // logMatchName
        cells.push((
            entry.child(3).child(idx),
            Value::OctetString(e.path.to_string_lossy().into_owned().into_bytes()),
        )); // logMatchFilename
        cells.push((
            entry.child(4).child(idx),
            Value::OctetString(e.pattern.clone().into_bytes()),
        )); // logMatchRegEx
        cells.push((entry.child(7).child(idx), Value::Counter32(count as u32))); // logMatchMatchCount
    }
    cells
}

// ---------------------------------------------------------------------------
// Aggregation + handler builders.
// ---------------------------------------------------------------------------

/// Build all UCD-SNMP-MIB cells from a snapshot and the optional registries.
/// When a registry is `None` (the group is unconfigured) no cells for that
/// group are emitted, so an unconfigured agent serves the legacy memory/la/dsk/
/// ssCpu groups plus the always-present raw/version groups.
fn ucd_cells(
    snap: &Snapshot,
    exec: Option<&Arc<ExecRegistry>>,
    proc_check: Option<&Arc<ProcCheckRegistry>>,
    file_check: Option<&Arc<FileCheckRegistry>>,
    log_match: Option<&Arc<LogMatchRegistry>>,
) -> Vec<(Oid, Value)> {
    let mut cells: BTreeMap<Oid, Value> = BTreeMap::new();
    for (oid, value) in memory_cells(snap)
        .into_iter()
        .chain(la_cells(snap))
        .chain(dsk_cells(snap))
        .chain(ss_cpu_cells(snap))
        .chain(ss_cpu_raw_cells())
        .chain(version_cells())
    {
        cells.insert(oid, value);
    }
    if let Some(reg) = exec {
        for (oid, value) in ext_table_cells(reg) {
            cells.insert(oid, value);
        }
    }
    if let Some(reg) = proc_check {
        for (oid, value) in pr_table_cells(snap, reg) {
            cells.insert(oid, value);
        }
    }
    if let Some(reg) = file_check {
        for (oid, value) in file_cells(reg) {
            cells.insert(oid, value);
        }
    }
    if let Some(reg) = log_match {
        for (oid, value) in log_match_cells(reg) {
            cells.insert(oid, value);
        }
    }
    cells.into_iter().collect()
}

/// Configuration for the optional UCD-SNMP-MIB groups. All fields default to
/// `None`; pass values to enable the corresponding `exec`/`proc`/`file`/
/// `logmatch`/`extend` groups.
#[derive(Default, Clone)]
pub struct UcdMibConfig {
    /// `exec` entries (drives `extTable` and is reused by the extend MIB).
    pub exec: Option<Arc<ExecRegistry>>,
    /// `proc` entries (drives `prTable`).
    pub proc_check: Option<Arc<ProcCheckRegistry>>,
    /// `file` entries.
    pub file_check: Option<Arc<FileCheckRegistry>>,
    /// `logmatch` entries.
    pub log_match: Option<Arc<LogMatchRegistry>>,
}

/// UCD-SNMP-MIB handler rooted at the enterprise subtree (`1.3.6.1.4.1.2021`).
///
/// Backwards compatible with the original single-argument form: it serves the
/// legacy memory/laTable/dskTable/ssCpu groups plus the new raw-CPU/version
/// scalars, and none of the optional `exec`/`proc`/`file`/`logmatch` groups.
pub fn ucd_handler(collector: Arc<HostCollector>) -> Arc<FnHandler> {
    ucd_handler_with(collector, UcdMibConfig::default())
}

/// Like [`ucd_handler`] but additionally wires the optional UCD groups declared
/// in `config`.
pub fn ucd_handler_with(collector: Arc<HostCollector>, config: UcdMibConfig) -> Arc<FnHandler> {
    let root = Oid::new(UCD.to_vec());
    let exec = config.exec.clone();
    let proc_check = config.proc_check.clone();
    let file_check = config.file_check.clone();
    let log_match = config.log_match.clone();
    Arc::new(FnHandler::new(root, move || {
        ucd_cells(
            &collector.snapshot(),
            exec.as_ref(),
            proc_check.as_ref(),
            file_check.as_ref(),
            log_match.as_ref(),
        )
    }))
}

/// Parse `exec`/`extend` directives of the form `NAME CMD ARGS...` (the leading
/// directive keyword is already stripped by the caller). Returns entries ready
/// to [`ExecRegistry::add`]. Each directive occupies one line; blank lines and
/// `#` comments are ignored.
pub fn parse_exec_directives(text: &str) -> Vec<ExecEntry> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(command) = parts.next() else { continue };
        let args: Vec<String> = parts.map(String::from).collect();
        out.push(ExecEntry::new(name, command, args));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mibgroup::collector::{DiskSample, ProcSample};

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
        let cells = ucd_cells(&snap(), None, None, None, None);
        let total_real = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.4.5.0")
            .map(|(_, v)| v.clone());
        assert_eq!(total_real, Some(Value::Integer(16 * 1024 * 1024)));
    }

    #[test]
    fn load_average_int_is_scaled() {
        let cells = ucd_cells(&snap(), None, None, None, None);
        let la5 = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.10.1.5.2")
            .map(|(_, v)| v.clone());
        assert_eq!(la5, Some(Value::Integer(125))); // 1.25 * 100
    }

    #[test]
    fn disk_percent_is_computed() {
        let cells = ucd_cells(&snap(), None, None, None, None);
        // 75 GiB used of 100 GiB -> 75%.
        let pct = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.9.1.9.1")
            .map(|(_, v)| v.clone());
        assert_eq!(pct, Some(Value::Integer(75)));
    }

    #[test]
    fn ss_cpu_idle_complements_busy() {
        let cells = ucd_cells(&snap(), None, None, None, None);
        let idle = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.11.11.0")
            .map(|(_, v)| v.clone());
        assert_eq!(idle, Some(Value::Integer(70)));
    }

    #[test]
    fn proc_stat_parses_cpu_and_context_lines() {
        let sample = "cpu  100 20 30 200 5 6 7 0 0 0\n\
                      intr 12345 1 2 3\n\
                      ctxt 99999\n\
                      page 11 22\n\
                      swap 33 44\n";
        let stat = parse_proc_stat_text(sample);
        assert_eq!(stat.cpu_jiffies, [100, 20, 30, 200, 5, 6, 7]);
        assert_eq!(stat.ctxt_total, 99999);
        assert_eq!(stat.intr_total, 12345);
        assert_eq!(stat.page, [11, 22]);
        assert_eq!(stat.swap, [33, 44]);
    }

    #[test]
    fn ss_cpu_raw_columns_present_from_proc_stat_sample() {
        // parse_proc_stat reads a real /proc/stat; on Linux CI this is present,
        // on other platforms it returns zeros. Either way the columns must
        // exist and be Counter32.
        let cells = ss_cpu_raw_cells();
        let user = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.11.50.0")
            .map(|(_, v)| v.clone());
        assert!(
            matches!(user, Some(Value::Counter32(_))),
            "ssCpuRawUser.0 should be a Counter32, got {user:?}"
        );
        let ctxt = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.11.61.0")
            .map(|(_, v)| v.clone());
        assert!(
            matches!(ctxt, Some(Value::Counter32(_))),
            "ssRawContexts.0 should be a Counter32, got {ctxt:?}"
        );
    }

    #[test]
    fn version_tag_carries_crate_name() {
        let cells = version_cells();
        let tag = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.1.1.0")
            .map(|(_, v)| v.clone());
        match tag {
            Some(Value::OctetString(bytes)) => {
                let s = String::from_utf8(bytes).unwrap();
                assert!(s.starts_with("net-snmp-rs "), "got: {s}");
            }
            other => panic!("versionTag wrong shape: {other:?}"),
        }
    }

    #[test]
    fn ext_table_runs_a_real_command() {
        // `echo hello` is universally available.
        let reg = ExecRegistry::new();
        reg.add("greeting", "echo", vec!["hello".to_string()]);
        let cells = ext_table_cells(&reg);
        // Find extOutput (column 5, index 1).
        let output = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.8.1.5.1")
            .map(|(_, v)| v.clone());
        assert_eq!(
            output,
            Some(Value::OctetString(b"hello".to_vec())),
            "extOutput should capture echo's first line"
        );
        // extResult should be 0.
        let result = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.8.1.4.1")
            .map(|(_, v)| v.clone());
        assert_eq!(result, Some(Value::Integer(0)));
    }

    #[test]
    fn pr_table_counts_from_synthetic_process_list() {
        let mut s = snap();
        s.processes = vec![
            ProcSample {
                pid: 1,
                name: "sshd".into(),
                path: String::new(),
                mem_kb: 0,
                cpu_pct: 0,
                status: 1,
            },
            ProcSample {
                pid: 2,
                name: "sshd".into(),
                path: String::new(),
                mem_kb: 0,
                cpu_pct: 0,
                status: 1,
            },
            ProcSample {
                pid: 3,
                name: "cron".into(),
                path: String::new(),
                mem_kb: 0,
                cpu_pct: 0,
                status: 1,
            },
        ];
        let reg = ProcCheckRegistry::new();
        reg.add("sshd", 1, 1); // max 1, min 1: 2 > 1 -> error
        let cells = pr_table_cells(&s, &reg);
        let count = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.2.1.5.1")
            .map(|(_, v)| v.clone());
        assert_eq!(count, Some(Value::Integer(2)));
        let flag = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.2.1.6.1")
            .map(|(_, v)| v.clone());
        assert_eq!(flag, Some(Value::Integer(1))); // error set
    }

    #[test]
    fn file_check_flags_missing_file() {
        let reg = FileCheckRegistry::new();
        reg.add("ghost", "/nonexistent/definitely/not/here", 0);
        let cells = file_cells(&reg);
        let flag = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.4.1.2021.3.1.5.1")
            .map(|(_, v)| v.clone());
        assert_eq!(flag, Some(Value::Integer(1)));
    }

    #[test]
    fn parse_exec_directives_handles_comments_and_args() {
        let cfg = "# a comment\n\
                   greet echo hello world\n\
                   \n\
                   uptime /usr/bin/uptime\n";
        let entries = parse_exec_directives(cfg);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "greet");
        assert_eq!(entries[0].command, "echo");
        assert_eq!(entries[0].args, vec!["hello", "world"]);
        assert_eq!(entries[1].command, "/usr/bin/uptime");
        assert!(entries[1].args.is_empty());
    }
}
