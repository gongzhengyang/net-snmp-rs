//! NET-SNMP-EXTEND-MIB (`1.3.6.1.4.1.8072.1.3.2`): the `extend` directive.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/agent/extend.c`. An `extend NAME
//! CMD ARGS...` directive runs a command on demand and exposes its stdout (line
//! 1, full output, line count) and exit code, indexed by the extend name as a
//! string OID index.
//!
//! This module reuses the [`ExecRegistry`] that backs
//! the legacy `extTable`: an entry added to that registry is visible under both
//! the `extTable` (numeric index) and the `nsExtendOutput1Table` (string
//! index). That mirrors Net-SNMP, where `extend` is the modern replacement for
//! `exec`.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use super::ucd::{ExecEntry, ExecRegistry};
use crate::scalar::FnHandler;

/// NET-SNMP enterprise root: `1.3.6.1.4.1.8072`.
const NETSNMP: [u32; 7] = [1, 3, 6, 1, 4, 1, 8072];

/// `nsExtendOutput1Table` root (`1.3.6.1.4.1.8072.1.3.2.3.1`).
const NS_EXTEND_OUTPUT1: [u32; 12] = [1, 3, 6, 1, 4, 1, 8072, 1, 3, 2, 3, 1];

/// `nsExtendCommand` column number under the output1 table.
const COL_COMMAND: u32 = 1;
/// `nsExtendResult` (exit code) column number.
const COL_RESULT: u32 = 2;
/// `nsExtendOutput1Line` (stdout line 1) column number.
const COL_OUTPUT1LINE: u32 = 3;
/// `nsExtendOutputFull` (full stdout) column number.
const COL_OUTPUT_FULL: u32 = 4;
/// `nsExtendOutNumLines` (number of stdout lines) column number.
const COL_NUM_LINES: u32 = 5;

/// Encode a string as an SNMP string OID index (each byte -> one sub-id).
fn string_index(name: &str) -> Vec<u32> {
    name.bytes().map(|b| b as u32).collect()
}

/// Run an entry once and produce the `(column, value)` pairs for its single
/// row. The command is executed exactly once per read; the exit code, first
/// stdout line, full stdout and line count are all derived from that single
/// invocation.
fn extend_row(e: &ExecEntry) -> Vec<(u32, Value)> {
    let (code, full) = run_full(&e);
    let first_line = full.lines().next().unwrap_or("").to_string();
    let num_lines = full.lines().count() as i64;
    vec![
        (COL_COMMAND, Value::OctetString(command_string(e).into_bytes())),
        (COL_RESULT, Value::Integer(code)),
        (COL_OUTPUT1LINE, Value::OctetString(first_line.into_bytes())),
        (COL_OUTPUT_FULL, Value::OctetString(full.into_bytes())),
        (COL_NUM_LINES, Value::Integer(num_lines)),
    ]
}

/// Reconstruct the `CMD ARGS...` display string for `nsExtendCommand`.
fn command_string(e: &ExecEntry) -> String {
    if e.args.is_empty() {
        e.command.clone()
    } else {
        format!("{} {}", e.command, e.args.join(" "))
    }
}

/// Run an entry and return `(exit_code, full_stdout)`. Reused rather than
/// calling [`ExecEntry::run`] so the full body is captured once.
fn run_full(e: &ExecEntry) -> (i64, String) {
    let out = std::process::Command::new(&e.command)
        .args(&e.args)
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) => {
            let code = o.status.code().unwrap_or(127) as i64;
            let body = String::from_utf8_lossy(&o.stdout).trim_end().to_string();
            (code, body)
        }
        Err(_) => (127, String::new()),
    }
}

/// Build the `nsExtendOutput1Table` cells for every entry in `reg`. Each entry
/// occupies a row indexed by its name (as a string OID index).
fn extend_cells(reg: &ExecRegistry) -> Vec<(Oid, Value)> {
    let root = Oid::new(NS_EXTEND_OUTPUT1.to_vec());
    let mut cells = Vec::new();
    for e in reg.entries() {
        let idx = string_index(&e.name);
        for (col, value) in extend_row(&e) {
            // instance OID = root.column.<string index>
            let mut oid_parts = root.as_slice().to_vec();
            oid_parts.push(col);
            oid_parts.extend_from_slice(&idx);
            cells.push((Oid::new(oid_parts), value));
        }
    }
    cells
}

/// Build a [`FnHandler`] rooted at the NET-SNMP-EXTEND-MIB `nsExtendOutput1`
/// subtree, backed by `reg`. Entries added to `reg` after registration are
/// reflected on the next read (the handler rebuilds its snapshot per request).
pub fn extend_handler(reg: Arc<ExecRegistry>) -> Arc<FnHandler> {
    let root = Oid::new(NS_EXTEND_OUTPUT1.to_vec());
    Arc::new(FnHandler::new(root, move || extend_cells(&reg)))
}

/// Root OID advertised by [`extend_handler`] (the `nsExtendOutput1Entry`).
pub fn extend_root() -> Oid {
    Oid::new(NS_EXTEND_OUTPUT1.to_vec())
}

/// The NET-SNMP enterprise root (`1.3.6.1.4.1.8072`). Exposed for handlers
/// that wish to register sibling subtrees.
pub fn netsnmp_root() -> Oid {
    Oid::new(NETSNMP.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MibHandler;

    #[test]
    fn extend_exposes_echo_output() {
        let reg = ExecRegistry::new();
        reg.add("pingcheck", "echo", vec!["hello".to_string()]);
        let cells = extend_cells(&reg);
        // The output1line cell for the "pingcheck" string index.
        let mut idx = NS_EXTEND_OUTPUT1.to_vec();
        idx.push(COL_OUTPUT1LINE);
        idx.extend(string_index("pingcheck"));
        let target = Oid::new(idx).to_string();
        let line = cells
            .iter()
            .find(|(o, _)| o.to_string() == target)
            .map(|(_, v)| v.clone());
        assert_eq!(
            line,
            Some(Value::OctetString(b"hello".to_vec())),
            "nsExtendOutput1Line for pingcheck"
        );
        // Result (exit code) is 0.
        let mut idx = NS_EXTEND_OUTPUT1.to_vec();
        idx.push(COL_RESULT);
        idx.extend(string_index("pingcheck"));
        let target = Oid::new(idx).to_string();
        let result = cells
            .iter()
            .find(|(o, _)| o.to_string() == target)
            .map(|(_, v)| v.clone());
        assert_eq!(result, Some(Value::Integer(0)));
    }

    #[test]
    fn extend_handler_get_returns_value() {
        let reg = ExecRegistry::new();
        reg.add("greet", "echo", vec!["hi".to_string()]);
        let h = extend_handler(reg);
        let mut oid_parts = NS_EXTEND_OUTPUT1.to_vec();
        oid_parts.push(COL_OUTPUT1LINE);
        oid_parts.extend(string_index("greet"));
        let oid = Oid::new(oid_parts);
        assert_eq!(
            h.get(&oid),
            Some(Value::OctetString(b"hi".to_vec()))
        );
    }

    #[test]
    fn extend_num_lines_counts_stdout() {
        // printf is widely available; emit two lines.
        let reg = ExecRegistry::new();
        reg.add("two", "sh", vec![
            "-c".to_string(),
            "printf 'a\\nb\\n'".to_string(),
        ]);
        let cells = extend_cells(&reg);
        let mut idx = NS_EXTEND_OUTPUT1.to_vec();
        idx.push(COL_NUM_LINES);
        idx.extend(string_index("two"));
        let target = Oid::new(idx).to_string();
        let n = cells
            .iter()
            .find(|(o, _)| o.to_string() == target)
            .map(|(_, v)| v.clone());
        assert_eq!(n, Some(Value::Integer(2)));
    }
}
