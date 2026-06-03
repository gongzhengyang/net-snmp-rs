//! Conceptual-table fetching and tabular display helpers.
//!
//! Shared by the table-oriented tools (`snmptable`, `snmpdf`, `snmpps`,
//! `snmpnetstat`): they all walk a MIB table entry, group the returned cells by
//! row index, and render the result as an aligned grid. Counterpart of the
//! table-walking logic spread across `apps/snmptable.c`,
//! `apps/snmpnetstat/*` and the various `apps/snmp*.c` helpers in C.

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools;
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::Client;

/// Return the index portion of `oid` relative to `prefix` (the sub-identifiers
/// that follow `prefix`), or `None` when `oid` is not under `prefix`.
pub fn index_suffix(prefix: &Oid, oid: &Oid) -> Option<Vec<u32>> {
    if !prefix.is_prefix_of(oid) {
        return None;
    }
    Some(oid.as_slice()[prefix.len()..].to_vec())
}

/// Build the full instance OID for a table cell: `entry.column.index...`.
pub fn cell_oid(entry: &Oid, column: u32, index: &[u32]) -> Oid {
    let mut parts = entry.as_slice().to_vec();
    parts.push(column);
    parts.extend_from_slice(index);
    Oid::new(parts)
}

/// Extract a value as a signed integer where that makes sense (Integer,
/// Counter32/64, Gauge32, TimeTicks). Used by tools that compute totals and
/// deltas (`snmpdf`, `snmpdelta`).
pub fn value_as_i128(value: &Value) -> Option<i128> {
    match value {
        Value::Integer(v) => Some(*v as i128),
        Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(*v as i128),
        Value::Counter64(v) => Some(*v as i128),
        _ => None,
    }
}

/// A conceptual table fetched from an agent: the distinct columns observed and
/// the rows keyed by their (raw) index sub-identifiers.
#[derive(Debug, Clone)]
pub struct TableData {
    /// The table entry OID the cells hang off of (e.g. `ifEntry`).
    pub entry: Oid,
    /// Distinct column sub-identifiers, ascending.
    pub columns: Vec<u32>,
    /// Rows keyed by index, each mapping column → value. Both maps are ordered,
    /// so iteration is deterministic.
    pub rows: BTreeMap<Vec<u32>, BTreeMap<u32, Value>>,
}

impl TableData {
    /// `true` when no cells were returned.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Walk the table rooted at `entry` (its `*Entry` OID) and assemble the cells
/// into a [`TableData`]. Uses GETBULK when available.
pub async fn fetch_table(
    client: &mut Client,
    entry: &Oid,
    max_repetitions: u32,
) -> netsnmp::Result<TableData> {
    let vars = client.bulk_walk(entry, max_repetitions).await?;
    let mut columns: BTreeSet<u32> = BTreeSet::new();
    let mut rows: BTreeMap<Vec<u32>, BTreeMap<u32, Value>> = BTreeMap::new();
    for vb in vars {
        let Some(suffix) = index_suffix(entry, &vb.oid) else {
            continue;
        };
        // suffix = column followed by the row index.
        let Some((&column, index)) = suffix.split_first() else {
            continue;
        };
        columns.insert(column);
        rows.entry(index.to_vec())
            .or_default()
            .insert(column, vb.value);
    }
    Ok(TableData {
        entry: entry.clone(),
        columns: columns.into_iter().collect(),
        rows,
    })
}

/// Human-readable label for a table column: the symbolic leaf name when the MIB
/// knows it (e.g. `ifDescr`), otherwise the numeric sub-identifier.
pub fn column_label(mib: &MibRegistry, entry: &Oid, column: u32) -> String {
    let object = entry.child(column);
    let formatted = mib.format_oid(&object);
    // format_oid yields forms like "IF-MIB::ifDescr" or a numeric ".1.3...".
    let leaf = formatted
        .rsplit("::")
        .next()
        .unwrap_or(&formatted)
        .trim_start_matches('.');
    if leaf.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        // Drop any trailing instance the formatter may have appended.
        leaf.split('.').next().unwrap_or(leaf).to_string()
    } else {
        column.to_string()
    }
}

/// Render a row index as a dotted string (e.g. `[1, 2]` → `1.2`).
pub fn index_label(index: &[u32]) -> String {
    index.iter().format(".").to_string()
}

/// Format a single cell value for display, using MIB type information for the
/// reconstructed instance OID.
pub fn cell_display(
    mib: &MibRegistry,
    entry: &Oid,
    column: u32,
    index: &[u32],
    value: &Value,
) -> String {
    let oid = cell_oid(entry, column, index);
    mib.format_value(&oid, value)
}

/// Lay out a grid (header + rows) as left-aligned, space-padded columns and
/// return it as individual lines. Pure string formatting, kept here so the
/// tools share one renderer.
pub fn render_grid(header: &[String], rows: &[Vec<String>]) -> Vec<String> {
    let cols = header.len();
    let mut widths: Vec<usize> = header.iter().map(String::len).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let format_row = |cells: &[String]| -> String {
        let mut line = String::new();
        for (i, &width) in widths.iter().enumerate().take(cols) {
            let cell = cells.get(i).map(String::as_str).unwrap_or("");
            if i + 1 == cols {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}  "));
            }
        }
        line.trim_end().to_string()
    };
    let mut out = Vec::with_capacity(rows.len() + 1);
    out.push(format_row(header));
    for row in rows {
        out.push(format_row(row));
    }
    out
}
