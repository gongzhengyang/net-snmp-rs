//! Generic in-memory table handler.
//!
//! Counterpart of `agent/helpers/table.c` + `table_data.c`. A [`TableHandler`]
//! serves a snapshot of rows produced by a closure. The snapshot is cached for
//! a short window (mirroring [`crate::scalar::FnHandler`]) so a full table walk
//! stays cheap.
//!
//! Instance OIDs follow the standard SNMP table layout: for a table rooted at
//! `R` with column numbers `c`, a cell is `R.c.<row index subids...>`. GETNEXT
//! walks cells in strict lexicographic (column-major) order, skipping any cell
//! a sparse row does not provide rather than emitting `noSuchInstance`.

use crate::handler::{MibHandler, Reading};
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The short window during which a built snapshot is reused across successive
/// GETNEXTs of a walk, so the table does not have to be rebuilt (and re-sorted)
/// on every step. Matches the [`crate::scalar::FnHandler`] cache.
const SNAPSHOT_TTL: Duration = Duration::from_millis(900);

/// A single row of a [`TableHandler`]: its index sub-identifiers and the cells
/// present, keyed by column number. Missing columns are simply absent.
#[derive(Clone, Debug, Default)]
pub struct Row {
    /// The row's index, as the trailing sub-identifiers of the instance OID
    /// (everything after the column number).
    pub index: Vec<u32>,
    /// The cells of this row, keyed by column number.
    pub cells: BTreeMap<u32, Value>,
}

impl Row {
    /// Create an empty row with the given index sub-identifiers.
    pub fn new(index: impl Into<Vec<u32>>) -> Self {
        Row {
            index: index.into(),
            cells: BTreeMap::new(),
        }
    }

    /// Builder: set the value of column `col` for this row.
    pub fn with(mut self, col: u32, value: Value) -> Self {
        self.cells.insert(col, value);
        self
    }
}

/// A snapshot of every cell in the table as `(oid, value)` pairs, sorted by
/// OID for O(log n) GET / GETNEXT. Built from a [`Row`] snapshot.
type CellSnapshot = Vec<(Oid, Value)>;

/// An in-memory SNMP table served from a closure that returns the current rows.
///
/// Columns are an explicit list so GETNEXT can emit a `noSuchInstance`-free
/// walk even when a row omits some columns (sparse rows). Equivalent to
/// registering a `table_dataset` in the C agent.
///
/// # Example
///
/// ```
/// use netsnmp_agent::helpers::{Row, TableHandler};
/// use netsnmp::value::Value;
/// use netsnmp_agent::MibHandler;
///
/// let root = "1.3.6.1.2.1.99".parse().unwrap();
/// let h = TableHandler::new(root, vec![1, 2], move || {
///     vec![
///         Row::new(vec![1])
///             .with(1, Value::Integer(100))
///             .with(2, Value::OctetString(b"alpha".to_vec())),
///         // Row 2 is sparse: column 2 is missing.
///         Row::new(vec![2]).with(1, Value::Integer(200)),
///     ]
/// });
/// // GET an exact cell.
/// let cell_oid = "1.3.6.1.2.1.99.1.1".parse().unwrap(); // root.col1.idx1
/// assert_eq!(h.get(&cell_oid), Some(Value::Integer(100)));
/// ```
pub struct TableHandler {
    root: Oid,
    columns: Vec<u32>,
    provider: Box<dyn Fn() -> Vec<Row> + Send + Sync>,
    cache: Mutex<Option<(Instant, CellSnapshot)>>,
}

impl TableHandler {
    /// Create a table handler rooted at `root` with the listed column numbers
    /// (the entry's column sub-identifiers, in MIB order). The `provider`
    /// closure returns the current rows on demand.
    pub fn new<F>(root: Oid, columns: Vec<u32>, provider: F) -> Self
    where
        F: Fn() -> Vec<Row> + Send + Sync + 'static,
    {
        TableHandler {
            root,
            columns,
            provider: Box::new(provider),
            cache: Mutex::new(None),
        }
    }

    /// The declared column numbers of this table (the entry sub-identifiers).
    /// Cells whose column is outside this list are still served if the
    /// provider emits them, but the list documents the table's MIB shape and
    /// is available to higher-level tooling.
    pub fn columns(&self) -> &[u32] {
        &self.columns
    }

    /// Build the flattened, OID-sorted snapshot of all present cells.
    fn snapshot(&self) -> CellSnapshot {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((built, cells)) = guard.as_ref() {
            if built.elapsed() < SNAPSHOT_TTL {
                return cells.clone();
            }
        }
        let rows = (self.provider)();
        let mut cells: Vec<(Oid, Value)> = Vec::new();
        for row in rows {
            for (col, value) in row.cells {
                // Instance OID: root.col.<row index...>
                let mut oid = self.root.clone();
                oid = oid.child(col);
                for &sub in &row.index {
                    oid = oid.child(sub);
                }
                cells.push((oid, value));
            }
        }
        cells.sort_by(|a, b| a.0.cmp(&b.0));
        *guard = Some((Instant::now(), cells.clone()));
        cells
    }
}

impl MibHandler for TableHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        let cells = self.snapshot();
        cells
            .binary_search_by(|(o, _)| o.cmp(oid))
            .ok()
            .map(|i| cells[i].1.clone())
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.snapshot();
        // First cell strictly greater than `oid` (cells are sorted).
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, value)| Reading {
            oid: o.clone(),
            value: value.clone(),
        })
    }

    fn set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
        // A `TableHandler` is read-only by design: it serves a provider's
        // snapshot. Writable tables use `TableDataSet`.
        Err(ErrorStatus::NotWritable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_handler() -> TableHandler {
        let root: Oid = "1.3.6.1.2.1.99".parse().unwrap();
        TableHandler::new(root, vec![1, 2, 3], move || {
            vec![
                Row::new(vec![1])
                    .with(1, Value::Integer(11))
                    .with(2, Value::OctetString(b"a".to_vec())),
                // Row 2 is sparse: only column 2.
                Row::new(vec![2]).with(2, Value::Integer(22)),
                Row::new(vec![3])
                    .with(1, Value::Integer(31))
                    .with(3, Value::OctetString(b"c".to_vec())),
            ]
        })
    }

    #[test]
    fn get_hits_present_cells() {
        let h = sample_handler();
        // root.1.1 (col 1, row 1)
        let oid: Oid = "1.3.6.1.2.1.99.1.1".parse().unwrap();
        assert_eq!(h.get(&oid), Some(Value::Integer(11)));
        // root.2.2 (col 2, row 2)
        let oid: Oid = "1.3.6.1.2.1.99.2.2".parse().unwrap();
        assert_eq!(h.get(&oid), Some(Value::Integer(22)));
    }

    #[test]
    fn get_misses_absent_cells() {
        let h = sample_handler();
        // root.3.1 (col 3, row 1) is absent.
        let oid: Oid = "1.3.6.1.2.1.99.3.1".parse().unwrap();
        assert_eq!(h.get(&oid), None);
        // Completely unknown row.
        let oid: Oid = "1.3.6.1.2.1.99.1.9".parse().unwrap();
        assert_eq!(h.get(&oid), None);
    }

    #[test]
    fn getnext_walks_column_major_skipping_sparse() {
        let h = sample_handler();
        let mut current: Oid = "1.3.6.1.2.1.99".parse().unwrap();
        let mut walk = Vec::new();
        while let Some(r) = h.get_next(&current) {
            walk.push(r.oid.to_string());
            current = r.oid;
        }
        // Lexicographic column-major order, skipping absent cells:
        //  .1.1 (col1,row1) .1.3 (col1,row3) .2.1 (col2,row1) .2.2 (col2,row2)
        //  .3.3 (col3,row3)
        assert_eq!(
            walk,
            vec![
                ".1.3.6.1.2.1.99.1.1",
                ".1.3.6.1.2.1.99.1.3",
                ".1.3.6.1.2.1.99.2.1",
                ".1.3.6.1.2.1.99.2.2",
                ".1.3.6.1.2.1.99.3.3",
            ]
        );
    }

    #[test]
    fn set_is_read_only() {
        let h = sample_handler();
        let oid: Oid = "1.3.6.1.2.1.99.1.1".parse().unwrap();
        assert_eq!(h.set(&oid, &Value::Integer(0)).unwrap_err(), ErrorStatus::NotWritable);
    }
}
