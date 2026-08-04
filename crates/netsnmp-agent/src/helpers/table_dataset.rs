//! Writable in-memory table with optional RowStatus lifecycle.
//!
//! Counterpart of `agent/helpers/table_dataset.c`. [`TableDataSet`] is a
//! directly-mutable SNMP table: rows live in a `BTreeMap` keyed by index,
//! each row carrying its cells. Optionally one column is designated the
//! RowStatus column; when set, the RFC 2579 state machine
//! ([`crate::row::transition`]) drives row creation and destruction.

use crate::handler::{MibHandler, Reading};
use crate::row::{self, RowStatus};
use crate::scalar::types_compatible;
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Metadata for a single column of a [`TableDataSet`], mirroring the
/// information `mib2c -c mib2c.dataset.conf` emits. Kept as plain strings so
/// this module does not depend on the (Task 5.17) SMI type system.
#[derive(Clone, Debug)]
pub struct ColumnMeta {
    /// The column number (the entry sub-identifier, e.g. 1 for `ifIndex`).
    pub number: u32,
    /// The SYNTAX clause as text, e.g. `"Integer32 (0..2147483647)"`.
    pub syntax: String,
    /// The MAX-ACCESS clause, e.g. `"read-create"` or `"read-only"`.
    pub access: String,
    /// The DEFVAL clause as text, if any.
    pub defval: Option<String>,
}

impl ColumnMeta {
    /// Create new column metadata.
    pub fn new(number: u32, syntax: impl Into<String>, access: impl Into<String>) -> Self {
        ColumnMeta {
            number,
            syntax: syntax.into(),
            access: access.into(),
            defval: None,
        }
    }

    /// Builder: set the DEFVAL.
    pub fn with_defval(mut self, defval: impl Into<String>) -> Self {
        self.defval = Some(defval.into());
        self
    }

    /// Whether this column's MAX-ACCESS permits writes.
    pub fn is_writable(&self) -> bool {
        let a = self.access.to_ascii_lowercase();
        a == "read-create" || a == "read-write"
    }
}

/// One row of a [`TableDataSet`]: cells keyed by column number.
type RowCells = BTreeMap<u32, Value>;

/// A writable in-memory SNMP table, optionally driven by a RowStatus column.
///
/// Rows are keyed by their index sub-identifiers (the trailing portion of the
/// instance OID, after the column number). GETNEXT walks column-major in
/// lexicographic order, skipping absent cells. SET is accepted for writable
/// columns; when a RowStatus column is configured, SETting it drives row
/// creation/destruction via [`crate::row::transition`].
///
/// # Example
///
/// ```
/// use netsnmp_agent::helpers::TableDataSet;
/// use netsnmp::value::Value;
/// use netsnmp_agent::MibHandler;
///
/// let root = "1.3.6.1.2.1.999".parse().unwrap();
/// // Columns: 1 = RowStatus, 2 = name (OctetString), 3 = value (Integer).
/// let mut t = TableDataSet::new(root, vec![1, 2, 3])
///     .with_row_status_column(1)
///     .with_required_columns(&[2]);
/// // Row absent: GET returns None.
/// let cell = "1.3.6.1.2.1.999.1.5".parse().unwrap();
/// assert_eq!(t.get(&cell), None);
/// // createAndGo(4) on index 5 with the required name column set first.
/// t.set(&"1.3.6.1.2.1.999.2.5".parse().unwrap(),
///       &Value::OctetString(b"hello".to_vec())).unwrap();
/// t.set(&"1.3.6.1.2.1.999.1.5".parse().unwrap(),
///       &Value::Integer(4)).unwrap();
/// // Now the RowStatus reads back as active(1).
/// assert_eq!(t.get(&cell), Some(Value::Integer(1)));
/// ```
pub struct TableDataSet {
    root: Oid,
    columns: Vec<u32>,
    meta: BTreeMap<u32, ColumnMeta>,
    rows: RwLock<BTreeMap<Vec<u32>, RowCells>>,
    row_status_column: Option<u32>,
    required_columns: Vec<u32>,
}

impl TableDataSet {
    /// Create a new writable table rooted at `root` serving the listed columns.
    /// All columns default to `read-create`.
    pub fn new(root: Oid, columns: Vec<u32>) -> Self {
        let meta = columns
            .iter()
            .map(|&c| (c, ColumnMeta::new(c, "Integer32", "read-create")))
            .collect();
        TableDataSet {
            root,
            columns,
            meta,
            rows: RwLock::new(BTreeMap::new()),
            row_status_column: None,
            required_columns: Vec::new(),
        }
    }

    /// Builder: attach [`ColumnMeta`] for a column, overriding the default.
    pub fn with_column_meta(mut self, meta: ColumnMeta) -> Self {
        let num = meta.number;
        self.meta.insert(num, meta);
        if !self.columns.contains(&num) {
            self.columns.push(num);
            self.columns.sort_unstable();
        }
        self
    }

    /// Builder: designate `col` as the RowStatus column. Once set, SETting
    /// that column drives row creation/destruction.
    pub fn with_row_status_column(mut self, col: u32) -> Self {
        self.row_status_column = Some(col);
        if !self.columns.contains(&col) {
            self.columns.push(col);
            self.columns.sort_unstable();
        }
        if !self.required_columns.contains(&col) {
            self.required_columns.push(col);
            self.required_columns.sort_unstable();
        }
        self
    }

    /// Builder: declare the columns a row must have populated before it can
    /// go `active`. Implied to include the RowStatus column itself.
    pub fn with_required_columns(mut self, cols: &[u32]) -> Self {
        for &c in cols {
            if !self.required_columns.contains(&c) {
                self.required_columns.push(c);
            }
        }
        self.required_columns.sort_unstable();
        self
    }

    /// Whether a column is writable according to its metadata.
    fn column_writable(&self, col: u32) -> bool {
        self.meta.get(&col).map(|m| m.is_writable()).unwrap_or(true)
    }

    /// Build the instance OID for `col`/`index`.
    fn instance_oid(&self, col: u32, index: &[u32]) -> Oid {
        let mut oid = self.root.child(col);
        for &sub in index {
            oid = oid.child(sub);
        }
        oid
    }

    /// Split an instance OID under this handler into `(column, index)`.
    /// Returns `None` if the OID is not under `root` or has no column sub-id.
    fn split_instance(&self, oid: &Oid) -> Option<(u32, Vec<u32>)> {
        let slice = oid.as_slice();
        let r = self.root.as_slice();
        if slice.len() < r.len() + 1 || &slice[..r.len()] != r {
            return None;
        }
        let col = slice[r.len()];
        let index = slice[r.len() + 1..].to_vec();
        Some((col, index))
    }

    /// Whether a row satisfies every required column. The RowStatus column is
    /// excluded from the check because it is self-satisfying: a `createAndGo`
    /// SET populates it as part of the same transaction, so it should not
    /// count against the row during transition evaluation.
    fn required_satisfied(
        rows: &BTreeMap<Vec<u32>, RowCells>,
        index: &[u32],
        required: &[u32],
        row_status_column: Option<u32>,
    ) -> bool {
        match rows.get(index) {
            Some(cells) => required
                .iter()
                .filter(|c| Some(**c) != row_status_column)
                .all(|c| cells.contains_key(c)),
            // A brand-new row has no cells yet other than what is being SET in
            // this transaction; treat its already-staged cells (written in an
            // earlier commit, or pre-populated via `put`) as satisfying the
            // requirement, and consider the row "potentially satisfied" so the
            // transition can decide. For a truly empty new row this returns
            // false unless `required` is empty.
            None => false,
        }
    }

    /// Insert or overwrite a cell directly (runtime API, not via SET).
    pub fn put(&self, col: u32, index: &[u32], value: Value) {
        let mut rows = self.rows.write().unwrap();
        let cells = rows.entry(index.to_vec()).or_default();
        cells.insert(col, value);
    }

    /// Remove a row by index. Returns whether a row was actually removed.
    pub fn remove_row(&self, index: &[u32]) -> bool {
        self.rows.write().unwrap().remove(index).is_some()
    }

    /// Apply a RowStatus SET to the row at `index`, returning the value to
    /// store in the RowStatus column (if any) and mutating rows accordingly.
    fn apply_row_status(
        &self,
        rows: &mut BTreeMap<Vec<u32>, RowCells>,
        index: &[u32],
        requested: RowStatus,
    ) -> Result<Option<Value>, ErrorStatus> {
        let current = rows
            .get(index)
            .and_then(|cells| cells.get(&self.row_status_column.unwrap()))
            .and_then(RowStatus::from_value);
        let satisfied = Self::required_satisfied(rows, index, &self.required_columns, self.row_status_column);
        let next = row::transition(current, requested, satisfied)?;
        match next {
            None => {
                rows.remove(index);
                Ok(None)
            }
            Some(status) => {
                let cells = rows.entry(index.to_vec()).or_default();
                cells.insert(self.row_status_column.unwrap(), Value::Integer(status.as_i64()));
                Ok(Some(Value::Integer(status.as_i64())))
            }
        }
    }
}

impl MibHandler for TableDataSet {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        let (col, index) = self.split_instance(oid)?;
        let rows = self.rows.read().unwrap();
        rows.get(&index).and_then(|cells| cells.get(&col).cloned())
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let rows = self.rows.read().unwrap();
        // Flatten to sorted (oid, value) pairs and binary-search the
        // successor. Table sizes are modest; this is O(rows*cols).
        let mut cells: Vec<(Oid, Value)> = Vec::new();
        for (index, row_cells) in rows.iter() {
            for (&col, value) in row_cells {
                cells.push((self.instance_oid(col, index), value.clone()));
            }
        }
        cells.sort_by(|a, b| a.0.cmp(&b.0));
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        let (col, index) = self
            .split_instance(oid)
            .ok_or(ErrorStatus::NoCreation)?;
        if !self.column_writable(col) {
            return Err(ErrorStatus::NotWritable);
        }

        // RowStatus column is validated by the state machine.
        if self.row_status_column == Some(col) {
            let requested = RowStatus::from_value(value).ok_or(ErrorStatus::WrongValue)?;
            let rows = self.rows.read().unwrap();
            let current = rows
                .get(&index)
                .and_then(|cells| cells.get(&col))
                .and_then(RowStatus::from_value);
            let satisfied = Self::required_satisfied(&rows, &index, &self.required_columns, self.row_status_column);
            // Run a dry transition to validate. We do NOT mutate here.
            row::transition(current, requested, satisfied)?;
            return Ok(());
        }

        // Non-RowStatus column: an existing cell must keep a compatible type;
        // a brand-new cell on a brand-new row is only allowed if a RowStatus
        // column is configured (the manager must drive creation via it).
        let rows = self.rows.read().unwrap();
        match rows.get(&index) {
            Some(cells) => match cells.get(&col) {
                Some(current) if !types_compatible(current, value) => {
                    Err(ErrorStatus::WrongType)
                }
                _ => Ok(()),
            },
            None => {
                if self.row_status_column.is_some() {
                    // Pre-creation SET of a non-status column: allow, it will
                    // be staged pending the createAndGo/createAndWait that
                    // follows in the same SET.
                    Ok(())
                } else {
                    Err(ErrorStatus::NoCreation)
                }
            }
        }
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        let (col, index) = self
            .split_instance(oid)
            .ok_or(ErrorStatus::NoCreation)?;

        let mut rows = self.rows.write().unwrap();

        // RowStatus column drives the state machine.
        if self.row_status_column == Some(col) {
            let requested = RowStatus::from_value(value).ok_or(ErrorStatus::WrongValue)?;
            self.apply_row_status(&mut rows, &index, requested)?;
            return Ok(());
        }

        // Regular column: write the cell. A row may be implicitly created if
        // a RowStatus column is configured (pre-creation staging); otherwise
        // the row must already exist (prepare_set enforced this).
        let cells = rows.entry(index).or_default();
        cells.insert(col, value.clone());
        Ok(())
    }

    fn set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        // Single-step fallback: validate then commit in one go.
        self.prepare_set(oid, value)?;
        self.commit_set(oid, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_table() -> TableDataSet {
        // Columns: 1 = RowStatus, 2 = name, 3 = count.
        let root: Oid = "1.3.6.1.2.1.888".parse().unwrap();
        TableDataSet::new(root, vec![1, 2, 3])
            .with_row_status_column(1)
            .with_required_columns(&[2])
    }

    #[test]
    fn create_and_go_creates_active_row() {
        let t = sample_table();
        // First stage the name column, then createAndGo.
        let name_oid: Oid = "1.3.6.1.2.1.888.2.7".parse().unwrap();
        let status_oid: Oid = "1.3.6.1.2.1.888.1.7".parse().unwrap();
        t.set(&name_oid, &Value::OctetString(b"x".to_vec())).unwrap();
        t.set(&status_oid, &Value::Integer(4)).unwrap();
        assert_eq!(t.get(&status_oid), Some(Value::Integer(1)));
        assert_eq!(t.get(&name_oid), Some(Value::OctetString(b"x".to_vec())));
    }

    #[test]
    fn create_and_go_missing_required_is_inconsistent_name() {
        let t = sample_table();
        let status_oid: Oid = "1.3.6.1.2.1.888.1.9".parse().unwrap();
        let err = t.set(&status_oid, &Value::Integer(4)).unwrap_err();
        assert_eq!(err, ErrorStatus::InconsistentName);
    }

    #[test]
    fn destroy_removes_row() {
        let t = sample_table();
        let name_oid: Oid = "1.3.6.1.2.1.888.2.3".parse().unwrap();
        let status_oid: Oid = "1.3.6.1.2.1.888.1.3".parse().unwrap();
        t.set(&name_oid, &Value::OctetString(b"y".to_vec())).unwrap();
        t.set(&status_oid, &Value::Integer(4)).unwrap();
        assert!(t.get(&status_oid).is_some());
        // Now destroy(6).
        t.set(&status_oid, &Value::Integer(6)).unwrap();
        assert_eq!(t.get(&status_oid), None);
        assert_eq!(t.get(&name_oid), None);
    }

    #[test]
    fn getnext_walks_column_major() {
        let t = sample_table();
        t.put(1, &[1], Value::Integer(1));
        t.put(2, &[1], Value::OctetString(b"a".to_vec()));
        t.put(1, &[2], Value::Integer(1));
        t.put(3, &[2], Value::Integer(50));
        let mut current: Oid = "1.3.6.1.2.1.888".parse().unwrap();
        let mut walk = Vec::new();
        while let Some(r) = t.get_next(&current) {
            walk.push(r.oid.to_string());
            current = r.oid;
        }
        // Column-major order: .1.1, .1.2, .2.1, .3.2
        assert_eq!(
            walk,
            vec![
                ".1.3.6.1.2.1.888.1.1",
                ".1.3.6.1.2.1.888.1.2",
                ".1.3.6.1.2.1.888.2.1",
                ".1.3.6.1.2.1.888.3.2",
            ]
        );
    }

    #[test]
    fn wrong_type_on_existing_cell_rejected() {
        let t = sample_table();
        let name_oid: Oid = "1.3.6.1.2.1.888.2.4".parse().unwrap();
        t.set(&name_oid, &Value::OctetString(b"x".to_vec())).unwrap();
        // Try to SET an Integer onto the OctetString cell.
        let err = t.set(&name_oid, &Value::Integer(1)).unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
    }

    #[test]
    fn column_metadata_controls_writability() {
        let root: Oid = "1.3.6.1.2.1.889".parse().unwrap();
        let t = TableDataSet::new(root, vec![1, 2])
            .with_column_meta(ColumnMeta::new(2, "DisplayString", "read-only"));
        t.put(1, &[1], Value::Integer(0));
        t.put(2, &[1], Value::OctetString(b"hi".to_vec()));
        // Column 1 is read-create by default: writable.
        t.set(
            &"1.3.6.1.2.1.889.1.1".parse().unwrap(),
            &Value::Integer(5),
        )
        .unwrap();
        // Column 2 is read-only: rejected.
        let err = t
            .set(
                &"1.3.6.1.2.1.889.2.1".parse().unwrap(),
                &Value::OctetString(b"bye".to_vec()),
            )
            .unwrap_err();
        assert_eq!(err, ErrorStatus::NotWritable);
    }
}
