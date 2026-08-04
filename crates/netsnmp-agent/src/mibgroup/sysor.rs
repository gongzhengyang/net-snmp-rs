//! `sysORTable` (`SNMPv2-MIB::sysORTable`, `1.3.6.1.2.1.1.9.1`).
//!
//! Counterpart of `agent/mibgroup/mibII/sysORTable.c`. Each row records an
//! "upgradable" subsystem that the agent knows about, with its MIB object
//! identifier (`sysORID`), a human description (`sysORDescr`) and the
//! `sysUpTime` value at which it was registered (`sysORUpTime`).
//!
//! Subsystems register themselves at startup via [`SysOrTable::register`]; the
//! resulting table is served read-only by [`sysor_handler`]. Rows are kept in a
//! [`RwLock`]`<Vec<_>>` so registration (write) and walks (read) never block
//! each other for long.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `sysORTable` root: `1.3.6.1.2.1.1.9.1` (`sysOREntry`).
const SYS_OR_ENTRY: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 9, 1];

/// One row of the `sysORTable`.
#[derive(Clone, Debug)]
struct SysOrEntry {
    /// `sysORIndex`, the 1-based row identifier assigned at registration time.
    index: u32,
    /// `sysORID` — the OID of the subsystem's MIB object.
    id: Oid,
    /// `sysORDescr` — textual description of the subsystem.
    descr: String,
    /// `sysORUpTime` — `sysUpTime` (in hundredths of a second) when the row was
    /// registered, frozen at registration time.
    uptime_ticks: u32,
}

/// The shared, append-only `sysORTable` store.
///
/// Built once per agent (see [`SysOrTable::new`]) and shared between the
/// [`sysor_handler`] serving it to walkers and the agent's own
/// `register_sysOR` calls. Internal storage is a [`RwLock`]`<`[`Vec`]`>` so
/// registrations (writers) and walks (readers) progress concurrently.
pub struct SysOrTable {
    rows: RwLock<Vec<SysOrEntry>>,
    boot_time: Instant,
}

impl SysOrTable {
    /// Create an empty `sysORTable`. `boot_time` is the agent start instant,
    /// used to compute each row's `sysORUpTime` at registration time.
    pub fn new(boot_time: Instant) -> Arc<Self> {
        Arc::new(Self {
            rows: RwLock::new(Vec::new()),
            boot_time,
        })
    }

    /// Register a new subsystem row.
    ///
    /// `id` is the subsystem's MIB object identifier (`sysORID`), `descr` its
    /// `sysORDescr` text. The 1-based `sysORIndex` of the new row is returned
    /// and is also stable for the lifetime of the table (rows are append-only).
    pub fn register(&self, id: Oid, descr: String) -> u32 {
        let uptime_ticks = (self.boot_time.elapsed().as_millis() / 10) as u32;
        let mut rows = self.rows.write().unwrap_or_else(|e| e.into_inner());
        let index = (rows.len() as u32) + 1;
        rows.push(SysOrEntry {
            index,
            id,
            descr,
            uptime_ticks,
        });
        index
    }

    /// Build the full set of instance cells currently in the table, as
    /// `(instance_oid, value)` pairs under `sysOREntry`.
    ///
    /// Cell OID layout is `sysOREntry.column.index`, i.e.
    /// `1.3.6.1.2.1.1.9.1.<column>.<index>`, matching the SNMPv2-MIB
    /// `sysORTable` column ordering: `sysORID`(2), `sysORDescr`(3),
    /// `sysORUpTime`(4).
    pub fn cells(&self) -> Vec<(Oid, Value)> {
        let rows = self.rows.read().unwrap_or_else(|e| e.into_inner());
        let entry = Oid::new(SYS_OR_ENTRY.to_vec());
        let mut cells = Vec::with_capacity(rows.len() * 3);
        for row in rows.iter() {
            cells.push((entry.child(2).child(row.index), Value::Oid(row.id.clone())));
            cells.push((
                entry.child(3).child(row.index),
                Value::OctetString(row.descr.clone().into_bytes()),
            ));
            cells.push((entry.child(4).child(row.index), Value::TimeTicks(row.uptime_ticks)));
        }
        cells
    }
}

/// Build the read-only `sysORTable` handler rooted at `1.3.6.1.2.1.1.9.1`.
///
/// The handler shares `table` with the agent, so subsystems that call
/// [`SysOrTable::register`] against the same [`Arc`] immediately become
/// walkable.
pub fn sysor_handler(table: Arc<SysOrTable>) -> Arc<dyn MibHandler> {
    let root = Oid::new(SYS_OR_ENTRY.to_vec());
    Arc::new(FnHandler::new(root, move || table.cells()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_two_entries_assigns_increasing_indices() {
        let table = SysOrTable::new(Instant::now());
        let i1 = table.register(
            "1.3.6.1.2.1.1".parse().unwrap(),
            "snmpv2 mib".to_string(),
        );
        let i2 = table.register(
            "1.3.6.1.6.3.10.2.1".parse().unwrap(),
            "snmp framework".to_string(),
        );
        assert_eq!((i1, i2), (1, 2));
    }

    #[test]
    fn cells_shape_matches_table_layout() {
        let table = SysOrTable::new(Instant::now());
        let _ = table.register(
            "1.3.6.1.2.1.1".parse().unwrap(),
            "snmpv2 mib".to_string(),
        );
        let _ = table.register(
            "1.3.6.1.6.3.10.2.1".parse().unwrap(),
            "snmp framework".to_string(),
        );

        let cells = table.cells();
        // 2 rows * 3 columns.
        assert_eq!(cells.len(), 6);

        // sysORID.1 (column 2, index 1) = the registered OID.
        let id1_oid: Oid = "1.3.6.1.2.1.1.9.1.2.1".parse().unwrap();
        let id1 = cells.iter().find(|(o, _)| o == &id1_oid).map(|(_, v)| v.clone());
        assert_eq!(id1, Some(Value::Oid("1.3.6.1.2.1.1".parse().unwrap())));

        // sysORDescr.2 (column 3, index 2) = the description octet string.
        let descr2_oid: Oid = "1.3.6.1.2.1.1.9.1.3.2".parse().unwrap();
        let descr2 = cells
            .iter()
            .find(|(o, _)| o == &descr2_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(
            descr2,
            Some(Value::OctetString(b"snmp framework".to_vec()))
        );

        // sysORUpTime.2 (column 4, index 2) is a TimeTicks.
        let up2_oid: Oid = "1.3.6.1.2.1.1.9.1.4.2".parse().unwrap();
        let up2 = cells.iter().find(|(o, _)| o == &up2_oid).map(|(_, v)| v.clone());
        assert!(matches!(up2, Some(Value::TimeTicks(_))));
    }

    #[test]
    fn handler_serves_registered_rows() {
        let table = SysOrTable::new(Instant::now());
        let _ = table.register(
            "1.3.6.1.2.1.1".parse().unwrap(),
            "snmpv2 mib".to_string(),
        );
        let handler = sysor_handler(table);

        // GET on sysORID.1 (column 2, index 1).
        let id1_oid: Oid = "1.3.6.1.2.1.1.9.1.2.1".parse().unwrap();
        let got = handler.get(&id1_oid);
        assert_eq!(got, Some(Value::Oid("1.3.6.1.2.1.1".parse().unwrap())));

        // GETNEXT from the table root lands on the first cell.
        let root: Oid = "1.3.6.1.2.1.1.9.1".parse().unwrap();
        let first = handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
