//! EtherLike-MIB (`1.3.6.1.2.1.10.7`) — RFC 1643 / RFC 3635.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/etherlike.c`. The
//! `dot3StatsTable` reports per-interface Ethernet-like media statistics
//! (alignment errors, FCS errors, deferred transmissions, internal MAC
//! transmit/receive errors, …).
//!
//! On most platforms (including Linux without ethtool counters wired up) this
//! crate has no authoritative source for these counters, so each registered
//! interface row reports **zero** for every column. The table is still
//! structurally walkable: a manager sees one row per `ifIndex` for Ethernet
//! interfaces, with the correct column OIDs and `Counter32` zero values.
//!
//! Objects exposed (a subset of the full `dot3StatsEntry`, RFC 3635 §2):
//! * `dot3StatsIndex` (col 1) — the `ifIndex` of the interface.
//! * `dot3StatsFCSErrors` (col 3).
//! * `dot3StatsDeferredTransmissions` (col 7).
//! * `dot3StatsInternalMacTransmitErrors` (col 10).
//! * `dot3StatsCarrierSenseErrors` (col 11).
//! * `dot3StatsFrameTooLongs` (col 13).
//! * `dot3StatsInternalMacReceiveErrors` (col 16).
//! * `dot3StatsEtherChipSet` (col 17) — an OID, reported as `0.0`.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// EtherLike-MIB root: `1.3.6.1.2.1.10.7`.
const ETHERLIKE: [u32; 8] = [1, 3, 6, 1, 2, 1, 10, 7];

/// `dot3StatsEntry` columns exposed. Each maps to the RFC 3635 column number.
mod col {
    /// `dot3StatsIndex` — the interface `ifIndex`.
    pub const INDEX: u32 = 1;
    /// `dot3StatsFCSErrors`.
    pub const FCS_ERRORS: u32 = 3;
    /// `dot3StatsDeferredTransmissions`.
    pub const DEFERRED: u32 = 7;
    /// `dot3StatsInternalMacTransmitErrors`.
    pub const INT_MAC_TX_ERRORS: u32 = 10;
    /// `dot3StatsCarrierSenseErrors`.
    pub const CARRIER_SENSE_ERRORS: u32 = 11;
    /// `dot3StatsFrameTooLongs`.
    pub const FRAME_TOO_LONG: u32 = 13;
    /// `dot3StatsInternalMacReceiveErrors`.
    pub const INT_MAC_RX_ERRORS: u32 = 16;
    /// `dot3StatsEtherChipSet` (an OBJECT IDENTIFIER).
    pub const CHIP_SET: u32 = 17;
}

/// A single per-interface Ethernet statistics row. All counters default to
/// zero on platforms without an authoritative source.
#[derive(Clone, Debug, Default)]
pub struct Dot3StatsRow {
    /// The `ifIndex` this row corresponds to.
    pub if_index: u32,
}

/// Build the `dot3StatsTable` instance cells (OID -> value) for the given rows.
///
/// Cell OID layout: `dot3StatsEntry(10.7.2.1.1).column(.C).ifIndex(.N)`.
/// All counter columns are `Counter32(0)`; `dot3StatsIndex` is the `ifIndex`
/// itself; `dot3StatsEtherChipSet` is the null OID `0.0`.
pub fn dot3_stats_cells(rows: &[Dot3StatsRow]) -> Vec<(Oid, Value)> {
    let entry = Oid::new(ETHERLIKE.to_vec()).child(2).child(1).child(1);
    let mut cells: Vec<(Oid, Value)> = Vec::new();
    for row in rows {
        let idx = row.if_index;
        cells.push((entry.child(col::INDEX).child(idx), Value::Integer(idx as i64)));
        cells.push((entry.child(col::FCS_ERRORS).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::DEFERRED).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::INT_MAC_TX_ERRORS).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::CARRIER_SENSE_ERRORS).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::FRAME_TOO_LONG).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::INT_MAC_RX_ERRORS).child(idx), Value::Counter32(0)));
        cells.push((entry.child(col::CHIP_SET).child(idx), Value::Oid(Oid::new(vec![0, 0]))));
    }
    cells
}

/// Build the [`MibHandler`] set for the EtherLike-MIB. The `dot3StatsTable`
/// handler is rooted at `1.3.6.1.2.1.10.7.2` and serves zeroed rows for the
/// host's Ethernet interfaces. On hosts without `/proc/net/dev` the table is
/// empty (but still walkable without error).
pub fn etherlike_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(ETHERLIKE.to_vec()).child(2);
    let handler = FnHandler::new(root, || dot3_stats_cells(&interface_rows()));
    vec![Arc::new(handler)]
}

/// Discover Ethernet interface indices from `/proc/net/dev`. Returns an empty
/// list when `/proc` is unavailable.
fn interface_rows() -> Vec<Dot3StatsRow> {
    let mut rows = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
        let mut ifindex = 0u32;
        for line in content.lines().skip(2) {
            ifindex += 1;
            // Only Ethernet-like interfaces (name starts with eth/enp/enx/ens);
            // others (lo, wlan, docker, …) are skipped so the row set matches
            // what an Ethernet-specific table would report.
            let name = line.split(':').next().unwrap_or("").trim();
            if name.starts_with("eth")
                || name.starts_with("enp")
                || name.starts_with("enx")
                || name.starts_with("ens")
            {
                rows.push(Dot3StatsRow { if_index: ifindex });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_use_correct_column_numbers() {
        let rows = vec![Dot3StatsRow { if_index: 2 }];
        let cells = dot3_stats_cells(&rows);
        // dot3StatsIndex.2 = column 1.
        let idx = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.10.7.2.1.1.1.2"
        });
        assert!(idx.is_some(), "dot3StatsIndex column missing");
        // dot3StatsFCSErrors.2 = column 3, Counter32(0).
        let fcs = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.10.7.2.1.1.3.2"
        });
        assert_eq!(fcs.map(|(_, v)| v.clone()), Some(Value::Counter32(0)));
        // dot3StatsInternalMacTransmitErrors.2 = column 10.
        let tx = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.10.7.2.1.1.10.2"
        });
        assert_eq!(tx.map(|(_, v)| v.clone()), Some(Value::Counter32(0)));
        // dot3StatsEtherChipSet.2 = column 17, OID 0.0.
        let chip = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.10.7.2.1.1.17.2"
        });
        assert_eq!(
            chip.map(|(_, v)| v.clone()),
            Some(Value::Oid(Oid::new(vec![0, 0])))
        );
    }

    #[test]
    fn handler_is_walkable_without_panic() {
        let handlers = etherlike_handlers();
        assert_eq!(handlers.len(), 1);
        let root: Oid = "1.3.6.1.2.1.10.7.2".parse().unwrap();
        // GETNEXT from the root must not panic regardless of /proc presence.
        let _ = handlers[0].get_next(&root);
    }

    #[test]
    fn getnext_walks_columns_in_order() {
        let rows = vec![Dot3StatsRow { if_index: 1 }];
        let cells = dot3_stats_cells(&rows);
        let mut sorted = cells.clone();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(cells.iter().map(|(o, _)| o.clone()).collect::<Vec<_>>(),
                   sorted.iter().map(|(o, _)| o.clone()).collect::<Vec<_>>());
        // First cell is dot3StatsIndex.1 (column 1).
        assert_eq!(cells[0].0.to_string(), ".1.3.6.1.2.1.10.7.2.1.1.1.1");
    }
}
