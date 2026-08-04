//! RMON-MIB (`1.3.6.1.2.1.16`) — RFC 2819.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/Rmon/`. The RMON-MIB exposes the
//! remote-network-monitoring `alarmTable` and `eventTable`. On a typical host
//! agent these tables are empty (no RMON probes configured). The handlers
//! remain walkable.
//!
//! Objects exposed (structurally, all empty):
//! * `alarmTable` (`16.3.1`) — threshold alarms.
//! * `eventTable` (`16.9.1`) — event/notification destinations.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// RMON-MIB root: `1.3.6.1.2.1.16`.
const RMON: [u32; 7] = [1, 3, 6, 1, 2, 1, 16];

/// `alarmEntry` columns (RFC 2819 §3.3).
mod alarm {
    /// `alarmIndex` — the row index.
    pub const INDEX: u32 = 1;
    /// `alarmInterval` — the sampling interval in seconds.
    pub const INTERVAL: u32 = 2;
    /// `alarmVariable` — the OID being monitored.
    pub const VARIABLE: u32 = 3;
    /// `alarmSampleType` — `absoluteValue(1)` / `deltaValue(2)`.
    pub const SAMPLE_TYPE: u32 = 4;
    /// `alarmValue` — the last sampled value.
    pub const VALUE: u32 = 5;
    /// `alarmStatus` — RowStatus/validity.
    pub const STATUS: u32 = 6;
}

/// `eventEntry` columns (RFC 2819 §3.9).
mod event {
    /// `eventIndex` — the row index.
    pub const INDEX: u32 = 1;
    /// `eventDescription` — a textual description.
    pub const DESCRIPTION: u32 = 2;
    /// `eventType` — `none(1)` / `log(2)` / `snmp-trap(3)` / `rlog(4)`.
    pub const TYPE: u32 = 3;
    /// `eventStatus` — RowStatus/validity.
    pub const STATUS: u32 = 7;
}

/// Build the (empty) RMON `alarmTable` and `eventTable` cells.
pub fn rmon_cells() -> Vec<(Oid, Value)> {
    let _ = (alarm::INDEX, alarm::INTERVAL, alarm::VARIABLE, alarm::SAMPLE_TYPE,
             alarm::VALUE, alarm::STATUS,
             event::INDEX, event::DESCRIPTION, event::TYPE, event::STATUS);
    Vec::new()
}

/// Build the [`MibHandler`] set for the RMON-MIB. Both the `alarmTable` and
/// `eventTable` handlers are empty (no configured alarms/events) but walkable
/// without error.
pub fn rmon_handlers() -> Vec<Arc<dyn MibHandler>> {
    let alarm_root = Oid::new(RMON.to_vec()).child(3).child(1);
    let event_root = Oid::new(RMON.to_vec()).child(9).child(1);
    vec![
        Arc::new(FnHandler::new(alarm_root, rmon_cells)),
        Arc::new(FnHandler::new(event_root, rmon_cells)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rmon_tables_are_empty_but_walkable() {
        let handlers = rmon_handlers();
        assert_eq!(handlers.len(), 2);
        for h in &handlers {
            let root = h.root().clone();
            assert!(h.get_next(&root).is_none());
        }
    }

    #[test]
    fn handlers_rooted_at_alarm_and_event_tables() {
        let handlers = rmon_handlers();
        assert_eq!(handlers[0].root().to_string(), ".1.3.6.1.2.1.16.3.1");
        assert_eq!(handlers[1].root().to_string(), ".1.3.6.1.2.1.16.9.1");
    }
}
