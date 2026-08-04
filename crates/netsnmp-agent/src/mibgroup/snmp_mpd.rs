//! SNMP-MPD-MIB `snmpMPDStats` group (`1.3.6.1.6.3.11.2.1`).
//!
//! Counterpart of the `snmpMPDStats` portion of `agent/mibgroup/mibII/vacm_vars.c`.
//! Reports the two Message Processing and Dispatch counters defined in RFC 3412:
//!
//! | Object                     | OID suffix | Meaning                                  |
//! |----------------------------|------------|------------------------------------------|
//! | `snmpUnknownSecurityModels`| `.1.0`     | messages with an unsupported sec model   |
//! | `snmpInvalidMsgs`          | `.2.0`     | messages that could not be parsed        |
//!
//! Both are `Counter32` instances. The dispatcher increments them via
//! [`SnmpMpdStats::inc_unknown_security_model`] /
//! [`SnmpMpdStats::inc_invalid_msg`]; [`snmp_mpd_handler`] serves the current
//! values to walkers from the same shared store.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `snmpMPDStats` group root: `1.3.6.1.6.3.11.2.1`.
const SNMP_MPD: [u32; 9] = [1, 3, 6, 1, 6, 3, 11, 2, 1];

/// Slot index for `snmpUnknownSecurityModels`.
const IDX_UNKNOWN_SEC_MODEL: usize = 0;
/// Slot index for `snmpInvalidMsgs`.
const IDX_INVALID_MSG: usize = 1;

/// The shared `snmpMPDStats` counters.
///
/// Wraps two [`AtomicU64`] counters (one per object) so the underlying count
/// never loses precision; the on-the-wire `Counter32` value is a 32-bit
/// truncation of the stored count. Created once per agent and shared between
/// the dispatcher and [`snmp_mpd_handler`].
pub struct SnmpMpdStats {
    counters: [AtomicU64; 2],
}

impl SnmpMpdStats {
    /// Create a fresh `SnmpMpdStats` with both counters at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: Default::default(),
        })
    }

    /// Increment `snmpUnknownSecurityModels` by one.
    pub fn inc_unknown_security_model(&self) {
        self.counters[IDX_UNKNOWN_SEC_MODEL].fetch_add(1, Ordering::Relaxed);
    }

    /// Increment `snmpInvalidMsgs` by one.
    pub fn inc_invalid_msg(&self) {
        self.counters[IDX_INVALID_MSG].fetch_add(1, Ordering::Relaxed);
    }

    /// Build the two `snmpMPDStats` instance cells as `(instance_oid, value)`
    /// pairs. Each cell OID is `snmpMPDStats.<n>.0` (the conventional `.0`
    /// instance form) and the value is a `Counter32` truncation of the count.
    pub fn cells(&self) -> Vec<(Oid, Value)> {
        let root = Oid::new(SNMP_MPD.to_vec());
        let unknown = self.counters[IDX_UNKNOWN_SEC_MODEL].load(Ordering::Relaxed) as u32;
        let invalid = self.counters[IDX_INVALID_MSG].load(Ordering::Relaxed) as u32;
        vec![
            (root.child(1).child(0), Value::Counter32(unknown)),
            (root.child(2).child(0), Value::Counter32(invalid)),
        ]
    }
}

impl Default for SnmpMpdStats {
    fn default() -> Self {
        Self {
            counters: Default::default(),
        }
    }
}

/// Build a read-only `snmpMPDStats` handler backed by a private
/// [`SnmpMpdStats`] store. Use [`snmp_mpd_handler_with`] when the dispatcher
/// needs to share its own store so its increments are visible to walkers.
pub fn snmp_mpd_handler() -> Arc<dyn MibHandler> {
    snmp_mpd_handler_with(SnmpMpdStats::new())
}

/// Build a read-only `snmpMPDStats` handler rooted at `1.3.6.1.6.3.11.2.1`,
/// sharing `stats` with the dispatcher.
pub fn snmp_mpd_handler_with(stats: Arc<SnmpMpdStats>) -> Arc<dyn MibHandler> {
    let root = Oid::new(SNMP_MPD.to_vec());
    Arc::new(FnHandler::new(root, move || stats.cells()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_return_two_counters() {
        let stats = SnmpMpdStats::new();
        let cells = stats.cells();
        assert_eq!(cells.len(), 2);

        let unknown = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.6.3.11.2.1.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(unknown, Some(Value::Counter32(0)));

        let invalid = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.6.3.11.2.1.2.0")
            .map(|(_, v)| v.clone());
        assert_eq!(invalid, Some(Value::Counter32(0)));
    }

    #[test]
    fn increments_are_visible_through_handler() {
        let stats = SnmpMpdStats::new();
        stats.inc_unknown_security_model();
        stats.inc_unknown_security_model();
        stats.inc_invalid_msg();
        let handler = snmp_mpd_handler_with(stats);

        let unknown_oid: Oid = "1.3.6.1.6.3.11.2.1.1.0".parse().unwrap();
        assert_eq!(handler.get(&unknown_oid), Some(Value::Counter32(2)));

        let invalid_oid: Oid = "1.3.6.1.6.3.11.2.1.2.0".parse().unwrap();
        assert_eq!(handler.get(&invalid_oid), Some(Value::Counter32(1)));

        // GETNEXT from the group root lands on the first counter.
        let root: Oid = "1.3.6.1.6.3.11.2.1".parse().unwrap();
        let first = handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
