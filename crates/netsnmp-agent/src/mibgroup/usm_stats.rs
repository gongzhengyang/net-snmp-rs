//! SNMP-USER-BASED-SM-MIB `usmStats` group (`1.3.6.1.6.3.15.1.1`).
//!
//! Counterpart of the `usmStats` portion of `agent/mibgroup/mibII/vacm_conf.c`
//! / `snmpusm.c`. Reports the six USM error counters that an authoritative
//! engine maintains (RFC 3414 §3.2) — each is a `Counter32` instance at
//! `usmStats.<n>.0`.
//!
//! The same [`UsmStats`] object is shared between the agent's v3 message
//! processing path (which calls [`UsmStats::inc`] when it rejects a message)
//! and the [`usm_stats_handler`] that serves the counters to walkers, so the
//! values a manager reads match the counts the engine has actually accumulated.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp::v3::UsmStat;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `usmStats` group root: `1.3.6.1.6.3.15.1.1`.
const USM_STATS: [u32; 9] = [1, 3, 6, 1, 6, 3, 15, 1, 1];

/// Map a [`UsmStat`] variant to its 0-based slot in the internal counter array.
/// The variant order in [`UsmStat`] matches RFC 3414's `usmStats.<1..6>` order.
fn index_of(which: UsmStat) -> usize {
    match which {
        UsmStat::UnsupportedSecLevels => 0,
        UsmStat::NotInTimeWindows => 1,
        UsmStat::UnknownUserNames => 2,
        UsmStat::UnknownEngineIDs => 3,
        UsmStat::WrongDigests => 4,
        UsmStat::DecryptionErrors => 5,
    }
}

/// The shared USM error counters reported under `usmStats`.
///
/// Holds six independent [`AtomicU64`] counters (one per [`UsmStat`] variant);
/// `AtomicU64` is used so 32-bit wraps on the wire can be computed without
/// losing the true accumulated count. Created once per agent and shared between
/// the agent's v3 path and [`usm_stats_handler`].
pub struct UsmStats {
    counters: [AtomicU64; 6],
}

impl UsmStats {
    /// Create a fresh `UsmStats` with all six counters at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: Default::default(),
        })
    }

    /// Increment the counter for `which` by one. Called by the v3 message
    /// processing path whenever it rejects a message for the corresponding
    /// USM reason.
    pub fn inc(&self, which: UsmStat) {
        self.counters[index_of(which)].fetch_add(1, Ordering::Relaxed);
    }

    /// Build the six `usmStats` instance cells as `(instance_oid, value)` pairs.
    ///
    /// Each cell OID is `usmStats.<n>.0` (the conventional `.0` instance form)
    /// and the value is a `Counter32` truncation of the underlying 64-bit count.
    pub fn cells(&self) -> Vec<(Oid, Value)> {
        let root = Oid::new(USM_STATS.to_vec());
        let variants = [
            UsmStat::UnsupportedSecLevels,
            UsmStat::NotInTimeWindows,
            UsmStat::UnknownUserNames,
            UsmStat::UnknownEngineIDs,
            UsmStat::WrongDigests,
            UsmStat::DecryptionErrors,
        ];
        variants
            .iter()
            .map(|&v| {
                let idx = index_of(v);
                let n = (idx + 1) as u32; // subid 1..6
                let count = self.counters[idx].load(Ordering::Relaxed) as u32;
                (root.child(n).child(0), Value::Counter32(count))
            })
            .collect()
    }
}

impl Default for UsmStats {
    fn default() -> Self {
        Self {
            counters: Default::default(),
        }
    }
}

/// Build the read-only `usmStats` handler rooted at `1.3.6.1.6.3.15.1.1`.
///
/// The handler shares `stats` with the agent so increments performed by the v3
/// message path are immediately visible to walkers.
pub fn usm_stats_handler(stats: Arc<UsmStats>) -> Arc<dyn MibHandler> {
    let root = Oid::new(USM_STATS.to_vec());
    Arc::new(FnHandler::new(root, move || stats.cells()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inc_updates_counters() {
        let stats = UsmStats::new();
        stats.inc(UsmStat::UnknownUserNames);
        stats.inc(UsmStat::UnknownUserNames);
        stats.inc(UsmStat::WrongDigests);

        let cells = stats.cells();
        assert_eq!(cells.len(), 6);

        let get = |col: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.6.3.15.1.1.{col}.0"))
                .map(|(_, v)| v.clone())
        };

        assert_eq!(get(3), Some(Value::Counter32(2))); // UnknownUserNames
        assert_eq!(get(5), Some(Value::Counter32(1))); // WrongDigests
        assert_eq!(get(1), Some(Value::Counter32(0))); // UnsupportedSecLevels
    }

    #[test]
    fn handler_serves_counter_cells() {
        let stats = UsmStats::new();
        stats.inc(UsmStat::DecryptionErrors);
        let handler = usm_stats_handler(stats);

        // GET on usmStatsDecryptionErrors.0 (column 6).
        let oid: Oid = "1.3.6.1.6.3.15.1.1.6.0".parse().unwrap();
        assert_eq!(handler.get(&oid), Some(Value::Counter32(1)));

        // GETNEXT from the group root lands on the first counter.
        let root: Oid = "1.3.6.1.6.3.15.1.1".parse().unwrap();
        let first = handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
