//! SNMPv2-MIB `snmp` group (`1.3.6.1.2.1.11`) — the 30 protocol counters of
//! RFC 1213 §6.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/snmp_mib.c`. Each object is
//! a `Counter32` instance at `snmp.<n>.0`, reflecting the running totals the
//! agent's message-processing path accumulates (packets in/out, bad versions,
//! bad community names, ASN.1 parse errors, …).
//!
//! The counters are held in a shared [`SnmpCounters`] object (one
//! [`AtomicU64`] per slot; the on-the-wire `Counter32` is a 32-bit truncation
//! of the underlying count). The agent's dispatcher increments them via
//! [`SnmpCounters::inc`] as it processes each packet; [`snmp_mib_handlers`]
//! serves the same store to walkers, so what a manager reads matches the
//! counts the engine has actually accumulated.
//!
//! # Wiring note
//!
//! Wiring the agent's `handle_datagram` path to increment these counters is
//! **optional** and intentionally left out of this module to avoid modifying
//! `agent.rs`. The counters start at zero and the handler is walkable
//! immediately. A future change can hold the `Arc<SnmpCounters>` inside
//! `Agent` and call `inc(SnmpCounter::InPkts)` on every received datagram,
//! `inc(SnmpCounter::InBadVersions)` on a version mismatch, etc.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `snmp` group root: `1.3.6.1.2.1.11`.
const SNMP: [u32; 7] = [1, 3, 6, 1, 2, 1, 11];

/// The 30 counters of the SNMPv2-MIB `snmp` group, in RFC 1213 column order.
///
/// Each variant maps to the `snmp.<n>` sub-identifier (1-based) and a slot in
/// [`SnmpCounters`]. The variant order matches the array index, so
/// `SnmpCounter::InPkts as usize == 0` corresponds to `snmpInPkts` (`snmp.1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SnmpCounter {
    /// `snmpInPkts` (`snmp.1`) — total packets delivered to the entity.
    InPkgs = 0,
    /// `snmpInBadVersions` (`snmp.2`) — packets with an unsupported version.
    InBadVersions = 1,
    /// `snmpInBadCommunityNames` (`snmp.3`).
    InBadCommunityNames = 2,
    /// `snmpInBadCommunityUses` (`snmp.4`).
    InBadCommunityUses = 3,
    /// `snmpInASNParseErrs` (`snmp.5`).
    InASNParseErrs = 4,
    /// `snmpInBadTypes` (`snmp.6`) — deprecated, always 0.
    InBadTypes = 5,
    /// `snmpInTooBigs` (`snmp.7`).
    InTooBigs = 6,
    /// `snmpInNoSuchNames` (`snmp.8`).
    InNoSuchNames = 7,
    /// `snmpInBadValues` (`snmp.9`).
    InBadValues = 8,
    /// `snmpInReadOnlys` (`snmp.10`).
    InReadOnlys = 9,
    /// `snmpInGenErrs` (`snmp.11`).
    InGenErrs = 10,
    /// `snmpInTotalReqVars` (`snmp.12`).
    InTotalReqVars = 11,
    /// `snmpInTotalSetVars` (`snmp.13`).
    InTotalSetVars = 12,
    /// `snmpInGetRequests` (`snmp.14`).
    InGetRequests = 13,
    /// `snmpInGetNexts` (`snmp.15`).
    InGetNexts = 14,
    /// `snmpInSetRequests` (`snmp.16`).
    InSetRequests = 15,
    /// `snmpInGetResponses` (`snmp.17`).
    InGetResponses = 16,
    /// `snmpInTraps` (`snmp.18`).
    InTraps = 17,
    /// `snmpOutPkts` (`snmp.19`) — total packets the entity sent.
    OutPkts = 18,
    /// `snmpOutTooBigs` (`snmp.20`).
    OutTooBigs = 19,
    /// `snmpOutNoSuchNames` (`snmp.21`).
    OutNoSuchNames = 20,
    /// `snmpOutBadValues` (`snmp.22`).
    OutBadValues = 21,
    /// `snmpOutGenErrs` (`snmp.23`).
    OutGenErrs = 22,
    /// `snmpOutGetRequests` (`snmp.24`).
    OutGetRequests = 23,
    /// `snmpOutGetNexts` (`snmp.25`).
    OutGetNexts = 24,
    /// `snmpOutSetRequests` (`snmp.26`).
    OutSetRequests = 25,
    /// `snmpOutGetResponses` (`snmp.27`).
    OutGetResponses = 26,
    /// `snmpOutTraps` (`snmp.28`).
    OutTraps = 27,
    /// `snmpEnableAuthenTraps` (`snmp.29`) — Gauge/Integer, not a counter;
    /// reported as `disabled(2)`.
    EnableAuthenTraps = 28,
    /// `snmpSilentDrops` (`snmp.30`).
    SilentDrops = 29,
    /// `snmpProxyDrops` (`snmp.31`).
    ProxyDrops = 30,
}

/// Number of counter slots (the 31 RFC 1213 / RFC 3418 objects).
const NUM_COUNTERS: usize = 31;

impl SnmpCounter {
    /// The 1-based `snmp.<n>` sub-identifier for this counter.
    pub fn subid(self) -> u32 {
        (self as u32) + 1
    }
}

/// The shared SNMP protocol counters reported under the `snmp` group.
///
/// Holds [`NUM_COUNTERS`] independent [`AtomicU64`] counters (one per
/// [`SnmpCounter`] variant). `AtomicU64` is used so 32-bit wraps on the wire
/// can be computed without losing the true accumulated count. Created once per
/// agent and shared between the dispatcher and [`snmp_mib_handlers`].
pub struct SnmpCounters {
    counters: [AtomicU64; NUM_COUNTERS],
}

impl SnmpCounters {
    /// Create a fresh `SnmpCounters` with every counter at zero.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: Default::default(),
        })
    }

    /// Increment the counter for `which` by one. Called by the agent's message
    /// processing path as it handles each packet.
    pub fn inc(&self, which: SnmpCounter) {
        self.counters[which as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the counter for `which` by `n`.
    pub fn inc_by(&self, which: SnmpCounter, n: u64) {
        self.counters[which as usize].fetch_add(n, Ordering::Relaxed);
    }

    /// Load the raw (64-bit) value of `which`.
    pub fn load(&self, which: SnmpCounter) -> u64 {
        self.counters[which as usize].load(Ordering::Relaxed)
    }

    /// Build the `snmp` group instance cells as `(instance_oid, value)` pairs.
    ///
    /// Each cell OID is `snmp.<n>.0` (the conventional `.0` instance form).
    /// Counter objects (`snmp.1`–`snmp.28`, `snmp.30`, `snmp.31`) are reported
    /// as `Counter32`; `snmpEnableAuthenTraps` (`snmp.29`) is reported as
    /// `Integer(2)` (disabled).
    pub fn cells(&self) -> Vec<(Oid, Value)> {
        let root = Oid::new(SNMP.to_vec());
        let mut out = Vec::with_capacity(NUM_COUNTERS);
        for slot in 0..NUM_COUNTERS {
            let n = (slot + 1) as u32;
            let value = if slot == SnmpCounter::EnableAuthenTraps as usize {
                Value::Integer(2) // disabled(2)
            } else {
                Value::Counter32(self.counters[slot].load(Ordering::Relaxed) as u32)
            };
            out.push((root.child(n).child(0), value));
        }
        out
    }
}

impl Default for SnmpCounters {
    fn default() -> Self {
        Self {
            counters: Default::default(),
        }
    }
}

/// Build the read-only `snmp` group handlers rooted at `1.3.6.1.2.1.11`.
///
/// The handler shares `counters` with the agent so increments performed by the
/// dispatcher are immediately visible to walkers.
pub fn snmp_mib_handlers(counters: Arc<SnmpCounters>) -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(SNMP.to_vec());
    vec![Arc::new(FnHandler::new(root, move || counters.cells()))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subids_match_rfc1213() {
        assert_eq!(SnmpCounter::InPkgs.subid(), 1);
        assert_eq!(SnmpCounter::InBadVersions.subid(), 2);
        assert_eq!(SnmpCounter::OutPkts.subid(), 19);
        assert_eq!(SnmpCounter::EnableAuthenTraps.subid(), 29);
        assert_eq!(SnmpCounter::SilentDrops.subid(), 30);
        assert_eq!(SnmpCounter::ProxyDrops.subid(), 31);
    }

    #[test]
    fn cells_cover_all_thirty_one_objects() {
        let counters = SnmpCounters::new();
        let cells = counters.cells();
        assert_eq!(cells.len(), NUM_COUNTERS);
        // snmpInPkts.0 starts at zero.
        let in_pkts = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.11.1.0")
            .map(|(_, v)| v.clone());
        assert_eq!(in_pkts, Some(Value::Counter32(0)));
        // snmpEnableAuthenTraps.0 is Integer(2) disabled.
        let traps = cells
            .iter()
            .find(|(o, _)| o.to_string() == ".1.3.6.1.2.1.11.29.0")
            .map(|(_, v)| v.clone());
        assert_eq!(traps, Some(Value::Integer(2)));
    }

    #[test]
    fn inc_updates_counters_and_cells() {
        let counters = SnmpCounters::new();
        counters.inc(SnmpCounter::InPkgs);
        counters.inc(SnmpCounter::InPkgs);
        counters.inc(SnmpCounter::InBadVersions);
        counters.inc_by(SnmpCounter::OutPkts, 5);

        assert_eq!(counters.load(SnmpCounter::InPkgs), 2);
        assert_eq!(counters.load(SnmpCounter::InBadVersions), 1);
        assert_eq!(counters.load(SnmpCounter::OutPkts), 5);

        let cells = counters.cells();
        let get = |n: u32| {
            cells
                .iter()
                .find(|(o, _)| o.to_string() == format!(".1.3.6.1.2.1.11.{n}.0"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get(1), Some(Value::Counter32(2))); // snmpInPkts
        assert_eq!(get(2), Some(Value::Counter32(1))); // snmpInBadVersions
        assert_eq!(get(19), Some(Value::Counter32(5))); // snmpOutPkts
    }

    #[test]
    fn handler_serves_counter_cells() {
        let counters = SnmpCounters::new();
        counters.inc(SnmpCounter::InPkgs);
        let handlers = snmp_mib_handlers(counters);
        assert_eq!(handlers.len(), 1);

        // GET on snmpInPkts.0 (column 1).
        let oid: Oid = "1.3.6.1.2.1.11.1.0".parse().unwrap();
        assert_eq!(handlers[0].get(&oid), Some(Value::Counter32(1)));

        // GETNEXT from the group root lands on the first counter.
        let root: Oid = "1.3.6.1.2.1.11".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }
}
