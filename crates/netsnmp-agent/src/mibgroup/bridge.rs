//! BRIDGE-MIB (`1.3.6.1.2.1.17`) — RFC 4188.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/brIpNetToMediaTable` /
//! `bridge` modules. The BRIDGE-MIB exposes the spanning-tree and forwarding
//! state of an 802.1D bridge. A typical host is **not** a bridge, so both
//! `dot1dBasePortTable` and `dot1dTpFdbTable` are empty here. The handlers
//! remain walkable: a manager GETNEXT-walking the subtree sees no rows and no
//! errors, which matches the C agent's behaviour on a non-bridge host.
//!
//! Objects exposed (structurally, all empty):
//! * `dot1dBasePortTable` (`17.1.4.1`) — bridge ports.
//! * `dot1dTpFdbTable` (`17.4.3.1`) — the forwarding database.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// BRIDGE-MIB root: `1.3.6.1.2.1.17`.
const BRIDGE: [u32; 7] = [1, 3, 6, 1, 2, 1, 17];

/// `dot1dBasePortEntry` columns (RFC 4188 §6.1). The empty table exposes only
/// the column OIDs so a GETNEXT walk terminates cleanly.
mod base_port {
    /// `dot1dBasePort` — the bridge port number.
    pub const PORT: u32 = 1;
    /// `dot1dBasePortIfIndex` — the corresponding `ifIndex`.
    pub const IF_INDEX: u32 = 2;
    /// `dot1dBasePortCircuit` — the circuit on which the port resides.
    pub const CIRCUIT: u32 = 3;
    /// `dot1dBasePortDelayExceededDiscards`.
    pub const DELAY_DISCARDS: u32 = 4;
    /// `dot1dBasePortMtuExceededDiscards`.
    pub const MTU_DISCARDS: u32 = 5;
}

/// `dot1dTpFdbEntry` columns (RFC 4188 §6.5).
mod tp_fdb {
    /// `dot1dTpFdbAddress` — the MAC address.
    pub const ADDRESS: u32 = 1;
    /// `dot1dTpFdbPort` — the port on which the address was learned.
    pub const PORT: u32 = 2;
    /// `dot1dTpFdbStatus` — `other(1)…invalid(4)`.
    pub const STATUS: u32 = 3;
}

/// Build the (empty) bridge MIB cells. The column-OID roots are not registered
/// as instances — only concrete rows would be — so this returns an empty
/// vector, mirroring a non-bridge host. Kept as a function so the column
/// numbers above remain referenced and documented.
pub fn bridge_cells() -> Vec<(Oid, Value)> {
    let _ = (base_port::PORT, base_port::IF_INDEX, base_port::CIRCUIT,
             base_port::DELAY_DISCARDS, base_port::MTU_DISCARDS,
             tp_fdb::ADDRESS, tp_fdb::PORT, tp_fdb::STATUS);
    Vec::new()
}

/// Build the [`MibHandler`] set for the BRIDGE-MIB. Both the
/// `dot1dBasePortTable` and `dot1dTpFdbTable` handlers are empty (no bridge
/// ports, no forwarding entries) but walkable without error.
pub fn bridge_handlers() -> Vec<Arc<dyn MibHandler>> {
    let base_root = Oid::new(BRIDGE.to_vec()).child(1).child(4);
    let fdb_root = Oid::new(BRIDGE.to_vec()).child(4).child(3);
    vec![
        Arc::new(FnHandler::new(base_root, bridge_cells)),
        Arc::new(FnHandler::new(fdb_root, bridge_cells)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_tables_are_empty_but_walkable() {
        let handlers = bridge_handlers();
        assert_eq!(handlers.len(), 2);
        for h in &handlers {
            let root = h.root().clone();
            // GETNEXT from the table root returns None (empty) but must not panic.
            assert!(h.get_next(&root).is_none());
        }
    }

    #[test]
    fn handlers_rooted_at_correct_subtrees() {
        let handlers = bridge_handlers();
        assert_eq!(handlers[0].root().to_string(), ".1.3.6.1.2.1.17.1.4");
        assert_eq!(handlers[1].root().to_string(), ".1.3.6.1.2.1.17.4.3");
    }
}
