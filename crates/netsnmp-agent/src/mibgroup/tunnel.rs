//! TUNNEL-MIB (`1.3.6.1.2.1.10.131`) — RFC 4087.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/tunnel`. The TUNNEL-MIB exposes
//! the configured tunnel interfaces. On a host without tunnel interfaces
//! configured (or without `/proc/net`-style introspection) the table is empty.
//! The handler remains walkable.
//!
//! Objects exposed (structurally, all empty):
//! * `tunnelIfTable` (`10.131.1.1`) — one row per tunnel interface.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// TUNNEL-MIB root: `1.3.6.1.2.1.10.131`.
const TUNNEL: [u32; 8] = [1, 3, 6, 1, 2, 1, 10, 131];

/// `tunnelIfEntry` columns (RFC 4087 §3.1).
mod col {
    /// `tunnelIfLocalAddress` — the source address of the tunnel.
    pub const LOCAL_ADDRESS: u32 = 1;
    /// `tunnelIfRemoteAddress` — the destination address.
    pub const REMOTE_ADDRESS: u32 = 2;
    /// `tunnelIfEncapsMethod` — the encapsulation (`direct(1)`, …).
    pub const ENCAPS_METHOD: u32 = 3;
    /// `tunnelIfHopLimit` — the TTL/hop limit.
    pub const HOP_LIMIT: u32 = 4;
    /// `tunnelIfSecurity` — the security model in use.
    pub const SECURITY: u32 = 5;
    /// `tunnelIfTOS` — the TOS/traffic-class value.
    pub const TOS: u32 = 6;
}

/// Build the (empty) `tunnelIfTable` cells. Returns an empty vector on hosts
/// without configured tunnels.
pub fn tunnel_cells() -> Vec<(Oid, Value)> {
    let _ = (col::LOCAL_ADDRESS, col::REMOTE_ADDRESS, col::ENCAPS_METHOD,
             col::HOP_LIMIT, col::SECURITY, col::TOS);
    Vec::new()
}

/// Build the [`MibHandler`] set for the TUNNEL-MIB. The `tunnelIfTable`
/// handler is rooted at `1.3.6.1.2.1.10.131.1.1` and is empty on hosts without
/// tunnel interfaces, but walkable without error.
pub fn tunnel_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(TUNNEL.to_vec()).child(1).child(1);
    vec![Arc::new(FnHandler::new(root, tunnel_cells))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_table_is_empty_but_walkable() {
        let handlers = tunnel_handlers();
        assert_eq!(handlers.len(), 1);
        let root = handlers[0].root().clone();
        assert!(handlers[0].get_next(&root).is_none());
    }

    #[test]
    fn handler_rooted_at_tunnel_if_table() {
        let handlers = tunnel_handlers();
        assert_eq!(handlers[0].root().to_string(), ".1.3.6.1.2.1.10.131.1.1");
    }
}
