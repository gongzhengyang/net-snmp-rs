//! MTA-MIB (`1.3.6.1.2.1.28`) — RFC 2262.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/ucd-snmp/mta_sendmail`. The
//! MTA-MIB exposes per-mail-transport-agent statistics. On a host without a
//! managed MTA the table is empty. The handler remains walkable.
//!
//! Objects exposed (structurally, all empty):
//! * `mtaTable` (`28.1.1`) — one row per MTA instance.

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// MTA-MIB root: `1.3.6.1.2.1.28`.
const MTA: [u32; 7] = [1, 3, 6, 1, 2, 1, 28];

/// `mtaEntry` columns (RFC 2262 §3.1).
mod col {
    /// `mtaReceivedMessages` — total messages received.
    pub const RECEIVED_MESSAGES: u32 = 1;
    /// `mtaStoredMessages` — messages currently stored.
    pub const STORED_MESSAGES: u32 = 2;
    /// `mtaTransmittedMessages` — total messages transmitted.
    pub const TRANSMITTED_MESSAGES: u32 = 3;
    /// `mtaReceivedVolume` — total volume received in KB.
    pub const RECEIVED_VOLUME: u32 = 4;
    /// `mtaStoredVolume` — volume stored in KB.
    pub const STORED_VOLUME: u32 = 5;
    /// `mtaTransmittedVolume` — volume transmitted in KB.
    pub const TRANSMITTED_VOLUME: u32 = 6;
}

/// Build the (empty) `mtaTable` cells.
pub fn mta_cells() -> Vec<(Oid, Value)> {
    let _ = (col::RECEIVED_MESSAGES, col::STORED_MESSAGES, col::TRANSMITTED_MESSAGES,
             col::RECEIVED_VOLUME, col::STORED_VOLUME, col::TRANSMITTED_VOLUME);
    Vec::new()
}

/// Build the [`MibHandler`] set for the MTA-MIB. The `mtaTable` handler is
/// rooted at `1.3.6.1.2.1.28.1.1` and is empty on hosts without a managed MTA,
/// but walkable without error.
pub fn mta_handlers() -> Vec<Arc<dyn MibHandler>> {
    let root = Oid::new(MTA.to_vec()).child(1).child(1);
    vec![Arc::new(FnHandler::new(root, mta_cells))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mta_table_is_empty_but_walkable() {
        let handlers = mta_handlers();
        assert_eq!(handlers.len(), 1);
        let root = handlers[0].root().clone();
        assert!(handlers[0].get_next(&root).is_none());
    }

    #[test]
    fn handler_rooted_at_mta_table() {
        let handlers = mta_handlers();
        assert_eq!(handlers[0].root().to_string(), ".1.3.6.1.2.1.28.1.1");
    }
}
