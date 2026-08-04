//! SCTP-MIB (`1.3.6.1.2.1.105`) — RFC 3873.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/sctp`. The SCTP-MIB exposes
//! per-endpoint and per-association SCTP statistics. On a host without SCTP
//! support (or with no active associations) the scalar group reports zeros and
//! the association table is empty.
//!
//! Objects exposed (scalars, all zero on hosts without SCTP):
//! * `sctpRtoAlgorithm.0` (col 1) — `other(1)` when no algorithm is reported.
//! * `sctpRtoMin.0` (col 2).
//! * `sctpRtoMax.0` (col 3).
//! * `sctpRtoInitial.0` (col 4).
//! * `sctpMaxAssocs.0` (col 7) — `4294967295` (unlimited) per RFC 3873.
//! * `sctpValCookieLife.0` (col 9).
//! * `sctpMaxInitRetr.0` (col 10).

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// SCTP-MIB root: `1.3.6.1.2.1.105`.
const SCTP: [u32; 7] = [1, 3, 6, 1, 2, 1, 105];

/// `sctpParams` scalar columns (RFC 3873 §4.1).
mod col {
    /// `sctpRtoAlgorithm` — `other(1)`.
    pub const RTO_ALGORITHM: u32 = 1;
    /// `sctpRtoMin`.
    pub const RTO_MIN: u32 = 2;
    /// `sctpRtoMax`.
    pub const RTO_MAX: u32 = 3;
    /// `sctpRtoInitial`.
    pub const RTO_INITIAL: u32 = 4;
    /// `sctpMaxAssocs` — `4294967295` means unlimited.
    pub const MAX_ASSOCS: u32 = 7;
    /// `sctpValCookieLife`.
    pub const VAL_COOKIE_LIFE: u32 = 9;
    /// `sctpMaxInitRetr`.
    pub const MAX_INIT_RETR: u32 = 10;
}

/// Build the SCTP scalar instance cells (OID -> value). All values are zero
/// except `sctpRtoAlgorithm` (`other(1)`) and `sctpMaxAssocs` (unlimited).
pub fn sctp_scalar_cells() -> Vec<(Oid, Value)> {
    let root = Oid::new(SCTP.to_vec());
    vec![
        (root.child(col::RTO_ALGORITHM).child(0), Value::Integer(1)),
        (root.child(col::RTO_MIN).child(0), Value::Integer(0)),
        (root.child(col::RTO_MAX).child(0), Value::Integer(0)),
        (root.child(col::RTO_INITIAL).child(0), Value::Integer(0)),
        (root.child(col::MAX_ASSOCS).child(0), Value::Gauge32(u32::MAX)),
        (root.child(col::VAL_COOKIE_LIFE).child(0), Value::Integer(0)),
        (root.child(col::MAX_INIT_RETR).child(0), Value::Integer(0)),
    ]
}

/// Build the [`MibHandler`] set for the SCTP-MIB. The scalar handler is rooted
/// at `1.3.6.1.2.1.105` and reports zeros for hosts without SCTP. A per-
/// association table handler (`sctpAssocTable`, `105.3.1`) is also installed
/// and remains empty.
pub fn sctp_handlers() -> Vec<Arc<dyn MibHandler>> {
    let scalar_root = Oid::new(SCTP.to_vec());
    let assoc_root = Oid::new(SCTP.to_vec()).child(3).child(1);
    vec![
        Arc::new(FnHandler::new(scalar_root, sctp_scalar_cells)),
        Arc::new(FnHandler::new(assoc_root, Vec::new)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_report_zero_or_unlimited() {
        let cells = sctp_scalar_cells();
        // sctpRtoAlgorithm.0 = other(1).
        let algo = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.105.1.0"
        });
        assert_eq!(algo.map(|(_, v)| v.clone()), Some(Value::Integer(1)));
        // sctpRtoMin.0 = 0.
        let rto_min = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.105.2.0"
        });
        assert_eq!(rto_min.map(|(_, v)| v.clone()), Some(Value::Integer(0)));
        // sctpMaxAssocs.0 = 4294967295 (unlimited).
        let max = cells.iter().find(|(o, _)| {
            o.to_string() == ".1.3.6.1.2.1.105.7.0"
        });
        assert_eq!(max.map(|(_, v)| v.clone()), Some(Value::Gauge32(u32::MAX)));
    }

    #[test]
    fn handlers_rooted_correctly() {
        let handlers = sctp_handlers();
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].root().to_string(), ".1.3.6.1.2.1.105");
        assert_eq!(handlers[1].root().to_string(), ".1.3.6.1.2.1.105.3.1");
    }

    #[test]
    fn getnext_walks_scalars_in_order() {
        let handlers = sctp_handlers();
        let root: Oid = "1.3.6.1.2.1.105".parse().unwrap();
        let first = handlers[0].get_next(&root).expect("first scalar");
        assert_eq!(first.oid.to_string(), ".1.3.6.1.2.1.105.1.0");
        // Association table is empty.
        let assoc_root: Oid = "1.3.6.1.2.1.105.3.1".parse().unwrap();
        assert!(handlers[1].get_next(&assoc_root).is_none());
    }
}
