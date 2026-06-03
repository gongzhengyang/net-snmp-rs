//! MIB handler abstraction.
//!
//! Counterpart of `agent/agent_handler.c` and the `helpers/` framework. Each
//! registered MIB object or subtree is served by a [`MibHandler`] that can
//! answer GET/GETNEXT requests and (optionally) accept SET requests.

use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;

/// The access mode of a request, mirroring the agent processing modes in
/// `snmp_agent.c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A GET request for an exact instance.
    Get,
    /// A GETNEXT request: find the lexicographic successor.
    GetNext,
    /// A SET request (commit phase, simplified into a single step here).
    Set,
}

/// The result of a successful GET/GETNEXT lookup: the concrete OID and value.
#[derive(Clone, Debug, PartialEq)]
pub struct Reading {
    /// The instance OID that was read (for GETNEXT this is the successor).
    pub oid: Oid,
    /// The value at that instance.
    pub value: Value,
}

/// Trait implemented by anything that can serve part of the MIB tree.
pub trait MibHandler: Send + Sync {
    /// The OID subtree this handler is responsible for.
    fn root(&self) -> &Oid;

    /// Handle a GET for an exact instance OID. Return `None` to signal that
    /// no such instance exists (the agent maps this to `noSuchInstance`).
    fn get(&self, oid: &Oid) -> Option<Value>;

    /// Handle a GETNEXT: return the first reading strictly greater than
    /// `oid` that is still within this handler's subtree, or `None` if there
    /// is no such successor.
    fn get_next(&self, oid: &Oid) -> Option<Reading>;

    /// Handle a SET. The default implementation rejects writes as read-only.
    fn set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
}
