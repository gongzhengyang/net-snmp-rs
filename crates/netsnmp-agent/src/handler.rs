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

/// Phase of a 4-phase SET transaction (RFC 3416 §4.2.5 / Net-SNMP "baby
/// steps"). Handlers may hook any subset of these by overriding
/// [`MibHandler::prepare_set`], [`MibHandler::commit_set`] and
/// [`MibHandler::undo_set`].
///
/// The phases are, in order:
///
/// 1. [`SetPhase::Reserve1`] — per-varbind type/range validation, no side
///    effects. Equivalent to Net-SNMP `MODE_SET_BEGIN` / reserve1.
/// 2. [`SetPhase::Reserve2`] — cross-varbind consistency and resource
///    reservation. May still abort the transaction. Equivalent to reserve2.
/// 3. [`SetPhase::Commit`] — apply side effects. By RFC 3416 a commit may no
///    longer be aborted; a failure here is reported as `commitFailed`.
/// 4. [`SetPhase::Undo`] — best-effort rollback of the commits already
///    applied. Failure is reported as `undoFailed`.
/// 5. [`SetPhase::Cleanup`] — release any reservation-allocated resources
///    regardless of outcome. Not dispatched through the handler trait methods;
///    documented for completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetPhase {
    /// Reserve1: per-varbind type/range validation, no side effects.
    Reserve1,
    /// Reserve2: cross-varbind consistency and resource reservation.
    Reserve2,
    /// Commit: apply side effects.
    Commit,
    /// Undo: best-effort rollback of the commits already applied.
    Undo,
    /// Cleanup: release any reservation-allocated resources.
    Cleanup,
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
///
/// # SET transactions
///
/// SET processing is organised as a four-phase transaction by the registry
/// (see [`crate::registry::Registry::process`]). Handlers may opt in to the
/// finer-grained phases by overriding the default trait methods:
///
/// - [`MibHandler::prepare_set`] runs in Reserve1/Reserve2 to validate without
///   committing. The default accepts any value.
/// - [`MibHandler::commit_set`] runs in the Commit phase to apply the side
///   effect. The default delegates to the legacy single-step [`set`], so
///   handlers written before the transactional API continue to work unchanged.
/// - [`MibHandler::undo_set`] runs in the Undo phase to roll back. The default
///   is a documented best-effort no-op.
///
/// [`set`]: MibHandler::set
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

    /// Handle a SET (single-step commit). The default implementation rejects
    /// writes as read-only.
    ///
    /// New handlers should prefer overriding [`prepare_set`](MibHandler::prepare_set)
    /// and [`commit_set`](MibHandler::commit_set). The single-step `set` is
    /// retained for backwards compatibility: when a handler does not override
    /// `commit_set`, the registry delegates the Commit phase to this method.
    fn set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }

    /// Reserve a SET value (Reserve1/Reserve2). This is the validation phase:
    /// check type, length, range and cross-varbind consistency, but perform no
    /// lasting side effect. Returning `Err` aborts the whole transaction
    /// before any commit, so no other varbind is modified.
    ///
    /// The default implementation accepts everything. Handlers that only
    /// override [`set`](MibHandler::set) therefore keep working: the registry
    /// will call `commit_set`, which by default delegates to `set`.
    fn prepare_set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), ErrorStatus> {
        Ok(())
    }

    /// Commit a previously-reserved SET value (Commit phase). Apply the side
    /// effect here. A failure is rare and, per RFC 3416 §4.2.5, is reported as
    /// `commitFailed` once every varbind has been attempted.
    ///
    /// The default delegates to the legacy single-step [`set`](MibHandler::set),
    /// so pre-transactional handlers continue to behave exactly as before.
    fn commit_set(&self, oid: &Oid, value: &Value) -> std::result::Result<(), ErrorStatus> {
        self.set(oid, value)
    }

    /// Undo a previously-committed SET value (Undo phase), best-effort. This is
    /// only invoked after a commit failure on some varbind, for the varbinds
    /// that were already successfully committed.
    ///
    /// The default is a documented no-op returning `Ok(())`: many simple
    /// handlers cannot truly reverse a side effect, and Net-SNMP itself
    /// treats undo as best-effort. Handlers that can roll back should override
    /// this.
    fn undo_set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), ErrorStatus> {
        Ok(())
    }
}
