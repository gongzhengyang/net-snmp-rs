//! MIB subtree registry and request dispatch.
//!
//! Counterpart of `agent/agent_registry.c` and the request dispatch in
//! `agent/snmp_agent.c`. The registry owns a set of [`MibHandler`]s keyed by
//! their root OID and routes each varbind to the correct handler.

use crate::handler::MibHandler;
use crate::vacm::{AccessView, Vacm};
use netsnmp::oid::Oid;
use netsnmp::pdu::{ErrorStatus, Pdu, PduType, VarBind};
use netsnmp::value::Value;
use std::sync::Arc;

/// A registry of MIB handlers, sorted by subtree root for ordered traversal.
#[derive(Default)]
pub struct Registry {
    handlers: Vec<Arc<dyn MibHandler>>,
}

/// The security context of an incoming request, consulted by
/// [`Registry::process_with_access`] for VACM access checks.
///
/// Mirrors the `netsnmp_session` security fields the C agent threads through
/// request dispatch. When `vacm` is `None` (or points at an empty [`Vacm`]),
/// [`Registry::process_with_access`] is permissive — exactly matching the
/// legacy [`Registry::process`] behaviour, which delegates to it with a
/// permissive context.
#[derive(Clone, Debug, Default)]
pub struct SecurityContext {
    /// The security model of the request (`1`=v1, `2`=v2c, `3`=USM).
    pub security_model: i32,
    /// The security name (community string or USM user name).
    pub security_name: Vec<u8>,
    /// The security level (0=noAuthNoPriv, 1=authNoPriv, 3=authPriv).
    pub security_level: i32,
    /// The context name (empty for v1/v2c and the default v3 context).
    pub context: Vec<u8>,
    /// The VACM to consult. `None` means permissive (no access control).
    pub vacm: Option<Arc<Vacm>>,
}

impl SecurityContext {
    /// Build a permissive security context (no VACM enforcement). Used by the
    /// legacy [`Registry::process`] path so it behaves exactly as before.
    pub fn permissive() -> Self {
        SecurityContext::default()
    }

    /// Whether the caller may access `oid` for the given view type under this
    /// context's VACM. Returns `true` when VACM is unset or empty.
    fn allows(&self, view_type: AccessView, oid: &Oid) -> bool {
        let Some(vacm) = &self.vacm else {
            return true;
        };
        vacm.is_view_accessible(
            view_type,
            self.security_model,
            &self.security_name,
            self.security_level,
            &self.context,
            oid,
        )
    }
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Registry {
            handlers: Vec::new(),
        }
    }

    /// Register a handler. Handlers are kept sorted by their root OID so that
    /// GETNEXT can walk subtrees in lexicographic order.
    pub fn register(&mut self, handler: Arc<dyn MibHandler>) {
        self.handlers.push(handler);
        self.handlers.sort_by(|a, b| a.root().cmp(b.root()));
    }

    /// Find the handler whose root is a prefix of `oid` (for GET/SET).
    fn handler_for(&self, oid: &Oid) -> Option<&Arc<dyn MibHandler>> {
        self.handlers
            .iter()
            .filter(|h| h.root().is_prefix_of(oid))
            // Longest matching root wins.
            .max_by_key(|h| h.root().len())
    }

    /// Resolve a single GET varbind.
    fn do_get(&self, oid: &Oid) -> Value {
        match self.handler_for(oid) {
            Some(h) => h.get(oid).unwrap_or(Value::NoSuchInstance),
            None => Value::NoSuchObject,
        }
    }

    /// Resolve a single GETNEXT varbind, walking across handlers as needed.
    fn do_get_next(&self, oid: &Oid) -> VarBind {
        // Handlers are sorted; try each whose subtree could contain a successor.
        for h in &self.handlers {
            // Skip handlers entirely below the requested oid's potential range.
            if let Some(reading) = h.get_next(oid) {
                return VarBind::new(reading.oid, reading.value);
            }
        }
        // No successor anywhere: end of MIB view (SNMPv2) at the same OID.
        VarBind::new(oid.clone(), Value::EndOfMibView)
    }

    /// Resolve a single GETNEXT varbind subject to VACM access control, skipping
    /// successors the caller may not read. Walks past denied OIDs until it finds
    /// an accessible one (or reaches the end of the MIB view).
    ///
    /// This mirrors net-snmp's `VIEW_UNACCESSIBLE` behaviour for GETNEXT/
    /// GETBULK: an inaccessible candidate is silently skipped rather than
    /// reported, so a walk never leaks the existence of hidden OIDs.
    ///
    /// When the walk exhausts the MIB, the returned `EndOfMibView` varbind
    /// carries the *last accessible* OID (or the requested `oid` if nothing was
    /// accessible) — never a denied OID, so hidden subtree locations are not
    /// leaked through the varbind's OID field.
    fn do_get_next_accessible(&self, oid: &Oid, sec: &SecurityContext) -> VarBind {
        let mut cursor = oid.clone();
        let last_accessible = oid.clone();
        loop {
            let next = self.do_get_next(&cursor);
            if next.value == Value::EndOfMibView {
                // End of MIB reached: report EndOfMibView at the last accessible
                // position, not at any denied candidate we walked past.
                return VarBind::new(last_accessible, Value::EndOfMibView);
            }
            if sec.allows(AccessView::Read, &next.oid) {
                return next;
            }
            // Access denied: keep walking from the candidate. Guard against an
            // infinite loop if a handler returns a non-advancing successor.
            if next.oid <= cursor {
                return VarBind::new(last_accessible, Value::EndOfMibView);
            }
            cursor = next.oid;
        }
    }

    /// Process a request PDU and produce the response PDU, implementing the
    /// GET/GETNEXT/GETBULK/SET semantics of RFC 3416.
    ///
    /// This is the legacy permissive path: no VACM access checks are applied.
    /// It delegates to [`Registry::process_with_access`] with a permissive
    /// [`SecurityContext`], so existing callers behave exactly as before.
    pub fn process(&self, request: &Pdu) -> Pdu {
        self.process_with_access(request, &SecurityContext::permissive())
    }

    /// Process a request PDU with VACM access control applied per varbind.
    ///
    /// When [`SecurityContext::vacm`] is `None` or an empty [`Vacm`], this is
    /// permissive (identical to [`Registry::process`]). Once VACM is configured:
    ///
    /// * **GET** — a varbind whose OID is not in the read view yields a
    ///   `noAccess` error-status with the 1-based error-index of that varbind,
    ///   and the request varbinds are echoed back (RFC 3415 §3.2 step 4).
    /// * **GETNEXT / GETBULK** — inaccessible successors are silently skipped:
    ///   the walk continues to the next accessible OID (net-snmp's
    ///   `VIEW_UNACCESSIBLE` behaviour), so hidden OIDs are never leaked.
    /// * **SET** — a varbind whose OID is not in the write view yields
    ///   `noAccess` (error-status + 1-based error-index, echoed varbinds),
    ///   checked before any handler reservation.
    pub fn process_with_access(&self, request: &Pdu, sec: &SecurityContext) -> Pdu {
        let mut response = Pdu::new(PduType::Response, request.request_id);

        match request.pdu_type {
            PduType::Get => {
                for (idx, vb) in request.variables.iter().enumerate() {
                    if !sec.allows(AccessView::Read, &vb.oid) {
                        response.error_status = ErrorStatus::NoAccess.code();
                        response.error_index = (idx + 1) as i64;
                        response.variables = request.variables.clone();
                        return response;
                    }
                    response
                        .variables
                        .push(VarBind::new(vb.oid.clone(), self.do_get(&vb.oid)));
                }
            }
            PduType::GetNext => {
                for vb in &request.variables {
                    response.variables.push(self.do_get_next_accessible(&vb.oid, sec));
                }
            }
            PduType::GetBulk => {
                // When VACM is permissive, take the original fast path that
                // does no per-iteration access check.
                if sec.vacm.is_none() {
                    self.process_bulk(request, &mut response);
                } else {
                    self.process_bulk_accessible(request, &mut response, sec);
                }
            }
            PduType::Set => {
                // VACM write-view check up front: deny before any reservation.
                for (idx, vb) in request.variables.iter().enumerate() {
                    if !sec.allows(AccessView::Write, &vb.oid) {
                        response.error_status = ErrorStatus::NoAccess.code();
                        response.error_index = (idx + 1) as i64;
                        response.variables = request.variables.clone();
                        return response;
                    }
                }
                self.process_set(request, &mut response);
            }
            other => {
                // Trap/Inform/Report are not served by the responder role.
                response.error_status = ErrorStatus::GenErr.code();
                let _ = other;
            }
        }

        response
    }

    /// GETBULK: `non_repeaters` scalars fetched once, the rest repeated up to
    /// `max_repetitions` times via successive GETNEXT.
    fn process_bulk(&self, request: &Pdu, response: &mut Pdu) {
        let non_repeaters = request.non_repeaters().max(0) as usize;
        let max_reps = request.max_repetitions().max(0) as usize;
        let vars = &request.variables;

        for vb in vars.iter().take(non_repeaters) {
            response.variables.push(self.do_get_next(&vb.oid));
        }

        let repeaters: Vec<Oid> = vars
            .iter()
            .skip(non_repeaters)
            .map(|vb| vb.oid.clone())
            .collect();
        let mut cursors = repeaters;
        for _ in 0..max_reps {
            let mut all_end = true;
            for cursor in cursors.iter_mut() {
                let next = self.do_get_next(cursor);
                if next.value != Value::EndOfMibView {
                    all_end = false;
                }
                *cursor = next.oid.clone();
                response.variables.push(next);
            }
            if all_end {
                break;
            }
        }
    }

    /// Access-aware GETBULK: like [`Registry::process_bulk`] but each successor
    /// is checked against the read view, skipping inaccessible OIDs.
    fn process_bulk_accessible(&self, request: &Pdu, response: &mut Pdu, sec: &SecurityContext) {
        let non_repeaters = request.non_repeaters().max(0) as usize;
        let max_reps = request.max_repetitions().max(0) as usize;
        let vars = &request.variables;

        for vb in vars.iter().take(non_repeaters) {
            response
                .variables
                .push(self.do_get_next_accessible(&vb.oid, sec));
        }

        let repeaters: Vec<Oid> = vars
            .iter()
            .skip(non_repeaters)
            .map(|vb| vb.oid.clone())
            .collect();
        let mut cursors = repeaters;
        for _ in 0..max_reps {
            let mut all_end = true;
            for cursor in cursors.iter_mut() {
                let next = self.do_get_next_accessible(cursor, sec);
                if next.value != Value::EndOfMibView {
                    all_end = false;
                }
                *cursor = next.oid.clone();
                response.variables.push(next);
            }
            if all_end {
                break;
            }
        }
    }

    /// SET: validate/apply each binding via the 4-phase transaction
    /// (Reserve1 -> Reserve2 -> Commit, with Undo on commit failure).
    ///
    /// On any failure the response carries the SNMP error-status and the
    /// 1-based error-index of the offending varbind, and echoes the request
    /// varbinds (matching the legacy contract).
    ///
    /// The phases mirror Net-SNMP's "baby steps" and RFC 3416 §4.2.5:
    ///
    /// 1. **Reserve1**: every varbind is validated by
    ///    [`MibHandler::prepare_set`](crate::handler::MibHandler::prepare_set).
    ///    The first failure aborts the transaction immediately (nothing has
    ///    been committed, so no Undo is needed).
    /// 2. **Reserve2**: a second pass re-runs `prepare_set` so handlers may
    ///    detect cross-varbind conflicts once every varbind has reserved. For
    ///    the default handlers Reserve2 is a no-op.
    /// 3. **Commit**: every varbind is committed by
    ///    [`MibHandler::commit_set`](crate::handler::MibHandler::commit_set).
    ///    Commits are attempted for *all* varbinds even if one fails (per RFC
    ///    3416); the first failure is reported and Undo is best-effort invoked
    ///    on the varbinds already committed.
    fn process_set(&self, request: &Pdu, response: &mut Pdu) {
        // Resolve each varbind's handler up front so we can re-use it across
        // phases. A varbind with no handler is NotWritable (reserve failure).
        let plans: Vec<(Option<&Arc<dyn MibHandler>>, &VarBind)> = request
            .variables
            .iter()
            .map(|vb| (self.handler_for(&vb.oid), vb))
            .collect();

        // --- Reserve1: per-varbind validation. First failure aborts. ---
        for (idx, (handler, vb)) in plans.iter().enumerate() {
            let status = match handler {
                Some(h) => match h.prepare_set(&vb.oid, &vb.value) {
                    Ok(()) => ErrorStatus::NoError,
                    Err(s) => s,
                },
                None => ErrorStatus::NotWritable,
            };
            if !status.is_ok() {
                response.error_status = status.code();
                response.error_index = (idx + 1) as i64;
                response.variables = request.variables.clone();
                return;
            }
        }

        // --- Reserve2: second validation pass for cross-varbind checks. ---
        // Handlers may detect conflicts once they know every varbind passed
        // Reserve1; the default `prepare_set` is a no-op, so existing
        // handlers incur no extra cost.
        for (idx, (handler, vb)) in plans.iter().enumerate() {
            let status = match handler {
                Some(h) => match h.prepare_set(&vb.oid, &vb.value) {
                    Ok(()) => ErrorStatus::NoError,
                    Err(s) => s,
                },
                None => ErrorStatus::NotWritable,
            };
            if !status.is_ok() {
                response.error_status = status.code();
                response.error_index = (idx + 1) as i64;
                response.variables = request.variables.clone();
                return;
            }
        }

        // --- Commit: apply side effects. Per RFC 3416, attempt every
        // varbind even on failure, then best-effort undo the ones already
        // committed. Report the first failure. ---
        let mut commit_failed: Option<(usize, ErrorStatus)> = None;
        let mut committed: Vec<usize> = Vec::with_capacity(plans.len());
        for (idx, (handler, vb)) in plans.iter().enumerate() {
            // A varbind with no handler should already have failed Reserve1.
            let h = match handler {
                Some(h) => *h,
                None => {
                    if commit_failed.is_none() {
                        commit_failed = Some((idx, ErrorStatus::NotWritable));
                    }
                    continue;
                }
            };
            match h.commit_set(&vb.oid, &vb.value) {
                Ok(()) => committed.push(idx),
                Err(s) => {
                    if commit_failed.is_none() {
                        commit_failed = Some((idx, s));
                    }
                }
            }
        }

        if let Some((idx, status)) = commit_failed {
            // Best-effort undo of the varbinds that were committed before the
            // failure. Per RFC 3416 §4.2.5 the agent may report commitFailed
            // (or undoFailed if undo itself breaks).
            let mut undo_failed = false;
            for &cidx in &committed {
                let (_, vb) = plans[cidx];
                if let Some(h) = self.handler_for(&vb.oid) {
                    if h.undo_set(&vb.oid, &vb.value).is_err() {
                        undo_failed = true;
                    }
                }
            }
            let reported = if undo_failed {
                ErrorStatus::UndoFailed
            } else {
                status
            };
            response.error_status = reported.code();
            response.error_index = (idx + 1) as i64;
            response.variables = request.variables.clone();
            return;
        }

        // Success: echo back the new values.
        response.variables = request.variables.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{MibHandler, Reading};
    use crate::scalar::{MapHandler, ScalarHandler};
    use std::sync::Mutex;

    fn sample_registry() -> Registry {
        let mut reg = Registry::new();
        reg.register(Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1.1".parse().unwrap(),
            Value::OctetString(b"net-snmp-rs".to_vec()),
        )));
        reg.register(Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1.5".parse().unwrap(),
            Value::OctetString(b"agent01".to_vec()),
        )));
        let if_descr: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
        reg.register(Arc::new(
            MapHandler::new(if_descr.clone())
                .with(if_descr.child(1), Value::OctetString(b"lo".to_vec()))
                .with(if_descr.child(2), Value::OctetString(b"eth0".to_vec())),
        ));
        reg
    }

    #[test]
    fn get_hit_and_miss() {
        let reg = sample_registry();
        let pdu = Pdu::new(PduType::Get, 1)
            .with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap())
            .with_null_var("1.3.6.1.2.1.1.9.0".parse().unwrap())
            .with_null_var("1.3.6.1.2.1.1.1.7".parse().unwrap());
        let resp = reg.process(&pdu);
        assert_eq!(
            resp.variables[0].value,
            Value::OctetString(b"net-snmp-rs".to_vec())
        );
        // No handler's root is a prefix of ...1.9.0, so the whole object is absent.
        assert_eq!(resp.variables[1].value, Value::NoSuchObject);
        // sysDescr exists, but instance .7 does not (only .0 is served).
        assert_eq!(resp.variables[2].value, Value::NoSuchInstance);
    }

    #[test]
    fn getnext_walks_in_order() {
        let reg = sample_registry();
        // Start below everything and walk the whole tree.
        let mut current: Oid = "1.3.6.1.2.1.1".parse().unwrap();
        let mut seen = Vec::new();
        loop {
            let pdu = Pdu::new(PduType::GetNext, 1).with_null_var(current.clone());
            let resp = reg.process(&pdu);
            let vb = &resp.variables[0];
            if vb.value == Value::EndOfMibView {
                break;
            }
            seen.push(vb.oid.to_string());
            current = vb.oid.clone();
        }
        assert_eq!(
            seen,
            vec![
                ".1.3.6.1.2.1.1.1.0",
                ".1.3.6.1.2.1.1.5.0",
                ".1.3.6.1.2.1.2.2.1.2.1",
                ".1.3.6.1.2.1.2.2.1.2.2",
            ]
        );
    }

    #[test]
    fn getbulk_repeats() {
        let reg = sample_registry();
        let pdu = {
            let mut p = Pdu::new(PduType::GetBulk, 1);
            p.error_status = 0; // non-repeaters
            p.error_index = 10; // max-repetitions
            p.variables
                .push(VarBind::null("1.3.6.1.2.1.2.2.1.2".parse().unwrap()));
            p
        };
        let resp = reg.process(&pdu);
        // Two interface rows then endOfMibView.
        assert!(resp.variables.len() >= 2);
        assert_eq!(resp.variables[0].oid.to_string(), ".1.3.6.1.2.1.2.2.1.2.1");
        assert_eq!(resp.variables[1].oid.to_string(), ".1.3.6.1.2.1.2.2.1.2.2");
    }

    #[test]
    fn set_read_only_fails() {
        let reg = sample_registry();
        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(
            "1.3.6.1.2.1.1.5.0".parse().unwrap(),
            Value::OctetString(b"newname".to_vec()),
        ));
        let resp = reg.process(&pdu);
        assert_eq!(resp.status(), ErrorStatus::NotWritable);
        assert_eq!(resp.error_index, 1);
    }

    /// A handler used to exercise the transactional SET phases. It records
    /// every phase invocation into a shared log so the test can assert the
    /// ordering (reserve1, reserve2, commit, undo) and that commits are not
    /// applied when reserve fails.
    struct PhaseSpy {
        root: Oid,
        log: Arc<Mutex<Vec<&'static str>>>,
        reserve_ok: bool,
        commit_ok: bool,
        last_value: Mutex<Option<Value>>,
    }

    impl PhaseSpy {
        fn new(root: Oid, log: Arc<Mutex<Vec<&'static str>>>) -> Self {
            PhaseSpy {
                root,
                log,
                reserve_ok: true,
                commit_ok: true,
                last_value: Mutex::new(None),
            }
        }

        fn with_reserve(mut self, ok: bool) -> Self {
            self.reserve_ok = ok;
            self
        }

        fn with_commit(mut self, ok: bool) -> Self {
            self.commit_ok = ok;
            self
        }
    }

    impl MibHandler for PhaseSpy {
        fn root(&self) -> &Oid {
            &self.root
        }
        fn get(&self, _oid: &Oid) -> Option<Value> {
            self.last_value.lock().unwrap().clone()
        }
        fn get_next(&self, oid: &Oid) -> Option<Reading> {
            self.last_value
                .lock()
                .unwrap()
                .clone()
                .map(|v| Reading { oid: self.root.clone(), value: v })
                .filter(|_| oid < &self.root)
        }
        fn prepare_set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
            self.log.lock().unwrap().push("prepare");
            if self.reserve_ok {
                Ok(())
            } else {
                Err(ErrorStatus::WrongValue)
            }
        }
        fn commit_set(&self, _oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
            self.log.lock().unwrap().push("commit");
            if self.commit_ok {
                *self.last_value.lock().unwrap() = Some(value.clone());
                Ok(())
            } else {
                Err(ErrorStatus::CommitFailed)
            }
        }
        fn undo_set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
            self.log.lock().unwrap().push("undo");
            *self.last_value.lock().unwrap() = None;
            Ok(())
        }
    }

    #[test]
    fn set_transaction_runs_all_phases() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let root: Oid = "1.3.6.1.2.1.99.1".parse().unwrap();
        let mut reg = Registry::new();
        reg.register(Arc::new(PhaseSpy::new(root.clone(), Arc::clone(&log))));

        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(
            root.clone(),
            Value::Integer(7),
        ));
        let resp = reg.process(&pdu);
        assert_eq!(resp.status(), ErrorStatus::NoError);
        // prepare is called twice (Reserve1 + Reserve2), commit once.
        assert_eq!(*log.lock().unwrap(), vec!["prepare", "prepare", "commit"]);
        assert_eq!(reg.handlers[0].get(&root), Some(Value::Integer(7)));
    }

    #[test]
    fn set_reserve_failure_skips_commit_and_undo() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let root: Oid = "1.3.6.1.2.1.99.2".parse().unwrap();
        let mut reg = Registry::new();
        reg.register(Arc::new(
            PhaseSpy::new(root.clone(), Arc::clone(&log)).with_reserve(false),
        ));

        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(root.clone(), Value::Integer(7)));
        let resp = reg.process(&pdu);
        assert_eq!(resp.status(), ErrorStatus::WrongValue);
        assert_eq!(resp.error_index, 1);
        // Reserve1 fails immediately: no second prepare, no commit, no undo.
        assert_eq!(*log.lock().unwrap(), vec!["prepare"]);
        assert_eq!(reg.handlers[0].get(&root), None);
    }

    #[test]
    fn set_multi_varbind_atomicity() {
        // Two writable scalars. The second rejects in Reserve; the first
        // must NOT have been committed.
        let mut reg = Registry::new();
        let a: Oid = "1.3.6.1.2.1.99.10".parse().unwrap();
        let b: Oid = "1.3.6.1.2.1.99.20".parse().unwrap();
        reg.register(Arc::new(
            ScalarHandler::new(a.clone(), Value::OctetString(b"old-a".to_vec())).writable(),
        ));
        reg.register(Arc::new(
            ScalarHandler::new(b.clone(), Value::OctetString(b"old-b".to_vec())).writable(),
        ));

        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(
            a.child(0),
            Value::OctetString(b"new-a".to_vec()),
        ));
        // Wrong type for B (Integer onto OctetString scalar): reserve fails.
        pdu.variables
            .push(VarBind::new(b.child(0), Value::Integer(99)));
        let resp = reg.process(&pdu);
        assert_eq!(resp.status(), ErrorStatus::WrongType);
        assert_eq!(resp.error_index, 2);

        // A retains its old value: no commit happened.
        let get_a = Pdu::new(PduType::Get, 2).with_null_var(a.child(0));
        let resp_a = reg.process(&get_a);
        assert_eq!(
            resp_a.variables[0].value,
            Value::OctetString(b"old-a".to_vec())
        );
    }

    #[test]
    fn set_commit_failure_triggers_undo() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let ok_root: Oid = "1.3.6.1.2.1.99.30".parse().unwrap();
        let bad_root: Oid = "1.3.6.1.2.1.99.40".parse().unwrap();
        let mut reg = Registry::new();
        reg.register(Arc::new(PhaseSpy::new(ok_root.clone(), Arc::clone(&log))));
        reg.register(Arc::new(
            PhaseSpy::new(bad_root.clone(), Arc::clone(&log)).with_commit(false),
        ));

        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(ok_root.clone(), Value::Integer(1)));
        pdu.variables.push(VarBind::new(bad_root.clone(), Value::Integer(2)));
        let resp = reg.process(&pdu);
        assert_eq!(resp.status(), ErrorStatus::CommitFailed);
        assert_eq!(resp.error_index, 2);
        // The first handler committed, then was undone because the second failed.
        let l = log.lock().unwrap();
        assert!(l.contains(&"undo"), "expected undo to be invoked, got {l:?}");
    }

    // --- VACM access-control integration with the registry ---

    use crate::vacm::{
        AccessView, ContextMatch, Vacm, VacmAccess, VacmGroup, VacmView, ViewTreeFamilyType,
    };

    /// A `Vacm` that grants community `public` read access to only the
    /// `1.3.6.1.2.1.1` (system) subtree and write access to `1.3.6.1.2.1.1.5`.
    fn restricted_vacm() -> Arc<Vacm> {
        let vacm = Arc::new(Vacm::new());
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"ro".to_vec()),
            write_view: Some(b"rw".to_vec()),
            notify_view: None,
        });
        vacm.add_view(
            b"ro".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        vacm.add_view(
            b"rw".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1.1.5".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        vacm
    }

    fn secure_ctx(vacm: Arc<Vacm>) -> SecurityContext {
        SecurityContext {
            security_model: 2,
            security_name: b"public".to_vec(),
            security_level: 0,
            context: Vec::new(),
            vacm: Some(vacm),
        }
    }

    #[test]
    fn permissive_context_keeps_legacy_behaviour() {
        let reg = sample_registry();
        let pdu = Pdu::new(PduType::Get, 1)
            .with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap())
            .with_null_var("1.3.6.1.2.1.2.2.1.2.1".parse().unwrap());
        // No VACM -> permissive, same as process().
        let resp = reg.process_with_access(&pdu, &SecurityContext::permissive());
        assert_eq!(resp.status(), ErrorStatus::NoError);
        assert_eq!(
            resp.variables[0].value,
            Value::OctetString(b"net-snmp-rs".to_vec())
        );
        assert_eq!(
            resp.variables[1].value,
            Value::OctetString(b"lo".to_vec())
        );
    }

    #[test]
    fn get_denied_by_vacm_returns_no_access() {
        let reg = sample_registry();
        let sec = secure_ctx(restricted_vacm());
        // sysDescr (allowed) + ifDescr.1 (denied): error on the second varbind.
        let pdu = Pdu::new(PduType::Get, 1)
            .with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap())
            .with_null_var("1.3.6.1.2.1.2.2.1.2.1".parse().unwrap());
        let resp = reg.process_with_access(&pdu, &sec);
        assert_eq!(resp.status(), ErrorStatus::NoAccess);
        assert_eq!(resp.error_index, 2);
        // Request varbinds are echoed.
        assert_eq!(resp.variables.len(), 2);
    }

    #[test]
    fn getnext_skips_inaccessible_oid() {
        let reg = sample_registry();
        let sec = secure_ctx(restricted_vacm());
        // GETNEXT from below the system group: the first accessible successor is
        // sysDescr.0 (1.3.6.1.2.1.1.1.0), which is under the granted view.
        let pdu = Pdu::new(PduType::GetNext, 1)
            .with_null_var("1.3.6.1.2.1.1".parse().unwrap());
        let resp = reg.process_with_access(&pdu, &sec);
        assert_eq!(resp.status(), ErrorStatus::NoError);
        assert_eq!(resp.variables[0].oid.to_string(), ".1.3.6.1.2.1.1.1.0");
        // A GETNEXT from sysName.0 (the last accessible system row) reaches the
        // end of the accessible view (interfaces are denied) -> EndOfMibView,
        // and its OID does NOT leak any hidden interface OID.
        let pdu2 = Pdu::new(PduType::GetNext, 2)
            .with_null_var("1.3.6.1.2.1.1.5.0".parse().unwrap());
        let resp2 = reg.process_with_access(&pdu2, &sec);
        assert_eq!(resp2.variables[0].value, Value::EndOfMibView);
        // The EndOfMibView varbind must not carry a denied OID: it stays at the
        // requested (last accessible) position.
        assert_eq!(resp2.variables[0].oid.to_string(), ".1.3.6.1.2.1.1.5.0");
    }

    #[test]
    fn set_denied_by_write_view_returns_no_access() {
        let reg = sample_registry();
        let sec = secure_ctx(restricted_vacm());
        // sysName.0 is in the write view -> allowed (then fails NotWritable on
        // the read-only ScalarHandler, but that's after the VACM check).
        // ifDescr.1 is NOT in the write view -> noAccess before reservation.
        let mut pdu = Pdu::new(PduType::Set, 1);
        pdu.variables.push(VarBind::new(
            "1.3.6.1.2.1.2.2.1.2.1".parse().unwrap(),
            Value::OctetString(b"x".to_vec()),
        ));
        let resp = reg.process_with_access(&pdu, &sec);
        assert_eq!(resp.status(), ErrorStatus::NoAccess);
        assert_eq!(resp.error_index, 1);
    }

    #[test]
    fn getbulk_skips_inaccessible_rows() {
        let reg = sample_registry();
        let sec = secure_ctx(restricted_vacm());
        let pdu = {
            let mut p = Pdu::new(PduType::GetBulk, 1);
            p.error_status = 0; // non-repeaters
            p.error_index = 10; // max-repetitions
            p.variables
                .push(VarBind::null("1.3.6.1.2.1.1".parse().unwrap()));
            p
        };
        let resp = reg.process_with_access(&pdu, &sec);
        // Only sysDescr.0 and sysName.0 are accessible; no interface OIDs leak,
        // including in any trailing EndOfMibView varbind's OID field.
        for vb in &resp.variables {
            assert!(
                vb.oid.as_slice().starts_with(&[1, 3, 6, 1, 2, 1, 1]),
                "leaked inaccessible OID {}",
                vb.oid
            );
        }
        for vb in &resp.variables {
            assert!(
                vb.oid.as_slice().starts_with(&[1, 3, 6, 1, 2, 1, 1]),
                "leaked inaccessible OID {}",
                vb.oid
            );
        }
    }

    #[test]
    fn empty_vacm_is_permissive_via_process_with_access() {
        let reg = sample_registry();
        // A VACM that is configured but empty should still be permissive.
        let sec = SecurityContext {
            security_model: 2,
            security_name: b"public".to_vec(),
            security_level: 0,
            context: Vec::new(),
            vacm: Some(Arc::new(Vacm::new())),
        };
        let pdu = Pdu::new(PduType::Get, 1)
            .with_null_var("1.3.6.1.2.1.2.2.1.2.1".parse().unwrap());
        let resp = reg.process_with_access(&pdu, &sec);
        assert_eq!(resp.status(), ErrorStatus::NoError);
        assert_eq!(
            resp.variables[0].value,
            Value::OctetString(b"lo".to_vec())
        );
        // Sanity: AccessView enum is reachable.
        let _ = AccessView::Read;
    }
}
