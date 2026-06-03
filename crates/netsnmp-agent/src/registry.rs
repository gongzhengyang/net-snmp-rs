//! MIB subtree registry and request dispatch.
//!
//! Counterpart of `agent/agent_registry.c` and the request dispatch in
//! `agent/snmp_agent.c`. The registry owns a set of [`MibHandler`]s keyed by
//! their root OID and routes each varbind to the correct handler.

use crate::handler::MibHandler;
use netsnmp::oid::Oid;
use netsnmp::pdu::{ErrorStatus, Pdu, PduType, VarBind};
use netsnmp::value::Value;
use std::sync::Arc;

/// A registry of MIB handlers, sorted by subtree root for ordered traversal.
#[derive(Default)]
pub struct Registry {
    handlers: Vec<Arc<dyn MibHandler>>,
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

    /// Resolve a single SET varbind, returning the SNMP error-status.
    fn do_set(&self, oid: &Oid, value: &Value) -> ErrorStatus {
        match self.handler_for(oid) {
            Some(h) => match h.set(oid, value) {
                Ok(()) => ErrorStatus::NoError,
                Err(status) => status,
            },
            None => ErrorStatus::NotWritable,
        }
    }

    /// Process a request PDU and produce the response PDU, implementing the
    /// GET/GETNEXT/GETBULK/SET semantics of RFC 3416.
    pub fn process(&self, request: &Pdu) -> Pdu {
        let mut response = Pdu::new(PduType::Response, request.request_id);

        match request.pdu_type {
            PduType::Get => {
                for vb in &request.variables {
                    response
                        .variables
                        .push(VarBind::new(vb.oid.clone(), self.do_get(&vb.oid)));
                }
            }
            PduType::GetNext => {
                for vb in &request.variables {
                    response.variables.push(self.do_get_next(&vb.oid));
                }
            }
            PduType::GetBulk => {
                self.process_bulk(request, &mut response);
            }
            PduType::Set => {
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

    /// SET: validate/apply each binding. On the first failure, report the
    /// error-status and 1-based error-index, echoing the request varbinds.
    fn process_set(&self, request: &Pdu, response: &mut Pdu) {
        for (idx, vb) in request.variables.iter().enumerate() {
            let status = self.do_set(&vb.oid, &vb.value);
            if !status.is_ok() {
                response.error_status = status.code();
                response.error_index = (idx + 1) as i64;
                response.variables = request.variables.clone();
                return;
            }
        }
        // Success: echo back the new values.
        response.variables = request.variables.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::{MapHandler, ScalarHandler};

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
}
