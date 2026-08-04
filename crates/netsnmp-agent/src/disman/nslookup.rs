//! DISMAN-NSLOOKUP-MIB (`1.3.6.1.2.1.82`, RFC 2925).
//!
//! Implements `lookupResultsTable`: on row creation the engine resolves the
//! target hostname via [`tokio::net::lookup_host`] (the system resolver, so no
//! extra DNS crate is required) and records the resolved addresses. Counterpart
//! of Net-SNMP's `agent/mibgroup/disman/nslookup/`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tracing::{debug, warn};

use crate::handler::{MibHandler, Reading};

/// DISMAN-NSLOOKUP-MIB root (`1.3.6.1.2.1.82`).
pub const NSLOOKUP_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 82];

/// `lookupResultsTable` entry OID (`1.3.6.1.2.1.82.1.2.1.1`).
pub const LOOKUP_RESULTS_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 82, 1, 2, 1, 1];

// lookupResultsTable column numbers (RFC 2925 §6.2).
const LK_RES_TARGET: u32 = 2;
const LK_RES_ADDRS: u32 = 3;
const LK_RES_COUNT: u32 = 4;
const LK_RES_STATUS: u32 = 8;

/// A parsed lookup-result row.
#[derive(Clone, Debug)]
pub struct LookupResult {
    /// The owner index (string index part 1).
    pub owner: String,
    /// The test name (string index part 2).
    pub test_name: String,
    /// The hostname that was resolved.
    pub target_host: String,
    /// The resolved addresses (in resolution order).
    pub addresses: Vec<IpAddr>,
    /// Row status (always `active` once populated).
    pub status: crate::row::RowStatus,
}

impl LookupResult {
    /// The addresses as a space-separated display string (for the
    /// `lookupResultsAddr` OctetString cell).
    pub fn addresses_display(&self) -> String {
        self.addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The DISMAN-NSLOOKUP engine.
pub struct NsLookupEngine {
    results: RwLock<HashMap<String, LookupResult>>,
}

impl NsLookupEngine {
    /// Create an empty engine.
    pub fn new() -> Arc<Self> {
        Arc::new(NsLookupEngine {
            results: RwLock::new(HashMap::new()),
        })
    }

    /// Record a result row from previously-resolved addresses.
    pub fn record_result(
        &self,
        owner: &str,
        test_name: &str,
        host: &str,
        addresses: Vec<IpAddr>,
    ) {
        let result = LookupResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            addresses,
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Record a "no result" row, used when resolution fails.
    pub fn record_failure(&self, owner: &str, test_name: &str, host: &str) {
        let result = LookupResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            addresses: Vec::new(),
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Resolve `host` via the system resolver and record the result. Uses
    /// [`tokio::net::lookup_host`]; a `host:0` form is supplied because
    /// `lookup_host` requires a `host:port` string (the port is irrelevant for
    /// name resolution and is discarded).
    pub async fn run(self: &Arc<Self>, owner: &str, test_name: &str, host: &str) {
        let lookup_target = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:0")
        };
        match tokio::net::lookup_host(&lookup_target).await {
            Ok(addrs) => {
                let addresses: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
                debug!(host, count = addresses.len(), "nslookup completed");
                self.record_result(owner, test_name, host, addresses);
            }
            Err(e) => {
                warn!(host, error = %e, "nslookup failed; recording empty result");
                self.record_failure(owner, test_name, host);
            }
        }
    }

    /// Snapshot of a result row.
    pub fn result(&self, owner: &str, test_name: &str) -> Option<LookupResult> {
        self.results
            .read()
            .unwrap()
            .get(&key(owner, test_name))
            .cloned()
    }

    /// Build the read-only `lookupResultsTable` handler.
    pub fn handlers(engine: Arc<NsLookupEngine>) -> Vec<Arc<dyn MibHandler>> {
        vec![Arc::new(LookupResultsHandler::new(engine))]
    }
}

fn key(owner: &str, test_name: &str) -> String {
    format!("{owner}\u{0}{test_name}")
}

/// Build the lookup target string passed to [`tokio::net::lookup_host`]. If the
/// host already contains a port (or is an IPv6 literal with a zone), it is
/// returned as-is; otherwise `:0` is appended. Exposed for unit testing.
pub fn build_lookup_target(host: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:0")
    }
}

/// Read-only handler exposing `lookupResultsTable`.
struct LookupResultsHandler {
    root: Oid,
    engine: Arc<NsLookupEngine>,
}

impl LookupResultsHandler {
    fn new(engine: Arc<NsLookupEngine>) -> Self {
        LookupResultsHandler {
            root: Oid::new(LOOKUP_RESULTS_ENTRY.to_vec()),
            engine,
        }
    }

    fn cells(&self) -> Vec<(Oid, Value)> {
        let results = self.engine.results.read().unwrap();
        let mut out = Vec::new();
        for r in results.values() {
            let mut index = r.owner.bytes().map(|b| b as u32).collect::<Vec<_>>();
            index.push(0);
            index.extend(r.test_name.bytes().map(|b| b as u32));
            let put = |col: u32, value: Value| -> (Oid, Value) {
                let mut oid = self.root.child(col);
                for &s in &index {
                    oid = oid.child(s);
                }
                (oid, value)
            };
            out.push(put(
                LK_RES_TARGET,
                Value::OctetString(r.target_host.bytes().collect()),
            ));
            out.push(put(
                LK_RES_ADDRS,
                Value::OctetString(r.addresses_display().into_bytes()),
            ));
            out.push(put(LK_RES_COUNT, Value::Gauge32(r.addresses.len() as u32)));
            out.push(put(LK_RES_STATUS, Value::Integer(r.status.as_i64())));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for LookupResultsHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.cells()
            .into_iter()
            .find(|(o, _)| o == oid)
            .map(|(_, v)| v)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.cells();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::MibHandler;

    #[test]
    fn build_lookup_target_appends_port() {
        assert_eq!(build_lookup_target("localhost"), "localhost:0");
        assert_eq!(build_lookup_target("localhost:80"), "localhost:80");
    }

    #[test]
    fn record_result_displays_addresses() {
        let engine = NsLookupEngine::new();
        engine.record_result(
            "alice",
            "dns1",
            "localhost",
            vec![IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))],
        );
        let r = engine.result("alice", "dns1").expect("present");
        assert_eq!(r.addresses_display(), "127.0.0.1");
        assert_eq!(r.status, crate::row::RowStatus::Active);
    }

    #[test]
    fn record_failure_marks_active_empty() {
        let engine = NsLookupEngine::new();
        engine.record_failure("bob", "bad", "nonexistent.invalid");
        let r = engine.result("bob", "bad").expect("present");
        assert!(r.addresses.is_empty());
        assert_eq!(r.status, crate::row::RowStatus::Active);
    }

    #[test]
    fn handler_walks_recorded_rows() {
        let engine = NsLookupEngine::new();
        engine.record_result(
            "carol",
            "lookup",
            "localhost",
            vec![IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))],
        );
        let handlers = NsLookupEngine::handlers(engine);
        let h = &handlers[0];
        let reading = h
            .get_next(&"1.3.6.1.2.1.82.1.2.1".parse().unwrap())
            .expect("cell present");
        assert!(reading.oid.as_slice().starts_with(LOOKUP_RESULTS_ENTRY));
    }

    /// Resolves `localhost` via the real system resolver. On any sane CI host
    /// this yields at least one loopback address; if the resolver is
    /// unavailable the engine still records an empty row, so the test asserts
    /// only that *some* row exists.
    #[tokio::test]
    async fn run_localhost_records_a_row() {
        let engine = NsLookupEngine::new();
        engine.run("dave", "local", "localhost").await;
        let r = engine.result("dave", "local");
        assert!(r.is_some(), "a row was recorded");
        // localhost should resolve to a loopback on a sane host.
        if let Some(r) = r {
            if !r.addresses.is_empty() {
                assert!(
                    r.addresses
                        .iter()
                        .any(|a| a.is_loopback()),
                    "expected a loopback address, got {:?}",
                    r.addresses
                );
            }
        }
    }
}
