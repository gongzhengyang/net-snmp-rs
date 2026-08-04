//! DISMAN-TRACEROUTE-MIB (`1.3.6.1.2.1.81`, RFC 2925).
//!
//! Implements `traceRouteResultsTable`: on row creation the engine shells out
//! to `/bin/traceroute` and records the round-trip time and hop count.
//! Counterpart of Net-SNMP's `agent/mibgroup/disman/traceroute/`.
//!
//! Like [`crate::disman::ping`], no extra crates are added; the actual UDP/ICMP
//! probe is delegated to the system `traceroute` binary via
//! `tokio::process::Command`. When the binary is absent, the engine records a
//! zero-result row instead of panicking.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tokio::process::Command;
use tracing::{debug, warn};

use crate::handler::{MibHandler, Reading};

/// DISMAN-TRACEROUTE-MIB root (`1.3.6.1.2.1.81`).
pub const TRACEROUTE_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 81];

/// `traceRouteResultsTable` entry OID (`1.3.6.1.2.1.81.1.2.1.1`).
pub const TRACEROUTE_RESULTS_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 81, 1, 2, 1, 1];

// traceRouteResultsTable column numbers (RFC 2925 §4.2).
const TR_RES_TARGET: u32 = 2;
const TR_RES_HOPS: u32 = 3;
const TR_RES_RTT: u32 = 5;
const TR_RES_STATUS: u32 = 10;

/// A parsed `traceroute`-result row.
#[derive(Clone, Debug)]
pub struct TracerouteResult {
    /// The owner index (string index part 1).
    pub owner: String,
    /// The test name (string index part 2).
    pub test_name: String,
    /// The host the traceroute targeted.
    pub target_host: String,
    /// Number of hops discovered.
    pub hop_count: u32,
    /// RTT of the final hop, in milliseconds (0 if unreachable).
    pub rtt_ms: u32,
    /// Row status (always `active` once populated).
    pub status: crate::row::RowStatus,
}

/// The DISMAN-TRACEROUTE engine.
pub struct TracerouteEngine {
    results: RwLock<HashMap<String, TracerouteResult>>,
}

impl TracerouteEngine {
    /// Create an empty engine.
    pub fn new() -> Arc<Self> {
        Arc::new(TracerouteEngine {
            results: RwLock::new(HashMap::new()),
        })
    }

    /// Record a result row from previously-captured command output.
    pub fn record_result(&self, owner: &str, test_name: &str, host: &str, output: &str) {
        let (hops, rtt) = parse_traceroute_output(output);
        let result = TracerouteResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            hop_count: hops,
            rtt_ms: rtt,
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Record a "no result" row, used when the binary is missing.
    pub fn record_failure(&self, owner: &str, test_name: &str, host: &str) {
        let result = TracerouteResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            hop_count: 0,
            rtt_ms: 0,
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Run a traceroute against `host` and record the result.
    pub async fn run(self: &Arc<Self>, owner: &str, test_name: &str, host: &str) {
        let (program, args) = build_traceroute_command(host, 5, Duration::from_secs(2));
        match Command::new(&program)
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
        {
            Ok(out) => {
                let body = String::from_utf8_lossy(&out.stdout);
                debug!(host, %body, "traceroute completed");
                self.record_result(owner, test_name, host, &body);
            }
            Err(e) => {
                warn!(host, error = %e, "traceroute binary unavailable; recording empty result");
                self.record_failure(owner, test_name, host);
            }
        }
    }

    /// Snapshot of a result row.
    pub fn result(&self, owner: &str, test_name: &str) -> Option<TracerouteResult> {
        self.results
            .read()
            .unwrap()
            .get(&key(owner, test_name))
            .cloned()
    }

    /// Build the read-only `traceRouteResultsTable` handler.
    pub fn handlers(engine: Arc<TracerouteEngine>) -> Vec<Arc<dyn MibHandler>> {
        vec![Arc::new(TracerouteResultsHandler::new(engine))]
    }
}

fn key(owner: &str, test_name: &str) -> String {
    format!("{owner}\u{0}{test_name}")
}

/// Build the `traceroute` command line for `host`, capping at `max_hops` hops
/// with a per-probe `timeout`. On Linux this is
/// `/bin/traceroute -m MAX_HOPS -w TIMEOUT_SECS HOST`.
pub fn build_traceroute_command(
    host: &str,
    max_hops: u32,
    timeout: Duration,
) -> (String, Vec<String>) {
    let program = "/bin/traceroute".to_string();
    let args = vec![
        "-m".to_string(),
        max_hops.to_string(),
        "-w".to_string(),
        timeout.as_secs().to_string(),
        host.to_string(),
    ];
    (program, args)
}

/// Parse a traceroute body into `(hop_count, last_rtt_ms)`. Best-effort: counts
/// the numbered hop lines and takes the RTT of the last one.
pub fn parse_traceroute_output(output: &str) -> (u32, u32) {
    let mut hops = 0u32;
    let mut rtt = 0u32;
    for line in output.lines() {
        let l = line.trim();
        // Hop lines look like " 1  192.168.1.1 (192.168.1.1)  0.423 ms ..."
        if let Some(first) = l.split_whitespace().next() {
            if first.parse::<u32>().is_ok() {
                hops = first.parse::<u32>().unwrap_or(hops);
                // Find the first "X ms" token in the line.
                let mut tokens = l.split_whitespace();
                let _ = tokens.next(); // hop number
                while let Some(t) = tokens.next() {
                    if t == "ms" {
                        // The previous token was the RTT.
                        break;
                    }
                    if let Ok(v) = t.trim_end_matches("ms").parse::<f64>() {
                        rtt = (v * 1000.0).round() as u32;
                        break;
                    }
                }
            }
        }
    }
    (hops, rtt)
}

/// Read-only handler exposing `traceRouteResultsTable`.
struct TracerouteResultsHandler {
    root: Oid,
    engine: Arc<TracerouteEngine>,
}

impl TracerouteResultsHandler {
    fn new(engine: Arc<TracerouteEngine>) -> Self {
        TracerouteResultsHandler {
            root: Oid::new(TRACEROUTE_RESULTS_ENTRY.to_vec()),
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
                TR_RES_TARGET,
                Value::OctetString(r.target_host.bytes().collect()),
            ));
            out.push(put(TR_RES_HOPS, Value::Gauge32(r.hop_count)));
            out.push(put(TR_RES_RTT, Value::Gauge32(r.rtt_ms)));
            out.push(put(TR_RES_STATUS, Value::Integer(r.status.as_i64())));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for TracerouteResultsHandler {
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

    #[test]
    fn build_traceroute_command_linux_form() {
        let (prog, args) = build_traceroute_command("8.8.8.8", 15, Duration::from_secs(2));
        assert_eq!(prog, "/bin/traceroute");
        assert_eq!(args, vec!["-m", "15", "-w", "2", "8.8.8.8"]);
    }

    #[test]
    fn parse_typical_output() {
        let body = "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets\n\
                    1  192.168.1.1 (192.168.1.1)  0.423 ms  0.398 ms  0.372 ms\n\
                    2  10.0.0.1 (10.0.0.1)  8.500 ms  8.450 ms  8.420 ms\n";
        let (hops, rtt) = parse_traceroute_output(body);
        assert_eq!(hops, 2);
        assert_eq!(rtt, 8500);
    }

    #[test]
    fn parse_missing_binary_output_is_zero() {
        let (hops, rtt) = parse_traceroute_output("");
        assert_eq!((hops, rtt), (0, 0));
    }

    #[test]
    fn record_failure_marks_active_with_zeros() {
        let engine = TracerouteEngine::new();
        engine.record_failure("alice", "trace1", "10.0.0.1");
        let r = engine.result("alice", "trace1").expect("present");
        assert_eq!(r.hop_count, 0);
        assert_eq!(r.rtt_ms, 0);
        assert_eq!(r.status, crate::row::RowStatus::Active);
    }

    #[test]
    fn handler_walks_recorded_rows() {
        let engine = TracerouteEngine::new();
        engine.record_result(
            "bob",
            "trace",
            "127.0.0.1",
            "1  127.0.0.1 (127.0.0.1)  0.100 ms\n",
        );
        let handlers = TracerouteEngine::handlers(engine);
        let h = &handlers[0];
        let reading = h
            .get_next(&"1.3.6.1.2.1.81.1.2.1".parse().unwrap())
            .expect("cell present");
        assert!(reading
            .oid
            .as_slice()
            .starts_with(TRACEROUTE_RESULTS_ENTRY));
    }

    #[tokio::test]
    async fn run_localhost_records_a_row() {
        let engine = TracerouteEngine::new();
        engine.run("carol", "local", "127.0.0.1").await;
        assert!(engine.result("carol", "local").is_some());
    }
}
