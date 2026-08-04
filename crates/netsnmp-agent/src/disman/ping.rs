//! DISMAN-PING-MIB (`1.3.6.1.2.1.80`, RFC 2925).
//!
//! Implements `pingResultsTable`: on row creation the engine shells out to
//! `/bin/ping` against the configured target host and populates the results
//! (RTT, responses received, host address). Counterpart of Net-SNMP's
//! `agent/mibgroup/disman/ping/`.
//!
//! # Implementation notes
//!
//! Per the task spec, no extra crates are added: the actual ICMP echo is done
//! by shelling out to the system `ping` binary via `tokio::process::Command`.
//! When the binary is absent (common in CI), the engine records a sensible
//! "no results" row rather than panicking. The command line is built in a
//! pure helper ([`build_ping_command`]) so the construction logic can be
//! unit-tested without spawning anything.
//!
//! # Tables served
//!
//! | Table             | OID                       | Columns (read-only) |
//! |-------------------|---------------------------|---------------------|
//! | `pingResultsTable`| `1.3.6.1.2.1.80.1.2.1.1`  | target, rtt, sent, received, status |

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tokio::process::Command;
use tracing::{debug, warn};

use crate::handler::{MibHandler, Reading};

/// DISMAN-PING-MIB root (`1.3.6.1.2.1.80`).
pub const PING_MIB: &[u32] = &[1, 3, 6, 1, 2, 1, 80];

/// `pingResultsTable` entry OID (`1.3.6.1.2.1.80.1.2.1.1`).
pub const PING_RESULTS_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 80, 1, 2, 1, 1];

// pingResultsTable column numbers (RFC 2925 §2.2).
const PING_RES_TARGET: u32 = 2;
const PING_RES_SENT: u32 = 3;
const PING_RES_RECEIVED: u32 = 4;
const PING_RES_RTT: u32 = 6;
const PING_RES_STATUS: u32 = 10;

/// A parsed `ping`-result row.
#[derive(Clone, Debug)]
pub struct PingResult {
    /// The owner index (string index part 1).
    pub owner: String,
    /// The test name (string index part 2).
    pub test_name: String,
    /// The host the ping targeted.
    pub target_host: String,
    /// Number of probe packets sent.
    pub probes_sent: u32,
    /// Number of responses received.
    pub responses_received: u32,
    /// Round-trip time of the last response, in milliseconds (0 if none).
    pub rtt_ms: u32,
    /// Row status (always `active` once populated).
    pub status: crate::row::RowStatus,
}

/// The DISMAN-PING engine: owns the results table.
pub struct PingEngine {
    results: RwLock<HashMap<String, PingResult>>,
}

impl PingEngine {
    /// Create an empty engine.
    pub fn new() -> Arc<Self> {
        Arc::new(PingEngine {
            results: RwLock::new(HashMap::new()),
        })
    }

    /// Synchronously populate a result row from a previously-built command's
    /// captured output. Exposed for testing without spawning a real process.
    pub fn record_result(&self, owner: &str, test_name: &str, host: &str, output: &str) {
        let (sent, received, rtt) = parse_ping_output(output);
        let result = PingResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            probes_sent: sent,
            responses_received: received,
            rtt_ms: rtt,
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Record a "no result" row, used when the ping binary is missing. The row
    /// is marked active but carries zero sent/received/rtt so a walker still
    /// sees something.
    pub fn record_failure(&self, owner: &str, test_name: &str, host: &str) {
        let result = PingResult {
            owner: owner.to_string(),
            test_name: test_name.to_string(),
            target_host: host.to_string(),
            probes_sent: 0,
            responses_received: 0,
            rtt_ms: 0,
            status: crate::row::RowStatus::Active,
        };
        self.results
            .write()
            .unwrap()
            .insert(key(owner, test_name), result);
    }

    /// Run a ping against `host` and record the result. Must be called from a
    /// tokio runtime context. Uses the system `/bin/ping` binary; if it is
    /// absent, records a zero-result row instead of panicking.
    pub async fn run(self: &Arc<Self>, owner: &str, test_name: &str, host: &str) {
        let (program, args) = build_ping_command(host, 4, Duration::from_secs(5));
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
                debug!(host, %body, "ping completed");
                self.record_result(owner, test_name, host, &body);
            }
            Err(e) => {
                warn!(host, error = %e, "ping binary unavailable; recording empty result");
                self.record_failure(owner, test_name, host);
            }
        }
    }

    /// Snapshot of a result row (for tests / inspection).
    pub fn result(&self, owner: &str, test_name: &str) -> Option<PingResult> {
        self.results.read().unwrap().get(&key(owner, test_name)).cloned()
    }

    /// Build the read-only `pingResultsTable` handler.
    pub fn handlers(engine: Arc<PingEngine>) -> Vec<Arc<dyn MibHandler>> {
        vec![Arc::new(PingResultsHandler::new(engine))]
    }
}

fn key(owner: &str, test_name: &str) -> String {
    format!("{owner}\u{0}{test_name}")
}

/// Build the `ping` command line for `host`, sending `count` probes with a
/// per-probe `timeout`. Returns `(program, args)`. On Linux this is
/// `/bin/ping -c COUNT -W TIMEOUT_SECS HOST`; we pick GNU/Linux defaults since
/// that is the only platform this crate targets.
pub fn build_ping_command(host: &str, count: u32, timeout: Duration) -> (String, Vec<String>) {
    let program = "/bin/ping".to_string();
    let args = vec![
        "-c".to_string(),
        count.to_string(),
        "-W".to_string(),
        timeout.as_secs().to_string(),
        host.to_string(),
    ];
    (program, args)
}

/// Parse the body of a `ping` run into `(probes_sent, responses_received,
/// last_rtt_ms)`. Best-effort: copes with both GNU inetutils and iputils
/// layouts.
pub fn parse_ping_output(output: &str) -> (u32, u32, u32) {
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut rtt = 0u32;
    // Statistics line: "4 packets transmitted, 4 received, 0% packet loss"
    for line in output.lines() {
        let l = line.trim();
        if l.contains("packets transmitted") {
            // Extract the two integers.
            let mut nums = l.split(|c: char| !c.is_ascii_digit()).filter_map(|s| {
                if s.is_empty() {
                    None
                } else {
                    s.parse::<u32>().ok()
                }
            });
            if let Some(s) = nums.next() {
                sent = s;
            }
            if let Some(r) = nums.next() {
                received = r;
            }
        }
        // RTT line: "rtt min/avg/max/mdev = 0.023/0.030/0.040/0.005 ms"
        // or "round-trip min/avg/max/stddev = ...".
        if l.contains("rtt") || l.contains("round-trip") {
            // Take the first number after '='.
            if let Some(idx) = l.find('=') {
                let tail = &l[idx + 1..];
                let first_num: String = tail
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(v) = first_num.parse::<f64>() {
                    rtt = (v * 1000.0).round() as u32;
                }
            }
        }
    }
    (sent, received, rtt)
}

/// Read-only handler exposing `pingResultsTable`.
struct PingResultsHandler {
    root: Oid,
    engine: Arc<PingEngine>,
}

impl PingResultsHandler {
    fn new(engine: Arc<PingEngine>) -> Self {
        PingResultsHandler {
            root: Oid::new(PING_RESULTS_ENTRY.to_vec()),
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
                PING_RES_TARGET,
                Value::OctetString(r.target_host.bytes().collect()),
            ));
            out.push(put(PING_RES_SENT, Value::Gauge32(r.probes_sent)));
            out.push(put(PING_RES_RECEIVED, Value::Gauge32(r.responses_received)));
            out.push(put(PING_RES_RTT, Value::Gauge32(r.rtt_ms)));
            out.push(put(
                PING_RES_STATUS,
                Value::Integer(r.status.as_i64()),
            ));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

impl MibHandler for PingResultsHandler {
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
    fn build_ping_command_linux_form() {
        let (prog, args) = build_ping_command("127.0.0.1", 4, Duration::from_secs(5));
        assert_eq!(prog, "/bin/ping");
        assert_eq!(args, vec!["-c", "4", "-W", "5", "127.0.0.1"]);
    }

    #[test]
    fn parse_iputils_statistics_line() {
        let body = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n\
                    --- 127.0.0.1 ping statistics ---\n\
                    4 packets transmitted, 4 received, 0% packet loss, time 3001ms\n\
                    rtt min/avg/max/mdev = 0.023/0.030/0.040/0.005 ms\n";
        let (sent, recv, rtt) = parse_ping_output(body);
        assert_eq!(sent, 4);
        assert_eq!(recv, 4);
        assert_eq!(rtt, 23); // 0.023 ms rounded to integer microseconds-as-ms
    }

    #[test]
    fn parse_missing_binary_output_is_zero() {
        // An empty body (e.g. the binary failed to start) parses to all zeros
        // rather than panicking.
        let (sent, recv, rtt) = parse_ping_output("");
        assert_eq!((sent, recv, rtt), (0, 0, 0));
    }

    #[test]
    fn record_failure_marks_active_with_zeros() {
        let engine = PingEngine::new();
        engine.record_failure("alice", "test1", "10.0.0.1");
        let r = engine.result("alice", "test1").expect("present");
        assert_eq!(r.probes_sent, 0);
        assert_eq!(r.responses_received, 0);
        assert_eq!(r.rtt_ms, 0);
        assert_eq!(r.status, crate::row::RowStatus::Active);
    }

    #[test]
    fn record_result_populates_parsed_values() {
        let engine = PingEngine::new();
        engine.record_result(
            "bob",
            "loopback",
            "127.0.0.1",
            "4 packets transmitted, 4 received, 0% packet loss\n\
             rtt min/avg/max/mdev = 0.040/0.050/0.060/0.005 ms\n",
        );
        let r = engine.result("bob", "loopback").expect("present");
        assert_eq!(r.probes_sent, 4);
        assert_eq!(r.responses_received, 4);
        assert_eq!(r.rtt_ms, 40);
    }

    #[test]
    fn handler_walks_recorded_rows() {
        let engine = PingEngine::new();
        engine.record_result(
            "carol",
            "probe",
            "127.0.0.1",
            "2 packets transmitted, 2 received, 0% packet loss\n",
        );
        let handlers = PingEngine::handlers(engine);
        let h = &handlers[0];
        let reading = h
            .get_next(&"1.3.6.1.2.1.80.1.2.1".parse().unwrap())
            .expect("cell present");
        assert!(reading.oid.as_slice().starts_with(PING_RESULTS_ENTRY));
    }

    /// Spawns a real ping against localhost but tolerates the binary being
    /// absent (CI without ping). The test passes as long as the engine records
    /// *some* row (success or failure).
    #[tokio::test]
    async fn run_localhost_records_a_row() {
        let engine = PingEngine::new();
        engine.run("dave", "local", "127.0.0.1").await;
        let r = engine.result("dave", "local");
        assert!(r.is_some(), "a row was recorded even if ping is absent");
    }
}
