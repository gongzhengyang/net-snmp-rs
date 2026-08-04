//! NOTIFICATION-LOG-MIB (`1.3.6.1.2.1.92`) `nlmLogTable` ring buffer.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/notificationlog*.c`. Each received
//! notification is appended to a bounded ring buffer; the buffer is exposed as
//! a walkable (read-only) MIB table rooted at `nlmLogTable`
//! (`1.3.6.1.2.1.92.1.3.1`).
//!
//! The ring is shared between the trap receiver (which calls
//! [`NotificationLog::record`] for each notification) and the
//! [`notiflog_handler`] serving it to walkers, so a manager can walk the recent
//! notification history exactly as the agent received it.
//!
//! Only a minimal subset of columns is exposed (the trap OID, the originator's
//! engine id / security name, and the receipt time), matching the upstream
//! `nlmLogVariableTable` shape loosely. The full per-varbind subtable
//! (`nlmLogVariableTable`) is not modelled here.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `nlmLogEntry`: `1.3.6.1.2.1.92.1.3.1.1` (the `nlmLogTable` row entry).
const NLM_LOG_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 92, 1, 3, 1, 1];

// Column numbers (from NOTIFICATION-LOG-MIB nlmLogEntry).
/// `nlmLogTime` (col 2): the `sysUpTime` at which the log entry was created.
const NLM_LOG_TIME: u32 = 2;
/// `nlmLogDateAndTime` (col 3): wall-clock receipt time.
const NLM_LOG_DATE_AND_TIME: u32 = 3;
/// `nlmLogEngineID` (col 4): the originator's `snmpEngineID`.
const NLM_LOG_ENGINE_ID: u32 = 4;
/// `nlmLogEngineTAddress` (col 5): the originator's transport address.
const NLM_LOG_ENGINE_TADDRESS: u32 = 5;
/// `nlmLogEngineTDomain` (col 6): the transport domain.
const NLM_LOG_ENGINE_TDOMAIN: u32 = 6;
/// `nlmLogContextEngineID` (col 7).
const NLM_LOG_CONTEXT_ENGINE_ID: u32 = 7;
/// `nlmLogContextName` (col 8).
const NLM_LOG_CONTEXT_NAME: u32 = 8;
/// `nlmLogNotificationID` (col 9): the `snmpTrapOID` value.
const NLM_LOG_NOTIFICATION_ID: u32 = 9;

/// The standard `snmpUDPDomain` transport-domain OID.
const SNMP_UDP_DOMAIN: &[u32] = &[1, 3, 6, 1, 6, 1, 1];

/// One logged notification entry.
#[derive(Clone, Debug)]
struct LoggedEntry {
    /// 1-based `nlmLogIndex` (assigned in arrival order, wraps with the ring).
    index: u32,
    /// `sysUpTime` (hundredths of a second since the log started) at receipt.
    uptime_ticks: u32,
    /// Wall-clock receipt time.
    received: SystemTime,
    /// The originator's engine id (empty for v1/v2c).
    engine_id: Vec<u8>,
    /// The originator's transport address (`host:port`).
    peer: String,
    /// The `snmpTrapOID` value.
    trap_oid: Oid,
}

/// A bounded ring buffer of recent notifications, exposed as the
/// NOTIFICATION-LOG-MIB `nlmLogTable`.
///
/// Created once per receiver and shared (via [`Arc`]) between the receiver's
/// serve loop (which calls [`NotificationLog::record`]) and the
/// [`notiflog_handler`] serving the table to walkers. The buffer is capped at
/// `cap` entries (default 1000): once full, each new entry evicts the oldest.
pub struct NotificationLog {
    entries: Mutex<VecDeque<LoggedEntry>>,
    cap: usize,
    start: Instant,
}

impl NotificationLog {
    /// Create a ring buffer holding at most `cap` recent notifications.
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
            cap,
            start: Instant::now(),
        })
    }

    /// Record one received notification. The oldest entry is evicted if the
    /// buffer is full.
    pub fn record(
        &self,
        trap_oid: Oid,
        engine_id: Vec<u8>,
        peer: String,
    ) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // Indices are 1-based and monotonic across evictions: the next index is
        // one past the last (or 1 for the first entry).
        let index = entries
            .back()
            .map(|e| e.index.wrapping_add(1))
            .unwrap_or(1);
        if entries.len() >= self.cap {
            entries.pop_front();
        }
        let uptime_ticks = (self.start.elapsed().as_millis() / 10) as u32;
        entries.push_back(LoggedEntry {
            index,
            uptime_ticks,
            received: SystemTime::now(),
            engine_id,
            peer,
            trap_oid,
        });
    }

    /// Build the full set of instance cells currently in the table, as
    /// `(instance_oid, value)` pairs under `nlmLogEntry`.
    ///
    /// Cell OID layout is `nlmLogEntry.column.index`, i.e.
    /// `1.3.6.1.2.1.92.1.3.1.1.<column>.<index>`.
    pub fn cells(&self) -> Vec<(Oid, Value)> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let entry = Oid::new(NLM_LOG_ENTRY.to_vec());
        let mut cells = Vec::with_capacity(entries.len() * 5);
        for e in entries.iter() {
            let cell = |col: u32| {
                let mut p = entry.as_slice().to_vec();
                p.push(col);
                p.push(e.index);
                Oid::new(p)
            };
            cells.push((cell(NLM_LOG_TIME), Value::TimeTicks(e.uptime_ticks)));
            cells.push((
                cell(NLM_LOG_DATE_AND_TIME),
                Value::OctetString(date_and_time(e.received)),
            ));
            cells.push((
                cell(NLM_LOG_ENGINE_ID),
                Value::OctetString(e.engine_id.clone()),
            ));
            cells.push((
                cell(NLM_LOG_ENGINE_TADDRESS),
                Value::OctetString(udp_address(&e.peer)),
            ));
            cells.push((
                cell(NLM_LOG_ENGINE_TDOMAIN),
                Value::Oid(Oid::new(SNMP_UDP_DOMAIN.to_vec())),
            ));
            cells.push((cell(NLM_LOG_CONTEXT_ENGINE_ID), Value::OctetString(Vec::new())));
            cells.push((cell(NLM_LOG_CONTEXT_NAME), Value::OctetString(Vec::new())));
            cells.push((cell(NLM_LOG_NOTIFICATION_ID), Value::Oid(e.trap_oid.clone())));
        }
        cells
    }
}

impl std::fmt::Debug for NotificationLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.entries.lock().map(|d| d.len()).unwrap_or(0);
        f.debug_struct("NotificationLog")
            .field("cap", &self.cap)
            .field("entries", &n)
            .finish()
    }
}

/// Encode `host:port` as a 6-byte `snmpUDPAddress` (4 IP octets + 2 port
/// octets). Returns an empty string for non-IPv4 peers.
fn udp_address(host_port: &str) -> Vec<u8> {
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => return Vec::new(),
    };
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return Vec::new();
    };
    let Ok(port) = port.parse::<u16>() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Encode a `SystemTime` as an SNMP `DateAndTime` octet string (11 bytes, per
/// RFC 2579 `DateAndTime` textual convention). Returns an empty string if the
/// time is before the epoch.
fn date_and_time(t: SystemTime) -> Vec<u8> {
    let dur = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let secs = dur.as_secs() as i64;
    // Decompose epoch seconds into UTC date/time fields (no leap-second
    // handling; matches the MIB's "best effort" semantics).
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = (rem / 3600) as u8;
    let minute = ((rem % 3600) / 60) as u8;
    let second = (rem % 60) as u8;
    // Civil date from days-since-epoch (1970-01-01) via the Howard Hinnant
    // algorithm (no external dependency).
    let (year, month, day) = civil_from_days(days);
    let mut out = Vec::with_capacity(11);
    out.extend_from_slice(&(year as u16).to_be_bytes());
    out.push(month);
    out.push(day);
    out.push(hour);
    out.push(minute);
    out.push(second);
    out.push(0); // deciseconds
    out.push(b'+'); // UTC direction
    out.extend_from_slice(&0u16.to_be_bytes()); // UTC offset (0)
    out
}

/// Convert days-since-epoch (1970-01-01) to a (year, month, day) triple.
/// Howard Hinnant's `days_from_civil` inverse.
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Build the read-only `nlmLogTable` handler rooted at `1.3.6.1.2.1.92.1.3.1.1`,
/// backed by the shared `log`.
pub fn notiflog_handler(log: Arc<NotificationLog>) -> Arc<dyn MibHandler> {
    let root = Oid::new(NLM_LOG_ENTRY.to_vec());
    Arc::new(FnHandler::new(root, move || log.cells()))
}

/// Register the NOTIFICATION-LOG-MIB `nlmLogTable` into `registry`, backed by
/// `log`. Convenience wrapper around [`notiflog_handler`].
pub fn register_notiflog_mibs(registry: &mut crate::registry::Registry, log: Arc<NotificationLog>) {
    registry.register(notiflog_handler(log));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_evicts_oldest_when_full() {
        let log = NotificationLog::new(2);
        log.record(
            "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            Vec::new(),
            "127.0.0.1:1".to_string(),
        );
        log.record(
            "1.3.6.1.6.3.1.1.5.2".parse().unwrap(),
            Vec::new(),
            "127.0.0.1:2".to_string(),
        );
        log.record(
            "1.3.6.1.6.3.1.1.5.3".parse().unwrap(),
            Vec::new(),
            "127.0.0.1:3".to_string(),
        );
        let cells = log.cells();
        // 2 rows * 8 columns.
        assert_eq!(cells.len(), 16);
        // The first entry (coldStart) was evicted; indices 2 and 3 remain.
        let ids: Vec<_> = cells
            .iter()
            .filter(|(o, _)| o.as_slice().ends_with(&[NLM_LOG_NOTIFICATION_ID, 2]))
            .collect();
        assert!(ids.iter().any(|(_, v)| matches!(v, Value::Oid(_))));
    }

    #[test]
    fn handler_serves_recorded_rows() {
        let log = NotificationLog::new(100);
        log.record(
            "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            vec![0x80, 0x01],
            "127.0.0.1:162".to_string(),
        );
        let handler = notiflog_handler(log);
        // nlmLogNotificationID.1 (col 9, index 1).
        let oid: Oid = "1.3.6.1.2.1.92.1.3.1.1.9.1".parse().unwrap();
        let got = handler.get(&oid);
        assert_eq!(got, Some(Value::Oid("1.3.6.1.6.3.1.1.5.1".parse().unwrap())));
        // GETNEXT from the table root lands on the first cell.
        let root: Oid = "1.3.6.1.2.1.92.1.3.1.1".parse().unwrap();
        let first = handler.get_next(&root).expect("first successor");
        assert!(first.oid > root);
    }

    #[test]
    fn date_and_time_is_eleven_bytes() {
        let bytes = date_and_time(SystemTime::now());
        assert_eq!(bytes.len(), 11);
        // Year is 2 bytes big-endian, non-zero for any modern date.
        let year = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert!(year >= 2024);
    }
}
