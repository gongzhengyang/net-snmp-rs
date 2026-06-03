//! Helpers shared by the community and USM session types: the request-id
//! source, the status-to-`Result` shim, and Report-PDU description.

use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::{Error, Result};
use crate::pdu::{ErrorStatus, Pdu};

/// A monotonically increasing request-id source, seeded from the clock.
static REQUEST_ID: AtomicI32 = AtomicI32::new(0);

pub(super) fn next_request_id() -> i32 {
    let mut id = REQUEST_ID.load(Ordering::Relaxed);
    if id == 0 {
        // Lazy seed so different processes/sessions don't all start at 1.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as i32 & 0x00ff_ffff)
            .unwrap_or(1)
            .max(1);
        let _ = REQUEST_ID.compare_exchange(0, seed, Ordering::Relaxed, Ordering::Relaxed);
        id = REQUEST_ID.load(Ordering::Relaxed);
    }
    REQUEST_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.wrapping_add(1).max(1))
        })
        .unwrap_or(id)
}

/// Render a Report PDU's first varbind OID as a human-readable USM stat name.
pub(super) fn describe_report(pdu: &Pdu) -> String {
    // usmStats counters live under 1.3.6.1.6.3.15.1.1.<n>.0
    const PREFIX: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1];
    if let Some(vb) = pdu.variables.first() {
        let s = vb.oid.as_slice();
        if s.len() > PREFIX.len() && s[..PREFIX.len()] == *PREFIX {
            let name = match s[PREFIX.len()] {
                1 => "usmStatsUnsupportedSecLevels",
                2 => "usmStatsNotInTimeWindows",
                3 => "usmStatsUnknownUserNames",
                4 => "usmStatsUnknownEngineIDs",
                5 => "usmStatsWrongDigests",
                6 => "usmStatsDecryptionErrors",
                _ => "usmStatsUnknown",
            };
            return format!("{name} ({})", vb.oid);
        }
        return format!("report oid {}", vb.oid);
    }
    "empty report".to_string()
}

/// Convenience: turn a non-ok response status into a `Result`.
pub fn ensure_ok(status: ErrorStatus, index: i64) -> Result<()> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(Error::SnmpError {
            status,
            index: index as usize,
        })
    }
}
