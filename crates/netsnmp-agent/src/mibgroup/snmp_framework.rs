//! SNMP-FRAMEWORK-MIB `snmpEngine` group (`1.3.6.1.6.3.10.2.1`).
//!
//! Counterpart of `agent/mibgroup/mibII/snmpv3Engine.c`. Exposes the
//! authoritative SNMPv3 engine state held inside [`Agent`](crate::Agent) as
//! four walkable scalars:
//!
//! | Object                  | OID suffix | Type        |
//! |-------------------------|------------|-------------|
//! | `snmpEngineID`          | `.1.0`     | OCTET STRING|
//! | `snmpEngineBoots`       | `.2.0`     | Integer32   |
//! | `snmpEngineTime`        | `.3.0`     | Integer32   |
//! | `snmpEngineMaxMessageSize` | `.4.0`  | Integer32   |
//!
//! Because the engine state is private to the agent, callers register a
//! [`EngineSnapshotProvider`] closure that rebuilds the current state on each
//! read — so `snmpEngineTime` advances naturally between requests.

use std::sync::Arc;
use std::time::Instant;

use netsnmp::oid::Oid;
use netsnmp::value::Value;

use crate::handler::MibHandler;
use crate::scalar::FnHandler;

/// `snmpEngine` group root: `1.3.6.1.6.3.10.2.1`.
const SNMP_ENGINE: [u32; 9] = [1, 3, 6, 1, 6, 3, 10, 2, 1];

/// Net-SNMP's advertised maximum message size. Mirrors `MAX_MSG_SIZE` /
/// `snmpEngineMaxMessageSize` from the framework MIB and the v3 `DEFAULT_MAX_SIZE`.
const MAX_MESSAGE_SIZE: i64 = 65_507;

/// A point-in-time snapshot of the authoritative SNMPv3 engine state.
///
/// Built by an [`EngineSnapshotProvider`] on each read. `boot_time` is optional
/// so test/non-live snapshots can omit it (in which case `snmpEngineTime`
/// reports zero).
#[derive(Clone, Debug, Default)]
pub struct EngineSnapshot {
    /// The `snmpEngineID` advertised to SNMPv3 peers (opaque octets).
    pub engine_id: Vec<u8>,
    /// The `snmpEngineBoots` counter (number of times the engine has booted).
    pub engine_boots: u32,
    /// The agent start instant used to derive `snmpEngineTime`, or `None` if the
    /// engine time should be reported as zero.
    pub boot_time: Option<Instant>,
}

impl EngineSnapshot {
    /// Compute `snmpEngineTime` — whole seconds since `boot_time`, or zero when
    /// no boot instant is available.
    pub fn engine_time(&self) -> u32 {
        self.boot_time
            .map(|t| t.elapsed().as_secs() as u32)
            .unwrap_or(0)
    }
}

/// A closure that produces the current [`EngineSnapshot`] on demand.
///
/// The agent supplies this at registration time so the framework scalars stay
/// live without exposing the engine's private state.
pub type EngineSnapshotProvider = Arc<dyn Fn() -> EngineSnapshot + Send + Sync>;

/// Build the four `snmpEngine` scalar handlers (one [`FnHandler::scalar`] per
/// object). Each handler re-invokes `provider` on every GET so `snmpEngineTime`
/// keeps advancing with wall-clock time.
pub fn snmp_framework_handlers(provider: EngineSnapshotProvider) -> Vec<Arc<dyn MibHandler>> {
    let base = Oid::new(SNMP_ENGINE.to_vec());

    let engine_id = Arc::new(FnHandler::scalar(base.child(1), {
        let provider = Arc::clone(&provider);
        move || Value::OctetString((provider)().engine_id.clone())
    }));

    let engine_boots = Arc::new(FnHandler::scalar(base.child(2), {
        let provider = Arc::clone(&provider);
        move || Value::Integer((provider)().engine_boots as i64)
    }));

    let engine_time = Arc::new(FnHandler::scalar(base.child(3), {
        let provider = Arc::clone(&provider);
        move || Value::Integer((provider)().engine_time() as i64)
    }));

    let engine_max_size = Arc::new(FnHandler::scalar(base.child(4), move || {
        // Constant per RFC — kept as a FnHandler for uniform caching/GETNEXT.
        let _ = &provider;
        Value::Integer(MAX_MESSAGE_SIZE)
    }));

    vec![engine_id, engine_boots, engine_time, engine_max_size]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_serves_known_snapshot() {
        let engine_id = b"0x80ENGINE".to_vec();
        let snapshot = EngineSnapshot {
            engine_id: engine_id.clone(),
            engine_boots: 7,
            boot_time: Some(Instant::now()),
        };
        let provider: EngineSnapshotProvider = Arc::new(move || snapshot.clone());

        let handlers = snmp_framework_handlers(provider);
        assert_eq!(handlers.len(), 4);

        // snmpEngineID.0
        let id_oid: Oid = "1.3.6.1.6.3.10.2.1.1.0".parse().unwrap();
        assert_eq!(
            handlers[0].get(&id_oid),
            Some(Value::OctetString(engine_id.clone()))
        );
        // snmpEngineBoots.0
        let boots_oid: Oid = "1.3.6.1.6.3.10.2.1.2.0".parse().unwrap();
        assert_eq!(handlers[1].get(&boots_oid), Some(Value::Integer(7)));
        // snmpEngineTime.0 — non-negative; exact value is time-dependent.
        let time_oid: Oid = "1.3.6.1.6.3.10.2.1.3.0".parse().unwrap();
        match handlers[2].get(&time_oid) {
            Some(Value::Integer(t)) => assert!(t >= 0),
            other => panic!("expected snmpEngineTime, got {other:?}"),
        }
        // snmpEngineMaxMessageSize.0
        let max_oid: Oid = "1.3.6.1.6.3.10.2.1.4.0".parse().unwrap();
        assert_eq!(handlers[3].get(&max_oid), Some(Value::Integer(65_507)));
    }

    #[test]
    fn engine_time_is_zero_without_boot_time() {
        let provider: EngineSnapshotProvider = Arc::new(|| EngineSnapshot {
            engine_id: Vec::new(),
            engine_boots: 1,
            boot_time: None,
        });
        let handlers = snmp_framework_handlers(provider);
        let time_oid: Oid = "1.3.6.1.6.3.10.2.1.3.0".parse().unwrap();
        assert_eq!(handlers[2].get(&time_oid), Some(Value::Integer(0)));
    }
}
