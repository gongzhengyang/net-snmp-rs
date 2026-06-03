//! SNMP notifications: traps and informs (RFC 3416 §4.2.6 / RFC 3418).
//!
//! Rust counterpart of the notification-building parts of `agent/agent_trap.c`
//! and the `apps/snmptrap.c` / `apps/snmptrapd.c` tools. It builds and parses
//! the two notification PDUs that share the standard PDU structure:
//!
//! * **SNMPv2-Trap** (`PduType::TrapV2`) — an unconfirmed notification.
//! * **InformRequest** (`PduType::Inform`) — a confirmed notification; the
//!   receiver echoes a Response with the same request-id.
//!
//! Both begin with two mandatory variable bindings (RFC 3418 §2):
//!
//! 1. `sysUpTime.0` — `1.3.6.1.2.1.1.3.0` (TimeTicks)
//! 2. `snmpTrapOID.0` — `1.3.6.1.6.3.1.1.4.1.0` (the notification's identity OID)
//!
//! followed by any number of caller-supplied bindings. The legacy SNMPv1
//! Trap-PDU (structurally different) is intentionally not built here, matching
//! the rest of this implementation's v2c/v3 focus.

use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, VarBind};
use crate::value::Value;

/// `sysUpTime.0` — the first varbind of every SNMPv2 notification.
pub const SYSUPTIME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

/// `snmpTrapOID.0` — the second varbind, identifying the notification.
pub const SNMP_TRAP_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// Build a notification PDU (an SNMPv2-Trap or InformRequest) with the two
/// mandatory leading varbinds (`sysUpTime.0`, `snmpTrapOID.0`) followed by the
/// caller-supplied `varbinds`.
///
/// Returns [`Error::Protocol`] if `pdu_type` is not a notification type.
pub fn build_notification(
    pdu_type: PduType,
    request_id: i32,
    sys_uptime: u32,
    trap_oid: &Oid,
    varbinds: Vec<VarBind>,
) -> Result<Pdu> {
    if !matches!(pdu_type, PduType::TrapV2 | PduType::Inform) {
        return Err(Error::Protocol(
            "notification PDU must be TrapV2 or Inform".into(),
        ));
    }
    let mut pdu = Pdu::new(pdu_type, request_id);
    pdu.variables.push(VarBind::new(
        Oid::new(SYSUPTIME_OID),
        Value::TimeTicks(sys_uptime),
    ));
    pdu.variables.push(VarBind::new(
        Oid::new(SNMP_TRAP_OID),
        Value::Oid(trap_oid.clone()),
    ));
    pdu.variables.extend(varbinds);
    Ok(pdu)
}

/// A parsed notification: the two mandatory fields plus any extra bindings.
#[derive(Clone, Debug, PartialEq)]
pub struct Notification {
    /// The `sysUpTime.0` value (hundredths of a second since restart).
    pub sys_uptime: u32,
    /// The `snmpTrapOID.0` value (the notification's identity).
    pub trap_oid: Oid,
    /// The remaining (caller-supplied) variable bindings.
    pub varbinds: Vec<VarBind>,
}

/// Extract a [`Notification`] from a received notification PDU, validating the
/// two mandatory leading varbinds (`sysUpTime.0` TimeTicks, `snmpTrapOID.0` OID).
pub fn parse_notification(pdu: &Pdu) -> Result<Notification> {
    if pdu.variables.len() < 2 {
        return Err(Error::Protocol(
            "notification is missing the mandatory sysUpTime.0/snmpTrapOID.0 varbinds".into(),
        ));
    }
    let sys_uptime = match &pdu.variables[0].value {
        Value::TimeTicks(t) => *t,
        other => {
            return Err(Error::Protocol(format!(
                "notification sysUpTime.0 must be TimeTicks, got {}",
                other.type_name()
            )));
        }
    };
    let trap_oid = match &pdu.variables[1].value {
        Value::Oid(o) => o.clone(),
        other => {
            return Err(Error::Protocol(format!(
                "notification snmpTrapOID.0 must be an OID, got {}",
                other.type_name()
            )));
        }
    };
    Ok(Notification {
        sys_uptime,
        trap_oid,
        varbinds: pdu.variables[2..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cold_start() -> Oid {
        // snmpTrapOID for coldStart: 1.3.6.1.6.3.1.1.5.1
        "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
    }

    #[test]
    fn build_and_parse_roundtrip() {
        let extra = vec![VarBind::new(
            "1.3.6.1.2.1.1.5.0".parse().unwrap(),
            Value::OctetString(b"host-a".to_vec()),
        )];
        let pdu =
            build_notification(PduType::TrapV2, 9, 4242, &cold_start(), extra.clone()).unwrap();
        assert_eq!(pdu.pdu_type, PduType::TrapV2);
        assert_eq!(pdu.variables.len(), 3);

        let note = parse_notification(&pdu).unwrap();
        assert_eq!(note.sys_uptime, 4242);
        assert_eq!(note.trap_oid, cold_start());
        assert_eq!(note.varbinds, extra);
    }

    #[test]
    fn rejects_non_notification_type() {
        let err = build_notification(PduType::Get, 1, 0, &cold_start(), Vec::new()).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn rejects_short_varbind_list() {
        let pdu =
            Pdu::new(PduType::TrapV2, 1).with_var(Oid::new(SYSUPTIME_OID), Value::TimeTicks(1));
        assert!(parse_notification(&pdu).is_err());
    }
}
