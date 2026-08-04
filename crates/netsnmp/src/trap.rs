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
//! followed by any number of caller-supplied bindings.
//!
//! The legacy SNMPv1 Trap-PDU is also supported: see [`build_v1_trap`] and
//! [`parse_v1_trap`] (and [`V1Trap`]). A v1 trap carries its identity in
//! structured PDU fields rather than a `snmpTrapOID` varbind; use
//! [`v1_generic_trap_to_oid`] to translate a v1 trap into its v2c/v3
//! `snmpTrapOID` equivalent per RFC 3584.

use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, VarBind, V1Trap, v1_generic_trap};
use crate::value::Value;
use std::net::Ipv4Addr;

/// `sysUpTime.0` — the first varbind of every SNMPv2 notification.
pub const SYSUPTIME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

/// `snmpTrapOID.0` — the second varbind, identifying the notification.
pub const SNMP_TRAP_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// The base OID under which the standard SNMPv1 generic traps are defined,
/// also serving as the `snmpTrapOID` value when a v1 trap is translated to the
/// v2c/v3 form (RFC 3584 §3): `snmpTraps.<generic_trap>`.
pub const SNMP_TRAPS_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 5];

/// Map an SNMPv1 generic-trap number to its v2c/v3 `snmpTrapOID` value per
/// RFC 3584 §3 Table 1. For `enterpriseSpecific` the caller must append the
/// `specific_trap` and the enterprise OID; this returns the `snmpTraps` base
/// OID for generic traps `0..=5` and `None` for `6` (enterpriseSpecific) or any
/// other value.
pub fn v1_generic_trap_to_oid(generic_trap: u8) -> Option<Oid> {
    match generic_trap {
        // coldStart(0) ..= egpNeighborLoss(5) map onto snmpTraps.<generic_trap>.
        v1_generic_trap::COLD_START
        | v1_generic_trap::WARM_START
        | v1_generic_trap::LINK_DOWN
        | v1_generic_trap::LINK_UP
        | v1_generic_trap::AUTH_FAILURE
        | v1_generic_trap::EGP_NEIGHBOR_LOSS => {
            let mut arcs = SNMP_TRAPS_OID.to_vec();
            arcs.push(generic_trap as u32);
            Some(Oid::new(arcs))
        }
        // enterpriseSpecific(6) and anything else: no fixed snmpTrapOID.
        _ => None,
    }
}

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

/// A parsed SNMPv1 Trap-PDU: the structured fields plus the trailing varbinds.
#[derive(Clone, Debug, PartialEq)]
pub struct V1Notification {
    /// The enterprise OID under which the trap is defined.
    pub enterprise: Oid,
    /// The originator's IPv4 address.
    pub agent_addr: Ipv4Addr,
    /// The generic-trap number (see [`v1_generic_trap`]).
    pub generic_trap: u8,
    /// The enterprise-specific trap number.
    pub specific_trap: u32,
    /// Elapsed time since the agent reinitialised (hundredths of a second).
    pub uptime: u32,
    /// The trailing variable bindings.
    pub varbinds: Vec<VarBind>,
}

/// Build an SNMPv1 Trap-PDU ready to be wrapped in a v1 [`Pdu`] / message.
///
/// `agent_addr` of `0.0.0.0` is conventional when the sender has no specific
/// address to report. The returned PDU carries the structured trap fields on
/// its [`v1_trap`](Pdu::v1_trap) slot and the trailing varbinds on
/// [`variables`](Pdu::variables).
pub fn build_v1_trap(
    enterprise: Oid,
    agent_addr: Ipv4Addr,
    generic_trap: u8,
    specific_trap: u32,
    uptime: u32,
    varbinds: Vec<VarBind>,
) -> Pdu {
    let trap = V1Trap::new(enterprise, agent_addr, generic_trap, specific_trap, uptime);
    Pdu::new_v1_trap(trap, varbinds)
}

/// Extract a [`V1Notification`] from a received SNMPv1 Trap-PDU.
///
/// Returns [`Error::Protocol`] if the PDU is not a v1 Trap-PDU (i.e. its
/// [`v1_trap`](Pdu::v1_trap) slot is unpopulated).
pub fn parse_v1_trap(pdu: &Pdu) -> Result<V1Notification> {
    let trap = pdu.v1_trap.as_ref().ok_or_else(|| {
        Error::Protocol("PDU is not an SNMPv1 Trap-PDU (missing V1Trap payload)".into())
    })?;
    Ok(V1Notification {
        enterprise: trap.enterprise.clone(),
        agent_addr: trap.agent_addr,
        generic_trap: trap.generic_trap,
        specific_trap: trap.specific_trap,
        uptime: trap.time_stamp,
        varbinds: pdu.variables.clone(),
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
