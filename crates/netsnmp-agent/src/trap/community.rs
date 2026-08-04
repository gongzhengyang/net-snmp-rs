//! Community (SNMPv1/v2c) trap and inform handling.

use netsnmp::error::Result;
use netsnmp::message::Message;
use netsnmp::pdu::PduType;
use netsnmp::trap;
use netsnmp::oid::Oid;
use tracing::debug;

use super::{NotifyVersion, ReceivedNotification, TrapDisposition, TrapReceiver, ack_pdu};

impl TrapReceiver {
    /// Handle a community (SNMPv1/v2c) trap or inform.
    pub(super) fn handle_community(&self, data: &[u8]) -> Result<TrapDisposition> {
        let msg = match Message::decode(data) {
            Ok(m) => m,
            Err(_) => return Ok(TrapDisposition::default()),
        };
        if let Some(expected) = &self.config.community
            && &msg.community != expected
        {
            debug!("dropping notification with wrong community");
            return Ok(TrapDisposition::default());
        }
        match msg.pdu.pdu_type {
            PduType::TrapV2 => Ok(TrapDisposition {
                notification: Some(ReceivedNotification {
                    version: NotifyVersion::Community,
                    security_name: None,
                    confirmed: false,
                    notification: trap::parse_notification(&msg.pdu)?,
                }),
                reply: None,
            }),
            PduType::Inform => {
                let notification = trap::parse_notification(&msg.pdu)?;
                let reply =
                    Message::new(msg.version, msg.community.clone(), ack_pdu(&msg.pdu)).encode()?;
                Ok(TrapDisposition {
                    notification: Some(ReceivedNotification {
                        version: NotifyVersion::Community,
                        security_name: None,
                        confirmed: true,
                        notification,
                    }),
                    reply: Some(reply),
                })
            }
            PduType::TrapV1 => self.handle_v1_trap(&msg),
            // Anything else (a stray GET, etc.) is not a notification: ignore.
            _ => Ok(TrapDisposition::default()),
        }
    }

    /// Handle a legacy SNMPv1 Trap-PDU. The v1 trap carries its identity in
    /// structured PDU fields (enterprise/generic/specific/agent-addr/uptime)
    /// rather than a `snmpTrapOID` varbind, so it is translated to the v2
    /// [`Notification`](trap::Notification) form (RFC 3584 §3) before being
    /// surfaced: generic traps map onto `snmpTraps.<generic>` and
    /// enterprise-specific traps onto `enterprise.0.<specific>`.
    fn handle_v1_trap(&self, msg: &Message) -> Result<TrapDisposition> {
        let v1 = trap::parse_v1_trap(&msg.pdu)?;
        let trap_oid = v1_generic_trap_oid(&v1);
        debug!(
            "v1 trap from {} enterprise={} generic={} specific={} -> {}",
            v1.agent_addr, v1.enterprise, v1.generic_trap, v1.specific_trap, trap_oid
        );
        Ok(TrapDisposition {
            notification: Some(ReceivedNotification {
                version: NotifyVersion::Community,
                security_name: None,
                confirmed: false,
                notification: trap::Notification {
                    sys_uptime: v1.uptime,
                    trap_oid,
                    varbinds: v1.varbinds,
                },
            }),
            reply: None,
        })
    }
}

/// Compute the `snmpTrapOID` value for a v1 trap (RFC 3584 §3 Table 1).
///
/// * Generic traps 0..=5 → `snmpTraps.<generic>`.
/// * `enterpriseSpecific` (6) → `enterprise.0.<specific>` (the extra `0` marks
///   it as enterprise-specific, matching upstream's `snmptrapd` behaviour).
fn v1_generic_trap_oid(v1: &trap::V1Notification) -> Oid {
    if let Some(oid) = trap::v1_generic_trap_to_oid(v1.generic_trap) {
        return oid;
    }
    // Enterprise-specific: enterprise.0.<specific_trap>.
    let mut arcs = v1.enterprise.as_slice().to_vec();
    arcs.push(0);
    arcs.push(v1.specific_trap);
    Oid::new(arcs)
}


