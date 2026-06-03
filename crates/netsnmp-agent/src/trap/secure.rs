//! SNMPv3/USM trap and inform handling: engine discovery, user lookup, HMAC
//! verification, decryption, and authenticated inform acknowledgements.

use netsnmp::error::{Error, Result};
use netsnmp::pdu::PduType;
use netsnmp::trap;
use netsnmp::v3::{self, HeaderData, UsmSecurityParameters, UsmStat};
use tracing::debug;

use super::{NotifyVersion, ReceivedNotification, TrapDisposition, TrapReceiver, ack_pdu};

/// The RFC 3414 time-window tolerance (seconds) for confirmed informs.
const TIME_WINDOW_SECS: i64 = 150;

impl TrapReceiver {
    /// Handle an SNMPv3/USM trap or inform.
    pub(super) fn handle_v3(
        &self,
        data: &[u8],
        header: &HeaderData,
        usm: &UsmSecurityParameters,
    ) -> Result<TrapDisposition> {
        let engine = self.engine();

        // Engine discovery (empty engineID): only confirmed informs probe us.
        if usm.engine_id.is_empty() {
            let report = v3::build_report(
                header.msg_id,
                None,
                &engine,
                UsmStat::UnknownEngineIDs,
                self.next_stat(),
                0,
            )?;
            return Ok(TrapDisposition {
                notification: None,
                reply: Some(report),
            });
        }

        let user = match self.users.get(&usm.user_name) {
            Some(u) => u,
            None => {
                let report = v3::build_report(
                    header.msg_id,
                    None,
                    &engine,
                    UsmStat::UnknownUserNames,
                    self.next_stat(),
                    0,
                )?;
                return Ok(TrapDisposition {
                    notification: None,
                    reply: Some(report),
                });
            }
        };

        // Verify the HMAC and decrypt using the user's key localized to the
        // engine id carried in the message (the sender's own, for traps).
        let msg = match v3::parse(data, Some(user)) {
            Ok(m) => m,
            Err(Error::AuthFailure(_)) => {
                debug!("USM authentication failed on notification, dropping");
                return Ok(TrapDisposition::default());
            }
            Err(Error::PrivFailure(_)) => {
                let report = v3::build_report(
                    header.msg_id,
                    Some(user),
                    &engine,
                    UsmStat::DecryptionErrors,
                    self.next_stat(),
                    0,
                )?;
                return Ok(TrapDisposition {
                    notification: None,
                    reply: Some(report),
                });
            }
            Err(_) => return Ok(TrapDisposition::default()),
        };

        let security_name = Some(user.name.clone());
        match msg.scoped.pdu.pdu_type {
            PduType::TrapV2 => Ok(TrapDisposition {
                notification: Some(ReceivedNotification {
                    version: NotifyVersion::V3,
                    security_name,
                    confirmed: false,
                    notification: trap::parse_notification(&msg.scoped.pdu)?,
                }),
                reply: None,
            }),
            PduType::Inform => {
                // For an inform we are the authoritative engine: the sender used
                // our engine id (learned via discovery), so enforce the time
                // window and acknowledge with an authenticated/encrypted reply.
                if user.security_level().has_auth() {
                    let drift = i64::from(engine.engine_time) - i64::from(usm.engine_time);
                    let in_window =
                        usm.engine_boots == engine.engine_boots && drift.abs() <= TIME_WINDOW_SECS;
                    if !in_window {
                        let report = v3::build_report(
                            header.msg_id,
                            Some(user),
                            &engine,
                            UsmStat::NotInTimeWindows,
                            self.next_stat(),
                            msg.scoped.pdu.request_id,
                        )?;
                        return Ok(TrapDisposition {
                            notification: None,
                            reply: Some(report),
                        });
                    }
                }
                let notification = trap::parse_notification(&msg.scoped.pdu)?;
                let reply = v3::build_response(
                    header.msg_id,
                    user,
                    &engine,
                    &engine.engine_id,
                    ack_pdu(&msg.scoped.pdu),
                )?;
                Ok(TrapDisposition {
                    notification: Some(ReceivedNotification {
                        version: NotifyVersion::V3,
                        security_name,
                        confirmed: true,
                        notification,
                    }),
                    reply: Some(reply),
                })
            }
            _ => Ok(TrapDisposition::default()),
        }
    }
}
