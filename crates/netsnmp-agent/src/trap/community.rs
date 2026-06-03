//! Community (SNMPv1/v2c) trap and inform handling.

use netsnmp::error::Result;
use netsnmp::message::Message;
use netsnmp::pdu::PduType;
use netsnmp::trap;
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
            // Anything else (a stray GET, etc.) is not a notification: ignore.
            _ => Ok(TrapDisposition::default()),
        }
    }
}
