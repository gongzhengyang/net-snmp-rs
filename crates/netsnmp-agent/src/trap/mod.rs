//! Notification receiver (the `snmptrapd` daemon core).
//!
//! Counterpart of `apps/snmptrapd*.c`: bind a UDP socket, receive SNMPv2-Trap
//! and InformRequest notifications (community v1/v2c or SNMPv3/USM), decode and
//! authenticate them, acknowledge informs, and surface the parsed
//! [`Notification`](netsnmp::trap::Notification) to the caller for
//! display/logging.
//!
//! The protocol handling is split by security model:
//!
//! * [`community`](mod@self::community) — the v1/v2c path.
//! * [`secure`](mod@self::secure) — the SNMPv3/USM path, reusing the USM
//!   machinery in [`netsnmp::v3`] (engine discovery, user lookup, HMAC
//!   verification, decryption, and authenticated inform acknowledgements).
//!
//! [`handle_datagram`](TrapReceiver::handle_datagram) dispatches between them.

mod community;
pub mod format;
mod notiflog;
mod secure;
pub mod sink;
mod types;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use netsnmp::error::{Error, Result};
use netsnmp::mib::MibRegistry;
use netsnmp::pdu::{Pdu, PduType};
use netsnmp::usm::UsmUser;
use netsnmp::v3::{self, EngineParams};
use tokio::net::UdpSocket;
use tracing::{debug, trace};

pub use notiflog::{NotificationLog, notiflog_handler, register_notiflog_mibs};
pub use sink::{FileSink, ForwardSink, HandleRule, HandleSink, StdoutSink, TrapSink};
pub use types::{NotifyVersion, ReceivedNotification, TrapDisposition, TrapReceiverConfig};

/// A UDP notification receiver: the core of `snmptrapd`.
pub struct TrapReceiver {
    config: TrapReceiverConfig,
    users: HashMap<Vec<u8>, UsmUser>,
    boot_time: Instant,
    usm_stats: AtomicU32,
    /// Optional MIB registry used to render symbolic names when sinks are
    /// configured (the `-F` format path). `None` falls back to numeric OIDs.
    mib: Option<Arc<MibRegistry>>,
    /// Optional NOTIFICATION-LOG-MIB ring buffer; when set, each received
    /// notification is recorded for walkable history.
    notiflog: Option<Arc<NotificationLog>>,
}

impl TrapReceiver {
    /// Create a receiver from its configuration.
    pub fn new(config: TrapReceiverConfig) -> Self {
        let users = config
            .users
            .iter()
            .map(|u| (u.name.as_bytes().to_vec(), u.clone()))
            .collect();
        TrapReceiver {
            config,
            users,
            boot_time: Instant::now(),
            usm_stats: AtomicU32::new(0),
            mib: None,
            notiflog: None,
        }
    }

    /// Attach a [`MibRegistry`] for symbolic OID rendering when sinks/format
    /// are configured (builder style). When `None`, sink output uses numeric
    /// OIDs.
    pub fn with_mib(mut self, mib: Arc<MibRegistry>) -> Self {
        self.mib = Some(mib);
        self
    }

    /// Attach a [`NotificationLog`] ring buffer: each received notification is
    /// appended to it (for the walkable `nlmLogTable`). The same [`Arc`] should
    /// be registered via [`register_notiflog_mibs`] so walkers see the entries.
    pub fn with_notiflog(mut self, log: Arc<NotificationLog>) -> Self {
        self.notiflog = Some(log);
        self
    }

    /// The current authoritative engine parameters.
    fn engine(&self) -> EngineParams {
        EngineParams {
            engine_id: self.config.engine_id.clone(),
            engine_boots: self.config.engine_boots,
            engine_time: self.boot_time.elapsed().as_secs() as u32,
        }
    }

    fn next_stat(&self) -> u32 {
        self.usm_stats
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Process one raw datagram, returning the surfaced notification (if valid)
    /// and any reply that must be sent back to the peer. Dispatches SNMPv3 to
    /// the USM path and community messages to the v1/v2c path. Exposed
    /// separately so it can be unit-tested without a socket.
    pub fn handle_datagram(&self, data: &[u8]) -> Result<TrapDisposition> {
        match v3::peek_security(data) {
            Ok((header, usm)) => self.handle_v3(data, &header, &usm),
            Err(Error::UnsupportedVersion(_)) => self.handle_community(data),
            Err(_) => {
                debug!(bytes = data.len(), "dropping unparseable notification");
                Ok(TrapDisposition::default())
            }
        }
    }

    /// Bind the listener socket.
    pub async fn bind(&self) -> Result<UdpSocket> {
        Ok(UdpSocket::bind(&self.config.bind_addr).await?)
    }

    /// Serve on an already-bound socket, invoking `on_notification` for each
    /// valid trap/inform and replying to the peer when an acknowledgement is
    /// required. This never returns under normal operation.
    ///
    /// When [`TrapReceiverConfig::sinks`] are configured they are also invoked
    /// for each notification (the formatted line is rendered via the
    /// [`format`](TrapReceiverConfig::format) string or the default form). The
    /// `on_notification` callback is always invoked as well, preserving
    /// backwards compatibility: existing callers that print via the callback
    /// keep working unchanged.
    pub async fn serve_on<F>(&self, socket: UdpSocket, mut on_notification: F) -> Result<()>
    where
        F: FnMut(&ReceivedNotification, std::net::SocketAddr),
    {
        let empty_mib = MibRegistry::new();
        let mib = self.mib.as_deref().unwrap_or(&empty_mib);
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            trace!(%peer, bytes = n, "received notification datagram");
            // A malformed datagram must not take down the listener.
            let disposition = match self.handle_datagram(&buf[..n]) {
                Ok(d) => d,
                Err(e) => {
                    debug!(%peer, error = %e, "error handling notification, ignoring");
                    continue;
                }
            };
            if let Some(note) = &disposition.notification {
                // NOTIFICATION-LOG-MIB ring buffer — record before sinks so the
                // entry is visible to a walker even if a sink errors.
                if let Some(log) = &self.notiflog {
                    let engine_id = note
                        .security_name
                        .as_deref()
                        .map(str::as_bytes)
                        .unwrap_or_default()
                        .to_vec();
                    log.record(
                        note.notification.trap_oid.clone(),
                        engine_id,
                        peer.to_string(),
                    );
                }
                // Sinks (file/traphandle/forward) — only when configured.
                if !self.config.sinks.is_empty() {
                    let line = sink::render_line(self.config.format.as_deref(), note, mib, peer);
                    for s in &self.config.sinks {
                        if let Err(e) = s.log(&line, note, peer) {
                            debug!(error = %e, "trap sink reported an error, continuing");
                        }
                    }
                }
                on_notification(note, peer);
            }
            if let Some(reply) = disposition.reply {
                let _ = socket.send_to(&reply, peer).await;
            }
        }
    }
}

/// Build the Response PDU acknowledging an inform: echo its bindings with a
/// zero error-status (RFC 3416 §4.2.7).
fn ack_pdu(inform: &Pdu) -> Pdu {
    let mut resp = Pdu::new(PduType::Response, inform.request_id);
    resp.variables = inform.variables.clone();
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::message::Message;
    use netsnmp::oid::Oid;
    use netsnmp::pdu::VarBind;
    use netsnmp::trap;
    use netsnmp::usm::{AuthProtocol, PrivProtocol};
    use netsnmp::value::Value;

    fn cold_start() -> Oid {
        "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
    }

    fn receiver(users: Vec<UsmUser>) -> TrapReceiver {
        TrapReceiver::new(TrapReceiverConfig {
            users,
            ..Default::default()
        })
    }

    #[test]
    fn community_trap_is_surfaced() {
        let rx = receiver(Vec::new());
        let pdu = trap::build_notification(PduType::TrapV2, 1, 100, &cold_start(), vec![]).unwrap();
        let msg = Message::new(netsnmp::message::Version::V2c, b"public".to_vec(), pdu);
        let disp = rx.handle_datagram(&msg.encode().unwrap()).unwrap();
        let note = disp.notification.expect("a notification");
        assert_eq!(note.version, NotifyVersion::Community);
        assert!(!note.confirmed);
        assert!(disp.reply.is_none());
        assert_eq!(note.notification.trap_oid, cold_start());
    }

    #[test]
    fn community_inform_is_acknowledged() {
        let rx = receiver(Vec::new());
        let pdu =
            trap::build_notification(PduType::Inform, 77, 100, &cold_start(), vec![]).unwrap();
        let msg = Message::new(netsnmp::message::Version::V2c, b"public".to_vec(), pdu);
        let disp = rx.handle_datagram(&msg.encode().unwrap()).unwrap();
        assert!(disp.notification.unwrap().confirmed);
        // The reply echoes the request id as a Response.
        let reply = Message::decode(&disp.reply.expect("ack")).unwrap();
        assert_eq!(reply.pdu.pdu_type, PduType::Response);
        assert_eq!(reply.pdu.request_id, 77);
    }

    #[test]
    fn wrong_community_dropped() {
        let rx = receiver(Vec::new());
        let pdu = trap::build_notification(PduType::TrapV2, 1, 0, &cold_start(), vec![]).unwrap();
        let msg = Message::new(netsnmp::message::Version::V2c, b"private".to_vec(), pdu);
        let disp = rx.handle_datagram(&msg.encode().unwrap()).unwrap();
        assert!(disp.notification.is_none());
    }

    #[test]
    fn v3_auth_priv_trap_is_verified() {
        let user = UsmUser::auth_priv(
            "notifier",
            AuthProtocol::HmacSha256,
            "authpassword",
            PrivProtocol::AesCfb128,
            "privpassword",
        );
        let rx = receiver(vec![user.clone()]);
        // Sender stamps its own engine id (a notification originator).
        let sender_engine = EngineParams {
            engine_id: vec![0x80, 0, 0, 0, 9, 1, 2, 3],
            engine_boots: 2,
            engine_time: 50,
        };
        let extra = vec![VarBind::new(
            "1.3.6.1.2.1.1.5.0".parse().unwrap(),
            Value::OctetString(b"sender".to_vec()),
        )];
        let pdu =
            trap::build_notification(PduType::TrapV2, 5, 12345, &cold_start(), extra).unwrap();
        let bytes =
            v3::build_response(42, &user, &sender_engine, &sender_engine.engine_id, pdu).unwrap();

        let disp = rx.handle_datagram(&bytes).unwrap();
        let note = disp.notification.expect("a verified v3 trap");
        assert_eq!(note.version, NotifyVersion::V3);
        assert_eq!(note.security_name.as_deref(), Some("notifier"));
        assert!(disp.reply.is_none());
        assert_eq!(note.notification.sys_uptime, 12345);
    }

    #[test]
    fn v3_unknown_user_reports() {
        let rx = receiver(vec![UsmUser::auth(
            "known",
            AuthProtocol::HmacSha1,
            "authpassword",
        )]);
        let stranger = UsmUser::auth("stranger", AuthProtocol::HmacSha1, "authpassword");
        let engine = EngineParams {
            engine_id: vec![0x80, 0, 0, 0, 9, 9, 9, 9],
            engine_boots: 1,
            engine_time: 1,
        };
        let pdu = trap::build_notification(PduType::TrapV2, 1, 0, &cold_start(), vec![]).unwrap();
        let bytes = v3::build_response(1, &stranger, &engine, &engine.engine_id, pdu).unwrap();
        let disp = rx.handle_datagram(&bytes).unwrap();
        assert!(disp.notification.is_none());
        // A usmStatsUnknownUserNames report is returned.
        let report = v3::parse(&disp.reply.expect("report"), None).unwrap();
        assert_eq!(
            report.scoped.pdu.variables[0].oid.to_string(),
            ".1.3.6.1.6.3.15.1.1.3.0"
        );
    }
}
