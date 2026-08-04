//! Configuration and result types for the trap receiver.

use std::sync::Arc;

use netsnmp::trap::Notification;
use netsnmp::usm::UsmUser;

use super::sink::TrapSink;

/// The SNMP message version a notification arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyVersion {
    /// Community-based SNMPv1/v2c.
    Community,
    /// SNMPv3 / USM.
    V3,
}

/// Configuration for a [`TrapReceiver`](super::TrapReceiver).
#[derive(Clone, Debug)]
pub struct TrapReceiverConfig {
    /// Address to bind, e.g. `"0.0.0.0:162"` or `"127.0.0.1:1162"`.
    pub bind_addr: String,
    /// Accepted community for v1/v2c (`None` accepts any community).
    pub community: Option<Vec<u8>>,
    /// The authoritative `snmpEngineID` (used for inform discovery/responses).
    pub engine_id: Vec<u8>,
    /// The authoritative `snmpEngineBoots`.
    pub engine_boots: u32,
    /// Configured SNMPv3/USM users (empty disables v3).
    pub users: Vec<UsmUser>,
    /// Optional `snmptrapd`-style `-F FORMAT` string. When set, each received
    /// notification is rendered via
    /// [`format_notification`](super::format::format_notification) before being
    /// handed to [`sinks`](Self::sinks); otherwise the default human-readable
    /// form is used.
    pub format: Option<String>,
    /// Output backends (file, traphandle, forward, ...). When non-empty, each
    /// received notification is passed to every sink; the legacy
    /// [`TrapReceiver::serve_on`](super::TrapReceiver::serve_on) callback is
    /// then *not* required (but is still invoked if supplied, for backwards
    /// compatibility). When empty (the default), behaviour is unchanged: the
    /// caller's callback is the sole output path.
    pub sinks: Vec<Arc<dyn TrapSink>>,
}

impl Default for TrapReceiverConfig {
    fn default() -> Self {
        TrapReceiverConfig {
            bind_addr: "127.0.0.1:1162".to_string(),
            community: Some(b"public".to_vec()),
            engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', b't', 0x01],
            engine_boots: 1,
            users: Vec::new(),
            format: None,
            sinks: Vec::new(),
        }
    }
}

/// A notification received and validated by a [`TrapReceiver`](super::TrapReceiver).
#[derive(Clone, Debug)]
pub struct ReceivedNotification {
    /// The transport security model the notification arrived under.
    pub version: NotifyVersion,
    /// The USM security name (v3 only).
    pub security_name: Option<String>,
    /// Whether this was a confirmed inform (an acknowledgement was sent).
    pub confirmed: bool,
    /// The parsed notification payload.
    pub notification: Notification,
}

/// The result of handling one datagram: an optional surfaced notification and
/// an optional reply datagram (an inform acknowledgement or a v3 Report).
#[derive(Clone, Debug, Default)]
pub struct TrapDisposition {
    /// The notification to surface to the caller, if any.
    pub notification: Option<ReceivedNotification>,
    /// Bytes to send back to the peer, if any.
    pub reply: Option<Vec<u8>>,
}
