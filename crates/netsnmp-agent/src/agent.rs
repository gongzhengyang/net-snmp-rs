//! The agent run-loop (the `snmpd` daemon core).
//!
//! Counterpart of `agent/snmpd.c` + `agent/snmp_agent.c`: bind a UDP socket,
//! receive community-based messages, dispatch them through the [`Registry`],
//! and send back responses. Community authentication is checked here, mirroring
//! the simple community ACL behaviour of the C agent's `snmpd.conf` rocommunity.

use crate::registry::{Registry, SecurityContext};
use crate::vacm::Vacm;
use netsnmp::error::{Error, Result};
use netsnmp::message::{Message, Version};
use netsnmp::usm::UsmUser;
use netsnmp::v3::{self, EngineParams, HeaderData, UsmSecurityParameters, UsmStat};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

/// The RFC 3414 time-window tolerance (seconds): authenticated requests whose
/// engine time differs from ours by more than this trigger a `notInTimeWindow`
/// Report so the peer can re-synchronize.
const TIME_WINDOW_SECS: i64 = 150;

/// Configuration for the agent listener.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Address to bind, e.g. `"0.0.0.0:161"` or `"127.0.0.1:1161"`.
    pub bind_addr: String,
    /// Accepted read community (others are dropped without reply).
    pub community: Vec<u8>,
    /// The authoritative `snmpEngineID` advertised to SNMPv3 peers.
    pub engine_id: Vec<u8>,
    /// The authoritative `snmpEngineBoots` counter.
    pub engine_boots: u32,
    /// Configured SNMPv3/USM users (empty disables v3).
    pub users: Vec<UsmUser>,
    /// Optional VACM (RFC 3415) access-control state. When `None` or when the
    /// [`Vacm`] is empty, the agent is permissive (backwards compatible —
    /// authentication alone gates access, exactly as before). Supply a
    /// populated `Vacm` to enforce per-view read/write/notify ACLs.
    pub vacm: Option<Arc<Vacm>>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            bind_addr: "127.0.0.1:1161".to_string(),
            community: b"public".to_vec(),
            engine_id: default_engine_id(),
            engine_boots: 1,
            users: Vec::new(),
            vacm: None,
        }
    }
}

/// Build a default RFC 3411 `snmpEngineID`: the net-snmp enterprise number
/// (8072 = `0x1F88`) with the high "non-IANA format" bit set, a format octet of
/// 4 (text), and an `"rs"` discriminator. Stable so discovery is reproducible.
fn default_engine_id() -> Vec<u8> {
    vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', 0x00, 0x01]
}

/// An SNMP agent: a registry of MIB handlers plus a UDP listener.
pub struct Agent {
    registry: Arc<Registry>,
    config: AgentConfig,
    /// Users keyed by their security name (`msgUserName`) bytes.
    users: HashMap<Vec<u8>, UsmUser>,
    /// Instant the agent started, used to derive `snmpEngineTime`.
    boot_time: Instant,
    /// Running USM error counter reported in `usmStats` Report PDUs.
    usm_stats: AtomicU32,
    /// The VACM access-control state. Defaults to an empty (permissive) `Vacm`
    /// so that agents constructed without VACM behave exactly as before. When
    /// non-empty, per-varbind read/write/notify views are enforced.
    vacm: Arc<Vacm>,
}

impl Agent {
    /// Create an agent from a populated registry and configuration.
    pub fn new(registry: Registry, config: AgentConfig) -> Self {
        let users = config
            .users
            .iter()
            .map(|u| (u.name.as_bytes().to_vec(), u.clone()))
            .collect();
        let vacm = config.vacm.clone().unwrap_or_else(|| Arc::new(Vacm::new()));
        Agent {
            registry: Arc::new(registry),
            config,
            users,
            boot_time: Instant::now(),
            usm_stats: AtomicU32::new(0),
            vacm,
        }
    }

    /// Attach a [`Vacm`] to this agent, replacing any existing one. The agent
    /// takes a clone of the [`Arc`] so callers may keep their own handle for
    /// runtime mutation (e.g. via `snmpvacm` SET).
    pub fn with_vacm(mut self, vacm: Arc<Vacm>) -> Self {
        self.vacm = vacm;
        self
    }

    /// Borrow the agent's VACM state. The returned [`Vacm`] is shared with the
    /// request dispatch path, so mutations through its `add_*`/`remove_*`
    /// methods take effect immediately for subsequent requests.
    pub fn vacm(&self) -> &Vacm {
        &self.vacm
    }

    /// Borrow the registry (e.g. to mutate handlers before serving — note the
    /// registry is shared via `Arc`, so register before constructing).
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The current authoritative engine parameters (engine time advances with
    /// wall-clock since start).
    fn engine(&self) -> EngineParams {
        EngineParams {
            engine_id: self.config.engine_id.clone(),
            engine_boots: self.config.engine_boots,
            engine_time: self.boot_time.elapsed().as_secs() as u32,
        }
    }

    /// Next value for a `usmStats` counter included in a Report PDU.
    fn next_stat(&self) -> u32 {
        self.usm_stats
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Process one raw datagram into an optional response datagram.
    ///
    /// Returns `Ok(None)` when the message should be silently dropped (bad
    /// community, failed authentication or unparseable), matching agent
    /// behaviour. Dispatches SNMPv3 messages to the USM path and community
    /// (v1/v2c) messages to the legacy path. Exposed separately so it can be
    /// unit-tested without a socket.
    pub fn handle_datagram(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        match v3::peek_security(data) {
            Ok((header, usm)) => self.handle_v3(data, &header, &usm),
            // Non-v3 versions fall through to the community responder.
            Err(Error::UnsupportedVersion(_)) => self.handle_community(data),
            // Unparseable as either: drop.
            Err(_) => {
                debug!(bytes = data.len(), "dropping unparseable datagram");
                Ok(None)
            }
        }
    }

    /// Handle a community-based (SNMPv1/v2c) datagram.
    fn handle_community(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let msg = match Message::decode(data) {
            Ok(m) => m,
            Err(_) => {
                debug!("dropping malformed community message");
                return Ok(None);
            }
        };
        if msg.community != self.config.community {
            // Wrong community: drop silently (the C agent increments
            // snmpInBadCommunityNames and does not reply). The community value
            // is intentionally not logged.
            debug!("dropping community message with wrong community");
            return Ok(None);
        }
        trace!(pdu_type = ?msg.pdu.pdu_type, request_id = msg.pdu.request_id, "dispatching community request");
        // Map the SNMP version onto a VACM security model: v1 -> 1, v2c -> 2.
        // (v3 never reaches this path.) The security name is the community
        // string and the security level is noAuthNoPriv (0).
        let security_model = match msg.version {
            Version::V1 => 1,
            _ => 2,
        };
        let sec = SecurityContext {
            security_model,
            security_name: msg.community.clone(),
            security_level: 0,
            context: Vec::new(),
            vacm: Some(Arc::clone(&self.vacm)),
        };
        let response_pdu = self.registry.process_with_access(&msg.pdu, &sec);
        let response = Message::new(msg.version, msg.community, response_pdu);
        Ok(Some(response.encode()?))
    }

    /// Handle an SNMPv3/USM datagram as the authoritative engine: answer engine
    /// discovery, look up the named user, verify/decrypt, enforce the time
    /// window, dispatch the inner PDU, and return an authenticated/encrypted
    /// response (or a `usmStats` Report).
    fn handle_v3(
        &self,
        data: &[u8],
        header: &HeaderData,
        usm: &UsmSecurityParameters,
    ) -> Result<Option<Vec<u8>>> {
        let engine = self.engine();

        // Engine discovery (RFC 3414 §4): an empty or mismatched engineID gets
        // an unauthenticated Report carrying our authoritative engine params.
        if usm.engine_id.is_empty() || usm.engine_id != engine.engine_id {
            trace!("engine discovery / unknown engine id, replying with Report");
            let report = v3::build_report(
                header.msg_id,
                None,
                &engine,
                UsmStat::UnknownEngineIDs,
                self.next_stat(),
                0,
            )?;
            return Ok(Some(report));
        }

        // Look up the user named in the security parameters. The security name
        // travels in cleartext under USM, so logging it leaks no secret.
        let user = match self.users.get(&usm.user_name) {
            Some(u) => u,
            None => {
                debug!(
                    user = %String::from_utf8_lossy(&usm.user_name),
                    "unknown USM user, replying with Report"
                );
                let report = v3::build_report(
                    header.msg_id,
                    None,
                    &engine,
                    UsmStat::UnknownUserNames,
                    self.next_stat(),
                    0,
                )?;
                return Ok(Some(report));
            }
        };

        // Verify the HMAC and decrypt the ScopedPDU with the matched user.
        let msg = match v3::parse(data, Some(user)) {
            Ok(m) => m,
            // Bad digest: drop silently (do not leak which step failed).
            Err(Error::AuthFailure(_)) => {
                debug!("USM authentication failed, dropping");
                return Ok(None);
            }
            Err(Error::PrivFailure(_)) => {
                debug!("USM decryption failed, replying with Report");
                let report = v3::build_report(
                    header.msg_id,
                    Some(user),
                    &engine,
                    UsmStat::DecryptionErrors,
                    self.next_stat(),
                    0,
                )?;
                return Ok(Some(report));
            }
            Err(_) => return Ok(None),
        };

        // Time-window check (only meaningful for authenticated messages).
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
                return Ok(Some(report));
            }
        }

        // Dispatch the inner PDU and build an authenticated/encrypted response
        // at the same security level the request used. VACM is consulted with
        // the USM security context: model 3, the user name as security name,
        // the request's security level, and the scoped PDU's context name.
        let security_level = match user.security_level() {
            netsnmp::usm::SecurityLevel::NoAuthNoPriv => 0,
            netsnmp::usm::SecurityLevel::AuthNoPriv => 1,
            netsnmp::usm::SecurityLevel::AuthPriv => 3,
        };
        let sec = SecurityContext {
            security_model: 3,
            security_name: user.name.as_bytes().to_vec(),
            security_level,
            context: msg.scoped.context_name.clone(),
            vacm: Some(Arc::clone(&self.vacm)),
        };
        let response_pdu = self.registry.process_with_access(&msg.scoped.pdu, &sec);
        let reply = v3::build_response(
            header.msg_id,
            user,
            &engine,
            &engine.engine_id,
            response_pdu,
        )?;
        Ok(Some(reply))
    }

    /// Bind the listener socket, returning it together with its bound address.
    /// Useful for tests that need the ephemeral port chosen by the OS.
    pub async fn bind(&self) -> Result<UdpSocket> {
        Ok(UdpSocket::bind(&self.config.bind_addr).await?)
    }

    /// Run the async serve loop on an already-bound socket. This never returns
    /// under normal operation; it is the equivalent of `snmpd`'s main
    /// `select`/`recvfrom` loop.
    pub async fn serve_on(&self, socket: UdpSocket) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;
            trace!(%peer, bytes = n, "received datagram");
            if let Some(reply) = self.handle_datagram(&buf[..n])? {
                socket.send_to(&reply, peer).await?;
            }
        }
    }

    /// Bind and run the serve loop. Equivalent of `snmpd`'s main loop.
    pub async fn serve_forever(&self) -> Result<()> {
        let socket = self.bind().await?;
        self.serve_on(socket).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::ScalarHandler;
    use netsnmp::message::Version;
    use netsnmp::pdu::{Pdu, PduType};
    use netsnmp::usm::{AuthProtocol, PrivProtocol};
    use netsnmp::value::Value;

    fn test_agent() -> Agent {
        let mut reg = Registry::new();
        reg.register(Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1.1".parse().unwrap(),
            Value::OctetString(b"net-snmp-rs agent".to_vec()),
        )));
        Agent::new(reg, AgentConfig::default())
    }

    fn v3_agent(user: UsmUser) -> Agent {
        let mut reg = Registry::new();
        reg.register(Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1.1".parse().unwrap(),
            Value::OctetString(b"net-snmp-rs agent".to_vec()),
        )));
        let config = AgentConfig {
            users: vec![user],
            ..AgentConfig::default()
        };
        Agent::new(reg, config)
    }

    #[test]
    fn responds_to_valid_community() {
        let agent = test_agent();
        let req = Message::new(
            Version::V2c,
            b"public".to_vec(),
            Pdu::new(PduType::Get, 42).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap()),
        );
        let reply = agent
            .handle_datagram(&req.encode().unwrap())
            .unwrap()
            .unwrap();
        let resp = Message::decode(&reply).unwrap();
        assert_eq!(resp.pdu.request_id, 42);
        assert_eq!(
            resp.pdu.variables[0].value,
            Value::OctetString(b"net-snmp-rs agent".to_vec())
        );
    }

    #[test]
    fn drops_wrong_community() {
        let agent = test_agent();
        let req = Message::new(
            Version::V2c,
            b"wrong".to_vec(),
            Pdu::new(PduType::Get, 1).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap()),
        );
        assert!(
            agent
                .handle_datagram(&req.encode().unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn v3_discovery_returns_engine_id() {
        let agent = v3_agent(UsmUser::auth(
            "tester",
            AuthProtocol::HmacSha1,
            "authpassword",
        ));
        let probe = v3::build_discovery(7, 1).unwrap();
        let reply = agent.handle_datagram(&probe).unwrap().expect("a report");
        // The discovery Report is noAuth, so it parses without a user.
        let msg = v3::parse(&reply, None).unwrap();
        assert_eq!(msg.usm.engine_id, agent.config.engine_id);
        assert_eq!(msg.scoped.pdu.pdu_type, PduType::Report);
    }

    /// Drive a full authenticated+encrypted exchange against the agent using the
    /// library's own v3 request/response framing (post-discovery).
    fn v3_request_roundtrip(user: UsmUser) {
        let agent = v3_agent(user.clone());
        let engine = agent.engine();
        let req_pdu =
            Pdu::new(PduType::Get, 4242).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
        let req = v3::build_request(99, &user, &engine, &engine.engine_id, req_pdu).unwrap();

        let reply = agent.handle_datagram(&req).unwrap().expect("a response");
        let msg = v3::parse(&reply, Some(&user)).unwrap();
        assert_eq!(msg.scoped.pdu.pdu_type, PduType::Response);
        assert_eq!(msg.scoped.pdu.request_id, 4242);
        assert_eq!(
            msg.scoped.pdu.variables[0].value,
            Value::OctetString(b"net-snmp-rs agent".to_vec())
        );
    }

    #[test]
    fn v3_auth_no_priv_get() {
        v3_request_roundtrip(UsmUser::auth(
            "tester",
            AuthProtocol::HmacSha1,
            "authpassword",
        ));
    }

    #[test]
    fn v3_auth_priv_get() {
        v3_request_roundtrip(UsmUser::auth_priv(
            "tester",
            AuthProtocol::HmacSha256,
            "authpassword",
            PrivProtocol::AesCfb128,
            "privpassword",
        ));
    }

    #[test]
    fn v3_unknown_user_reports() {
        let agent = v3_agent(UsmUser::auth(
            "known",
            AuthProtocol::HmacSha1,
            "authpassword",
        ));
        let engine = agent.engine();
        // A different (unknown) user name.
        let stranger = UsmUser::auth("stranger", AuthProtocol::HmacSha1, "authpassword");
        let pdu = Pdu::new(PduType::Get, 1).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
        let req = v3::build_request(1, &stranger, &engine, &engine.engine_id, pdu).unwrap();
        let reply = agent.handle_datagram(&req).unwrap().expect("a report");
        let report = v3::parse(&reply, None).unwrap();
        assert_eq!(report.scoped.pdu.pdu_type, PduType::Report);
        // usmStatsUnknownUserNames = 1.3.6.1.6.3.15.1.1.3.0
        assert_eq!(
            report.scoped.pdu.variables[0].oid.to_string(),
            ".1.3.6.1.6.3.15.1.1.3.0"
        );
    }

    #[test]
    fn v3_wrong_password_is_dropped() {
        let agent = v3_agent(UsmUser::auth(
            "tester",
            AuthProtocol::HmacSha1,
            "correct-password",
        ));
        let engine = agent.engine();
        let imposter = UsmUser::auth("tester", AuthProtocol::HmacSha1, "wrong-password");
        let pdu = Pdu::new(PduType::Get, 1).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
        let req = v3::build_request(1, &imposter, &engine, &engine.engine_id, pdu).unwrap();
        // Bad HMAC: silently dropped.
        assert!(agent.handle_datagram(&req).unwrap().is_none());
    }
}
