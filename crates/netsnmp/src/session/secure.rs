//! The SNMPv3/USM client [`V3Session`]: engine discovery, time synchronization,
//! and authenticated/encrypted request handling.

use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, VarBind};
use crate::transport::{Transport, UdpTransport};
use crate::usm::UsmUser;
use crate::v3::{self, EngineParams};
use crate::value::Value;
use tokio::time::timeout;
use tracing::debug;

use super::common::{describe_report, next_request_id};

/// An SNMPv3/USM client session: performs engine discovery, builds authenticated
/// and/or encrypted requests, and verifies responses.
pub struct V3Session<T: Transport = UdpTransport> {
    transport: T,
    user: UsmUser,
    engine: EngineParams,
    /// Wall-clock instant at which `engine.engine_time` was learned, used to
    /// advance the authoritative time on subsequent requests.
    time_base: Instant,
    timeout: Duration,
    retries: u32,
    msg_id: AtomicI32,
}

impl V3Session<UdpTransport> {
    /// Open a UDP SNMPv3 session and perform engine discovery against `peer`.
    pub async fn open_udp(
        peer: &str,
        user: UsmUser,
        timeout_dur: Duration,
        retries: u32,
    ) -> Result<Self> {
        let transport = UdpTransport::connect(peer).await?;
        let mut session = V3Session {
            transport,
            user,
            engine: EngineParams::default(),
            time_base: Instant::now(),
            timeout: timeout_dur,
            retries,
            msg_id: AtomicI32::new(1),
        };
        session.discover().await?;
        Ok(session)
    }

    /// Open a UDP SNMPv3 session for sending **traps** without engine discovery.
    ///
    /// A notification originator (trap sender) is itself the authoritative engine
    /// (RFC 3414 §4): it does not discover the receiver, but stamps its own
    /// `engine` into the message. The receiver verifies using the user's key
    /// localized to that engine id.
    pub async fn open_udp_notifier(
        peer: &str,
        user: UsmUser,
        engine: EngineParams,
        timeout_dur: Duration,
        retries: u32,
    ) -> Result<Self> {
        let transport = UdpTransport::connect(peer).await?;
        Ok(V3Session {
            transport,
            user,
            engine,
            time_base: Instant::now(),
            timeout: timeout_dur,
            retries,
            msg_id: AtomicI32::new(1),
        })
    }
}

impl<T: Transport> V3Session<T> {
    /// Build a v3 session over an arbitrary transport without auto-discovery
    /// (useful for tests that pre-seed the engine parameters).
    pub fn with_transport(
        transport: T,
        user: UsmUser,
        engine: EngineParams,
        timeout_dur: Duration,
        retries: u32,
    ) -> Self {
        V3Session {
            transport,
            user,
            engine,
            time_base: Instant::now(),
            timeout: timeout_dur,
            retries,
            msg_id: AtomicI32::new(1),
        }
    }

    /// The discovered authoritative engine parameters.
    pub fn engine(&self) -> &EngineParams {
        &self.engine
    }

    fn next_msg_id(&self) -> i32 {
        self.msg_id.fetch_add(1, Ordering::Relaxed).max(1)
    }

    /// The authoritative engine time, advanced by the elapsed wall-clock since
    /// discovery (RFC 3414 §2.2.3 keeps a local notion of the remote's time).
    fn current_engine_time(&self) -> u32 {
        let elapsed = self.time_base.elapsed().as_secs() as u32;
        self.engine.engine_time.wrapping_add(elapsed)
    }

    /// Perform RFC 3414 §4 engine discovery: send a `noAuthNoPriv` probe and
    /// learn the authoritative engineID / boots / time from the Report.
    pub async fn discover(&mut self) -> Result<()> {
        let request_id = next_request_id();
        let bytes = v3::build_discovery(self.next_msg_id(), request_id)?;
        let raw = self.exchange(&bytes).await?;
        let msg = v3::parse(&raw, None)?;
        if msg.usm.engine_id.is_empty() {
            return Err(Error::Report(
                "discovery response carried no engine id".into(),
            ));
        }
        self.engine = EngineParams {
            engine_id: msg.usm.engine_id,
            engine_boots: msg.usm.engine_boots,
            engine_time: msg.usm.engine_time,
        };
        self.time_base = Instant::now();
        debug!(
            engine_id = %self.engine.engine_id_hex(),
            engine_boots = self.engine.engine_boots,
            engine_time = self.engine.engine_time,
            "discovered authoritative engine"
        );
        Ok(())
    }

    /// Low-level: send `bytes` once and await one datagram, honoring the timeout.
    async fn exchange(&self, bytes: &[u8]) -> Result<bytes::Bytes> {
        self.transport.send(bytes).await?;
        match timeout(self.timeout, self.transport.receive()).await {
            Ok(Ok(raw)) => Ok(raw),
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(Error::Timeout),
        }
    }

    /// Send an authenticated/encrypted request PDU and return the response PDU.
    ///
    /// On a `notInTimeWindow` Report the engine time is re-synchronized and the
    /// request retried once, as recommended by RFC 3414 §3.2.
    pub async fn request(&mut self, mut pdu: Pdu) -> Result<Pdu> {
        pdu.request_id = next_request_id();
        let mut resynced = false;
        let mut last_err = Error::Timeout;

        for _ in 0..=self.retries {
            let engine = EngineParams {
                engine_id: self.engine.engine_id.clone(),
                engine_boots: self.engine.engine_boots,
                engine_time: self.current_engine_time(),
            };
            let bytes = v3::build_request(
                self.next_msg_id(),
                &self.user,
                &engine,
                &self.engine.engine_id,
                pdu.clone(),
            )?;

            let raw = match self.exchange(&bytes).await {
                Ok(raw) => raw,
                Err(Error::Timeout) => {
                    last_err = Error::Timeout;
                    continue;
                }
                Err(e) => return Err(e),
            };

            // A Report at noAuth level is sent on USM errors; resync time once.
            let parsed = match v3::parse(&raw, Some(&self.user)) {
                Ok(p) => p,
                Err(Error::AuthFailure(_)) if !resynced => {
                    // Could be a noAuth Report; re-parse without auth to learn time.
                    if let Ok(report) = v3::parse(&raw, None)
                        && report.scoped.pdu.pdu_type == PduType::Report
                    {
                        self.engine.engine_boots = report.usm.engine_boots;
                        self.engine.engine_time = report.usm.engine_time;
                        self.time_base = Instant::now();
                        resynced = true;
                        continue;
                    }
                    return Err(Error::AuthFailure("response verification failed".into()));
                }
                Err(e) => return Err(e),
            };

            if parsed.scoped.pdu.pdu_type == PduType::Report {
                if !resynced {
                    self.engine.engine_boots = parsed.usm.engine_boots;
                    self.engine.engine_time = parsed.usm.engine_time;
                    self.time_base = Instant::now();
                    resynced = true;
                    continue;
                }
                return Err(Error::Report(describe_report(&parsed.scoped.pdu)));
            }

            if parsed.scoped.pdu.request_id != pdu.request_id {
                last_err = Error::RequestIdMismatch {
                    sent: pdu.request_id,
                    received: parsed.scoped.pdu.request_id,
                };
                continue;
            }
            return Ok(parsed.scoped.pdu);
        }
        Err(last_err)
    }

    /// As [`V3Session::request`] but fails on a non-zero `error-status`.
    pub async fn checked_request(&mut self, pdu: Pdu) -> Result<Pdu> {
        let resp = self.request(pdu).await?;
        let status = resp.status();
        if !status.is_ok() {
            return Err(Error::SnmpError {
                status,
                index: resp.error_index as usize,
            });
        }
        Ok(resp)
    }

    /// Perform a GET for one or more OIDs.
    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::Get, 0);
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// GET a single OID, returning just its value.
    pub async fn get_one(&mut self, oid: &Oid) -> Result<Value> {
        let vars = self.get(std::slice::from_ref(oid)).await?;
        vars.into_iter()
            .next()
            .map(|vb| vb.value)
            .ok_or_else(|| Error::Protocol("empty response varbind list".into()))
    }

    /// Perform a GETNEXT for the given OIDs.
    pub async fn get_next(&mut self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::GetNext, 0);
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Perform a GETBULK.
    pub async fn get_bulk(
        &mut self,
        non_repeaters: u32,
        max_repetitions: u32,
        oids: &[Oid],
    ) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::GetBulk, 0);
        pdu.error_status = non_repeaters as i64;
        pdu.error_index = max_repetitions as i64;
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Perform a SET.
    pub async fn set(&mut self, bindings: Vec<VarBind>) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::Set, 0);
        pdu.variables = bindings;
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Send an unconfirmed SNMPv3 SNMPv2-Trap, stamped with this session's
    /// authoritative `engine` (see [`V3Session::open_udp_notifier`]). No reply
    /// is awaited.
    pub async fn send_trap(
        &mut self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        let pdu = crate::trap::build_notification(
            PduType::TrapV2,
            next_request_id(),
            sys_uptime,
            trap_oid,
            varbinds,
        )?;
        let engine = EngineParams {
            engine_id: self.engine.engine_id.clone(),
            engine_boots: self.engine.engine_boots,
            engine_time: self.current_engine_time(),
        };
        let bytes = v3::build_response(
            self.next_msg_id(),
            &self.user,
            &engine,
            &self.engine.engine_id,
            pdu,
        )?;
        self.transport.send(&bytes).await
    }

    /// Send a confirmed SNMPv3 InformRequest and await the acknowledging
    /// Response. The receiver is authoritative, so this is just a confirmed
    /// request over the discovered engine.
    pub async fn send_inform(
        &mut self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> Result<Pdu> {
        let pdu =
            crate::trap::build_notification(PduType::Inform, 0, sys_uptime, trap_oid, varbinds)?;
        self.checked_request(pdu).await
    }

    /// Walk the subtree rooted at `root` via repeated GETNEXT.
    pub async fn walk(&mut self, root: &Oid) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        let mut current = root.clone();
        loop {
            let vars = self.get_next(std::slice::from_ref(&current)).await?;
            let Some(vb) = vars.into_iter().next() else {
                break;
            };
            match vb.value {
                Value::EndOfMibView | Value::NoSuchObject | Value::NoSuchInstance => break,
                _ => {}
            }
            if !root.is_prefix_of(&vb.oid) || vb.oid <= current {
                break;
            }
            current = vb.oid.clone();
            results.push(vb);
        }
        Ok(results)
    }
}
