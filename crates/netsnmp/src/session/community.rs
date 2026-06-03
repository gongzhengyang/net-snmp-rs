//! The community (SNMPv1/v2c) client [`Session`].

use crate::error::{Error, Result};
use crate::message::{Message, Version};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, VarBind};
use crate::transport::{TcpTransport, Transport, UdpTransport};
use crate::value::Value;
use futures::stream::{Stream, TryStreamExt};
use tokio::time::timeout;
use tracing::{debug, trace};

use super::common::next_request_id;
use super::config::SessionConfig;

/// A client session bound to a single agent over a transport.
pub struct Session<T: Transport = UdpTransport> {
    transport: T,
    config: SessionConfig,
}

impl Session<UdpTransport> {
    /// Open a UDP session to `peer` (host:port).
    pub async fn open_udp(peer: &str, config: SessionConfig) -> Result<Self> {
        let transport = UdpTransport::connect(peer).await?;
        Ok(Session { transport, config })
    }
}

impl Session<TcpTransport> {
    /// Open a TCP session to `peer` (host:port), using `snmpTCPDomain` framing.
    pub async fn open_tcp(peer: &str, config: SessionConfig) -> Result<Self> {
        let transport = TcpTransport::connect(peer).await?;
        Ok(Session { transport, config })
    }
}

#[cfg(feature = "tls")]
impl Session<crate::tls::TlsClientTransport> {
    /// Open a TLS session to `peer` (host:port) using `client` to perform the
    /// handshake and validate the peer certificate (`snmpTLSTCPDomain` channel).
    pub async fn open_tls(
        client: &crate::tls::TlsClient,
        peer: &str,
        config: SessionConfig,
    ) -> Result<Self> {
        let transport = client.connect(peer).await?;
        Ok(Session { transport, config })
    }
}

impl<T: Transport> Session<T> {
    /// Build a session over an arbitrary transport (useful for tests).
    pub fn with_transport(transport: T, config: SessionConfig) -> Self {
        Session { transport, config }
    }

    /// Borrow the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Send a request PDU and return the matching response PDU, applying the
    /// retry/timeout policy and validating the request-id.
    pub async fn request(&self, mut pdu: Pdu) -> Result<Pdu> {
        pdu.request_id = next_request_id();
        let msg = Message::new(
            self.config.version,
            self.config.community.clone(),
            pdu.clone(),
        );
        let bytes = msg.encode()?;

        let mut last_err = Error::Timeout;
        for attempt in 0..=self.config.retries {
            trace!(
                request_id = pdu.request_id,
                pdu_type = ?pdu.pdu_type,
                attempt,
                "sending request"
            );
            self.transport.send(&bytes).await?;
            match timeout(self.config.timeout, self.transport.receive()).await {
                Ok(Ok(raw)) => {
                    let response = Message::decode(&raw)?;
                    let resp_pdu = response.pdu;
                    if resp_pdu.request_id != pdu.request_id {
                        // A stale/forged datagram; keep waiting within budget.
                        debug!(
                            sent = pdu.request_id,
                            received = resp_pdu.request_id,
                            "request-id mismatch, ignoring datagram"
                        );
                        last_err = Error::RequestIdMismatch {
                            sent: pdu.request_id,
                            received: resp_pdu.request_id,
                        };
                        continue;
                    }
                    trace!(request_id = resp_pdu.request_id, "received response");
                    return Ok(resp_pdu);
                }
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    debug!(request_id = pdu.request_id, attempt, "request timed out");
                    last_err = Error::Timeout;
                    continue;
                }
            }
        }
        Err(last_err)
    }

    /// Send a request and additionally fail if the response carries a non-zero
    /// `error-status`.
    pub async fn checked_request(&self, pdu: Pdu) -> Result<Pdu> {
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

    /// Perform a GET for one or more OIDs, returning the response varbinds.
    pub async fn get(&self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::Get, 0);
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// GET a single OID, returning just its value.
    pub async fn get_one(&self, oid: &Oid) -> Result<Value> {
        let vars = self.get(std::slice::from_ref(oid)).await?;
        vars.into_iter()
            .next()
            .map(|vb| vb.value)
            .ok_or_else(|| Error::Protocol("empty response varbind list".into()))
    }

    /// Perform a GETNEXT for the given OIDs.
    pub async fn get_next(&self, oids: &[Oid]) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::GetNext, 0);
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Perform a GETBULK (SNMPv2c). `non_repeaters` scalars are fetched once;
    /// the remaining OIDs are repeated up to `max_repetitions` times.
    pub async fn get_bulk(
        &self,
        non_repeaters: u32,
        max_repetitions: u32,
        oids: &[Oid],
    ) -> Result<Vec<VarBind>> {
        if self.config.version == Version::V1 {
            return Err(Error::Protocol("GETBULK requires SNMPv2c".into()));
        }
        let mut pdu = Pdu::new(PduType::GetBulk, 0);
        pdu.error_status = non_repeaters as i64; // non-repeaters field
        pdu.error_index = max_repetitions as i64; // max-repetitions field
        for oid in oids {
            pdu.variables.push(VarBind::null(oid.clone()));
        }
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Perform a SET with the given (OID, value) bindings.
    pub async fn set(&self, bindings: Vec<VarBind>) -> Result<Vec<VarBind>> {
        let mut pdu = Pdu::new(PduType::Set, 0);
        pdu.variables = bindings;
        Ok(self.checked_request(pdu).await?.variables)
    }

    /// Send an unconfirmed SNMPv2-Trap notification (fire-and-forget; no reply
    /// is awaited). Mirrors `snmptrap`. Requires SNMPv2c (the legacy v1 Trap-PDU
    /// is not supported).
    pub async fn send_trap(
        &self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> Result<()> {
        if self.config.version == Version::V1 {
            return Err(Error::Protocol(
                "SNMPv1 traps are not supported (use -v 2c)".into(),
            ));
        }
        let pdu = crate::trap::build_notification(
            PduType::TrapV2,
            next_request_id(),
            sys_uptime,
            trap_oid,
            varbinds,
        )?;
        let msg = Message::new(self.config.version, self.config.community.clone(), pdu);
        self.transport.send(&msg.encode()?).await
    }

    /// Send a confirmed InformRequest notification and await the acknowledging
    /// Response, applying the retry/timeout policy. Mirrors `snmpinform`.
    pub async fn send_inform(
        &self,
        sys_uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> Result<Pdu> {
        let pdu =
            crate::trap::build_notification(PduType::Inform, 0, sys_uptime, trap_oid, varbinds)?;
        self.checked_request(pdu).await
    }

    /// Walk the MIB subtree rooted at `root` using repeated GETNEXT, yielding
    /// every varbind whose OID is within the subtree as an async [`Stream`].
    ///
    /// This is the streaming counterpart of [`walk`](Self::walk): it lets the
    /// caller process (and print) each varbind as it arrives and bounds memory
    /// to a single binding, instead of buffering the whole subtree. The stream
    /// ends after the first transport error (which is yielded), an out-of-tree
    /// OID, an end-of-MIB marker, or a lack of forward progress.
    pub fn walk_stream<'a>(
        &'a self,
        root: &Oid,
    ) -> impl Stream<Item = Result<VarBind>> + 'a {
        let root = root.clone();
        // State is the next OID to GETNEXT from, or `None` once finished.
        futures::stream::unfold(Some(root.clone()), move |state| {
            let root = root.clone();
            async move {
                let current = state?;
                match self.get_next(std::slice::from_ref(&current)).await {
                    Err(e) => Some((Err(e), None)),
                    Ok(vars) => {
                        let vb = vars.into_iter().next()?;
                        match vb.value {
                            Value::EndOfMibView
                            | Value::NoSuchObject
                            | Value::NoSuchInstance => None,
                            // Stop on leaving the subtree or no forward progress.
                            _ if !root.is_prefix_of(&vb.oid) || vb.oid <= current => None,
                            _ => {
                                let next = vb.oid.clone();
                                Some((Ok(vb), Some(next)))
                            }
                        }
                    }
                }
            }
        })
    }

    /// Walk the MIB subtree rooted at `root` and collect every in-subtree
    /// varbind into a `Vec`. Mirrors `snmpwalk`. Built on [`walk_stream`].
    pub async fn walk(&self, root: &Oid) -> Result<Vec<VarBind>> {
        self.walk_stream(root).try_collect().await
    }
}
