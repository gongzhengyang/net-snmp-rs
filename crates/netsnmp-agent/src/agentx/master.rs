//! AgentX master agent (RFC 2741 §4).
//!
//! Counterpart of `agent/mibgroup/agentx/master.c` and
//! `agent/mibgroup/agentx/master_admin.c`. The master listens on a Unix (or
//! TCP) socket, accepts subagent connections, assigns session IDs, tracks
//! subtree registrations, and forwards GET/GETNEXT/SET requests received from
//! the SNMP side out to the owning subagent.
//!
//! # Concurrency
//!
//! Each accepted subagent connection runs in its own tokio task. The shared
//! state (sessions + subtrees) is guarded by an `RwLock`. Subtree reclamation
//! happens on connection drop: the connection task removes every registration
//! owned by that session on exit.
//!
//! # Lifetime
//!
//! [`AgentxMaster::serve_unix`] takes `self: Arc<Self>` so each spawned
//! connection task can hold its own cheap clone of the master. The master is
//! expected to live for the agent process lifetime, mirroring net-snmp's static
//! `agentx_master` global.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tracing::{debug, warn};

use super::protocol::{
    decode_pdu, encode_pdu, AgentxData, AgentxError, AgentxHeader, AgentxVarBind, Pdu, PduBody,
    PduType, RegisterBody, ResponseBody, SearchBody, SetBody, VERSION,
};

/// First session ID handed out by the master. Per RFC 2741 §6.1 session IDs are
/// assigned by the master; net-snmp starts at 1.
const FIRST_SESSION_ID: u32 = 1;

/// Default per-request forward timeout.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);

/// A subtree registration owned by a subagent session.
#[derive(Clone, Debug)]
pub struct Registration {
    /// Start of the registered subtree.
    pub subtree: Oid,
    /// Inclusive upper bound of the subtree (for range registrations). The
    /// empty OID means "no upper bound" (an open, non-range registration).
    pub range_end: Oid,
    /// Owning subagent session ID.
    pub session_id: u32,
    /// Registration priority (lower wins).
    pub priority: u8,
}

/// An outstanding request waiting for a subagent Response, keyed by packet ID.
struct Pending {
    /// One-shot notifier woken when the Response arrives.
    tx: oneshot::Sender<Pdu>,
}

/// A live subagent connection: a writer half and its pending-request table.
struct Session {
    /// Write half of the subagent connection, serialized so concurrent
    /// forwarders do not interleave PDUs.
    writer: Arc<AsyncMutex<tokio::io::WriteHalf<UnixStream>>>,
    /// Outbound packet-ID counter for this session's requests.
    next_packet_id: AtomicU32,
    /// Pending request table: packet_id -> notifier.
    pending: Arc<Mutex<HashMap<u32, Pending>>>,
    /// The subagent's identity OID from Open (for diagnostics).
    #[allow(dead_code)]
    subagent_id: Oid,
}

impl Session {
    /// Allocate the next outbound packet ID for this session.
    fn next_packet(&self) -> u32 {
        self.next_packet_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }
}

/// The AgentX master agent: accepts subagent connections, tracks registrations,
/// and forwards SNMP GET/GETNEXT/SET to the owning subagent.
pub struct AgentxMaster {
    sessions: RwLock<HashMap<u32, Arc<Session>>>,
    subtrees: RwLock<Vec<Registration>>,
    next_session_id: AtomicU32,
}

impl Default for AgentxMaster {
    fn default() -> Self {
        AgentxMaster::new()
    }
}

impl AgentxMaster {
    /// Create a new master with no sessions or registrations.
    pub fn new() -> Self {
        AgentxMaster {
            sessions: RwLock::new(HashMap::new()),
            subtrees: RwLock::new(Vec::new()),
            next_session_id: AtomicU32::new(FIRST_SESSION_ID),
        }
    }

    /// Listen on a Unix domain socket and serve subagent connections forever.
    ///
    /// Each accepted connection is dispatched in its own task; this future runs
    /// until the listener errors (typically on shutdown). Existing socket files
    /// at `path` are removed before binding.
    pub async fn serve_unix(self: Arc<Self>, path: &str) -> std::io::Result<()> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        debug!(path = %path, "AgentX master listening");
        loop {
            let (stream, _peer) = listener.accept().await?;
            let master = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = master.handle_connection(stream).await {
                    debug!(error = %e, "AgentX subagent connection ended");
                }
            });
        }
    }

    /// How many subagent sessions are currently connected.
    pub fn session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// How many subtree registrations are currently active.
    pub fn registration_count(&self) -> usize {
        self.subtrees.read().unwrap().len()
    }

    /// Handle one subagent connection: read PDUs, dispatch Open/Register/Notify/
    /// Ping/Cleanup, route Responses to outstanding forwarders, reclaim
    /// registrations on disconnect.
    async fn handle_connection(&self, stream: UnixStream) -> std::io::Result<()> {
        // Split the connection into independent read and write halves. The read
        // half drives this loop; the write half lives in the shared `Session`
        // so request forwarders (and this loop's responses) share one mutex.
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = read_half;
        let shared_writer = Arc::new(AsyncMutex::new(write_half));

        // The very first PDU must be Open.
        let first = read_pdu_split(&mut reader).await?;
        let (session_id, session) = match first.body {
            PduBody::Open(ref open) => {
                self.assign_session(&first.header, &open.id, shared_writer.clone())
                    .await?
            }
            _ => {
                // Not an Open: drop.
                return Ok(());
            }
        };

        loop {
            let pdu = match read_pdu_split(&mut reader).await {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, session_id, "subagent read ended");
                    break;
                }
            };
            let req_header = pdu.header.clone();
            match pdu.body {
                PduBody::Close(_) => {
                    debug!(session_id, "subagent closed");
                    break;
                }
                PduBody::Register(r) => {
                    self.add_registration(session_id, &r);
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                PduBody::Unregister(u) => {
                    self.remove_registration(session_id, &u.subtree);
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                PduBody::Ping(_) => {
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                PduBody::Notify(_) => {
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                PduBody::Cleanup(_) => {
                    // Cleanup carries no body; acknowledge by doing nothing.
                }
                PduBody::AddAgentCaps(_) | PduBody::RemoveAgentCaps(_) => {
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                PduBody::Response(resp) => {
                    // Route to the outstanding forwarder waiting on this packet.
                    let mut pending = session.pending.lock().unwrap();
                    if let Some(p) = pending.remove(&req_header.packet_id) {
                        let _ = p.tx.send(Pdu {
                            header: req_header.clone(),
                            body: PduBody::Response(resp),
                        });
                    }
                }
                PduBody::IndexAllocate(_) | PduBody::IndexDeallocate(_) => {
                    self.send_response(&shared_writer, &req_header, session_id, AgentxError::NoError, &[])
                        .await?;
                }
                // Get/GetNext/Set/Undo are master->subagent direction; receiving
                // one from a subagent is a protocol violation. Drop silently.
                _ => {
                    warn!(session_id, "unexpected PDU from subagent, ignoring");
                }
            }
        }

        // Reclaim this session's registrations.
        self.reclaim_session(session_id);
        Ok(())
    }

    /// Assign a new session ID, register the session, send back an Open Response.
    /// Returns the session ID and the shared `Arc<Session>`.
    async fn assign_session(
        &self,
        req_header: &AgentxHeader,
        subagent_id: &Oid,
        writer: Arc<AsyncMutex<tokio::io::WriteHalf<UnixStream>>>,
    ) -> std::io::Result<(u32, Arc<Session>)> {
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session {
            writer,
            next_packet_id: AtomicU32::new(0),
            pending: Arc::new(Mutex::new(HashMap::new())),
            subagent_id: subagent_id.clone(),
        });
        self.sessions
            .write()
            .unwrap()
            .insert(session_id, Arc::clone(&session));

        // Open Response echoes the session_id.
        let resp_header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Response.as_u8(),
            flags: req_header.flags,
            session_id,
            transaction_id: req_header.transaction_id,
            packet_id: req_header.packet_id,
            payload_length: 0,
            timeout: 0,
        };
        let resp = Pdu {
            header: resp_header,
            body: PduBody::Response(ResponseBody {
                sys_up_time: 0,
                error: AgentxError::NoError as u16,
                index: 0,
                varbinds: Vec::new(),
            }),
        };
        let bytes = encode_pdu(&resp);
        {
            let mut guard = session.writer.lock().await;
            guard.write_all(&bytes).await?;
        }
        Ok((session_id, session))
    }

    /// Record a registration for the given session.
    fn add_registration(&self, session_id: u32, r: &RegisterBody) {
        // For a non-range registration (range_subid == 0) the subtree is
        // open-ended: any OID starting with `subtree` matches. We represent
        // that with an empty `range_end`, which `owner_for` treats as "no
        // upper bound". For a range registration the upper bound is the arc at
        // `range_subid - 1` replaced by `range_bound`'s first arc.
        let range_end = if r.range_subid != 0 {
            let idx = (r.range_subid as usize).saturating_sub(1);
            let bound = r.range_bound.as_slice().first().copied().unwrap_or(0);
            let mut end = r.subtree.as_slice().to_vec();
            if idx < end.len() {
                end[idx] = bound;
            }
            Oid::new(end)
        } else {
            // Empty OID sentinel = no upper bound (open subtree).
            Oid::null()
        };
        let reg = Registration {
            subtree: r.subtree.clone(),
            range_end,
            session_id,
            priority: r.priority,
        };
        let mut subtrees = self.subtrees.write().unwrap();
        subtrees.push(reg);
        // Sort by subtree then priority so lookup can find the best match.
        subtrees.sort_by(|a, b| a.subtree.cmp(&b.subtree).then(a.priority.cmp(&b.priority)));
    }

    /// Remove registrations for `session_id` matching `subtree`.
    fn remove_registration(&self, session_id: u32, subtree: &Oid) {
        let mut subtrees = self.subtrees.write().unwrap();
        subtrees.retain(|r| !(r.session_id == session_id && &r.subtree == subtree));
    }

    /// Reclaim every registration owned by `session_id` (on disconnect).
    fn reclaim_session(&self, session_id: u32) {
        let mut subtrees = self.subtrees.write().unwrap();
        subtrees.retain(|r| r.session_id != session_id);
        self.sessions.write().unwrap().remove(&session_id);
    }

    /// Borrow the session for `session_id`, if still connected.
    fn session(&self, session_id: u32) -> Option<Arc<Session>> {
        self.sessions.read().unwrap().get(&session_id).cloned()
    }

    /// Send a Response PDU back to the subagent via the shared writer.
    async fn send_response(
        &self,
        writer: &Arc<AsyncMutex<tokio::io::WriteHalf<UnixStream>>>,
        req: &AgentxHeader,
        session_id: u32,
        error: AgentxError,
        varbinds: &[AgentxVarBind],
    ) -> std::io::Result<()> {
        let resp_header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Response.as_u8(),
            flags: req.flags,
            session_id,
            transaction_id: req.transaction_id,
            packet_id: req.packet_id,
            payload_length: 0,
            timeout: 0,
        };
        let resp = Pdu {
            header: resp_header,
            body: PduBody::Response(ResponseBody {
                sys_up_time: 0,
                error: error as u16,
                index: 0,
                varbinds: varbinds.to_vec(),
            }),
        };
        let bytes = encode_pdu(&resp);
        let mut guard = writer.lock().await;
        guard.write_all(&bytes).await
    }

    /// Find the registration that owns `oid` (longest subtree-prefix match,
    /// lowest priority wins). Returns the owning session ID.
    fn owner_for(&self, oid: &Oid) -> Option<u32> {
        let subtrees = self.subtrees.read().unwrap();
        subtrees
            .iter()
            .filter(|r| {
                // Subtree must be a prefix of the OID, and (for range
                // registrations) the OID must not exceed the upper bound. An
                // empty range_end means "no upper bound" (open subtree).
                r.subtree.is_prefix_of(oid)
                    && (r.range_end.is_empty() || oid <= &r.range_end)
            })
            .min_by_key(|r| (r.subtree.len(), r.priority))
            .map(|r| r.session_id)
    }

    /// Forward a GET for a single OID to its owning subagent and await the
    /// Response, returning the value. Errors when no subagent owns the OID or
    /// the subagent reported an error / disconnected.
    pub async fn forward_get(&self, oid: &Oid) -> Result<Value, ForwardError> {
        let session_id = self.owner_for(oid).ok_or(ForwardError::NoOwner)?;
        let session = self.session(session_id).ok_or(ForwardError::NoOwner)?;
        let packet_id = session.next_packet();
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Get.as_u8(),
            flags: 0,
            session_id,
            transaction_id: 0,
            packet_id,
            payload_length: 0,
            timeout: 0,
        };
        // GET search range: [oid, oid+1). The end bound is empty to mean
        // "no upper limit" within the subagent's subtree (net-snmp convention).
        let pdu = Pdu {
            header: header.clone(),
            body: PduBody::Get(SearchBody {
                context: None,
                search_range: vec![(oid.clone(), Oid::null())],
            }),
        };
        let resp = self.exchange(&session, packet_id, pdu).await?;
        match resp.body {
            PduBody::Response(r) => {
                if r.error != 0 {
                    return Err(ForwardError::AgentxError(r.error));
                }
                let vb = r.varbinds.into_iter().next().ok_or(ForwardError::NoData)?;
                Ok(data_to_value(vb.data))
            }
            _ => Err(ForwardError::NoData),
        }
    }

    /// Forward a GETNEXT for a single OID, returning the successor (oid, value).
    pub async fn forward_get_next(&self, oid: &Oid) -> Result<(Oid, Value), ForwardError> {
        let session_id = self.owner_for(oid).ok_or(ForwardError::NoOwner)?;
        let session = self.session(session_id).ok_or(ForwardError::NoOwner)?;
        let packet_id = session.next_packet();
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::GetNext.as_u8(),
            flags: 0,
            session_id,
            transaction_id: 0,
            packet_id,
            payload_length: 0,
            timeout: 0,
        };
        let pdu = Pdu {
            header,
            body: PduBody::GetNext(SearchBody {
                context: None,
                search_range: vec![(oid.clone(), Oid::null())],
            }),
        };
        let resp = self.exchange(&session, packet_id, pdu).await?;
        match resp.body {
            PduBody::Response(r) => {
                if r.error != 0 {
                    return Err(ForwardError::AgentxError(r.error));
                }
                let vb = r.varbinds.into_iter().next().ok_or(ForwardError::NoData)?;
                Ok((vb.name, data_to_value(vb.data)))
            }
            _ => Err(ForwardError::NoData),
        }
    }

    /// Forward a SET for a single OID.
    pub async fn forward_set(&self, oid: &Oid, value: &Value) -> Result<(), ForwardError> {
        let session_id = self.owner_for(oid).ok_or(ForwardError::NoOwner)?;
        let session = self.session(session_id).ok_or(ForwardError::NoOwner)?;
        let packet_id = session.next_packet();
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Set.as_u8(),
            flags: 0,
            session_id,
            transaction_id: 0,
            packet_id,
            payload_length: 0,
            timeout: 0,
        };
        let data = value_to_data(value);
        let pdu = Pdu {
            header,
            body: PduBody::Set(SetBody {
                context: None,
                varbinds: vec![AgentxVarBind {
                    name: oid.clone(),
                    data,
                }],
            }),
        };
        let resp = self.exchange(&session, packet_id, pdu).await?;
        match resp.body {
            PduBody::Response(r) => {
                if r.error != 0 {
                    return Err(ForwardError::AgentxError(r.error));
                }
                Ok(())
            }
            _ => Err(ForwardError::NoData),
        }
    }

    /// Send a request PDU and await its Response via the pending table.
    async fn exchange(
        &self,
        session: &Arc<Session>,
        packet_id: u32,
        pdu: Pdu,
    ) -> Result<Pdu, ForwardError> {
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = session.pending.lock().unwrap();
            pending.insert(packet_id, Pending { tx });
        }
        let bytes = encode_pdu(&pdu);
        {
            let writer = session.writer.clone();
            let mut guard = writer.lock().await;
            guard
                .write_all(&bytes)
                .await
                .map_err(|_| ForwardError::Disconnected)?;
        }
        match tokio::time::timeout(FORWARD_TIMEOUT, rx).await {
            Ok(Ok(resp)) => Ok(resp),
            _ => {
                let mut pending = session.pending.lock().unwrap();
                pending.remove(&packet_id);
                Err(ForwardError::Timeout)
            }
        }
    }
}

/// Errors returned by [`AgentxMaster`] forwarding methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// No subagent has registered a subtree covering the OID.
    NoOwner,
    /// The owning subagent reported an AgentX error code.
    AgentxError(u16),
    /// The subagent connection was lost.
    Disconnected,
    /// The request timed out.
    Timeout,
    /// The subagent returned no varbind in its Response.
    NoData,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::NoOwner => write!(f, "no AgentX subagent owns this OID"),
            ForwardError::AgentxError(c) => write!(f, "AgentX error code {c}"),
            ForwardError::Disconnected => write!(f, "AgentX subagent disconnected"),
            ForwardError::Timeout => write!(f, "AgentX request timed out"),
            ForwardError::NoData => write!(f, "AgentX response carried no varbind"),
        }
    }
}

impl std::error::Error for ForwardError {}

/// Read exactly one AgentX PDU from a stream: first the 20-byte header to learn
/// the payload length, then the payload.
pub(crate) async fn read_pdu(stream: &mut UnixStream) -> std::io::Result<Pdu> {
    let mut header_buf = [0u8; 20];
    stream.read_exact(&mut header_buf).await?;
    let (header, _) = AgentxHeader::decode(&header_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut payload = vec![0u8; header.payload_length as usize];
    if !payload.is_empty() {
        stream.read_exact(&mut payload).await?;
    }
    let mut full = header_buf.to_vec();
    full.extend_from_slice(&payload);
    decode_pdu(&full)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Read exactly one AgentX PDU from a split read half (used by the connection
/// task after `tokio::io::split`).
pub(crate) async fn read_pdu_split(
    reader: &mut tokio::io::ReadHalf<UnixStream>,
) -> std::io::Result<Pdu> {
    let mut header_buf = [0u8; 20];
    reader.read_exact(&mut header_buf).await?;
    let (header, _) = AgentxHeader::decode(&header_buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut payload = vec![0u8; header.payload_length as usize];
    if !payload.is_empty() {
        reader.read_exact(&mut payload).await?;
    }
    let mut full = header_buf.to_vec();
    full.extend_from_slice(&payload);
    decode_pdu(&full)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Convert an AgentX data value into the SNMP [`Value`] domain type.
pub(crate) fn data_to_value(data: AgentxData) -> Value {
    match data {
        AgentxData::Integer(v) => Value::Integer(v as i64),
        AgentxData::OctetString(b) => Value::OctetString(b),
        AgentxData::Null => Value::Null,
        AgentxData::Oid(o) => Value::Oid(o),
        AgentxData::IpAddress(ip) => Value::IpAddress(ip),
        AgentxData::Counter32(v) => Value::Counter32(v),
        AgentxData::Gauge32(v) => Value::Gauge32(v),
        AgentxData::TimeTicks(v) => Value::TimeTicks(v),
        AgentxData::Opaque(b) => Value::Opaque(b),
        AgentxData::Counter64(v) => Value::Counter64(v),
    }
}

/// Convert an SNMP [`Value`] into the AgentX data type.
pub(crate) fn value_to_data(value: &Value) -> AgentxData {
    match value {
        Value::Integer(v) => AgentxData::Integer(*v as i32),
        Value::OctetString(b) => AgentxData::OctetString(b.clone()),
        Value::Null => AgentxData::Null,
        Value::Oid(o) => AgentxData::Oid(o.clone()),
        Value::IpAddress(ip) => AgentxData::IpAddress(*ip),
        Value::Counter32(v) => AgentxData::Counter32(*v),
        Value::Gauge32(v) => AgentxData::Gauge32(*v),
        Value::TimeTicks(v) => AgentxData::TimeTicks(*v),
        Value::Opaque(b) => AgentxData::Opaque(b.clone()),
        Value::Counter64(v) => AgentxData::Counter64(*v),
        // Exception markers map to Null on the AgentX wire.
        Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => AgentxData::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentx::subagent::Subagent;
    use netsnmp::value::Value;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test(flavor = "multi_thread")]
    async fn master_subagent_loopback_get() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("agentx-master-{}-{nanos}.sock", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        // Build the master behind an Arc so spawned tasks can clone it.
        let master = Arc::new(AgentxMaster::new());
        let master_clone = Arc::clone(&master);
        let path = tmp.to_str().unwrap().to_string();
        tokio::spawn(async move {
            let _ = master_clone.serve_unix(&path).await;
        });

        // Wait briefly for the listener to come up.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Subagent handler returning a fixed value for .9999.1.0.
        struct Fixed;
        impl crate::agentx::SubagentHandler for Fixed {
            fn get(&self, oid: &Oid) -> Option<Value> {
                if oid.as_slice() == [1, 3, 6, 1, 4, 1, 9999, 1, 0] {
                    Some(Value::OctetString(b"ax-ok".to_vec()))
                } else {
                    None
                }
            }
            fn get_next(&self, _oid: &Oid) -> Option<(Oid, Value)> {
                None
            }
            fn set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), u16> {
                Ok(())
            }
        }

        let mut sub = Subagent::connect_unix(tmp.to_str().unwrap())
            .await
            .expect("connect");
        sub.register("1.3.6.1.4.1.9999".parse().unwrap(), 127)
            .await
            .expect("register");
        // The run loop takes ownership of the subagent; the registration has
        // already landed before we move it into the task.
        tokio::spawn(async move {
            let _ = sub.run(Arc::new(Fixed)).await;
        });

        // Give the registration a moment to land.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let oid: Oid = "1.3.6.1.4.1.9999.1.0".parse().unwrap();
        let value = master.forward_get(&oid).await.expect("forward_get");
        assert_eq!(value, Value::OctetString(b"ax-ok".to_vec()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn master_reclaims_subtree_after_disconnect() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!(
            "agentx-reclaim-{}-{nanos}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);

        let master = Arc::new(AgentxMaster::new());
        let master_clone = Arc::clone(&master);
        let path = tmp.to_str().unwrap().to_string();
        tokio::spawn(async move {
            let _ = master_clone.serve_unix(&path).await;
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        struct Fixed;
        impl crate::agentx::SubagentHandler for Fixed {
            fn get(&self, oid: &Oid) -> Option<Value> {
                if oid.as_slice() == [1, 3, 6, 1, 4, 1, 9999, 2, 0] {
                    Some(Value::Integer(99))
                } else {
                    None
                }
            }
            fn get_next(&self, _oid: &Oid) -> Option<(Oid, Value)> {
                None
            }
            fn set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), u16> {
                Ok(())
            }
        }

        // Connect, register, then immediately close by dropping the subagent.
        {
            let mut sub = Subagent::connect_unix(tmp.to_str().unwrap())
                .await
                .expect("connect");
            sub.register("1.3.6.1.4.1.9999".parse().unwrap(), 127)
                .await
                .expect("register");
            // Drop here: the run loop was never started, so the connection is
            // still open. Dropping the UnixStream closes it; the master's read
            // loop will observe EOF and reclaim.
        }
        // Allow the master's read loop to notice the EOF and reclaim.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let oid: Oid = "1.3.6.1.4.1.9999.2.0".parse().unwrap();
        let err = master.forward_get(&oid).await.expect_err("reclaimed");
        assert_eq!(err, ForwardError::NoOwner);
    }
}
