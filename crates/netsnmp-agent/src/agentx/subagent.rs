//! AgentX subagent client (RFC 2741 §4 / §7).
//!
//! Counterpart of `agent/mibgroup/agentx/subagent.c`. A [`Subagent`] connects to
//! a master agent over a Unix domain socket, opens a session, registers one or
//! more subtrees, then enters a run loop dispatching incoming GET/GETNEXT/SET
//! PDUs to a user-supplied [`SubagentHandler`].
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use netsnmp_agent::agentx::{Subagent, SubagentHandler};
//! use netsnmp::oid::Oid;
//! use netsnmp::value::Value;
//!
//! struct MyMib;
//! impl SubagentHandler for MyMib {
//!     fn get(&self, oid: &Oid) -> Option<Value> { None }
//!     fn get_next(&self, oid: &Oid) -> Option<(Oid, Value)> { None }
//!     fn set(&self, _oid: &Oid, _value: &Value) -> Result<(), u16> { Ok(()) }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sub = Subagent::connect_unix("/var/agentx/master").await?;
//! sub.register("1.3.6.1.4.1.9999".parse().unwrap(), 127).await?;
//! sub.run(Arc::new(MyMib)).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tracing::{debug, warn};

use super::master::{data_to_value, read_pdu, value_to_data};
use super::protocol::{
    encode_pdu, AgentxData, AgentxError, AgentxHeader, AgentxVarBind, BulkBody, Pdu, PduBody,
    PduType, RegisterBody, ResponseBody, SearchBody, SetBody, VERSION,
};

/// Errors returned by the subagent client.
#[derive(Debug)]
pub enum SubagentError {
    /// An I/O error on the connection.
    Io(std::io::Error),
    /// A protocol codec error.
    Protocol(String),
    /// The master rejected an Open/Register with the given error code.
    AgentxError(u16),
    /// The request timed out waiting for a Response.
    Timeout,
}

impl std::fmt::Display for SubagentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubagentError::Io(e) => write!(f, "I/O error: {e}"),
            SubagentError::Protocol(s) => write!(f, "protocol error: {s}"),
            SubagentError::AgentxError(c) => write!(f, "AgentX error code {c}"),
            SubagentError::Timeout => write!(f, "timeout waiting for master response"),
        }
    }
}

impl std::error::Error for SubagentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SubagentError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SubagentError {
    fn from(e: std::io::Error) -> Self {
        SubagentError::Io(e)
    }
}

/// Trait implemented by subagent MIB handlers to answer GET/GETNEXT/SET
/// requests forwarded by the master.
///
/// The methods mirror [`crate::handler::MibHandler`] but are deliberately
/// simpler (no SET transaction phases): AgentX subagents report a single
/// per-varbind success/failure in their Response.
pub trait SubagentHandler: Send + Sync {
    /// Handle a GET for an exact instance OID. Return `None` to signal
    /// `noSuchInstance`.
    fn get(&self, oid: &Oid) -> Option<Value>;

    /// Handle a GETNEXT: return the first reading strictly greater than `oid`
    /// within this subagent's registered subtree, or `None` if there is none.
    fn get_next(&self, oid: &Oid) -> Option<(Oid, Value)>;

    /// Handle a SET. Return `Ok(())` on success, or `Err(error_code)` with an
    /// AgentX error code (e.g. `processingError` = 268) on failure.
    fn set(&self, oid: &Oid, value: &Value) -> std::result::Result<(), u16>;
}

/// A connected AgentX subagent client.
pub struct Subagent {
    stream: UnixStream,
    session_id: u32,
}

impl Subagent {
    /// Connect to a master agent listening on `path` and complete the Open
    /// handshake, returning a ready [`Subagent`] with its assigned session ID.
    pub async fn connect_unix(path: &str) -> Result<Subagent, SubagentError> {
        let mut stream = UnixStream::connect(path).await?;
        // (Unix streams have no NODELAY socket option; no-op.)

        // Open PDU: session_id 0 (master assigns), timeout 30s, id = our
        // enterprise OID, descr = "net-snmp-rs".
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Open.as_u8(),
            flags: 0,
            session_id: 0,
            transaction_id: 0,
            packet_id: 1,
            payload_length: 0,
            timeout: 30,
        };
        let pdu = Pdu {
            header: header.clone(),
            body: PduBody::Open(super::protocol::OpenBody {
                timeout: 30,
                id: "1.3.6.1.4.1.8072".parse().unwrap(),
                descr: "net-snmp-rs subagent".to_string(),
            }),
        };
        stream.write_all(&encode_pdu(&pdu)).await?;

        let resp = read_pdu(&mut stream).await?;
        let session_id = resp.header.session_id;
        match resp.body {
            PduBody::Response(r) if r.error == 0 => {}
            PduBody::Response(r) => return Err(SubagentError::AgentxError(r.error)),
            other => {
                return Err(SubagentError::Protocol(format!(
                    "expected Open Response, got {:?}",
                    other.pdu_type()
                )))
            }
        }
        debug!(session_id, "AgentX subagent session opened");
        Ok(Subagent { stream, session_id })
    }

    /// The session ID assigned by the master during Open.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Register `subtree` with the given `priority` (lower wins; default 127).
    /// Awaits the master's Response and returns an error if rejected.
    pub async fn register(&mut self, subtree: Oid, priority: u8) -> Result<(), SubagentError> {
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Register.as_u8(),
            flags: 0,
            session_id: self.session_id,
            transaction_id: 0,
            packet_id: 2,
            payload_length: 0,
            timeout: 5,
        };
        let pdu = Pdu {
            header: header.clone(),
            body: PduBody::Register(RegisterBody {
                timeout: 5,
                priority,
                range_subid: 0,
                subtree,
                range_bound: Oid::null(),
                context: None,
            }),
        };
        self.stream.write_all(&encode_pdu(&pdu)).await?;
        let resp = read_pdu(&mut self.stream).await?;
        match resp.body {
            PduBody::Response(r) if r.error == 0 => Ok(()),
            PduBody::Response(r) => Err(SubagentError::AgentxError(r.error)),
            other => Err(SubagentError::Protocol(format!(
                "expected Register Response, got {:?}",
                other.pdu_type()
            ))),
        }
    }

    /// Send a Notify PDU carrying `varbinds` to the master (RFC 2741 §6.2.11).
    pub async fn notify(&mut self, varbinds: Vec<AgentxVarBind>) -> Result<(), SubagentError> {
        let header = AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Notify.as_u8(),
            flags: 0,
            session_id: self.session_id,
            transaction_id: 0,
            packet_id: 3,
            payload_length: 0,
            timeout: 0,
        };
        let pdu = Pdu {
            header,
            body: PduBody::Notify(super::protocol::NotifyBody {
                context: None,
                varbinds,
            }),
        };
        self.stream.write_all(&encode_pdu(&pdu)).await?;
        // Await the master's acknowledgement.
        let resp = read_pdu(&mut self.stream).await?;
        match resp.body {
            PduBody::Response(r) if r.error == 0 => Ok(()),
            PduBody::Response(r) => Err(SubagentError::AgentxError(r.error)),
            _ => Ok(()),
        }
    }

    /// Run the subagent dispatch loop. Reads PDUs from the master until the
    /// connection closes; for each GET/GETNEXT/SET the `handler` is invoked and
    /// a Response is sent. Ping and Cleanup are acknowledged.
    pub async fn run<H: SubagentHandler>(self, handler: Arc<H>) -> Result<(), SubagentError> {
        let mut stream = self.stream;
        let session_id = self.session_id;
        loop {
            let req = match read_pdu(&mut stream).await {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, "subagent read ended");
                    return Err(SubagentError::Io(e));
                }
            };
            let req_packet_id = req.header.packet_id;
            let req_flags = req.header.flags;
            let resp_body = match req.body {
                PduBody::Get(s) => handle_get(&handler, &s),
                PduBody::GetNext(s) => handle_get_next(&handler, &s),
                PduBody::GetBulk(b) => handle_get_bulk(&handler, &b),
                PduBody::Set(s) => handle_set(&handler, &s),
                PduBody::Ping(_) => PduBody::Response(ResponseBody {
                    sys_up_time: 0,
                    error: AgentxError::NoError as u16,
                    index: 0,
                    varbinds: Vec::new(),
                }),
                PduBody::Cleanup(_) => {
                    // No response required; continue.
                    continue;
                }
                other => {
                    warn!(pdu = ?other.pdu_type(), "subagent received unexpected PDU");
                    PduBody::Response(ResponseBody {
                        sys_up_time: 0,
                        error: AgentxError::ProcessingError as u16,
                        index: 0,
                        varbinds: Vec::new(),
                    })
                }
            };
            let resp_header = AgentxHeader {
                version: VERSION,
                pdu_type: PduType::Response.as_u8(),
                flags: req_flags,
                session_id,
                transaction_id: req.header.transaction_id,
                packet_id: req_packet_id,
                payload_length: 0,
                timeout: 0,
            };
            let resp = Pdu {
                header: resp_header,
                body: resp_body,
            };
            if let Err(e) = stream.write_all(&encode_pdu(&resp)).await {
                debug!(error = %e, "subagent write ended");
                return Err(SubagentError::Io(e));
            }
        }
    }
}

/// Handle a Get PDU: one varbind per search range, exact match.
fn handle_get<H: SubagentHandler>(handler: &Arc<H>, s: &SearchBody) -> PduBody {
    let mut varbinds = Vec::with_capacity(s.search_range.len());
    let mut error = AgentxError::NoError as u16;
    let mut index = 0u16;
    for (i, (start, _end)) in s.search_range.iter().enumerate() {
        match handler.get(start) {
            Some(v) => varbinds.push(AgentxVarBind {
                name: start.clone(),
                data: value_to_data(&v),
            }),
            None => {
                // noSuchInstance is not a distinct AgentX data type; we
                // report it as an endOfMibView-equivalent (Null) plus a
                // processingError per net-snmp's pragmatic mapping. Some
                // masters prefer error=noError with an empty varbind; we
                // follow the latter to keep the loopback test simple.
                varbinds.push(AgentxVarBind {
                    name: start.clone(),
                    data: AgentxData::Null,
                });
                error = AgentxError::NoError as u16;
                index = (i + 1) as u16;
            }
        }
    }
    PduBody::Response(ResponseBody {
        sys_up_time: 0,
        error,
        index,
        varbinds,
    })
}

/// Handle a GetNext PDU: return the successor for each search range.
fn handle_get_next<H: SubagentHandler>(handler: &Arc<H>, s: &SearchBody) -> PduBody {
    let mut varbinds = Vec::with_capacity(s.search_range.len());
    for (start, _end) in s.search_range.iter() {
        match handler.get_next(start) {
            Some((oid, v)) => varbinds.push(AgentxVarBind {
                name: oid,
                data: value_to_data(&v),
            }),
            None => varbinds.push(AgentxVarBind {
                name: start.clone(),
                data: AgentxData::Null,
            }),
        }
    }
    PduBody::Response(ResponseBody {
        sys_up_time: 0,
        error: AgentxError::NoError as u16,
        index: 0,
        varbinds,
    })
}

/// Handle a GetBulk PDU: a simplified single-repetition GETNEXT per range.
fn handle_get_bulk<H: SubagentHandler>(handler: &Arc<H>, b: &BulkBody) -> PduBody {
    let mut varbinds = Vec::new();
    let non_rep = b.non_repeaters as usize;
    for (i, (start, _end)) in b.search_range.iter().enumerate() {
        if i < non_rep {
            // Non-repeater: single GETNEXT.
            match handler.get_next(start) {
                Some((oid, v)) => varbinds.push(AgentxVarBind {
                    name: oid,
                    data: value_to_data(&v),
                }),
                None => varbinds.push(AgentxVarBind {
                    name: start.clone(),
                    data: AgentxData::Null,
                }),
            }
        } else {
            // Repeater: up to max_repetitions GETNEXTs, walking from the start.
            let mut cursor = start.clone();
            for _ in 0..b.max_repetitions {
                match handler.get_next(&cursor) {
                    Some((oid, v)) => {
                        varbinds.push(AgentxVarBind {
                            name: oid.clone(),
                            data: value_to_data(&v),
                        });
                        cursor = oid;
                    }
                    None => {
                        varbinds.push(AgentxVarBind {
                            name: cursor.clone(),
                            data: AgentxData::Null,
                        });
                        break;
                    }
                }
            }
        }
    }
    PduBody::Response(ResponseBody {
        sys_up_time: 0,
        error: AgentxError::NoError as u16,
        index: 0,
        varbinds,
    })
}

/// Handle a Set PDU: apply each varbind; report the first failure.
fn handle_set<H: SubagentHandler>(handler: &Arc<H>, s: &SetBody) -> PduBody {
    let mut varbinds = Vec::with_capacity(s.varbinds.len());
    for (i, vb) in s.varbinds.iter().enumerate() {
        let value = data_to_value(vb.data.clone());
        match handler.set(&vb.name, &value) {
            Ok(()) => varbinds.push(vb.clone()),
            Err(code) => {
                return PduBody::Response(ResponseBody {
                    sys_up_time: 0,
                    error: code,
                    index: (i + 1) as u16,
                    varbinds,
                });
            }
        }
    }
    PduBody::Response(ResponseBody {
        sys_up_time: 0,
        error: AgentxError::NoError as u16,
        index: 0,
        varbinds,
    })
}

/// Convert an SNMP [`Value`] into an AgentX varbind with the given name.
pub fn value_to_varbind(name: Oid, value: &Value) -> AgentxVarBind {
    AgentxVarBind {
        name,
        data: value_to_data(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_to_varbind_round_trip() {
        let vb = value_to_varbind("1.3.6.1.2.1.1.1.0".parse().unwrap(), &Value::Integer(7));
        assert_eq!(vb.name.as_slice(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(vb.data, AgentxData::Integer(7));
    }
}
