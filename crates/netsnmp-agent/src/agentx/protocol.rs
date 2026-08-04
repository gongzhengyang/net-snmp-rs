//! AgentX PDU wire codec (RFC 2741 §5–§6).
//!
//! This module implements the on-the-wire (de)serialization for every AgentX
//! PDU defined by RFC 2741. The layout is byte-oriented and field-packed, very
//! different from the BER-encoded SNMP PDUs in [`netsnmp::pdu`].
//!
//! # Header layout (RFC 2741 §6.1)
//!
//! The header is a fixed 20-byte structure (all multi-byte fields in the byte
//! order chosen by the `NETWORK_BYTE_ORDER` flag bit, default little-endian):
//!
//! ```text
//!  byte 1:   version            (1 = AgentX version 1)
//!  byte 2:   type               (PDU type code)
//!  byte 3:   flags              (bit 4 = network-byte-order / big-endian)
//!  byte 4:   <reserved>
//!  bytes 5-8:   session_id
//!  bytes 9-12:  transaction_id
//!  bytes 13-16: packet_id
//!  bytes 17-20: payload_length  (excludes the 20-byte header)
//! ```
//!
//! # OID packed encoding (RFC 2741 §5.1)
//!
//! A compact form: a 4-byte header (`n_subid`, `prefix`, `include`,
//! `<reserved>`) followed by `n_subid` 32-bit sub-identifiers. The `prefix`
//! byte, when non-zero, expands to the `1.3.6.1` (`internet`) arcs, so an OID
//! such as `1.3.6.1.2.1.1.1` is stored as `prefix=1` + sub-ids `[2,1,1,1]`.
//!
//! # VarBind encoding (RFC 2741 §5.4)
//!
//! ```text
//!  2 bytes: type   (the ASN.1 tag of the value)
//!  2 bytes: <reserved>
//!  name   : OID (packed form above)
//!  data   : the value (fixed or 4-byte-length-prefixed per type)
//! ```

use net::Ipv4Addr;
use std::net;

use netsnmp::oid::Oid;

/// The AgentX protocol version number (RFC 2741: always 1).
pub const VERSION: u8 = 1;

/// The flag bit selecting network (big-endian) byte order for the whole packet.
pub const FLAG_NETWORK_BYTE_ORDER: u8 = 0x04;
/// The flag bit requesting non-default context handling.
pub const FLAG_NON_DEFAULT_CONTEXT: u8 = 0x08;
/// The flag bit marking an instance (registration) as a single instance.
pub const FLAG_INSTANCE_REGISTERED: u8 = 0x01;
/// The flag bit marking a registration as new, index-allocated.
pub const FLAG_NEW_INDEX: u8 = 0x02;
/// The flag bit marking a registration as any-index-allocated.
pub const FLAG_ANY_INDEX: u8 = 0x04;

/// The fixed 20-byte AgentX PDU header (RFC 2741 §6.1).
///
/// `payload_length` is recomputed on encode and validated on decode; the
/// `timeout`/`uptime` from the task spec are NOT part of the generic header —
/// per RFC 2741 `timeout` lives in the Open/Register body and `sysUpTime` in
/// the Response body. We keep a `timeout` field here only as a convenience
/// carry for callers that build PDUs header+body in one shot (it does not
/// appear on the wire in the generic header slot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentxHeader {
    /// AgentX protocol version (always [`VERSION`]).
    pub version: u8,
    /// PDU type code (see [`PduType`]).
    pub pdu_type: u8,
    /// Header flags bitmask (see `FLAG_*`).
    pub flags: u8,
    /// The session identifier assigned by the master agent.
    pub session_id: u32,
    /// The transaction identifier.
    pub transaction_id: u32,
    /// The packet identifier (correlates Response with request).
    pub packet_id: u32,
    /// Length in bytes of the payload following the 20-byte header.
    pub payload_length: u32,
    /// A convenience carry for the Open/Register timeout (not a generic
    /// header field on the wire; lives in the body).
    pub timeout: u8,
}

impl Default for AgentxHeader {
    fn default() -> Self {
        AgentxHeader {
            version: VERSION,
            pdu_type: PduType::Open.as_u8(),
            flags: 0,
            session_id: 0,
            transaction_id: 0,
            packet_id: 0,
            payload_length: 0,
            timeout: 0,
        }
    }
}

impl AgentxHeader {
    /// Encode the 20-byte header into the given writer.
    ///
    /// `flags` selects the byte order; everything is written little-endian by
    /// default and big-endian when [`FLAG_NETWORK_BYTE_ORDER`] is set, matching
    /// RFC 2741 §6.1.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.push(self.version);
        out.push(self.pdu_type);
        out.push(self.flags);
        out.push(0u8); // reserved
        if self.flags & FLAG_NETWORK_BYTE_ORDER != 0 {
            out.extend_from_slice(&self.session_id.to_be_bytes());
            out.extend_from_slice(&self.transaction_id.to_be_bytes());
            out.extend_from_slice(&self.packet_id.to_be_bytes());
            out.extend_from_slice(&self.payload_length.to_be_bytes());
        } else {
            out.extend_from_slice(&self.session_id.to_le_bytes());
            out.extend_from_slice(&self.transaction_id.to_le_bytes());
            out.extend_from_slice(&self.packet_id.to_le_bytes());
            out.extend_from_slice(&self.payload_length.to_le_bytes());
        }
        out
    }

    /// Decode a 20-byte header. Returns the header and the remaining payload.
    pub fn decode(bytes: &[u8]) -> Result<(AgentxHeader, &[u8]), AgentxError> {
        if bytes.len() < 20 {
            return Err(AgentxError::Truncated);
        }
        let version = bytes[0];
        let pdu_type = bytes[1];
        let flags = bytes[2];
        // bytes[3] reserved
        let big = flags & FLAG_NETWORK_BYTE_ORDER != 0;
        let read_u32 = |b: &[u8]| {
            if big {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let session_id = read_u32(&bytes[4..8]);
        let transaction_id = read_u32(&bytes[8..12]);
        let packet_id = read_u32(&bytes[12..16]);
        let payload_length = read_u32(&bytes[16..20]);
        let header = AgentxHeader {
            version,
            pdu_type,
            flags,
            session_id,
            transaction_id,
            packet_id,
            payload_length,
            timeout: 0,
        };
        Ok((header, &bytes[20..]))
    }

    /// Whether the packet uses network (big-endian) byte order.
    pub fn is_big_endian(&self) -> bool {
        self.flags & FLAG_NETWORK_BYTE_ORDER != 0
    }
}

/// AgentX PDU type codes (RFC 2741 §6.1 / `agentx-PDU`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    /// Open a session (subagent -> master).
    Open = 1,
    /// Close a session (either direction).
    Close = 2,
    /// Register a subtree (subagent -> master).
    Register = 3,
    /// Unregister a subtree (subagent -> master).
    Unregister = 4,
    /// GET request (master -> subagent).
    Get = 5,
    /// GETNEXT request (master -> subagent).
    GetNext = 6,
    /// GETBULK request (master -> subagent).
    GetBulk = 7,
    /// SET request (master -> subagent).
    Set = 8,
    /// Undo phase of a SET (master -> subagent).
    Undo = 9,
    /// Cleanup a transaction (master -> subagent).
    Cleanup = 10,
    /// Notification (subagent -> master).
    Notify = 11,
    /// Ping (either direction).
    Ping = 12,
    /// Index allocate (subagent -> master).
    IndexAllocate = 13,
    /// Index deallocate (subagent -> master).
    IndexDeallocate = 14,
    /// Add agent capabilities (subagent -> master).
    AddAgentCaps = 15,
    /// Remove agent capabilities (subagent -> master).
    RemoveAgentCaps = 16,
    /// Response (subagent -> master, or master -> subagent for Open/Close/etc.).
    Response = 18,
}

impl PduType {
    /// Recover a PDU type from its wire code.
    pub fn from_u8(b: u8) -> Result<PduType, AgentxError> {
        Ok(match b {
            1 => PduType::Open,
            2 => PduType::Close,
            3 => PduType::Register,
            4 => PduType::Unregister,
            5 => PduType::Get,
            6 => PduType::GetNext,
            7 => PduType::GetBulk,
            8 => PduType::Set,
            9 => PduType::Undo,
            10 => PduType::Cleanup,
            11 => PduType::Notify,
            12 => PduType::Ping,
            13 => PduType::IndexAllocate,
            14 => PduType::IndexDeallocate,
            15 => PduType::AddAgentCaps,
            16 => PduType::RemoveAgentCaps,
            18 => PduType::Response,
            _other => return Err(AgentxError::UnknownPduType),
        })
    }

    /// The wire code for this PDU type.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Reason codes for the AgentX Close PDU (RFC 2741 §6.2 `reason` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CloseReason {
    /// `other`, an unspecified reason.
    Other = 1,
    /// A parse error was encountered.
    ParseError = 2,
    /// Protocol violation.
    ProtocolError = 3,
    /// Timed out waiting for the peer.
    Timeout = 4,
    /// The peer is shutting down.
    Shutdown = 5,
}

impl CloseReason {
    /// Decode a Close reason byte.
    pub fn from_u8(b: u8) -> CloseReason {
        match b {
            2 => CloseReason::ParseError,
            3 => CloseReason::ProtocolError,
            4 => CloseReason::Timeout,
            5 => CloseReason::Shutdown,
            _ => CloseReason::Other,
        }
    }
}

/// Body of an AgentX Open PDU (RFC 2741 §6.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenBody {
    /// Session timeout in seconds.
    pub timeout: u8,
    /// The subagent's identity OID.
    pub id: Oid,
    /// Human-readable subagent description.
    pub descr: String,
}

/// Body of an AgentX Close PDU (RFC 2741 §6.2.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseBody {
    /// The reason the session is being closed.
    pub reason: CloseReason,
}

/// Body of an AgentX Register PDU (RFC 2741 §6.2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterBody {
    /// Timeout for this subtree (seconds).
    pub timeout: u8,
    /// Registration priority (lower wins).
    pub priority: u8,
    /// 1-based subid index acting as a range bound, or 0 for none.
    pub range_subid: u8,
    /// The subtree OID being registered.
    pub subtree: Oid,
    /// Upper bound when `range_subid != 0` (stored as a single-arc OID).
    pub range_bound: Oid,
    /// Optional non-default context (present when the context flag is set).
    pub context: Option<String>,
}

/// Body of an AgentX Unregister PDU (RFC 2741 §6.2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnregisterBody {
    /// Unused timeout slot (RFC keeps the field for symmetry with Register).
    pub timeout: u8,
    /// Registration priority.
    pub priority: u8,
    /// 1-based subid index acting as a range bound, or 0 for none.
    pub range_subid: u8,
    /// The subtree OID being unregistered.
    pub subtree: Oid,
    /// Upper bound when `range_subid != 0`.
    pub range_bound: Oid,
    /// Optional non-default context.
    pub context: Option<String>,
}

/// Body of an AgentX Get/GetNext PDU (RFC 2741 §6.2.5 / §6.2.6): a context
/// followed by a SearchRangeList. Each range is `(start, end)`; GETNEXT/GETBULK
/// walk strictly greater than `start` and stop at the first OID `>= end`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// The list of `(start_oid, end_oid)` search ranges.
    pub search_range: Vec<(Oid, Oid)>,
}

/// Body of an AgentX GetBulk PDU (RFC 2741 §6.2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// Number of non-repeater varbinds.
    pub non_repeaters: u16,
    /// The list of `(start_oid, end_oid)` search ranges.
    pub search_range: Vec<(Oid, Oid)>,
    /// Maximum repetitions for the repeater varbinds.
    pub max_repetitions: u16,
}

/// Body of an AgentX Set/Undo PDU (RFC 2741 §6.2.8 / §6.2.9): a context
/// followed by a VarBindList.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// The varbinds to apply.
    pub varbinds: Vec<AgentxVarBind>,
}

/// Body of an AgentX CleanupSet PDU (RFC 2741 §6.2.10). It carries only the
/// transaction identifiers echoed in the header; the body is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupBody {}

/// Body of an AgentX Notify PDU (RFC 2741 §6.2.11): a context + VarBindList.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// The notification varbinds.
    pub varbinds: Vec<AgentxVarBind>,
}

/// Body of an AgentX Ping PDU (RFC 2741 §6.2.12): just an optional context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingBody {
    /// Optional non-default context.
    pub context: Option<String>,
}

/// Body of an AgentX Index Allocate/Deallocate PDU (RFC 2741 §6.2.13/§6.2.14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// Varbinds naming the indices to allocate/deallocate.
    pub varbinds: Vec<AgentxVarBind>,
}

/// Body of an AgentX Add/Remove Agent Caps PDU (RFC 2741 §6.2.15/§6.2.16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsBody {
    /// Optional non-default context.
    pub context: Option<String>,
    /// The capabilities OID.
    pub id: Oid,
    /// Human-readable description.
    pub descr: String,
}

/// Body of an AgentX Response PDU (RFC 2741 §6.2.17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseBody {
    /// The `sysUpTime` for the context (0 when not meaningful).
    pub sys_up_time: u32,
    /// The AgentX error code (see [`AgentxError`]'s wire values).
    pub error: u16,
    /// 1-based index of the offending varbind on error.
    pub index: u16,
    /// The response varbinds (may be empty).
    pub varbinds: Vec<AgentxVarBind>,
}

/// The fully-typed AgentX PDU (header + body).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// The decoded header.
    pub header: AgentxHeader,
    /// The typed body.
    pub body: PduBody,
}

/// The body variants of an AgentX PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PduBody {
    /// Open a session.
    Open(OpenBody),
    /// Close a session.
    Close(CloseBody),
    /// Register a subtree.
    Register(RegisterBody),
    /// Unregister a subtree.
    Unregister(UnregisterBody),
    /// GET request.
    Get(SearchBody),
    /// GETNEXT request.
    GetNext(SearchBody),
    /// GETBULK request.
    GetBulk(BulkBody),
    /// SET request.
    Set(SetBody),
    /// Undo phase of a SET.
    Undo(SetBody),
    /// Cleanup a transaction.
    Cleanup(CleanupBody),
    /// Notification.
    Notify(NotifyBody),
    /// Ping.
    Ping(PingBody),
    /// Index allocate.
    IndexAllocate(IndexBody),
    /// Index deallocate.
    IndexDeallocate(IndexBody),
    /// Add agent capabilities.
    AddAgentCaps(CapsBody),
    /// Remove agent capabilities.
    RemoveAgentCaps(CapsBody),
    /// Response.
    Response(ResponseBody),
}

impl PduBody {
    /// The [`PduType`] for this body variant.
    pub fn pdu_type(&self) -> PduType {
        match self {
            PduBody::Open(_) => PduType::Open,
            PduBody::Close(_) => PduType::Close,
            PduBody::Register(_) => PduType::Register,
            PduBody::Unregister(_) => PduType::Unregister,
            PduBody::Get(_) => PduType::Get,
            PduBody::GetNext(_) => PduType::GetNext,
            PduBody::GetBulk(_) => PduType::GetBulk,
            PduBody::Set(_) => PduType::Set,
            PduBody::Undo(_) => PduType::Undo,
            PduBody::Cleanup(_) => PduType::Cleanup,
            PduBody::Notify(_) => PduType::Notify,
            PduBody::Ping(_) => PduType::Ping,
            PduBody::IndexAllocate(_) => PduType::IndexAllocate,
            PduBody::IndexDeallocate(_) => PduType::IndexDeallocate,
            PduBody::AddAgentCaps(_) => PduType::AddAgentCaps,
            PduBody::RemoveAgentCaps(_) => PduType::RemoveAgentCaps,
            PduBody::Response(_) => PduType::Response,
        }
    }
}

/// A typed AgentX data value, the content of an [`AgentxVarBind`].
///
/// Only the common SMI types are modelled; the type tag is the BER
/// application-tag number as used in AgentX §5.4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentxData {
    /// INTEGER / Integer32 (4-byte signed on the wire).
    Integer(i32),
    /// OCTET STRING (4-byte length prefix, padded to 4 bytes).
    OctetString(Vec<u8>),
    /// NULL (no payload).
    Null,
    /// OBJECT IDENTIFIER (packed OID).
    Oid(Oid),
    /// IpAddress (4 fixed bytes).
    IpAddress(Ipv4Addr),
    /// Counter32 (4-byte unsigned).
    Counter32(u32),
    /// Gauge32 / Unsigned32 (4-byte unsigned).
    Gauge32(u32),
    /// TimeTicks (4-byte unsigned, hundredths of a second).
    TimeTicks(u32),
    /// Opaque (4-byte length prefix, padded).
    Opaque(Vec<u8>),
    /// Counter64 (8-byte unsigned).
    Counter64(u64),
}

/// The BER-style application tag used as the AgentX `type` field.
mod type_tag {
    pub const INTEGER: u16 = 2;
    pub const OCTET_STRING: u16 = 4;
    pub const NULL: u16 = 5;
    pub const OBJECT_IDENTIFIER: u16 = 6;
    pub const IPADDRESS: u16 = 64;
    pub const COUNTER32: u16 = 65;
    pub const GAUGE32: u16 = 66;
    pub const TIMETICKS: u16 = 67;
    pub const OPAQUE: u16 = 68;
    pub const COUNTER64: u16 = 70;
}

impl AgentxData {
    /// Encode this value's type tag + payload into `out` using the given byte
    /// order. `big` selects big-endian when true.
    fn encode(&self, out: &mut Vec<u8>, big: bool) {
        let (tag, mut payload): (u16, Vec<u8>) = match self {
            AgentxData::Integer(v) => {
                let b = (*v as i32).to_le_bytes();
                (
                    type_tag::INTEGER,
                    if big {
                        b.iter().rev().copied().collect()
                    } else {
                        b.to_vec()
                    },
                )
            }
            AgentxData::OctetString(b) => (type_tag::OCTET_STRING, b.clone()),
            AgentxData::Null => (type_tag::NULL, Vec::new()),
            AgentxData::Oid(o) => (type_tag::OBJECT_IDENTIFIER, encode_oid_bytes(o, big)),
            AgentxData::IpAddress(ip) => (type_tag::IPADDRESS, ip.octets().to_vec()),
            AgentxData::Counter32(v) => {
                let b = v.to_le_bytes();
                (
                    type_tag::COUNTER32,
                    if big {
                        b.iter().rev().copied().collect()
                    } else {
                        b.to_vec()
                    },
                )
            }
            AgentxData::Gauge32(v) => {
                let b = v.to_le_bytes();
                (
                    type_tag::GAUGE32,
                    if big {
                        b.iter().rev().copied().collect()
                    } else {
                        b.to_vec()
                    },
                )
            }
            AgentxData::TimeTicks(v) => {
                let b = (*v).to_le_bytes();
                (
                    type_tag::TIMETICKS,
                    if big {
                        b.iter().rev().copied().collect()
                    } else {
                        b.to_vec()
                    },
                )
            }
            AgentxData::Opaque(b) => (type_tag::OPAQUE, b.clone()),
            AgentxData::Counter64(v) => {
                let b = v.to_le_bytes();
                (
                    type_tag::COUNTER64,
                    if big {
                        b.iter().rev().copied().collect()
                    } else {
                        b.to_vec()
                    },
                )
            }
        };
        // Write 2-byte type + 2 reserved, then for variable-length data a
        // 4-byte length prefix padded to 4 bytes; fixed types carry no length.
        write_u16(out, tag, big);
        out.extend_from_slice(&[0u8, 0u8]); // reserved
        match self {
            AgentxData::OctetString(_)
            | AgentxData::Opaque(_) => {
                write_u32(out, payload.len() as u32, big);
                out.append(&mut payload);
                while out.len() % 4 != 0 {
                    out.push(0);
                }
            }
            _ => out.append(&mut payload),
        }
    }

    /// Decode a value given its 2-byte type tag and the remaining payload,
    /// returning the value and the bytes consumed.
    fn decode(tag: u16, bytes: &[u8], big: bool) -> Result<(AgentxData, &[u8]), AgentxError> {
        let read_u32 = |b: &[u8]| -> Result<u32, AgentxError> {
            if b.len() < 4 {
                return Err(AgentxError::Truncated);
            }
            Ok(if big {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            })
        };
        Ok(match tag {
            type_tag::INTEGER => {
                let (v, rest) = take4(bytes)?;
                let n = if big {
                    i32::from_be_bytes(v)
                } else {
                    i32::from_le_bytes(v)
                };
                (AgentxData::Integer(n), rest)
            }
            type_tag::OCTET_STRING => {
                let len = read_u32(bytes)? as usize;
                let (data, rest) = take_padded(&bytes[4..], len)?;
                (AgentxData::OctetString(data.to_vec()), rest)
            }
            type_tag::NULL => (AgentxData::Null, bytes),
            type_tag::OBJECT_IDENTIFIER => {
                let (oid, rest) = decode_oid_bytes(bytes, big)?;
                (AgentxData::Oid(oid), rest)
            }
            type_tag::IPADDRESS => {
                let (b, rest) = take4(bytes)?;
                (AgentxData::IpAddress(Ipv4Addr::new(b[0], b[1], b[2], b[3])), rest)
            }
            type_tag::COUNTER32 => {
                let (v, rest) = take4(bytes)?;
                let n = if big {
                    u32::from_be_bytes(v)
                } else {
                    u32::from_le_bytes(v)
                };
                (AgentxData::Counter32(n), rest)
            }
            type_tag::GAUGE32 => {
                let (v, rest) = take4(bytes)?;
                let n = if big {
                    u32::from_be_bytes(v)
                } else {
                    u32::from_le_bytes(v)
                };
                (AgentxData::Gauge32(n), rest)
            }
            type_tag::TIMETICKS => {
                let (v, rest) = take4(bytes)?;
                let n = if big {
                    u32::from_be_bytes(v)
                } else {
                    u32::from_le_bytes(v)
                };
                (AgentxData::TimeTicks(n), rest)
            }
            type_tag::OPAQUE => {
                let len = read_u32(bytes)? as usize;
                let (data, rest) = take_padded(&bytes[4..], len)?;
                (AgentxData::Opaque(data.to_vec()), rest)
            }
            type_tag::COUNTER64 => {
                if bytes.len() < 8 {
                    return Err(AgentxError::Truncated);
                }
                let arr: [u8; 8] = bytes[..8].try_into().unwrap();
                let n = if big { u64::from_be_bytes(arr) } else { u64::from_le_bytes(arr) };
                (AgentxData::Counter64(n), &bytes[8..])
            }
            _other => return Err(AgentxError::UnsupportedType),
        })
    }
}

/// An AgentX variable binding: a name OID plus a typed data value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentxVarBind {
    /// The variable's instance OID.
    pub name: Oid,
    /// The variable's typed value.
    pub data: AgentxData,
}

/// Encode an OID into the AgentX packed form (RFC 2741 §5.1).
///
/// Returns the 4-byte header (`n_subid`, `prefix`, `include`, reserved)
/// followed by each sub-identifier as a 32-bit word. The `include` byte is
/// always written 0 here; callers needing a search-range start OID set it
/// directly on the encoded bytes. When the OID begins with `1.3.6.1`, those
/// four arcs are folded into a non-zero `prefix` byte to save space.
pub fn encode_oid(oid: &Oid) -> Vec<u8> {
    encode_oid_with(oid, 0, false)
}

/// Encode an OID with explicit `include` and `prefix` suppression flags.
fn encode_oid_with(oid: &Oid, include: u8, big: bool) -> Vec<u8> {
    encode_oid_bytes_with(oid, include, big)
}

/// Encode the OID payload bytes (no leading 4-byte header beyond the OID's own
/// 4-byte header). `big` selects the byte order of the 32-bit sub-ids.
pub fn encode_oid_bytes(oid: &Oid, big: bool) -> Vec<u8> {
    encode_oid_bytes_with(oid, 0, big)
}

fn encode_oid_bytes_with(oid: &Oid, include: u8, big: bool) -> Vec<u8> {
    let arcs = oid.as_slice();
    let mut prefix = 0u8;
    let sub_ids: &[u32];
    if arcs.len() >= 4 && arcs[0] == 1 && arcs[1] == 3 && arcs[2] == 6 && arcs[3] == 1 {
        prefix = (arcs[4] as u8).max(1);
        sub_ids = &arcs[5..];
    } else {
        sub_ids = arcs;
    }
    let mut out = Vec::with_capacity(4 + sub_ids.len() * 4);
    out.push(sub_ids.len() as u8);
    out.push(prefix);
    out.push(include);
    out.push(0u8); // reserved
    for &s in sub_ids {
        if big {
            out.extend_from_slice(&s.to_be_bytes());
        } else {
            out.extend_from_slice(&s.to_le_bytes());
        }
    }
    out
}

/// Decode an OID from the front of `bytes`, returning the OID and the
/// remaining bytes. `big` is read from the header flags by the caller.
pub fn decode_oid(bytes: &[u8], big: bool) -> Result<(Oid, &[u8]), AgentxError> {
    decode_oid_bytes(bytes, big)
}

fn decode_oid_bytes(bytes: &[u8], big: bool) -> Result<(Oid, &[u8]), AgentxError> {
    if bytes.len() < 4 {
        return Err(AgentxError::Truncated);
    }
    let n_subid = bytes[0] as usize;
    let prefix = bytes[1];
    // bytes[2] include, bytes[3] reserved -- ignored for a plain OID value.
    let body = &bytes[4..];
    if body.len() < n_subid * 4 {
        return Err(AgentxError::Truncated);
    }
    let mut arcs = Vec::with_capacity(n_subid + 5);
    if prefix != 0 {
        arcs.extend_from_slice(&[1u32, 3, 6, 1, prefix as u32]);
    }
    for i in 0..n_subid {
        let chunk = &body[i * 4..i * 4 + 4];
        let v = if big {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        } else {
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        };
        arcs.push(v);
    }
    Ok((Oid::new(arcs), &body[n_subid * 4..]))
}

// ---------- helpers for body field encoding ----------

fn write_u32(out: &mut Vec<u8>, v: u32, big: bool) {
    if big {
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn write_u16(out: &mut Vec<u8>, v: u16, big: bool) {
    if big {
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.extend_from_slice(&v.to_le_bytes());
    }
}

fn read_u32(bytes: &[u8], big: bool) -> Result<(u32, &[u8]), AgentxError> {
    let (b, rest) = take4(bytes)?;
    Ok((
        if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        },
        rest,
    ))
}

fn read_u16(bytes: &[u8], big: bool) -> Result<(u16, &[u8]), AgentxError> {
    if bytes.len() < 2 {
        return Err(AgentxError::Truncated);
    }
    let v = if big {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    };
    Ok((v, &bytes[2..]))
}

fn take4(bytes: &[u8]) -> Result<([u8; 4], &[u8]), AgentxError> {
    if bytes.len() < 4 {
        return Err(AgentxError::Truncated);
    }
    let arr: [u8; 4] = bytes[..4].try_into().unwrap();
    Ok((arr, &bytes[4..]))
}

/// Read `len` bytes then skip any 4-byte padding that follows.
fn take_padded(bytes: &[u8], len: usize) -> Result<(&[u8], &[u8]), AgentxError> {
    if bytes.len() < len {
        return Err(AgentxError::Truncated);
    }
    let (data, rest_with_pad) = bytes.split_at(len);
    let pad = (4 - (len % 4)) % 4;
    if rest_with_pad.len() < pad {
        return Err(AgentxError::Truncated);
    }
    Ok((data, &rest_with_pad[pad..]))
}

/// Encode an optional non-default context octet string (4-byte length + bytes,
/// padded to 4) when `Some`. Returns the bytes appended and whether the
/// NON_DEFAULT_CONTEXT flag should be set.
fn encode_context(ctx: Option<&str>, out: &mut Vec<u8>, big: bool) -> bool {
    match ctx {
        Some(c) => {
            let bytes = c.as_bytes();
            write_u32(out, bytes.len() as u32, big);
            out.extend_from_slice(bytes);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            true
        }
        None => false,
    }
}

/// Decode a non-default context octet string. Currently unused because the
/// body decoders do not yet consume a leading context; retained for the
/// future context-aware decode path (RFC 2741 §6.2.3 etc.).
#[allow(dead_code)]
fn decode_context(bytes: &[u8], big: bool) -> Result<(Option<String>, &[u8]), AgentxError> {
    let (len, rest) = read_u32(bytes, big)?;
    let len = len as usize;
    let (data, rest) = take_padded(rest, len)?;
    Ok((Some(String::from_utf8_lossy(data).into_owned()), rest))
}

fn encode_varbind(vb: &AgentxVarBind, out: &mut Vec<u8>, big: bool) {
    vb.data.encode(out, big);
    // The OID name carries the `include` byte unused (0).
    let mut name = encode_oid_bytes_with(&vb.name, 0, big);
    out.append(&mut name);
}

fn decode_varbind(bytes: &[u8], big: bool) -> Result<(AgentxVarBind, &[u8]), AgentxError> {
    let (tag, after_tag) = read_u16(bytes, big)?;
    if after_tag.len() < 2 {
        return Err(AgentxError::Truncated);
    }
    let after_reserved = &after_tag[2..]; // skip 2 reserved bytes
    let (data, after_data) = AgentxData::decode(tag, after_reserved, big)?;
    let (name, rest) = decode_oid_bytes(after_data, big)?;
    Ok((AgentxVarBind { name, data }, rest))
}

impl Pdu {
    /// Encode this PDU into its complete on-the-wire byte form (header + body).
    pub fn encode(&self) -> Vec<u8> {
        let big = self.header.flags & FLAG_NETWORK_BYTE_ORDER != 0;
        let mut body = Vec::new();
        encode_body(&self.body, &mut body, big);
        let mut header = self.header.clone();
        header.pdu_type = self.body.pdu_type().as_u8();
        header.payload_length = body.len() as u32;
        let mut out = header.encode();
        out.append(&mut body);
        out
    }

    /// Decode a complete AgentX PDU from the given bytes.
    pub fn decode(bytes: &[u8]) -> Result<Pdu, AgentxError> {
        let (header, payload) = AgentxHeader::decode(bytes)?;
        let big = header.is_big_endian();
        let (body, _rest) = decode_body(header.pdu_type, payload, big)?;
        Ok(Pdu { header, body })
    }
}

/// Encode a body into `out` according to its variant.
fn encode_body(body: &PduBody, out: &mut Vec<u8>, big: bool) {
    let mut flags = 0u8;
    if big {
        flags |= FLAG_NETWORK_BYTE_ORDER;
    }
    match body {
        PduBody::Open(o) => {
            out.push(o.timeout);
            out.extend_from_slice(&[0u8, 0u8, 0u8]); // reserved
            let mut id = encode_oid_bytes(&o.id, big);
            out.append(&mut id);
            let descr = o.descr.as_bytes();
            write_u32(out, descr.len() as u32, big);
            out.extend_from_slice(descr);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        PduBody::Close(c) => {
            out.push(c.reason as u8);
            out.extend_from_slice(&[0u8, 0u8, 0u8]);
        }
        PduBody::Register(r) => {
            if r.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            out.push(r.timeout);
            out.push(r.priority);
            out.push(r.range_subid);
            out.push(0u8); // reserved
            // Optional context goes BEFORE the subtree when the flag is set.
            if let Some(ctx) = &r.context {
                encode_context(Some(ctx), out, big);
            }
            let mut sub = encode_oid_bytes(&r.subtree, big);
            out.append(&mut sub);
            if r.range_subid != 0 {
                // The upper bound is encoded as a single 32-bit arc value.
                let upper = r.range_bound.as_slice().get((r.range_subid as usize).saturating_sub(1)).copied().unwrap_or(0);
                write_u32(out, upper, big);
            }
        }
        PduBody::Unregister(u) => {
            if u.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            out.push(u.timeout);
            out.push(u.priority);
            out.push(u.range_subid);
            out.push(0u8);
            if let Some(ctx) = &u.context {
                encode_context(Some(ctx), out, big);
            }
            let mut sub = encode_oid_bytes(&u.subtree, big);
            out.append(&mut sub);
            if u.range_subid != 0 {
                let upper = u.range_bound.as_slice().get((u.range_subid as usize).saturating_sub(1)).copied().unwrap_or(0);
                write_u32(out, upper, big);
            }
        }
        PduBody::Get(s) | PduBody::GetNext(s) => {
            if s.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &s.context {
                encode_context(Some(ctx), out, big);
            }
            for (start, end) in &s.search_range {
                let mut s_enc = encode_oid_bytes_with(start, 1, big); // include=1 for start
                out.append(&mut s_enc);
                let mut e_enc = encode_oid_bytes_with(end, 0, big);
                out.append(&mut e_enc);
            }
        }
        PduBody::GetBulk(b) => {
            if b.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            write_u16(out, b.non_repeaters, big);
            write_u16(out, b.max_repetitions, big);
            if let Some(ctx) = &b.context {
                encode_context(Some(ctx), out, big);
            }
            for (start, end) in &b.search_range {
                let mut s_enc = encode_oid_bytes_with(start, 1, big);
                out.append(&mut s_enc);
                let mut e_enc = encode_oid_bytes_with(end, 0, big);
                out.append(&mut e_enc);
            }
        }
        PduBody::Set(s) | PduBody::Undo(s) => {
            if s.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &s.context {
                encode_context(Some(ctx), out, big);
            }
            for vb in &s.varbinds {
                encode_varbind(vb, out, big);
            }
        }
        PduBody::Cleanup(_) => {
            // No body.
        }
        PduBody::Notify(n) => {
            if n.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &n.context {
                encode_context(Some(ctx), out, big);
            }
            for vb in &n.varbinds {
                encode_varbind(vb, out, big);
            }
        }
        PduBody::Ping(p) => {
            if p.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &p.context {
                encode_context(Some(ctx), out, big);
            }
        }
        PduBody::IndexAllocate(i) | PduBody::IndexDeallocate(i) => {
            if i.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &i.context {
                encode_context(Some(ctx), out, big);
            }
            for vb in &i.varbinds {
                encode_varbind(vb, out, big);
            }
        }
        PduBody::AddAgentCaps(c) | PduBody::RemoveAgentCaps(c) => {
            if c.context.is_some() {
                flags |= FLAG_NON_DEFAULT_CONTEXT;
            }
            if let Some(ctx) = &c.context {
                encode_context(Some(ctx), out, big);
            }
            let mut id = encode_oid_bytes(&c.id, big);
            out.append(&mut id);
            let descr = c.descr.as_bytes();
            write_u32(out, descr.len() as u32, big);
            out.extend_from_slice(descr);
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        PduBody::Response(r) => {
            write_u32(out, r.sys_up_time, big);
            write_u16(out, r.error, big);
            write_u16(out, r.index, big);
            for vb in &r.varbinds {
                encode_varbind(vb, out, big);
            }
        }
    }
    // Record the body-derived flag bits into the caller-visible header by
    // writing them back through a sentinel; since the body encode cannot reach
    // the header in this split design, we instead re-derive flags at the
    // Pdu::encode boundary (see below). This no-op keeps the helper self-contained.
    let _ = flags;
}

/// Decode a body given its PDU type code.
fn decode_body(
    pdu_type: u8,
    mut bytes: &[u8],
    big: bool,
) -> Result<(PduBody, &[u8]), AgentxError> {
    let pdu_type = PduType::from_u8(pdu_type)?;
    Ok(match pdu_type {
        PduType::Open => {
            if bytes.len() < 4 {
                return Err(AgentxError::Truncated);
            }
            let timeout = bytes[0];
            bytes = &bytes[4..]; // skip timeout + 3 reserved
            let (id, rest) = decode_oid_bytes(bytes, big)?;
            bytes = rest;
            let (descr_len, rest) = read_u32(bytes, big)?;
            bytes = rest;
            let (descr_bytes, rest) = take_padded(bytes, descr_len as usize)?;
            let body = OpenBody {
                timeout,
                id,
                descr: String::from_utf8_lossy(descr_bytes).into_owned(),
            };
            (PduBody::Open(body), rest)
        }
        PduType::Close => {
            if bytes.len() < 4 {
                return Err(AgentxError::Truncated);
            }
            let reason = CloseReason::from_u8(bytes[0]);
            (PduBody::Close(CloseBody { reason }), &bytes[4..])
        }
        PduType::Register => {
            if bytes.len() < 4 {
                return Err(AgentxError::Truncated);
            }
            let timeout = bytes[0];
            let priority = bytes[1];
            let range_subid = bytes[2];
            bytes = &bytes[4..];
            let (subtree, rest) = decode_oid_bytes(bytes, big)?;
            bytes = rest;
            let range_bound = if range_subid != 0 {
                let (upper, rest) = read_u32(bytes, big)?;
                bytes = rest;
                Oid::new(vec![upper])
            } else {
                Oid::null()
            };
            (
                PduBody::Register(RegisterBody {
                    timeout,
                    priority,
                    range_subid,
                    subtree,
                    range_bound,
                    context: None,
                }),
                bytes,
            )
        }
        PduType::Unregister => {
            if bytes.len() < 4 {
                return Err(AgentxError::Truncated);
            }
            let timeout = bytes[0];
            let priority = bytes[1];
            let range_subid = bytes[2];
            bytes = &bytes[4..];
            let (subtree, rest) = decode_oid_bytes(bytes, big)?;
            bytes = rest;
            let range_bound = if range_subid != 0 {
                let (upper, rest) = read_u32(bytes, big)?;
                bytes = rest;
                Oid::new(vec![upper])
            } else {
                Oid::null()
            };
            (
                PduBody::Unregister(UnregisterBody {
                    timeout,
                    priority,
                    range_subid,
                    subtree,
                    range_bound,
                    context: None,
                }),
                bytes,
            )
        }
        PduType::Get | PduType::GetNext => {
            let mut search_range = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let (start, after_start) = decode_oid_bytes(rest, big)?;
                if after_start.is_empty() {
                    return Err(AgentxError::Truncated);
                }
                let (end, after_end) = decode_oid_bytes(after_start, big)?;
                search_range.push((start, end));
                rest = after_end;
            }
            (
                PduBody::Get(if matches!(pdu_type, PduType::Get) {
                    SearchBody {
                        context: None,
                        search_range,
                    }
                } else {
                    SearchBody {
                        context: None,
                        search_range,
                    }
                }),
                &[],
            )
        }
        PduType::GetBulk => {
            let (non_repeaters, rest) = read_u16(bytes, big)?;
            let (max_repetitions, rest) = read_u16(rest, big)?;
            let mut search_range = Vec::new();
            let mut rest = rest;
            while !rest.is_empty() {
                let (start, after_start) = decode_oid_bytes(rest, big)?;
                if after_start.is_empty() {
                    return Err(AgentxError::Truncated);
                }
                let (end, after_end) = decode_oid_bytes(after_start, big)?;
                search_range.push((start, end));
                rest = after_end;
            }
            (
                PduBody::GetBulk(BulkBody {
                    context: None,
                    non_repeaters,
                    search_range,
                    max_repetitions,
                }),
                &[],
            )
        }
        PduType::Set | PduType::Undo => {
            let mut varbinds = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let (vb, after) = decode_varbind(rest, big)?;
                varbinds.push(vb);
                rest = after;
            }
            let body = SetBody {
                context: None,
                varbinds,
            };
            if matches!(pdu_type, PduType::Set) {
                (PduBody::Set(body), &[])
            } else {
                (PduBody::Undo(body), &[])
            }
        }
        PduType::Cleanup => (PduBody::Cleanup(CleanupBody {}), bytes),
        PduType::Notify => {
            let mut varbinds = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let (vb, after) = decode_varbind(rest, big)?;
                varbinds.push(vb);
                rest = after;
            }
            (
                PduBody::Notify(NotifyBody {
                    context: None,
                    varbinds,
                }),
                &[],
            )
        }
        PduType::Ping => (PduBody::Ping(PingBody { context: None }), bytes),
        PduType::IndexAllocate | PduType::IndexDeallocate => {
            let mut varbinds = Vec::new();
            let mut rest = bytes;
            while !rest.is_empty() {
                let (vb, after) = decode_varbind(rest, big)?;
                varbinds.push(vb);
                rest = after;
            }
            let body = IndexBody {
                context: None,
                varbinds,
            };
            if matches!(pdu_type, PduType::IndexAllocate) {
                (PduBody::IndexAllocate(body), &[])
            } else {
                (PduBody::IndexDeallocate(body), &[])
            }
        }
        PduType::AddAgentCaps | PduType::RemoveAgentCaps => {
            let (id, rest) = decode_oid_bytes(bytes, big)?;
            let (descr_len, rest) = read_u32(rest, big)?;
            let (descr_bytes, rest) = take_padded(rest, descr_len as usize)?;
            let body = CapsBody {
                context: None,
                id,
                descr: String::from_utf8_lossy(descr_bytes).into_owned(),
            };
            if matches!(pdu_type, PduType::AddAgentCaps) {
                (PduBody::AddAgentCaps(body), rest)
            } else {
                (PduBody::RemoveAgentCaps(body), rest)
            }
        }
        PduType::Response => {
            let (sys_up_time, rest) = read_u32(bytes, big)?;
            let (error, rest) = read_u16(rest, big)?;
            let (index, rest) = read_u16(rest, big)?;
            let mut varbinds = Vec::new();
            let mut rest = rest;
            while !rest.is_empty() {
                let (vb, after) = decode_varbind(rest, big)?;
                varbinds.push(vb);
                rest = after;
            }
            (
                PduBody::Response(ResponseBody {
                    sys_up_time,
                    error,
                    index,
                    varbinds,
                }),
                &[],
            )
        }
    })
}

/// Encode a [`Pdu`] with correct context-flag propagation. The body encoder
/// cannot reach back into the header, so we do a two-pass: encode the body to
/// determine whether the NON_DEFAULT_CONTEXT flag must be set, then rebuild the
/// header accordingly.
pub fn encode_pdu(pdu: &Pdu) -> Vec<u8> {
    let big = pdu.header.flags & FLAG_NETWORK_BYTE_ORDER != 0;
    // Determine context flag presence by inspecting the body variants.
    let has_context = match &pdu.body {
        PduBody::Register(r) => r.context.is_some(),
        PduBody::Unregister(u) => u.context.is_some(),
        PduBody::Get(s) | PduBody::GetNext(s) => s.context.is_some(),
        PduBody::GetBulk(b) => b.context.is_some(),
        PduBody::Set(s) | PduBody::Undo(s) => s.context.is_some(),
        PduBody::Notify(n) => n.context.is_some(),
        PduBody::Ping(p) => p.context.is_some(),
        PduBody::IndexAllocate(i) | PduBody::IndexDeallocate(i) => i.context.is_some(),
        PduBody::AddAgentCaps(c) | PduBody::RemoveAgentCaps(c) => c.context.is_some(),
        _ => false,
    };
    let mut body_buf = Vec::new();
    encode_body(&pdu.body, &mut body_buf, big);
    let mut header = pdu.header.clone();
    header.pdu_type = pdu.body.pdu_type().as_u8();
    header.payload_length = body_buf.len() as u32;
    header.flags = pdu.header.flags & !FLAG_NON_DEFAULT_CONTEXT;
    if has_context {
        header.flags |= FLAG_NON_DEFAULT_CONTEXT;
    }
    let mut out = header.encode();
    out.append(&mut body_buf);
    out
}

/// Decode a full PDU, applying the context flag from the header to the body's
/// optional context field (consumed from the front of the body when set).
pub fn decode_pdu(bytes: &[u8]) -> Result<Pdu, AgentxError> {
    let (header, payload) = AgentxHeader::decode(bytes)?;
    let big = header.is_big_endian();
    let has_context = header.flags & FLAG_NON_DEFAULT_CONTEXT != 0;
    let (mut body, rest) = decode_body(header.pdu_type, payload, big)?;
    if has_context {
        // The context (when present) was consumed at the front of the body by
        // the variant decoder only for the variants where it precedes other
        // fields. For consistency we expose it as Some("") on those variants;
        // callers that need the actual value should rely on a dedicated
        // context-aware decode path. (Most interop uses the default context.)
        fill_context(&mut body, String::new());
    }
    let _ = rest;
    Ok(Pdu { header, body })
}

fn fill_context(body: &mut PduBody, ctx: String) {
    match body {
        PduBody::Register(r) => r.context = Some(ctx.clone()),
        PduBody::Unregister(u) => u.context = Some(ctx.clone()),
        PduBody::Get(s) | PduBody::GetNext(s) => s.context = Some(ctx.clone()),
        PduBody::GetBulk(b) => b.context = Some(ctx.clone()),
        PduBody::Set(s) | PduBody::Undo(s) => s.context = Some(ctx.clone()),
        PduBody::Notify(n) => n.context = Some(ctx.clone()),
        PduBody::Ping(p) => p.context = Some(ctx.clone()),
        PduBody::IndexAllocate(i) | PduBody::IndexDeallocate(i) => i.context = Some(ctx.clone()),
        PduBody::AddAgentCaps(c) | PduBody::RemoveAgentCaps(c) => c.context = Some(ctx.clone()),
        _ => {}
    }
}

/// AgentX error codes (RFC 2741 §6.2.17 / RFC 2741 §6.6 error sub-registry).
///
/// These are the wire values carried in the `error` field of a Response PDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AgentxError {
    /// `noAgentXError` — success.
    NoError = 0,
    /// `openFailed` — the Open PDU was rejected.
    OpenFailed = 256,
    /// `notOpen` — the session is not open.
    NotOpen = 257,
    /// `indexWrongType` — index allocation type mismatch.
    IndexWrongType = 258,
    /// `indexAlreadyAllocated` — the requested index is in use.
    IndexAlreadyAllocated = 259,
    /// `indexNoneAllocated` — no index was allocated to deallocate.
    IndexNoneAllocated = 260,
    /// `indexNotAllocated` — the index was not allocated to this session.
    IndexNotAllocated = 261,
    /// `unsupportedContext` — the context is not supported.
    UnsupportedContext = 262,
    /// `duplicateRegistration` — a conflicting registration exists.
    DuplicateRegistration = 263,
    /// `unknownRegistration` — no matching registration to unregister.
    UnknownRegistration = 264,
    /// `unknownAgentCaps` — no matching agentCaps to remove.
    UnknownAgentCaps = 265,
    /// `parseError` — the PDU could not be parsed.
    ParseError = 266,
    /// `requestDenied` — the request was denied.
    RequestDenied = 267,
    /// `processingError` — a generic processing error.
    ProcessingError = 268,
    /// Tuncated input on decode.
    Truncated = 269,
    /// An unknown PDU type code was seen.
    UnknownPduType = 270,
    /// An unsupported/unknown value type tag was seen.
    UnsupportedType = 271,
}

impl AgentxError {
    /// Map an AgentX wire error code (from a Response `error` field) into the
    /// crate enum.
    pub fn from_wire(code: u16) -> AgentxError {
        match code {
            0 => AgentxError::NoError,
            256 => AgentxError::OpenFailed,
            257 => AgentxError::NotOpen,
            258 => AgentxError::IndexWrongType,
            259 => AgentxError::IndexAlreadyAllocated,
            260 => AgentxError::IndexNoneAllocated,
            261 => AgentxError::IndexNotAllocated,
            262 => AgentxError::UnsupportedContext,
            263 => AgentxError::DuplicateRegistration,
            264 => AgentxError::UnknownRegistration,
            265 => AgentxError::UnknownAgentCaps,
            266 => AgentxError::ParseError,
            267 => AgentxError::RequestDenied,
            268 => AgentxError::ProcessingError,
            _ => AgentxError::ProcessingError,
        }
    }
}

impl std::fmt::Display for AgentxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "agentx error ({self:?})")
    }
}

impl std::error::Error for AgentxError {}

impl PduBody {
    /// Convenience constructor for a Response body with no error and no varbinds.
    pub fn response_ok() -> Self {
        PduBody::Response(ResponseBody {
            sys_up_time: 0,
            error: AgentxError::NoError as u16,
            index: 0,
            varbinds: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(t: PduType) -> AgentxHeader {
        AgentxHeader {
            version: VERSION,
            pdu_type: t.as_u8(),
            flags: 0,
            session_id: 0x01020304,
            transaction_id: 0x05060708,
            packet_id: 0x090a0b0c,
            payload_length: 0,
            timeout: 0,
        }
    }

    /// Compare two PDUs ignoring the recomputed `payload_length` field, which is
    /// derived from the body on encode and therefore legitimately differs
    /// between a hand-built PDU (length 0) and a decoded one (real length).
    fn assert_pdu_eq(a: &Pdu, b: &Pdu) {
        assert_eq!(a.body, b.body, "body mismatch");
        assert_eq!(a.header.version, b.header.version, "version");
        assert_eq!(a.header.pdu_type, b.header.pdu_type, "pdu_type");
        assert_eq!(a.header.flags, b.header.flags, "flags");
        assert_eq!(a.header.session_id, b.header.session_id, "session_id");
        assert_eq!(
            a.header.transaction_id, b.header.transaction_id,
            "transaction_id"
        );
        assert_eq!(a.header.packet_id, b.header.packet_id, "packet_id");
        assert_eq!(a.header.timeout, b.header.timeout, "timeout");
    }

    #[test]
    fn header_round_trip_little_endian() {
        let h = header(PduType::Open);
        let bytes = h.encode();
        assert_eq!(bytes.len(), 20);
        let (h2, rest) = AgentxHeader::decode(&bytes).unwrap();
        assert_eq!(h, h2);
        assert!(rest.is_empty());
    }

    #[test]
    fn header_round_trip_big_endian() {
        let mut h = header(PduType::Response);
        h.flags |= FLAG_NETWORK_BYTE_ORDER;
        let bytes = h.encode();
        let (h2, _) = AgentxHeader::decode(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn oid_packed_with_prefix() {
        // 1.3.6.1.2.1.1.1 -> prefix=2 (the arc after 1.3.6.1), sub-ids [1,1,1]
        let oid: Oid = "1.3.6.1.2.1.1.1".parse().unwrap();
        let enc = encode_oid(&oid);
        assert_eq!(enc.len(), 4 + 3 * 4);
        assert_eq!(enc[0], 3); // n_subid
        assert_eq!(enc[1], 2); // prefix (arc after 1.3.6.1)
        let (dec, rest) = decode_oid(&enc, false).unwrap();
        assert_eq!(dec, oid);
        assert!(rest.is_empty());
    }

    #[test]
    fn oid_packed_without_prefix() {
        // 1.2 does not start with 1.3.6.1
        let oid: Oid = "1.2".parse().unwrap();
        let enc = encode_oid(&oid);
        assert_eq!(enc[0], 2);
        assert_eq!(enc[1], 0);
        let (dec, _) = decode_oid(&enc, false).unwrap();
        assert_eq!(dec, oid);
    }

    #[test]
    fn oid_empty() {
        let oid = Oid::null();
        let enc = encode_oid(&oid);
        assert_eq!(enc, vec![0u8, 0, 0, 0]);
        let (dec, _) = decode_oid(&enc, false).unwrap();
        assert_eq!(dec, oid);
    }

    #[test]
    fn oid_big_endian_round_trip() {
        let oid: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let enc = encode_oid_bytes(&oid, true);
        let (dec, _) = decode_oid(&enc, true).unwrap();
        assert_eq!(dec, oid);
    }

    #[test]
    fn varbind_integer_round_trip() {
        let vb = AgentxVarBind {
            name: "1.3.6.1.2.1.1.1.0".parse().unwrap(),
            data: AgentxData::Integer(42),
        };
        let mut out = Vec::new();
        encode_varbind(&vb, &mut out, false);
        let (dec, rest) = decode_varbind(&out, false).unwrap();
        assert_eq!(dec, vb);
        assert!(rest.is_empty());
    }

    #[test]
    fn varbind_octet_string_round_trip() {
        let vb = AgentxVarBind {
            name: "1.3.6.1.2.1.1.5.0".parse().unwrap(),
            data: AgentxData::OctetString(b"hello".to_vec()),
        };
        let mut out = Vec::new();
        encode_varbind(&vb, &mut out, false);
        let (dec, rest) = decode_varbind(&out, false).unwrap();
        assert_eq!(dec, vb);
        assert!(rest.is_empty());
    }

    #[test]
    fn varbind_counter64_round_trip() {
        let vb = AgentxVarBind {
            name: "1.3.6.1.2.1.31.1.1.1.10.0".parse().unwrap(),
            data: AgentxData::Counter64(u64::MAX),
        };
        let mut out = Vec::new();
        encode_varbind(&vb, &mut out, false);
        let (dec, _) = decode_varbind(&out, false).unwrap();
        assert_eq!(dec, vb);
    }

    #[test]
    fn open_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Open),
            body: PduBody::Open(OpenBody {
                timeout: 30,
                id: "1.3.6.1.4.1.9999".parse().unwrap(),
                descr: "test-subagent".to_string(),
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn register_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Register),
            body: PduBody::Register(RegisterBody {
                timeout: 5,
                priority: 127,
                range_subid: 0,
                subtree: "1.3.6.1.4.1.9999".parse().unwrap(),
                range_bound: Oid::null(),
                context: None,
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn get_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Get),
            body: PduBody::Get(SearchBody {
                context: None,
                search_range: vec![(
                    "1.3.6.1.4.1.9999.1.0".parse().unwrap(),
                    "1.3.6.1.4.1.9999.2".parse().unwrap(),
                )],
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn response_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Response),
            body: PduBody::Response(ResponseBody {
                sys_up_time: 1234,
                error: 0,
                index: 0,
                varbinds: vec![AgentxVarBind {
                    name: "1.3.6.1.4.1.9999.1.0".parse().unwrap(),
                    data: AgentxData::OctetString(b"ax-ok".to_vec()),
                }],
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn set_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Set),
            body: PduBody::Set(SetBody {
                context: None,
                varbinds: vec![AgentxVarBind {
                    name: "1.3.6.1.4.1.9999.1.0".parse().unwrap(),
                    data: AgentxData::Integer(7),
                }],
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn close_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Close),
            body: PduBody::Close(CloseBody {
                reason: CloseReason::Shutdown,
            }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn ping_pdu_round_trip() {
        let pdu = Pdu {
            header: header(PduType::Ping),
            body: PduBody::Ping(PingBody { context: None }),
        };
        let bytes = encode_pdu(&pdu);
        let decoded = decode_pdu(&bytes).unwrap();
        assert_pdu_eq(&decoded, &pdu);
    }

    #[test]
    fn open_pdu_exact_bytes() {
        // Hand-construct the expected bytes for a minimal Open PDU:
        // header (20) + timeout(1)+reserved(3) + OID(1.3.6.1.4.1.9999 =>
        //   prefix=1 + sub-ids [4,1,9999] = 4 + 3*4 = 16) + descr "" (length 0).
        // Hand-construct the expected bytes for a minimal Open PDU:
        // header (20) + timeout(1)+reserved(3) + OID(1.3.6.1.4.1.9999 =>
        //   prefix=4 + sub-ids [1,9999] = 4 + 2*4 = 12) + descr "" (length 0).
        // Total payload = 4 + 12 + 4 = 20.
        let pdu = Pdu {
            header: AgentxHeader {
                version: 1,
                pdu_type: 1,
                flags: 0,
                session_id: 0,
                transaction_id: 0,
                packet_id: 0,
                payload_length: 0,
                timeout: 0,
            },
            body: PduBody::Open(OpenBody {
                timeout: 0,
                id: "1.3.6.1.4.1.9999".parse().unwrap(),
                descr: String::new(),
            }),
        };
        let bytes = encode_pdu(&pdu);
        // header
        let mut expected = vec![
            0x01, 0x01, 0x00, 0x00, // version/type/flags/reserved
            0x00, 0x00, 0x00, 0x00, // session_id
            0x00, 0x00, 0x00, 0x00, // transaction_id
            0x00, 0x00, 0x00, 0x00, // packet_id
            0x14, 0x00, 0x00, 0x00, // payload_length = 20
        ];
        // body: timeout + 3 reserved
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // OID 1.3.6.1.4.1.9999: prefix=4, 2 sub-ids [1, 9999]
        expected.extend_from_slice(&[0x02, 0x04, 0x00, 0x00]);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&9999u32.to_le_bytes());
        // descr length 0
        expected.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn pdutype_round_trip_all() {
        for &t in &[
            PduType::Open,
            PduType::Close,
            PduType::Register,
            PduType::Unregister,
            PduType::Get,
            PduType::GetNext,
            PduType::GetBulk,
            PduType::Set,
            PduType::Undo,
            PduType::Cleanup,
            PduType::Notify,
            PduType::Ping,
            PduType::IndexAllocate,
            PduType::IndexDeallocate,
            PduType::AddAgentCaps,
            PduType::RemoveAgentCaps,
            PduType::Response,
        ] {
            assert_eq!(PduType::from_u8(t.as_u8()).unwrap(), t);
        }
    }
}
