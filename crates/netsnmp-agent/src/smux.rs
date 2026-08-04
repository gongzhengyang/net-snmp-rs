//! SMUX peer protocol (RFC 1227).
//!
//! SMUX ("SNMP Multiplex") is a **legacy** TCP-based peer protocol by which a
//! cooperating daemon (historically Quagga, FRR, or `gated`) registers one or
//! more MIB subtrees with an SNMP agent and then answers the agent's GET /
//! GETNEXT requests for those subtrees. The agent, in turn, exposes the peer's
//! objects to SNMP managers as if they were local.
//!
//! The protocol runs over TCP (default port **199**, IANA-assigned "smux").
//! After a peer opens a connection it sends [`SmuxOpen`]; the agent replies
//! with a [`SmuxRRsp`] (register response) only after the peer has issued one
//! or more register requests. From then on GET/GETNEXT for a registered
//! subtree are forwarded to the owning peer over the same TCP stream and the
//! peer's SNMP Response is relayed back to the manager.
//!
//! # Status and recommendations
//!
//! SMUX is retained primarily for **historical compatibility** with existing
//! router-daemon deployments. New deployments should prefer **AgentX** (RFC
//! 2741, Net-SNMP's `agentx` master/subagent model): AgentX is far more widely
//! supported, has a richer control protocol (region priority, ping/heartbeat,
//! response forwarding for SET), and is not tied to the SNMPv1/v2c PDU shapes.
//! SMUX carries only the v1-style Get/GetNext/GetResponse/SetRequest PDUs and
//! provides no native v3 support.
//!
//! This implementation mirrors the [`ProxyForwarder`](crate::proxy::ProxyForwarder)
//! delegation model: a [`SmuxServer`] listens for inbound peer connections,
//! tracks each peer's registered subtrees, and serves them via a set of
//! [`SmuxSubtreeHandler`]s produced by [`smux_handler`].
//!
//! # Encoding
//!
//! The SMUX-specific PDUs ([`SmuxOpen`], [`SmuxClose`], [`SmuxRRsp`],
//! [`SmuxSout`]) use context-tagged constructed BER (RFC 1227 §5.3). They are
//! hand-rolled here to avoid pulling the `rasn` derive macros into this crate
//! (which is `#![forbid(unsafe_code)]` and must not gain new dependencies).
//! The Get/GetNext/Set/Response PDUs carried inside SMUX reuse the standard
//! SNMP [`Message`](netsnmp::message::Message) codec unchanged.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::Mutex;

use netsnmp::config::Directive;
use netsnmp::message::{Message, Version};
use netsnmp::oid::Oid;
use netsnmp::pdu::{ErrorStatus, Pdu, PduType, VarBind};
use netsnmp::value::Value;

use crate::handler::{MibHandler, Reading};

/// SMUX PDU tags (RFC 1227 §5.3). Each is a context-constructed tag
/// (`0xA0 | n`), matching the SNMP GetRequest-style tag numbering SMUX borrows.
pub mod tags {
    /// `SMUX_OPEN` (open a peer session).
    pub const SMUX_OPEN: u8 = 0xA0;
    /// `SMUX_RRSP` (register response, sent by the agent).
    pub const SMUX_RRSP: u8 = 0xA1;
    /// Close (agent/peer shutdown).
    pub const SMUX_CLOSE: u8 = 0xA4;
    /// `SMUX_SOUT` (commit/out-of-band signal; rarely used).
    pub const SMUX_SOUT: u8 = 0xA5;
}

/// Default SMUX TCP port (IANA "smux").
pub const SMUX_PORT: u16 = 199;

/// Register-response code returned by the agent for a register request
/// (RFC 1227 §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RRspCode {
    /// Registration rejected (`-1`).
    Reject = -1,
    /// Registration accepted read-only (`0`).
    ReadOnly = 0,
    /// Registration accepted read-write (`1`).
    ReadWrite = 1,
}

impl RRspCode {
    /// The integer wire value.
    pub fn code(self) -> i64 {
        self as i64
    }
}

/// `SMUX_OPEN` PDU (RFC 1227 §5.3.1).
///
/// Encoded as an IMPLICIT `[0]` SEQUENCE:
/// ```text
/// SmuxOpen ::= [0] IMPLICIT SEQUENCE {
///     version     INTEGER (version-1),
///     identity    OBJECT IDENTIFIER,
///     description OCTET STRING,
///     password    OCTET STRING
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmuxOpen {
    /// SMUX protocol version (`0` == version-1).
    pub version: i64,
    /// The peer's identity (enterprise OID).
    pub identity: Oid,
    /// Free-form peer description.
    pub description: String,
    /// Shared password (matched against the configured `smuxpeer` password).
    pub password: String,
}

/// `SMUX_CLOSE` PDU (RFC 1227 §5.3.4). Carries a single close-reason integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmuxClose {
    /// Close reason code (see RFC 1227 §5.4).
    pub code: i64,
}

/// `SMUX_RRSP` (register response) PDU. Encoded as `[1]` SEQUENCE wrapping a
/// single integer (the [`RRspCode`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmuxRRsp {
    /// The register-response code.
    pub code: i64,
}

/// `SMUX_SOUT` PDU (RFC 1227 §5.3.5). Rarely used commit signal. Carries an
/// integer argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmuxSout {
    /// The sout argument.
    pub arg: i64,
}

// ---------------------------------------------------------------------------
// Minimal BER helpers (hand-rolled, no external dep).
// ---------------------------------------------------------------------------

fn ber_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        // Long-form length: number of length bytes (high bit set) then big-endian.
        let mut bytes = Vec::new();
        let mut v = n;
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        bytes.reverse();
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
        out
    }
}

fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(tag);
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode a non-negative integer as BER `INTEGER` (tag `0x02`). Negative
/// integers use a two's-complement encoding so SMUX close reasons (which can
/// be `-1`) round-trip correctly.
fn ber_integer(v: i64) -> Vec<u8> {
    let bytes = if v >= 0 {
        // Minimal big-endian; prepend 0x00 if the high bit would make it negative.
        let mut b = v.to_be_bytes().to_vec();
        while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
            b.remove(0);
        }
        if b[0] & 0x80 != 0 {
            let mut with_sign = Vec::with_capacity(b.len() + 1);
            with_sign.push(0x00);
            with_sign.extend_from_slice(&b);
            b = with_sign;
        }
        b
    } else {
        // Two's complement minimal form.
        let mut b = v.to_be_bytes().to_vec();
        while b.len() > 1
            && b[0] == 0xff
            && b[1] & 0x80 != 0
        {
            b.remove(0);
        }
        b
    };
    ber_tlv(0x02, &bytes)
}

/// Encode an OID as BER `OBJECT IDENTIFIER` (tag `0x06`). The first two arcs
/// are packed as `40*a + b` per X.690.
fn ber_oid(oid: &Oid) -> Vec<u8> {
    let arcs = oid.as_slice();
    let mut content = Vec::new();
    if arcs.is_empty() {
        content.push(0);
    } else {
        let first = if arcs.len() >= 2 {
            40 * arcs[0] + arcs[1]
        } else {
            40 * arcs[0]
        };
        encode_base128(first, &mut content);
        for &a in &arcs[2.min(arcs.len())..] {
            encode_base128(a, &mut content);
        }
    }
    ber_tlv(0x06, &content)
}

fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    if value == 0 {
        out.push(0);
        return;
    }
    let mut tmp = [0u8; 5];
    let mut n = 0;
    while value > 0 {
        tmp[n] = (value & 0x7f) as u8;
        value >>= 7;
        n += 1;
    }
    for i in (0..n).rev() {
        let mut b = tmp[i];
        if i != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

fn ber_octet_string(bytes: &[u8]) -> Vec<u8> {
    ber_tlv(0x04, bytes)
}

/// Parse a BER length, returning `(length, bytes_consumed)`.
fn parse_len(buf: &[u8]) -> Result<(usize, usize), SmuxError> {
    if buf.is_empty() {
        return Err(SmuxError::Truncated);
    }
    let first = buf[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let nbytes = (first & 0x7f) as usize;
    if nbytes == 0 || nbytes > 4 || 1 + nbytes > buf.len() {
        return Err(SmuxError::Truncated);
    }
    let mut len = 0usize;
    for &b in &buf[1..1 + nbytes] {
        len = (len << 8) | (b as usize);
    }
    Ok((len, 1 + nbytes))
}

/// Split a BER TLV: returns `(tag, content_bytes, total_consumed)`.
fn parse_tlv(buf: &[u8]) -> Result<(u8, &[u8], usize), SmuxError> {
    if buf.len() < 2 {
        return Err(SmuxError::Truncated);
    }
    let tag = buf[0];
    let (len, len_bytes) = parse_len(&buf[1..])?;
    let start = 1 + len_bytes;
    if start + len > buf.len() {
        return Err(SmuxError::Truncated);
    }
    Ok((tag, &buf[start..start + len], 1 + len_bytes + len))
}

fn parse_integer(buf: &[u8]) -> Result<i64, SmuxError> {
    if buf.is_empty() {
        return Err(SmuxError::Truncated);
    }
    // Sign-extend the leading byte.
    let mut v = (buf[0] as i8) as i64;
    for &b in &buf[1..] {
        v = (v << 8) | (b as i64);
    }
    Ok(v)
}

fn parse_oid(buf: &[u8]) -> Result<Oid, SmuxError> {
    if buf.is_empty() {
        return Err(SmuxError::Truncated);
    }
    let mut arcs = Vec::new();
    let first = buf[0] as u32;
    arcs.push(first / 40);
    arcs.push(first % 40);
    let mut idx = 1;
    while idx < buf.len() {
        let mut value = 0u32;
        loop {
            if idx >= buf.len() {
                return Err(SmuxError::Truncated);
            }
            let b = buf[idx];
            idx += 1;
            value = (value << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        arcs.push(value);
    }
    Ok(Oid::new(arcs))
}

fn parse_octet_string(buf: &[u8]) -> Result<Vec<u8>, SmuxError> {
    Ok(buf.to_vec())
}

// ---------------------------------------------------------------------------
// PDU encode / decode.
// ---------------------------------------------------------------------------

impl SmuxOpen {
    /// BER-encode this `SMUX_OPEN` as `[0] IMPLICIT SEQUENCE`.
    pub fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&ber_integer(self.version));
        content.extend_from_slice(&ber_oid(&self.identity));
        content.extend_from_slice(&ber_octet_string(self.description.as_bytes()));
        content.extend_from_slice(&ber_octet_string(self.password.as_bytes()));
        ber_tlv(tags::SMUX_OPEN, &content)
    }

    /// Decode an `SMUX_OPEN` from the content bytes (i.e. after the outer tag
    /// and length have been stripped by [`parse_smux_pdu`]).
    pub fn decode_content(content: &[u8]) -> Result<Self, SmuxError> {
        let (_, v_buf, c1) = parse_tlv(content)?;
        let version = parse_integer(v_buf)?;
        let rest = &content[c1..];
        let (_, id_buf, c2) = parse_tlv(rest)?;
        let identity = parse_oid(id_buf)?;
        let rest = &rest[c2..];
        let (_, d_buf, c3) = parse_tlv(rest)?;
        let description = String::from_utf8_lossy(&parse_octet_string(d_buf)?).into_owned();
        let rest = &rest[c3..];
        let (_, p_buf, _c4) = parse_tlv(rest)?;
        let password = String::from_utf8_lossy(&parse_octet_string(p_buf)?).into_owned();
        Ok(SmuxOpen {
            version,
            identity,
            description,
            password,
        })
    }
}

impl SmuxClose {
    /// BER-encode this `SMUX_CLOSE` as `[4] SEQUENCE { INTEGER }`.
    pub fn encode(&self) -> Vec<u8> {
        ber_tlv(tags::SMUX_CLOSE, &ber_integer(self.code))
    }

    /// Decode from the content bytes.
    pub fn decode_content(content: &[u8]) -> Result<Self, SmuxError> {
        let (_, b, _) = parse_tlv(content)?;
        Ok(SmuxClose {
            code: parse_integer(b)?,
        })
    }
}

impl SmuxRRsp {
    /// BER-encode as `[1] SEQUENCE { INTEGER }`.
    pub fn encode(&self) -> Vec<u8> {
        ber_tlv(tags::SMUX_RRSP, &ber_integer(self.code))
    }

    /// Decode from the content bytes.
    pub fn decode_content(content: &[u8]) -> Result<Self, SmuxError> {
        let (_, b, _) = parse_tlv(content)?;
        Ok(SmuxRRsp {
            code: parse_integer(b)?,
        })
    }
}

impl SmuxSout {
    /// BER-encode as `[5] SEQUENCE { INTEGER }`.
    pub fn encode(&self) -> Vec<u8> {
        ber_tlv(tags::SMUX_SOUT, &ber_integer(self.arg))
    }
}

/// A decoded SMUX PDU. The Get/GetNext/Set/Response PDUs are carried as
/// standard SNMP v1 messages (identical wire shape) and exposed here in their
/// decoded form for the agent to act on.
#[derive(Clone, Debug)]
pub enum SmuxPdu {
    /// Open session.
    Open(SmuxOpen),
    /// Close session.
    Close(SmuxClose),
    /// Register response (sent by the agent).
    RRsp(SmuxRRsp),
    /// Sout (commit).
    Sout(SmuxSout),
    /// An SNMP PDU (Get/GetNext/Set/Response) carried over SMUX. These reuse
    /// the standard SNMP message framing minus the version/community wrapper:
    /// SMUX peers send the bare PDU TLV, which has the same tag and structure
    /// as the SNMP PDU. We wrap it in a v1 message for the codec.
    Snmp(Message),
    /// A register request. Encoded as a GetRequest-PDU whose enterprise OID
    /// carries the registered subtree plus priority/operation sub-identifiers
    /// (RFC 1227 §5.2). Exposed structurally for the server.
    Register {
        /// The subtree being registered.
        subtree: Oid,
        /// Priority (lower wins on conflict).
        priority: i64,
        /// Operation: `1` = register, `-1` = unregister.
        operation: i64,
    },
}

/// Decode a single SMUX PDU (any variant) from a buffer that holds exactly one
/// top-level TLV. Returns the parsed PDU plus the total byte count consumed.
pub fn decode_smux_pdu(buf: &[u8]) -> Result<(SmuxPdu, usize), SmuxError> {
    let (tag, content, total) = parse_tlv(buf)?;
    match tag {
        // `0xA0` is overloaded in SMUX: it is both the `SMUX_OPEN` tag (RFC
        // 1227 §5.3.1) AND the SNMP GetRequest-PDU tag reused for register
        // requests (§5.2). Distinguish by structure: a register PDU is
        // `{ INTEGER, INTEGER, INTEGER, SEQUENCE OF VarBind }` (its 4th
        // element is a SEQUENCE), while an Open is
        // `{ INTEGER, OID, OCTET STRING, OCTET STRING }` (its 2nd element is
        // an OID). Try the register/GetRequest shape first; on any structural
        // mismatch fall back to Open.
        tags::SMUX_OPEN => {
            if let Some(reg) = try_decode_register(tag, content)? {
                return Ok((reg, total));
            }
            Ok((SmuxPdu::Open(SmuxOpen::decode_content(content)?), total))
        }
        tags::SMUX_CLOSE => Ok((SmuxPdu::Close(SmuxClose::decode_content(content)?), total)),
        tags::SMUX_RRSP => Ok((SmuxPdu::RRsp(SmuxRRsp::decode_content(content)?), total)),
        tags::SMUX_SOUT => {
            let (_, b, _) = parse_tlv(content)?;
            Ok((
                SmuxPdu::Sout(SmuxSout {
                    arg: parse_integer(b)?,
                }),
                total,
            ))
        }
        _ => {
            // Any other SNMP-PDU tag (GetNext/Set/Response/…) is an
            // SNMP-over-SMUX PDU. Re-frame it inside a v1 community message so
            // we can reuse the standard SNMP codec.
            let msg = Message {
                version: Version::V1,
                community: Vec::new(),
                pdu: decode_bare_snmp_pdu(tag, content)?,
            };
            if msg.pdu.pdu_type == PduType::Get && msg.pdu.variables.len() == 1 {
                if let Some((subtree, priority, operation)) =
                    decode_register_from_varbind(&msg.pdu.variables[0])
                {
                    return Ok((SmuxPdu::Register { subtree, priority, operation }, total));
                }
            }
            Ok((SmuxPdu::Snmp(msg), total))
        }
    }
}

/// Attempt to decode a `0xA0`-tagged PDU as a register request (a GetRequest-
/// PDU whose single varbind encodes `<subtree>.<priority>.<operation>`). Returns
/// `None` if the body does not look like a GetRequest-PDU (i.e. it is actually
/// an `SMUX_OPEN`).
fn try_decode_register(tag: u8, content: &[u8]) -> Result<Option<SmuxPdu>, SmuxError> {
    // A GetRequest-PDU body is { INTEGER, INTEGER, INTEGER, SEQUENCE }. An
    // SMUX_OPEN body is { INTEGER, OID, OCTET STRING, OCTET STRING }. Peek at
    // the 2nd element's tag: an OID (0x06) means Open, an INTEGER (0x02) means
    // a PDU. We rely on `decode_bare_snmp_pdu` to fail outright on an Open body
    // (its 2nd field, an OID, won't parse as the error-status INTEGER position
    // — actually it will parse as integer bytes, so we additionally require the
    // 4th element to be a SEQUENCE).
    let parts = peek_four_tlv_tags(content)?;
    // Open: [0x02 INTEGER, 0x06 OID, 0x04 OCTET STRING, 0x04 OCTET STRING].
    // Register/PDU: [0x02, 0x02, 0x02, 0x30 SEQUENCE].
    if parts[1] == 0x06 || parts[3] != 0x30 {
        return Ok(None);
    }
    let pdu = decode_bare_snmp_pdu(tag, content)?;
    if pdu.pdu_type == PduType::Get && pdu.variables.len() == 1 {
        if let Some((subtree, priority, operation)) =
            decode_register_from_varbind(&pdu.variables[0])
        {
            return Ok(Some(SmuxPdu::Register {
                subtree,
                priority,
                operation,
            }));
        }
    }
    Ok(None)
}

/// Peek at the tags of the first four top-level TLVs inside `content` (the body
/// of a constructed TLV). Returns the four tag bytes; fewer-than-four yields a
/// truncated error.
fn peek_four_tlv_tags(content: &[u8]) -> Result<[u8; 4], SmuxError> {
    let mut tags_arr = [0u8; 4];
    let mut off = 0;
    for slot in &mut tags_arr {
        if off >= content.len() {
            return Err(SmuxError::Truncated);
        }
        let (t, _body, consumed) = parse_tlv(&content[off..])?;
        *slot = t;
        off += consumed;
    }
    Ok(tags_arr)
}

/// Decode a bare SNMP PDU (the body of a `0xA0`-family tag) into a [`Pdu`].
/// The standard SNMP v2 PDU structure is `{ request-id, error-status,
/// error-index, varbind-list }` — we decode it directly.
fn decode_bare_snmp_pdu(tag: u8, content: &[u8]) -> Result<Pdu, SmuxError> {
    let pdu_type = PduType::from_tag(tag).map_err(|e| SmuxError::Decode(e.to_string()))?;
    // content is a SEQUENCE of four TLVs: request-id (INTEGER), error-status
    // (INTEGER), error-index (INTEGER), varbind-list (SEQUENCE OF SEQUENCE).
    let (_, id_buf, c1) = parse_tlv(content)?;
    let request_id = parse_integer(id_buf)? as i32;
    let rest = &content[c1..];
    let (_, es_buf, c2) = parse_tlv(rest)?;
    let error_status = parse_integer(es_buf)?;
    let rest = &rest[c2..];
    let (_, ei_buf, c3) = parse_tlv(rest)?;
    let error_index = parse_integer(ei_buf)?;
    let rest = &rest[c3..];
    let (_, vbs_buf, _c4) = parse_tlv(rest)?;
    let mut variables = Vec::new();
    let mut off = 0;
    while off < vbs_buf.len() {
        let (_, vb_content, consumed) = parse_tlv(&vbs_buf[off..])?;
        off += consumed;
        // varbind = SEQUENCE { name OID, value ANY }
        let (_, name_buf, nc) = parse_tlv(vb_content)?;
        let oid = parse_oid(name_buf)?;
        let val_buf = &vb_content[nc..];
        let value = decode_snmp_value(val_buf)?;
        variables.push(VarBind::new(oid, value));
    }
    Ok(Pdu {
        pdu_type,
        request_id,
        error_status,
        error_index,
        variables,
        v1_trap: None,
    })
}

/// Decode a single SNMP value from its TLV. `full` is the complete value TLV
/// (tag + length + content). Covers the small set of types SMUX peers carry.
fn decode_snmp_value(full: &[u8]) -> Result<Value, SmuxError> {
    let (tag, content, _) = parse_tlv(full)?;
    Ok(decode_value_by_tag(tag, content))
}

fn decode_value_by_tag(tag: u8, content: &[u8]) -> Value {
    match tag {
        0x02 => Value::Integer(parse_integer(content).unwrap_or(0)),
        0x04 => Value::OctetString(content.to_vec()),
        0x06 => Value::Oid(parse_oid(content).unwrap_or_else(|_| Oid::null())),
        0x05 => Value::Null,
        0x41 => Value::Counter32(parse_unsigned(content)),
        0x42 => Value::Gauge32(parse_unsigned(content)),
        0x43 => Value::TimeTicks(parse_unsigned(content)),
        0x40 => {
            // IpAddress: 4 octets.
            if content.len() == 4 {
                Value::IpAddress(std::net::Ipv4Addr::new(
                    content[0], content[1], content[2], content[3],
                ))
            } else {
                Value::Null
            }
        }
        0x44 => Value::Opaque(content.to_vec()),
        0x46 => Value::Counter64(parse_unsigned_u64(content)),
        0x80 => Value::NoSuchObject,
        0x81 => Value::NoSuchInstance,
        0x82 => Value::EndOfMibView,
        _ => Value::Null,
    }
}

fn parse_unsigned(content: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in content {
        v = v.wrapping_shl(8) | (b as u32);
    }
    v
}

fn parse_unsigned_u64(content: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in content {
        v = v.wrapping_shl(8) | (b as u64);
    }
    v
}

/// Decode a register request from a varbind, per RFC 1227 §5.2. The varbind
/// name is `<subtree>.<priority>.<operation>` and its value is NULL. We
/// require at least two trailing sub-identifiers after the subtree itself to
/// interpret the request as a register; otherwise we return `None` and the
/// caller treats the PDU as a plain Get.
fn decode_register_from_varbind(vb: &VarBind) -> Option<(Oid, i64, i64)> {
    let parts = vb.oid.as_slice();
    if parts.len() < 3 {
        return None;
    }
    // The last two arcs are priority and operation. (Real SMUX peers also append
    // an operation; some implementations append only priority. We accept both.)
    let n = parts.len();
    let priority = parts[n - 2] as i64;
    let operation = parts[n - 1] as i64;
    // Only treat as a register when the operation is the conventional 1/-1.
    if operation != 1 && operation != -1 {
        return None;
    }
    let subtree = Oid::new(parts[..n - 2].to_vec());
    Some((subtree, priority, operation))
}

/// Encode a register request (for use by a peer client or test mock) as the
/// GetRequest-style PDU SMUX uses. The resulting bytes are a single TLV ready
/// to write to the SMUX stream.
pub fn encode_register(subtree: &Oid, priority: i64, operation: i64) -> Vec<u8> {
    let mut name = subtree.as_slice().to_vec();
    name.push(priority as u32);
    name.push(operation as u32);
    let oid_oid = Oid::new(name);
    // Build a GetRequest-PDU body: request-id=0, error=0, index=0, one varbind.
    let mut body = Vec::new();
    body.extend_from_slice(&ber_integer(0)); // request-id
    body.extend_from_slice(&ber_integer(0)); // error-status
    body.extend_from_slice(&ber_integer(0)); // error-index
    // varbind list: a SEQUENCE OF VarBind, each VarBind a SEQUENCE { name, value }.
    let mut vb = Vec::new();
    vb.extend_from_slice(&ber_oid(&oid_oid));
    vb.extend_from_slice(&ber_tlv(0x05, &[])); // NULL value
    let one_varbind = ber_tlv(0x30, &vb);
    let varbind_list = ber_tlv(0x30, &one_varbind);
    body.extend_from_slice(&varbind_list);
    ber_tlv(PduType::Get.tag(), &body)
}

/// Encode an SNMP Response-PDU (for use by a peer client/test mock) ready to
/// write to the SMUX stream. The request-id, error fields and varbinds are
/// taken from `pdu`.
pub fn encode_snmp_response(pdu: &Pdu) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ber_integer(pdu.request_id as i64));
    body.extend_from_slice(&ber_integer(pdu.error_status));
    body.extend_from_slice(&ber_integer(pdu.error_index));
    let mut vbs = Vec::new();
    for vb in &pdu.variables {
        let mut one = Vec::new();
        one.extend_from_slice(&ber_oid(&vb.oid));
        one.extend_from_slice(&encode_value(&vb.value));
        vbs.extend_from_slice(&ber_tlv(0x30, &one));
    }
    body.extend_from_slice(&ber_tlv(0x30, &vbs));
    ber_tlv(PduType::Response.tag(), &body)
}

/// Encode a GET/GETNEXT request (for the agent to forward to a peer) ready to
/// write to the SMUX stream.
pub fn encode_snmp_request(pdu_type: PduType, request_id: i32, oid: &Oid) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ber_integer(request_id as i64));
    body.extend_from_slice(&ber_integer(0));
    body.extend_from_slice(&ber_integer(0));
    let mut vb = Vec::new();
    vb.extend_from_slice(&ber_oid(oid));
    vb.extend_from_slice(&ber_tlv(0x05, &[])); // NULL
    let one_varbind = ber_tlv(0x30, &vb);
    let varbind_list = ber_tlv(0x30, &one_varbind);
    body.extend_from_slice(&varbind_list);
    ber_tlv(pdu_type.tag(), &body)
}

fn encode_value(value: &Value) -> Vec<u8> {
    match value {
        Value::Integer(v) => ber_tlv(0x02, &ber_integer_content(*v)),
        Value::OctetString(b) => ber_octet_string(b),
        Value::Oid(o) => ber_oid(o),
        Value::Null => ber_tlv(0x05, &[]),
        Value::Counter32(v) => ber_tlv(0x41, &ber_unsigned_content(*v as u64, 4)),
        Value::Gauge32(v) => ber_tlv(0x42, &ber_unsigned_content(*v as u64, 4)),
        Value::TimeTicks(v) => ber_tlv(0x43, &ber_unsigned_content(*v as u64, 4)),
        Value::IpAddress(ip) => ber_tlv(0x40, &ip.octets()),
        Value::Opaque(b) => ber_tlv(0x44, b),
        Value::Counter64(v) => ber_tlv(0x46, &ber_unsigned_content(*v, 8)),
        Value::NoSuchObject => ber_tlv(0x80, &[]),
        Value::NoSuchInstance => ber_tlv(0x81, &[]),
        Value::EndOfMibView => ber_tlv(0x82, &[]),
    }
}

fn ber_integer_content(v: i64) -> Vec<u8> {
    // Reuse the same minimal-encoding logic as ber_integer minus the outer TLV.
    let encoded = ber_integer(v);
    // ber_integer = tag(0x02) + len + content; strip tag+len.
    if encoded.len() < 2 {
        return vec![];
    }
    let (_, content, _) = parse_tlv(&encoded).unwrap_or((0, &[], 0));
    content.to_vec()
}

fn ber_unsigned_content(v: u64, min_bytes: usize) -> Vec<u8> {
    let mut b = v.to_be_bytes().to_vec();
    while b.len() > min_bytes && b[0] == 0 {
        b.remove(0);
    }
    if b.is_empty() {
        b.push(0);
    }
    b
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// An error arising from the SMUX protocol layer.
#[derive(Debug)]
pub enum SmuxError {
    /// The peer closed the stream / sent incomplete data.
    Truncated,
    /// A PDU failed to decode.
    Decode(String),
    /// An I/O error on the peer stream.
    Io(std::io::Error),
}

impl std::fmt::Display for SmuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmuxError::Truncated => f.write_str("truncated SMUX message"),
            SmuxError::Decode(s) => write!(f, "SMUX decode error: {s}"),
            SmuxError::Io(e) => write!(f, "SMUX i/o error: {e}"),
        }
    }
}

impl std::error::Error for SmuxError {}

impl From<std::io::Error> for SmuxError {
    fn from(e: std::io::Error) -> Self {
        SmuxError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Peer / server.
// ---------------------------------------------------------------------------

/// One end of an established SMUX peer connection.
///
/// The TCP stream is split into read and write halves. A dedicated background
/// reader task owns the read half and routes every incoming PDU: peer-initiated
/// PDUs (`Register`, `Close`) go onto [`peer_pdus`] for the server loop to
/// consume, while agent-initiated responses (SNMP `Response` PDUs to a
/// forwarded GET/GETNEXT) go into the [`pending_response`] one-shot slot the
/// forwarder is awaiting. This avoids the read-contention deadlock that would
/// arise if both the server loop and the forwarder read from the same half:
/// only the reader task reads, and it demultiplexes by PDU type.
///
/// SMUX multiplexes requests over a single TCP connection with no in-band
/// demultiplexer beyond the SNMP `request-id`, so the simplest correct design
/// is to serve one outstanding request at a time per peer.
pub struct SmuxPeer {
    /// The write half of the peer's TCP stream (the forwarder writes requests
    /// here).
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    /// The one-shot slot holding the response to the currently-outstanding
    /// forwarded request, filled by the reader task.
    pub pending_response: Arc<Mutex<Option<Vec<u8>>>>,
    /// The identity OID advertised in the peer's `SMUX_OPEN`.
    pub identity: Oid,
    /// The peer's free-form description.
    pub description: String,
    /// The subtrees this peer has registered.
    pub subtrees: RwLock<Vec<Oid>>,
}

impl std::fmt::Debug for SmuxPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmuxPeer")
            .field("identity", &self.identity)
            .field("description", &self.description)
            .field("subtrees", &self.subtrees.read().unwrap_or_else(|e| e.into_inner()))
            .finish()
    }
}

/// Configuration parsed from `smuxpeer` / `smuxsocket` directives.
#[derive(Clone, Debug, Default)]
pub struct SmuxServerConfig {
    /// The address to listen on (e.g. `0.0.0.0:199`). Defaults to port 199.
    pub listen_addr: String,
    /// Authorised peers: `(password, subtree)` tuples. A peer connecting with a
    /// matching password may register the given subtree.
    pub peers: Vec<SmuxPeerEntry>,
}

/// One configured `smuxpeer` line.
#[derive(Clone, Debug)]
pub struct SmuxPeerEntry {
    /// The expected password (matched against `SmuxOpen.password`).
    pub password: String,
    /// The subtree the peer is permitted to register.
    pub subtree: Oid,
}

/// Parse `smuxpeer` and `smuxsocket` directives into an [`SmuxServerConfig`].
///
/// Syntax mirrors the Net-SNMP directives:
/// ```text
/// smuxpeer PASSWORD OID
/// smuxsocket HOST:PORT
/// ```
/// `smuxsocket` defaults to `0.0.0.0:199` when absent. Only `smuxpeer` and
/// `smuxsocket` directives are consumed; everything else is ignored.
pub fn from_config_directives(directives: &[Directive]) -> SmuxServerConfig {
    let mut cfg = SmuxServerConfig {
        listen_addr: format!("0.0.0.0:{SMUX_PORT}"),
        peers: Vec::new(),
    };
    for d in directives {
        if d.is("smuxsocket") {
            if let Some(addr) = d.arg(0) {
                cfg.listen_addr = addr.to_string();
            }
        } else if d.is("smuxpeer") {
            if let (Some(pw), Some(oid)) = (d.arg(0), d.arg(1)) {
                if let Ok(subtree) = oid.parse::<Oid>() {
                    cfg.peers.push(SmuxPeerEntry {
                        password: pw.to_string(),
                        subtree,
                    });
                }
            }
        }
    }
    cfg
}

/// The SMUX server: holds the registered peers and their subtrees. A single
/// server instance is shared (via `Arc`) between the TCP accept loop and the
/// [`SmuxSubtreeHandler`]s installed in the agent's [`Registry`](crate::Registry).
pub struct SmuxServer {
    /// Registered peers keyed by a monotonically-increasing peer id.
    pub peers: RwLock<HashMap<u32, Arc<SmuxPeer>>>,
    /// Subtree -> owning peer id. Looked up by the subtree handlers to decide
    /// which peer stream to forward a request to.
    pub subtrees: RwLock<Vec<(Oid, u32)>>,
    next_peer_id: AtomicU32,
    /// Authorised peers from configuration.
    config: RwLock<SmuxServerConfig>,
}

impl std::fmt::Debug for SmuxServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmuxServer")
            .field("peers", &self.peers.read().unwrap_or_else(|e| e.into_inner()).len())
            .field("subtrees", &self.subtrees.read().unwrap_or_else(|e| e.into_inner()).len())
            .finish()
    }
}

impl SmuxServer {
    /// Create an empty SMUX server with the given configuration.
    pub fn new(config: SmuxServerConfig) -> Arc<Self> {
        Arc::new(SmuxServer {
            peers: RwLock::new(HashMap::new()),
            subtrees: RwLock::new(Vec::new()),
            next_peer_id: AtomicU32::new(1),
            config: RwLock::new(config),
        })
    }

    /// Create an empty SMUX server with default configuration (no authorised
    /// peers, listens on `0.0.0.0:199`). Convenience for tests.
    pub fn new_default() -> Arc<Self> {
        Self::new(SmuxServerConfig::default())
    }

    /// Allow a peer that connected with an unconfigured password. By default
    /// (no `smuxpeer` lines) any password is accepted; if at least one
    /// `smuxpeer` is configured, the password must match one of them and the
    /// registered subtree must be within that peer's authorised subtree.
    fn authorize(&self, password: &str, subtree: &Oid) -> bool {
        let cfg = self.config.read().unwrap_or_else(|e| e.into_inner());
        if cfg.peers.is_empty() {
            return true;
        }
        cfg.peers.iter().any(|p| {
            p.password == password && p.subtree.is_prefix_of(subtree)
        })
    }

    /// Allocate the next peer id.
    fn next_id(&self) -> u32 {
        self.next_peer_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Bind and accept SMUX peer connections in a background task. Returns
    /// immediately after spawning the accept loop; the loop runs until the
    /// listener errors (e.g. the runtime shuts down).
    ///
    /// Returns the bound local address (useful when `addr` requests an
    /// ephemeral port via `:0`).
    pub async fn listen_tcp(self: Arc<Self>, addr: &str) -> std::io::Result<String> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?.to_string();
        let server = Arc::clone(&self);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let server = Arc::clone(&server);
                        tokio::spawn(async move {
                            if let Err(e) = server.handle_connection(stream).await {
                                tracing::debug!(%peer_addr, error = %e, "smux peer session ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "smux accept failed");
                        break;
                    }
                }
            }
        });
        // Keep the Arc alive for the duration of the listener.
        std::mem::forget(self);
        Ok(bound)
    }

    /// Drive a single SMUX peer connection through its lifecycle: read
    /// `SMUX_OPEN`, validate, then loop on register / forwarded-SNMP / close.
    async fn handle_connection(self: Arc<Self>, stream: TcpStream) -> Result<(), SmuxError> {
        // Read the Open before splitting: it is the very first PDU and must be
        // consumed before any forwarded request can race.
        let mut stream = stream;
        let open_bytes = read_one_pdu(&mut stream).await?;
        let open = match decode_smux_pdu(&open_bytes)?.0 {
            SmuxPdu::Open(o) => o,
            _ => {
                return Err(SmuxError::Decode(
                    "expected SMUX_OPEN as first PDU".into(),
                ));
            }
        };
        tracing::info!(
            identity = %open.identity,
            desc = %open.description,
            "smux peer opened"
        );

        // Split into read/write halves. A dedicated reader task owns the read
        // half and demultiplexes incoming PDUs: peer-initiated PDUs (Register/
        // Close) go to a channel this loop consumes, while SNMP Response PDUs
        // (answers to forwarded GET/GETNEXT) go into a one-shot slot the
        // forwarder awaits. This avoids read-contention between the loop and
        // the forwarder.
        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));
        let pending_response: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let (pdu_tx, pdu_rx) = tokio::sync::mpsc::channel::<SmuxPdu>(16);
        let reader_pending = Arc::clone(&pending_response);
        tokio::spawn(async move {
            let mut read_half = read_half;
            loop {
                match read_one_pdu_async(&mut read_half).await {
                    Ok(buf) => {
                        let pdu = match decode_smux_pdu(&buf) {
                            Ok((p, _)) => p,
                            Err(_) => break,
                        };
                        let is_response = matches!(&pdu, SmuxPdu::Snmp(m) if m.pdu.pdu_type == PduType::Response);
                        if is_response {
                            // Hand the raw bytes to the waiting forwarder.
                            {
                                let mut slot = reader_pending.lock().await;
                                *slot = Some(buf);
                            }
                        } else {
                            // Peer-initiated: enqueue for the server loop.
                            if pdu_tx.send(pdu).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let mut peer_pdus = pdu_rx;
        let peer = Arc::new(SmuxPeer {
            writer: Arc::clone(&writer),
            pending_response: Arc::clone(&pending_response),
            identity: open.identity.clone(),
            description: open.description.clone(),
            subtrees: RwLock::new(Vec::new()),
        });

        // We accept the open before any register: record the peer so its
        // registered subtrees become forwardable.
        let peer_id = self.next_id();
        self.peers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_id, Arc::clone(&peer));

        // 2. Main loop: consume peer-initiated PDUs (Register/Close) routed by
        //    the reader task until EOF / close.
        loop {
            let pdu = match peer_pdus.recv().await {
                Some(p) => p,
                None => break,
            };
            match pdu {
                SmuxPdu::Register {
                    subtree,
                    priority: _,
                    operation,
                } => {
                    let accepted = if operation == 1 {
                        self.authorize(&open.password, &subtree)
                    } else {
                        false
                    };
                    if accepted {
                        self.subtrees
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((subtree.clone(), peer_id));
                        peer.subtrees
                            .write()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(subtree);
                    }
                    // Reply with an RRsp.
                    let code = if accepted {
                        RRspCode::ReadOnly.code()
                    } else {
                        RRspCode::Reject.code()
                    };
                    let rsp = SmuxRRsp { code }.encode();
                    let mut w = writer.lock().await;
                    w.write_all(&rsp).await?;
                }
                SmuxPdu::Close(_) => break,
                SmuxPdu::RRsp(_) | SmuxPdu::Sout(_) => {
                    // Agent-initiated; ignore inbound.
                }
                SmuxPdu::Open(_) => {
                    // Duplicate open; ignore.
                }
                SmuxPdu::Snmp(_) => {
                    // A non-response SNMP PDU the reader task did not route to
                    // the response slot (e.g. an unsolicited Get/Set from the
                    // peer). Nothing to do at the server level; just drop it.
                }
            }
        }

        // Tear down: remove the peer and its subtrees.
        self.peers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&peer_id);
        self.subtrees
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(_, id)| *id != peer_id);
        Ok(())
    }

    /// Forward a GET to the peer owning `oid` and return its value. Returns
    /// `None` if no peer owns the subtree, the peer is gone, or the request
    /// fails for any reason.
    fn forward_get(self: &Arc<Self>, oid: &Oid) -> Option<Value> {
        Self::block_on(Self::forward_get_async(Arc::clone(self), oid))
    }

    /// Forward a GETNEXT to the peer owning `oid` and return the successor
    /// reading. Returns `None` on any failure.
    fn forward_get_next(self: &Arc<Self>, oid: &Oid) -> Option<Reading> {
        Self::block_on(Self::forward_get_next_async(Arc::clone(self), oid))
    }

    async fn forward_get_async(self: Arc<Self>, oid: &Oid) -> Option<Value> {
        let peer = self.owner_of(oid)?;
        let req = encode_snmp_request(PduType::Get, next_request_id(), oid);
        let resp = forward_roundtrip(&peer.writer, &peer.pending_response, &req).await?;
        let (pdu, _) = decode_snmp_response(&resp)?;
        let vb = pdu.variables.into_iter().next()?;
        match vb.value {
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => None,
            v => Some(v),
        }
    }

    async fn forward_get_next_async(self: Arc<Self>, oid: &Oid) -> Option<Reading> {
        let peer = self.owner_of(oid)?;
        let req = encode_snmp_request(PduType::GetNext, next_request_id(), oid);
        let resp = forward_roundtrip(&peer.writer, &peer.pending_response, &req).await?;
        let (pdu, _) = decode_snmp_response(&resp)?;
        let vb = pdu.variables.into_iter().next()?;
        match vb.value {
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => None,
            _ => Some(Reading {
                oid: vb.oid,
                value: vb.value,
            }),
        }
    }

    /// Bridge a sync handler call into the async SMUX layer. Mirrors
    /// [`ProxyForwarder`](crate::proxy::ProxyForwarder)'s bridge: the agent
    /// must run under a multi-threaded tokio runtime.
    fn block_on<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(fut)
        })
    }

    /// Find the peer that owns the subtree containing `oid`.
    fn owner_of(&self, oid: &Oid) -> Option<Arc<SmuxPeer>> {
        let subtrees = self.subtrees.read().unwrap_or_else(|e| e.into_inner());
        // Pick the longest matching subtree prefix (most-specific owner).
        let mut best: Option<(&Oid, u32)> = None;
        for (sub, id) in subtrees.iter() {
            if sub.is_prefix_of(oid) {
                if best.as_ref().map_or(true, |(b, _)| b.len() < sub.len()) {
                    best = Some((sub, *id));
                }
            }
        }
        let id = best?.1;
        self.peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .cloned()
    }

    /// Snapshot of registered `(subtree, peer_id)` tuples (for the SMUX-MIB).
    pub fn registered_subtrees(&self) -> Vec<(Oid, u32)> {
        self.subtrees
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Decode an SNMP Response-PDU from the bytes a peer wrote back.
fn decode_snmp_response(buf: &[u8]) -> Option<(Pdu, usize)> {
    let (tag, content, total) = parse_tlv(buf).ok()?;
    if PduType::from_tag(tag).ok()? != PduType::Response {
        return None;
    }
    let pdu = decode_bare_snmp_pdu(tag, content).ok()?;
    Some((pdu, total))
}

/// Write `req` to the peer's write half, then await the response the reader
/// task will deposit in `pending_response`. Clears the slot first so a stale
/// response from a previous (failed) request is not returned.
async fn forward_roundtrip(
    writer: &Arc<Mutex<OwnedWriteHalf>>,
    pending: &Arc<Mutex<Option<Vec<u8>>>>,
    req: &[u8],
) -> Option<Vec<u8>> {
    {
        let mut slot = pending.lock().await;
        *slot = None;
    }
    {
        let mut w = writer.lock().await;
        w.write_all(req).await.ok()?;
    }
    // Poll the slot until the reader task fills it (or time out).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        {
            let mut slot = pending.lock().await;
            if slot.is_some() {
                return slot.take();
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Monotonic request-id source for forwarded SMUX requests.
fn next_request_id() -> i32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed) as i32
}

/// Read exactly one SMUX/SNMP PDU from `stream` (borrowed). Returns the raw
/// bytes of the top-level TLV.
async fn read_one_pdu(stream: &mut TcpStream) -> Result<Vec<u8>, SmuxError> {
    read_one_pdu_async(stream).await
}

/// Generic PDU reader over any `AsyncRead + Unpin`.
async fn read_one_pdu_async<R>(stream: &mut R) -> Result<Vec<u8>, SmuxError>
where
    R: AsyncReadExt + Unpin,
{
    // Read the tag byte.
    let mut tag_buf = [0u8; 1];
    stream.read_exact(&mut tag_buf).await?;
    // Read the length (short or long form).
    let mut first_len = [0u8; 1];
    stream.read_exact(&mut first_len).await?;
    let mut len_bytes = vec![first_len[0]];
    let total_len;
    if first_len[0] & 0x80 == 0 {
        total_len = first_len[0] as usize;
    } else {
        let n = (first_len[0] & 0x7f) as usize;
        let mut rest = vec![0u8; n];
        stream.read_exact(&mut rest).await?;
        let mut len = 0usize;
        for &b in &rest {
            len = (len << 8) | (b as usize);
        }
        total_len = len;
        len_bytes.extend_from_slice(&rest);
    }
    let mut content = vec![0u8; total_len];
    stream.read_exact(&mut content).await?;
    let mut out = Vec::with_capacity(1 + len_bytes.len() + total_len);
    out.push(tag_buf[0]);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(&content);
    Ok(out)
}

// ---------------------------------------------------------------------------
// MIB handler for a registered SMUX subtree.
// ---------------------------------------------------------------------------

/// A [`MibHandler`] that forwards GET/GETNEXT for one registered SMUX subtree
/// to its owning peer. One handler is created per registered subtree; use
/// [`smux_handler`] to build the full set.
pub struct SmuxSubtreeHandler {
    root: Oid,
    server: Arc<SmuxServer>,
}

impl std::fmt::Debug for SmuxSubtreeHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmuxSubtreeHandler")
            .field("root", &self.root)
            .finish()
    }
}

impl SmuxSubtreeHandler {
    /// Construct a handler rooted at `root` that forwards to the peers known
    /// to `server`.
    pub fn new(root: Oid, server: Arc<SmuxServer>) -> Self {
        SmuxSubtreeHandler { root, server }
    }
}

impl MibHandler for SmuxSubtreeHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.server.forward_get(oid)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        self.server.forward_get_next(oid)
    }

    fn set(&self, _oid: &Oid, _value: &Value) -> std::result::Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
}

/// Build the set of [`MibHandler`]s for the currently-registered SMUX
/// subtrees. The returned handlers are rooted at each registered subtree; the
/// caller registers them with the agent's [`Registry`](crate::Registry).
///
/// Because peers register and unregister dynamically, the handlers are
/// refreshed lazily by re-querying the server. For static registration the
/// returned vector captures the subtrees known *at call time*.
pub fn smux_handler(server: Arc<SmuxServer>) -> Vec<Arc<dyn MibHandler>> {
    let subtrees = server.registered_subtrees();
    let mut out: Vec<Arc<dyn MibHandler>> = Vec::new();
    for (sub, _id) in subtrees {
        out.push(Arc::new(SmuxSubtreeHandler::new(sub, Arc::clone(&server))));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smux_open_roundtrip() {
        let open = SmuxOpen {
            version: 0,
            identity: "1.3.6.1.4.1.9999".parse().unwrap(),
            description: "test-peer".into(),
            password: "secret".into(),
        };
        let bytes = open.encode();
        // Outer tag must be SMUX_OPEN (0xA0).
        assert_eq!(bytes[0], tags::SMUX_OPEN);
        let (pdu, consumed) = decode_smux_pdu(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match pdu {
            SmuxPdu::Open(o) => {
                assert_eq!(o.version, 0);
                assert_eq!(o.identity.to_string(), ".1.3.6.1.4.1.9999");
                assert_eq!(o.description, "test-peer");
                assert_eq!(o.password, "secret");
            }
            _ => panic!("expected Open, got {pdu:?}"),
        }
    }

    #[test]
    fn smux_close_roundtrip() {
        let close = SmuxClose { code: -1 };
        let bytes = close.encode();
        assert_eq!(bytes[0], tags::SMUX_CLOSE);
        let (pdu, consumed) = decode_smux_pdu(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match pdu {
            SmuxPdu::Close(c) => assert_eq!(c.code, -1),
            _ => panic!("expected Close"),
        }
    }

    #[test]
    fn smux_rrsp_roundtrip() {
        let rsp = SmuxRRsp {
            code: RRspCode::ReadOnly.code(),
        };
        let bytes = rsp.encode();
        assert_eq!(bytes[0], tags::SMUX_RRSP);
        let (pdu, _) = decode_smux_pdu(&bytes).unwrap();
        match pdu {
            SmuxPdu::RRsp(r) => assert_eq!(r.code, 0),
            _ => panic!("expected RRsp"),
        }
    }

    #[test]
    fn register_encode_decode_roundtrip() {
        let subtree: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let bytes = encode_register(&subtree, 5, 1);
        // The register PDU is a GetRequest (tag 0xA0 == SMUX_OPEN's tag, but
        // distinguished structurally: an Open decodes as a SEQUENCE of 4 fields,
        // a register as a 4-field PDU with a varbind list). Our decoder detects
        // the register shape and exposes it as Register.
        let (pdu, _) = decode_smux_pdu(&bytes).unwrap();
        match pdu {
            SmuxPdu::Register {
                subtree: s,
                priority,
                operation,
            } => {
                assert_eq!(s.to_string(), ".1.3.6.1.4.1.9999");
                assert_eq!(priority, 5);
                assert_eq!(operation, 1);
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    #[test]
    fn config_parses_smuxpeer_and_smuxsocket() {
        let directives = vec![
            Directive {
                token: "smuxpeer".into(),
                args: vec!["secret".into(), "1.3.6.1.4.1.9999".into()],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 1,
            },
            Directive {
                token: "smuxsocket".into(),
                args: vec!["127.0.0.1:1199".into()],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 2,
            },
            Directive {
                token: "rocommunity".into(),
                args: vec!["public".into()],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 3,
            },
        ];
        let cfg = from_config_directives(&directives);
        assert_eq!(cfg.listen_addr, "127.0.0.1:1199");
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].password, "secret");
        assert_eq!(cfg.peers[0].subtree.to_string(), ".1.3.6.1.4.1.9999");
    }

    /// A minimal mock SMUX peer: connect, send Open, send Register, then
    /// answer one Get with a Response carrying a fixed value.
    struct MockPeer {
        value_oid: Oid,
        value: Value,
    }

    impl MockPeer {
        async fn run(addr: &str, password: &str, subtree: &Oid, value_oid: Oid, value: Value) {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // Send Open.
            let open = SmuxOpen {
                version: 0,
                identity: subtree.clone(),
                description: "mock".into(),
                password: password.into(),
            };
            stream.write_all(&open.encode()).await.unwrap();
            // Send Register.
            stream
                .write_all(&encode_register(subtree, 5, 1))
                .await
                .unwrap();
            // Read RRsp.
            let _rrsp = read_one_pdu(&mut stream).await.unwrap();
            // Now wait for the forwarded Get and reply.
            let req = read_one_pdu(&mut stream).await.unwrap();
            let (tag, content, _) = parse_tlv(&req).unwrap();
            assert_eq!(tag, PduType::Get.tag());
            // Decode request-id from the PDU body.
            let (_, id_buf, _c1) = parse_tlv(content).unwrap();
            let request_id = parse_integer(id_buf).unwrap() as i32;
            let resp = Pdu {
                pdu_type: PduType::Response,
                request_id,
                error_status: 0,
                error_index: 0,
                variables: vec![VarBind::new(value_oid.clone(), value.clone())],
                v1_trap: None,
            };
            stream.write_all(&encode_snmp_response(&resp)).await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn smux_server_forwards_get_to_mock_peer() {
        let server = SmuxServer::new_default();
        let bound = Arc::clone(&server)
            .listen_tcp("127.0.0.1:0")
            .await
            .unwrap();

        let subtree: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let value_oid: Oid = "1.3.6.1.4.1.9999.1.0".parse().unwrap();
        let value = Value::Integer(42);

        // Spawn the mock peer.
        let addr = bound.clone();
        let sub = subtree.clone();
        let vo = value_oid.clone();
        let v = value.clone();
        tokio::spawn(async move {
            MockPeer::run(&addr, "ignored", &sub, vo, v).await;
        });
        // Give the peer a moment to connect + register.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // The handler set reflects the registered subtree.
        let handlers = smux_handler(Arc::clone(&server));
        // Wait for registration to land (the connection is async).
        for _ in 0..20 {
            if !handlers.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // Even if the handler snapshot is empty (peer registered after the
        // snapshot), the server itself should be able to forward because it
        // looks up the owner dynamically. Use the server directly via a
        // freshly-built handler rooted at the subtree.
        let handler = SmuxSubtreeHandler::new(subtree.clone(), Arc::clone(&server));
        // Wait for the subtree to appear.
        let mut got = None;
        for _ in 0..40 {
            if let Some(v) = handler.get(&value_oid) {
                got = Some(v);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(got, Some(value));
    }
}
