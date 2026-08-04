//! Protocol Data Units (PDUs) and variable bindings.
//!
//! Rust counterpart of the PDU structures in `snmp.h` / `snmp_api.c` and the
//! request/response processing in `snmp_client.c`.

use crate::convert::{int_to_i64, oid_from_rasn, oid_to_rasn};
use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::value::Value;
use rasn::types::Integer;
use rasn_snmp::v2::{
    BulkPdu, GetBulkRequest, GetNextRequest, GetRequest, InformRequest, Pdu as RasnPdu, Pdus,
    Report, Response, SetRequest, Trap, VarBind as RasnVarBind,
};
use rasn_snmp::v1;
use std::fmt;
use std::net::Ipv4Addr;

/// The SNMP PDU type (the context-specific constructed tag, low nibble).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    /// GetRequest-PDU.
    Get = 0,
    /// GetNextRequest-PDU.
    GetNext = 1,
    /// Response-PDU (GetResponse in v1).
    Response = 2,
    /// SetRequest-PDU.
    Set = 3,
    /// Trap-PDU (SNMPv1 only; structurally different — not built here).
    TrapV1 = 4,
    /// GetBulkRequest-PDU (SNMPv2c+).
    GetBulk = 5,
    /// InformRequest-PDU.
    Inform = 6,
    /// SNMPv2-Trap-PDU.
    TrapV2 = 7,
    /// Report-PDU.
    Report = 8,
}

impl PduType {
    /// The full context-constructed ASN.1 tag for this PDU type
    /// (`0xA0 | pdu-type`).
    pub fn tag(self) -> u8 {
        0xA0 | self as u8
    }

    /// Recover a PDU type from a context-constructed tag.
    pub fn from_tag(t: u8) -> Result<PduType> {
        let kind = match t & 0x1f {
            0 => PduType::Get,
            1 => PduType::GetNext,
            2 => PduType::Response,
            3 => PduType::Set,
            4 => PduType::TrapV1,
            5 => PduType::GetBulk,
            6 => PduType::Inform,
            7 => PduType::TrapV2,
            8 => PduType::Report,
            _ => return Err(Error::Protocol(format!("unknown PDU tag 0x{t:02x}"))),
        };
        Ok(kind)
    }
}

/// SNMP error-status values (RFC 3416 §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorStatus {
    /// No error.
    NoError,
    /// Response too big to fit in a single message.
    TooBig,
    /// The named variable does not exist.
    NoSuchName,
    /// A supplied value is the wrong type/length/encoding.
    BadValue,
    /// The variable is read-only.
    ReadOnly,
    /// General/unspecified error.
    GenErr,
    /// Access denied.
    NoAccess,
    /// Wrong type in a SET.
    WrongType,
    /// Wrong length in a SET.
    WrongLength,
    /// Wrong encoding in a SET.
    WrongEncoding,
    /// Wrong value in a SET.
    WrongValue,
    /// Creation not supported.
    NoCreation,
    /// Value inconsistent with current state.
    InconsistentValue,
    /// Resource unavailable.
    ResourceUnavailable,
    /// Commit failed.
    CommitFailed,
    /// Undo failed.
    UndoFailed,
    /// Authorization error.
    AuthorizationError,
    /// Variable is not writable.
    NotWritable,
    /// OID name is inconsistent.
    InconsistentName,
    /// An error-status code outside the standard set.
    Other(i64),
}

impl ErrorStatus {
    /// Convert to the on-the-wire integer code.
    pub fn code(self) -> i64 {
        match self {
            ErrorStatus::NoError => 0,
            ErrorStatus::TooBig => 1,
            ErrorStatus::NoSuchName => 2,
            ErrorStatus::BadValue => 3,
            ErrorStatus::ReadOnly => 4,
            ErrorStatus::GenErr => 5,
            ErrorStatus::NoAccess => 6,
            ErrorStatus::WrongType => 7,
            ErrorStatus::WrongLength => 8,
            ErrorStatus::WrongEncoding => 9,
            ErrorStatus::WrongValue => 10,
            ErrorStatus::NoCreation => 11,
            ErrorStatus::InconsistentValue => 12,
            ErrorStatus::ResourceUnavailable => 13,
            ErrorStatus::CommitFailed => 14,
            ErrorStatus::UndoFailed => 15,
            ErrorStatus::AuthorizationError => 16,
            ErrorStatus::NotWritable => 17,
            ErrorStatus::InconsistentName => 18,
            ErrorStatus::Other(v) => v,
        }
    }

    /// Build from the on-the-wire integer code.
    pub fn from_code(code: i64) -> ErrorStatus {
        match code {
            0 => ErrorStatus::NoError,
            1 => ErrorStatus::TooBig,
            2 => ErrorStatus::NoSuchName,
            3 => ErrorStatus::BadValue,
            4 => ErrorStatus::ReadOnly,
            5 => ErrorStatus::GenErr,
            6 => ErrorStatus::NoAccess,
            7 => ErrorStatus::WrongType,
            8 => ErrorStatus::WrongLength,
            9 => ErrorStatus::WrongEncoding,
            10 => ErrorStatus::WrongValue,
            11 => ErrorStatus::NoCreation,
            12 => ErrorStatus::InconsistentValue,
            13 => ErrorStatus::ResourceUnavailable,
            14 => ErrorStatus::CommitFailed,
            15 => ErrorStatus::UndoFailed,
            16 => ErrorStatus::AuthorizationError,
            17 => ErrorStatus::NotWritable,
            18 => ErrorStatus::InconsistentName,
            other => ErrorStatus::Other(other),
        }
    }

    /// Whether this status indicates success.
    pub fn is_ok(self) -> bool {
        matches!(self, ErrorStatus::NoError)
    }
}

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorStatus::NoError => "noError",
            ErrorStatus::TooBig => "tooBig",
            ErrorStatus::NoSuchName => "noSuchName",
            ErrorStatus::BadValue => "badValue",
            ErrorStatus::ReadOnly => "readOnly",
            ErrorStatus::GenErr => "genErr",
            ErrorStatus::NoAccess => "noAccess",
            ErrorStatus::WrongType => "wrongType",
            ErrorStatus::WrongLength => "wrongLength",
            ErrorStatus::WrongEncoding => "wrongEncoding",
            ErrorStatus::WrongValue => "wrongValue",
            ErrorStatus::NoCreation => "noCreation",
            ErrorStatus::InconsistentValue => "inconsistentValue",
            ErrorStatus::ResourceUnavailable => "resourceUnavailable",
            ErrorStatus::CommitFailed => "commitFailed",
            ErrorStatus::UndoFailed => "undoFailed",
            ErrorStatus::AuthorizationError => "authorizationError",
            ErrorStatus::NotWritable => "notWritable",
            ErrorStatus::InconsistentName => "inconsistentName",
            ErrorStatus::Other(v) => return write!(f, "error({v})"),
        };
        f.write_str(s)
    }
}

/// A variable binding: an OID paired with its value.
#[derive(Clone, Debug, PartialEq)]
pub struct VarBind {
    /// The object identifier.
    pub oid: Oid,
    /// The bound value (`Null` in requests).
    pub value: Value,
}

impl VarBind {
    /// Construct a varbind.
    pub fn new(oid: Oid, value: Value) -> Self {
        VarBind { oid, value }
    }

    /// A varbind with a `Null` value, used in GET/GETNEXT requests.
    pub fn null(oid: Oid) -> Self {
        VarBind {
            oid,
            value: Value::Null,
        }
    }

    /// Convert into a `rasn-snmp` variable binding.
    pub(crate) fn to_rasn(&self) -> Result<RasnVarBind> {
        Ok(RasnVarBind {
            name: oid_to_rasn(&self.oid)?,
            value: self.value.to_var_bind_value()?,
        })
    }

    /// Build from a decoded `rasn-snmp` variable binding.
    pub(crate) fn from_rasn(vb: RasnVarBind) -> Result<VarBind> {
        Ok(VarBind {
            oid: oid_from_rasn(&vb.name),
            value: Value::from_var_bind_value(vb.value)?,
        })
    }
}

/// Generic-trap numbers for the SNMPv1 Trap-PDU (RFC 1157 §4.1.6).
///
/// Values `0..=6` are the standard well-known traps; values `>= 7` are not
/// defined by the standard and are carried as-is for enterprise-specific use
/// (where the meaning is given by `enterprise` + `specific_trap`).
pub mod v1_generic_trap {
    /// `coldStart` — the agent reinitialised itself.
    pub const COLD_START: u8 = 0;
    /// `warmStart` — the agent reinitialised but kept its configuration.
    pub const WARM_START: u8 = 1;
    /// `linkDown` — a connected interface went down.
    pub const LINK_DOWN: u8 = 2;
    /// `linkUp` — a connected interface came up.
    pub const LINK_UP: u8 = 3;
    /// `authenticationFailure` — a received message failed community auth.
    pub const AUTH_FAILURE: u8 = 4;
    /// `egpNeighborLoss` — an EGP neighbour went down.
    pub const EGP_NEIGHBOR_LOSS: u8 = 5;
    /// `enterpriseSpecific` — the meaning comes from `specific_trap`.
    pub const ENTERPRISE_SPECIFIC: u8 = 6;
}

/// The legacy SNMPv1 Trap-PDU payload (RFC 1157 §4.1.6).
///
/// Unlike the v2c/v3 notification PDUs, the v1 Trap-PDU is structurally
/// distinct: it carries enterprise/generic-trap/specific-trap/agent-addr fields
/// directly in the PDU rather than as varbinds. This type models those fields;
/// it is held on [`Pdu::v1_trap`] whenever `pdu_type == TrapV1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1Trap {
    /// The enterprise OID under which the trap is defined. By convention the
    /// generic traps live under `1.3.6.1.6.3.1.1.5`; enterprise-specific traps
    /// append `specific_trap` to this value.
    pub enterprise: Oid,
    /// The address of the originator. `0.0.0.0` (the default) lets the receiver
    /// fill it from the transport; the sender may also set it explicitly.
    pub agent_addr: Ipv4Addr,
    /// The generic-trap number; see [`v1_generic_trap`].
    pub generic_trap: u8,
    /// The enterprise-specific trap number (meaningful only when
    /// `generic_trap == enterpriseSpecific`).
    pub specific_trap: u32,
    /// Elapsed time since the agent reinitialised (hundredths of a second).
    pub time_stamp: u32,
}

impl V1Trap {
    /// Construct a v1 trap payload.
    pub fn new(
        enterprise: Oid,
        agent_addr: Ipv4Addr,
        generic_trap: u8,
        specific_trap: u32,
        time_stamp: u32,
    ) -> Self {
        V1Trap {
            enterprise,
            agent_addr,
            generic_trap,
            specific_trap,
            time_stamp,
        }
    }

    /// Convert into the `rasn-snmp` v1 [`Trap`](v1::Trap) PDU body.
    pub(crate) fn to_rasn(&self, variable_bindings: Vec<v1::VarBind>) -> Result<v1::Trap> {
        Ok(v1::Trap {
            enterprise: oid_to_rasn(&self.enterprise)?,
            agent_addr: smi_v1_internet_addr(self.agent_addr),
            generic_trap: Integer::from(self.generic_trap as i64),
            specific_trap: Integer::from(self.specific_trap as i64),
            time_stamp: rasn_smi_v1_time_ticks(self.time_stamp),
            variable_bindings,
        })
    }

    /// Build a [`V1Trap`] plus the carried v1 varbind list from a decoded
    /// `rasn-snmp` v1 [`Trap`](v1::Trap).
    pub(crate) fn from_rasn(rasn: v1::Trap) -> Result<(V1Trap, Vec<v1::VarBind>)> {
        let agent_addr = match rasn.agent_addr {
            rasn_smi::v1::NetworkAddress::Internet(ip) => {
                // `FixedOctetString<4>` implements `AsRef<[u8]>`.
                let bytes: [u8; 4] = ip.0.as_ref().try_into().expect("IpAddress is 4 octets");
                Ipv4Addr::from(bytes)
            }
        };
        let generic = int_to_i64(&rasn.generic_trap)?;
        let specific = int_to_i64(&rasn.specific_trap)?;
        let trap = V1Trap {
            enterprise: oid_from_rasn(&rasn.enterprise),
            agent_addr,
            generic_trap: u8::try_from(generic).map_err(|_| {
                Error::Protocol(format!("v1 generic_trap out of range: {generic}"))
            })?,
            specific_trap: u32::try_from(specific).map_err(|_| {
                Error::Protocol(format!("v1 specific_trap out of range: {specific}"))
            })?,
            time_stamp: rasn_smi_v1_time_ticks_value(&rasn.time_stamp),
        };
        Ok((trap, rasn.variable_bindings))
    }
}

/// Build an SMIv1 `NetworkAddress::Internet(IpAddress(..))` for an IPv4 address.
fn smi_v1_internet_addr(addr: Ipv4Addr) -> rasn_smi::v1::NetworkAddress {
    rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(addr.octets().into()))
}

/// Wrap a centisecond count as an SMIv1 `TimeTicks`.
fn rasn_smi_v1_time_ticks(ticks: u32) -> rasn_smi::v1::TimeTicks {
    rasn_smi::v1::TimeTicks(ticks)
}

/// Read the centisecond value out of an SMIv1 `TimeTicks`.
fn rasn_smi_v1_time_ticks_value(ticks: &rasn_smi::v1::TimeTicks) -> u32 {
    ticks.0
}

/// Convert a list of domain [`VarBind`]s into the SMIv1 `ObjectSyntax` form used
/// by the v1 Trap-PDU. v1 has no exception markers, so every value becomes a
/// plain `ObjectSyntax`; the domain `Value` never carries an exception marker
/// in a v1 trap built by this crate (a `NoSuch*`/`EndOfMibView` is mapped to
/// NULL, matching upstream behaviour where v1 traps only carry real values).
pub(crate) fn varbinds_to_v1(varbinds: &[VarBind]) -> Result<Vec<v1::VarBind>> {
    varbinds
        .iter()
        .map(|vb| -> Result<v1::VarBind> {
            Ok(v1::VarBind {
                name: oid_to_rasn(&vb.oid)?,
                value: value_to_v1_object_syntax(&vb.value)?,
            })
        })
        .collect()
}

/// Parse a list of SMIv1 varbinds back into domain [`VarBind`]s.
pub(crate) fn varbinds_from_v1(vbs: Vec<v1::VarBind>) -> Result<Vec<VarBind>> {
    vbs.into_iter()
        .map(|vb| -> Result<VarBind> {
            Ok(VarBind {
                oid: oid_from_rasn(&vb.name),
                value: value_from_v1_object_syntax(vb.value),
            })
        })
        .collect()
}

/// Map a domain [`Value`] to an SMIv1 `ObjectSyntax`. Exception markers collapse
/// to `Empty` (the v1 spelling of NULL) since the v1 Trap-PDU cannot carry them.
fn value_to_v1_object_syntax(value: &Value) -> Result<rasn_smi::v1::ObjectSyntax> {
    use rasn_smi::v1::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
    let syntax = match value {
        Value::Integer(v) => ObjectSyntax::Simple(SimpleSyntax::Number(Integer::from(*v))),
        Value::OctetString(b) => {
            ObjectSyntax::Simple(SimpleSyntax::String(crate::convert::octet_string(b)))
        }
        Value::Oid(o) => ObjectSyntax::Simple(SimpleSyntax::Object(oid_to_rasn(o)?)),
        // v1 SimpleSyntax has no Empty variant spelled as NULL-by-value, but the
        // enum carries `Empty`; map NULL and the v2 exception markers to it.
        Value::Null
        | Value::NoSuchObject
        | Value::NoSuchInstance
        | Value::EndOfMibView => ObjectSyntax::Simple(SimpleSyntax::Empty),
        Value::IpAddress(ip) => ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(
            rasn_smi::v1::NetworkAddress::Internet(rasn_smi::v1::IpAddress(ip.octets().into())),
        )),
        Value::Counter32(v) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(rasn_smi::v1::Counter(*v)))
        }
        Value::Gauge32(v) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Gauge(rasn_smi::v1::Gauge(*v)))
        }
        Value::TimeTicks(v) => ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(
            rasn_smi::v1::TimeTicks(*v),
        )),
        Value::Opaque(b) => ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(
            crate::convert::opaque_from_bytes(b)?,
        )),
        // Counter64 does not exist in SMIv1; carry it as a Gauge (best effort,
        // same as upstream's v1 path) since v1 traps rarely carry 64-bit stats.
        Value::Counter64(v) => ObjectSyntax::ApplicationWide(ApplicationSyntax::Gauge(
            rasn_smi::v1::Gauge(u32::try_from(*v).unwrap_or(u32::MAX)),
        )),
    };
    Ok(syntax)
}

/// Map an SMIv1 `ObjectSyntax` back to a domain [`Value`].
fn value_from_v1_object_syntax(syntax: rasn_smi::v1::ObjectSyntax) -> Value {
    use rasn_smi::v1::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
    match syntax {
        ObjectSyntax::Simple(SimpleSyntax::Number(i)) => {
            Value::Integer(crate::convert::int_to_i64(&i).unwrap_or(0))
        }
        ObjectSyntax::Simple(SimpleSyntax::String(s)) => Value::OctetString(s.to_vec()),
        ObjectSyntax::Simple(SimpleSyntax::Object(o)) => Value::Oid(oid_from_rasn(&o)),
        ObjectSyntax::Simple(SimpleSyntax::Empty) => Value::Null,
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(addr)) => match addr {
            rasn_smi::v1::NetworkAddress::Internet(ip) => {
                let bytes: [u8; 4] = ip.0.as_ref().try_into().expect("IpAddress is 4 octets");
                Value::IpAddress(std::net::Ipv4Addr::from(bytes))
            }
        },
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(c)) => Value::Counter32(c.0),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Gauge(g)) => Value::Gauge32(g.0),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(t)) => Value::TimeTicks(t.0),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(op)) => {
            Value::Opaque(op.as_ref().to_vec())
        }
    }
}

/// A complete SNMP PDU (everything inside the message wrapper).
#[derive(Clone, Debug, PartialEq)]
pub struct Pdu {
    /// The PDU type.
    pub pdu_type: PduType,
    /// The request-id correlating responses with requests.
    pub request_id: i32,
    /// error-status (also `non-repeaters` for GetBulk).
    pub error_status: i64,
    /// error-index (also `max-repetitions` for GetBulk).
    pub error_index: i64,
    /// The variable bindings.
    pub variables: Vec<VarBind>,
    /// The structured payload of an SNMPv1 Trap-PDU. `None` for every other PDU
    /// type. For a v1 trap the [`V1Trap`] fields are authoritative and
    /// [`Pdu::variables`] additionally carries the trap's trailing varbinds.
    pub v1_trap: Option<V1Trap>,
}

impl Pdu {
    /// Create a request PDU with the given type and request-id.
    pub fn new(pdu_type: PduType, request_id: i32) -> Self {
        Pdu {
            pdu_type,
            request_id,
            error_status: 0,
            error_index: 0,
            variables: Vec::new(),
            v1_trap: None,
        }
    }

    /// Create an SNMPv1 Trap-PDU. The trap's trailing varbinds go into
    /// [`Pdu::variables`]; the structured trap fields live on the returned
    /// PDU's [`v1_trap`](Pdu::v1_trap) slot. `request_id` is unused on the v1
    /// wire (the Trap-PDU has no request-id field) but kept here for uniform
    /// logging; pass `0`.
    pub fn new_v1_trap(trap: V1Trap, varbinds: Vec<VarBind>) -> Self {
        Pdu {
            pdu_type: PduType::TrapV1,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            variables: varbinds,
            v1_trap: Some(trap),
        }
    }

    /// Builder: add a null-valued varbind (for GET-style requests).
    pub fn with_null_var(mut self, oid: Oid) -> Self {
        self.variables.push(VarBind::null(oid));
        self
    }

    /// Builder: add a varbind with an explicit value (for SET).
    pub fn with_var(mut self, oid: Oid, value: Value) -> Self {
        self.variables.push(VarBind::new(oid, value));
        self
    }

    /// For GetBulk: the non-repeaters field aliases `error_status`.
    pub fn non_repeaters(&self) -> i64 {
        self.error_status
    }

    /// For GetBulk: the max-repetitions field aliases `error_index`.
    pub fn max_repetitions(&self) -> i64 {
        self.error_index
    }

    /// Interpret `error_status` as a typed `ErrorStatus` (non-bulk PDUs).
    pub fn status(&self) -> ErrorStatus {
        ErrorStatus::from_code(self.error_status)
    }

    /// Convert into the `rasn-snmp` PDU choice, ready to be wrapped in a message
    /// and BER-encoded.
    ///
    /// Returns [`Error::Protocol`] for the legacy SNMPv1 Trap-PDU, which uses a
    /// distinct `rasn-snmp::v1` structure; encode such a PDU via
    /// [`Pdu::to_v1_rasn`] and wrap it in a `rasn_snmp::v1::Message` instead
    /// (see [`crate::message::Message::encode`]).
    pub(crate) fn to_rasn(&self) -> Result<Pdus> {
        let variable_bindings = self
            .variables
            .iter()
            .map(VarBind::to_rasn)
            .collect::<Result<Vec<_>>>()?;

        let error_status = u32::try_from(self.error_status).map_err(|_| Error::IntegerOverflow)?;
        let error_index = u32::try_from(self.error_index).map_err(|_| Error::IntegerOverflow)?;
        let std = || RasnPdu {
            request_id: self.request_id,
            error_status,
            error_index,
            variable_bindings: variable_bindings.clone(),
        };

        let pdus = match self.pdu_type {
            PduType::Get => Pdus::GetRequest(GetRequest(std())),
            PduType::GetNext => Pdus::GetNextRequest(GetNextRequest(std())),
            PduType::Response => Pdus::Response(Response(std())),
            PduType::Set => Pdus::SetRequest(SetRequest(std())),
            PduType::Inform => Pdus::InformRequest(InformRequest(std())),
            PduType::TrapV2 => Pdus::Trap(Trap(std())),
            PduType::Report => Pdus::Report(Report(std())),
            PduType::GetBulk => Pdus::GetBulkRequest(GetBulkRequest(BulkPdu {
                request_id: self.request_id,
                non_repeaters: error_status,
                max_repetitions: error_index,
                variable_bindings,
            })),
            PduType::TrapV1 => {
                return Err(Error::Protocol(
                    "SNMPv1 Trap-PDU must be encoded via Pdu::to_v1_rasn / a v1 Message".into(),
                ));
            }
        };
        Ok(pdus)
    }

    /// Convert an SNMPv1 Trap-PDU into the `rasn-snmp::v1::Trap` body. The caller
    /// wraps this in a `rasn_snmp::v1::Message` for BER encoding.
    pub(crate) fn to_v1_rasn(&self) -> Result<v1::Trap> {
        let trap = self.v1_trap.as_ref().ok_or_else(|| {
            Error::Protocol("v1 Trap-PDU is missing its V1Trap payload".into())
        })?;
        let bindings = varbinds_to_v1(&self.variables)?;
        trap.to_rasn(bindings)
    }

    /// Build a PDU from a decoded `rasn-snmp` PDU choice (v2/v3 path).
    pub(crate) fn from_rasn(pdus: Pdus) -> Result<Pdu> {
        // Map the variant to (pdu_type, request_id, error_status/non_repeaters,
        // error_index/max_repetitions, bindings).
        let (pdu_type, request_id, status, index, bindings) = match pdus {
            Pdus::GetRequest(GetRequest(p)) => Self::from_std(PduType::Get, p),
            Pdus::GetNextRequest(GetNextRequest(p)) => Self::from_std(PduType::GetNext, p),
            Pdus::Response(Response(p)) => Self::from_std(PduType::Response, p),
            Pdus::SetRequest(SetRequest(p)) => Self::from_std(PduType::Set, p),
            Pdus::InformRequest(InformRequest(p)) => Self::from_std(PduType::Inform, p),
            Pdus::Trap(Trap(p)) => Self::from_std(PduType::TrapV2, p),
            Pdus::Report(Report(p)) => Self::from_std(PduType::Report, p),
            Pdus::GetBulkRequest(GetBulkRequest(b)) => (
                PduType::GetBulk,
                b.request_id,
                b.non_repeaters as i64,
                b.max_repetitions as i64,
                b.variable_bindings,
            ),
        };

        let variables = bindings
            .into_iter()
            .map(VarBind::from_rasn)
            .collect::<Result<Vec<_>>>()?;

        Ok(Pdu {
            pdu_type,
            request_id,
            error_status: status,
            error_index: index,
            variables,
            v1_trap: None,
        })
    }

    /// Build a v1 Trap-PDU from a decoded `rasn-snmp::v1::Trap` body.
    pub(crate) fn from_v1_rasn(trap: v1::Trap) -> Result<Pdu> {
        let (v1_trap, bindings) = V1Trap::from_rasn(trap)?;
        let variables = varbinds_from_v1(bindings)?;
        Ok(Pdu {
            pdu_type: PduType::TrapV1,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            variables,
            v1_trap: Some(v1_trap),
        })
    }

    /// Destructure a standard `rasn-snmp` PDU into the common decode tuple.
    fn from_std(
        pdu_type: PduType,
        p: RasnPdu,
    ) -> (PduType, i32, i64, i64, Vec<RasnVarBind>) {
        (
            pdu_type,
            p.request_id,
            p.error_status as i64,
            p.error_index as i64,
            p.variable_bindings,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pdu_roundtrip_through_rasn(pdu: &Pdu) -> Pdu {
        let pdus = pdu.to_rasn().unwrap();
        let bytes = rasn::ber::encode(&pdus).unwrap();
        let decoded: Pdus = rasn::ber::decode(&bytes).unwrap();
        Pdu::from_rasn(decoded).unwrap()
    }

    #[test]
    fn pdu_roundtrip() {
        let pdu = Pdu::new(PduType::Get, 0x1234)
            .with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap())
            .with_null_var("1.3.6.1.2.1.1.5.0".parse().unwrap());

        let decoded = pdu_roundtrip_through_rasn(&pdu);
        assert_eq!(decoded, pdu);
        assert_eq!(decoded.variables.len(), 2);
    }

    #[test]
    fn response_pdu_with_values() {
        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: 7,
            error_status: 0,
            error_index: 0,
            variables: vec![VarBind::new(
                "1.3.6.1.2.1.1.3.0".parse().unwrap(),
                Value::TimeTicks(123456),
            )],
            v1_trap: None,
        };
        assert_eq!(pdu_roundtrip_through_rasn(&pdu), pdu);
    }

    #[test]
    fn get_bulk_roundtrip_preserves_bulk_fields() {
        let mut pdu = Pdu::new(PduType::GetBulk, 42);
        pdu.error_status = 1; // non-repeaters
        pdu.error_index = 10; // max-repetitions
        pdu.variables
            .push(VarBind::null("1.3.6.1.2.1.2.2".parse().unwrap()));
        assert_eq!(pdu_roundtrip_through_rasn(&pdu), pdu);
    }

    #[test]
    fn error_status_roundtrip() {
        for code in 0..=18 {
            assert_eq!(ErrorStatus::from_code(code).code(), code);
        }
    }

    #[test]
    fn v1_trap_roundtrip_through_message() {
        // Encode a v1 Trap-PDU inside a v1 community message and decode it back,
        // exercising the v1 codec path in Message::encode/decode.
        let enterprise: Oid = "1.3.6.1.4.1.8072.2".parse().unwrap();
        let trap = V1Trap::new(
            enterprise.clone(),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            v1_generic_trap::ENTERPRISE_SPECIFIC,
            42,
            99,
        );
        let pdu = Pdu::new_v1_trap(
            trap,
            vec![VarBind::new(
                "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                Value::OctetString(b"host-a".to_vec()),
            )],
        );
        let msg = crate::message::Message::new(crate::message::Version::V1, b"public".to_vec(), pdu);
        let bytes = msg.encode().unwrap();
        let decoded = crate::message::Message::decode(&bytes).unwrap();
        assert_eq!(decoded.version, crate::message::Version::V1);
        assert_eq!(decoded.community, b"public");
        assert_eq!(decoded.pdu.pdu_type, PduType::TrapV1);
        let trap = decoded.pdu.v1_trap.expect("v1 trap payload");
        assert_eq!(trap.enterprise, enterprise);
        assert_eq!(trap.agent_addr, std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(trap.generic_trap, v1_generic_trap::ENTERPRISE_SPECIFIC);
        assert_eq!(trap.specific_trap, 42);
        assert_eq!(trap.time_stamp, 99);
        assert_eq!(decoded.pdu.variables.len(), 1);
        assert_eq!(
            decoded.pdu.variables[0].value,
            Value::OctetString(b"host-a".to_vec())
        );
    }

    #[test]
    fn v1_trap_matches_known_wire_bytes() {
        // The canonical v1 Trap-PDU from rasn-snmp's own test suite (RFC 1157
        // example): enterprise 1.3.6.1.4.1.11779.1.42.3.7.8, agent 10.11.12.13,
        // generic 6, specific 2, uptime 11932, two varbinds.
        #[rustfmt::skip]
        let known: [u8; 0x51] = [
            0x30, 0x4f,
                0x02, 0x01, 0x00,
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
                0xa4, 0x42,
                    0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xDC, 0x03, 0x01,
                              0x2a, 0x03, 0x07, 0x08,
                    0x40, 0x04, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x02, 0x01, 0x06,
                    0x02, 0x01, 0x02,
                    0x43, 0x02, 0x2e, 0x9c,
                    0x30, 0x22,
                        0x30, 0x0d,
                            0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03,
                            0x43, 0x02, 0x2e, 0x9c,
                        0x30, 0x11,
                            0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xDC, 0x03,
                                      0x01, 0x2a, 0x02, 0x01, 0x07,
                            0x42, 0x01, 0x01,
        ];
        let decoded = crate::message::Message::decode(&known).unwrap();
        assert_eq!(decoded.pdu.pdu_type, PduType::TrapV1);
        let trap = decoded.pdu.v1_trap.as_ref().unwrap();
        assert_eq!(trap.enterprise.to_string(), ".1.3.6.1.4.1.11779.1.42.3.7.8");
        assert_eq!(trap.agent_addr, std::net::Ipv4Addr::new(10, 11, 12, 13));
        assert_eq!(trap.generic_trap, 6);
        assert_eq!(trap.specific_trap, 2);
        assert_eq!(trap.time_stamp, 11_932);
        assert_eq!(decoded.pdu.variables.len(), 2);
        // Re-encoding yields identical bytes (round-trip stability).
        let reencoded = decoded.encode().unwrap();
        assert_eq!(reencoded, known);
    }
}
