//! Protocol Data Units (PDUs) and variable bindings.
//!
//! Rust counterpart of the PDU structures in `snmp.h` / `snmp_api.c` and the
//! request/response processing in `snmp_client.c`.

use crate::convert::{oid_from_rasn, oid_to_rasn};
use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::value::Value;
use rasn_snmp::v2::{
    BulkPdu, GetBulkRequest, GetNextRequest, GetRequest, InformRequest, Pdu as RasnPdu, Pdus,
    Report, Response, SetRequest, Trap, VarBind as RasnVarBind,
};
use std::fmt;

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
    /// Returns [`Error::Protocol`] for the legacy SNMPv1 Trap-PDU, which has a
    /// distinct structure and is intentionally not built here (matching the
    /// crate's v2c/v3 focus).
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
                    "SNMPv1 Trap-PDU encoding is not supported".into(),
                ));
            }
        };
        Ok(pdus)
    }

    /// Build a PDU from a decoded `rasn-snmp` PDU choice.
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
}
