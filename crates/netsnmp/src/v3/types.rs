//! The SNMPv3 wire types: header, USM security parameters, ScopedPDU, engine
//! parameters, and the fully parsed message.
//!
//! These are the crate's stable domain types; their wire (de)serialization maps
//! onto the `rasn-snmp` v3 message types ([`rasn_snmp::v3`]).

use crate::convert::{int_to_i64, int_to_u32, octet_string};
use crate::error::Result;
use crate::pdu::Pdu;

use rasn::types::Integer;
use rasn_snmp::v3::{
    HeaderData as RHeaderData, ScopedPdu as RScopedPdu, USMSecurityParameters as RUsmParameters,
};

/// The SNMPv3 message version field value.
pub const VERSION_V3: i64 = 3;

/// The USM security model number.
pub const SECURITY_MODEL_USM: i64 = 3;

/// Default `msgMaxSize` advertised by this implementation.
pub const DEFAULT_MAX_SIZE: i64 = 65507;

/// `msgFlags` bit: authentication applied.
pub(super) const FLAG_AUTH: u8 = 0x01;
/// `msgFlags` bit: privacy applied.
pub(super) const FLAG_PRIV: u8 = 0x02;
/// `msgFlags` bit: a Report PDU is expected on error.
pub(super) const FLAG_REPORTABLE: u8 = 0x04;

/// The `msgGlobalData` (HeaderData) of an SNMPv3 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderData {
    /// `msgID`, used to correlate requests and responses at the v3 layer.
    pub msg_id: i32,
    /// `msgMaxSize`, the largest response the sender can accept.
    pub max_size: i32,
    /// `msgFlags` (auth/priv/reportable bits).
    pub flags: u8,
    /// `msgSecurityModel` (3 = USM).
    pub security_model: i32,
}

impl HeaderData {
    /// Convert into the `rasn-snmp` header type.
    pub(super) fn to_rasn(&self) -> RHeaderData {
        RHeaderData {
            message_id: Integer::from(self.msg_id),
            max_size: Integer::from(self.max_size),
            flags: octet_string(&[self.flags]),
            security_model: Integer::from(self.security_model),
        }
    }

    /// Build from a decoded `rasn-snmp` header.
    pub(super) fn from_rasn(h: &RHeaderData) -> Result<Self> {
        Ok(HeaderData {
            msg_id: int_to_i64(&h.message_id)? as i32,
            max_size: int_to_i64(&h.max_size)? as i32,
            flags: h.flags.first().copied().unwrap_or(0),
            security_model: int_to_i64(&h.security_model)? as i32,
        })
    }
}

/// The USM `msgSecurityParameters`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UsmSecurityParameters {
    /// `msgAuthoritativeEngineID`.
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`.
    pub engine_boots: u32,
    /// `msgAuthoritativeEngineTime`.
    pub engine_time: u32,
    /// `msgUserName`.
    pub user_name: Vec<u8>,
    /// `msgAuthenticationParameters` (the truncated HMAC, or empty).
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters` (the privacy salt, or empty).
    pub priv_params: Vec<u8>,
}

impl UsmSecurityParameters {
    /// Convert into the `rasn-snmp` USM parameters.
    pub(super) fn to_rasn(&self) -> RUsmParameters {
        RUsmParameters {
            authoritative_engine_id: octet_string(&self.engine_id),
            authoritative_engine_boots: Integer::from(self.engine_boots),
            authoritative_engine_time: Integer::from(self.engine_time),
            user_name: octet_string(&self.user_name),
            authentication_parameters: octet_string(&self.auth_params),
            privacy_parameters: octet_string(&self.priv_params),
        }
    }

    /// Build from decoded `rasn-snmp` USM parameters.
    pub(super) fn from_rasn(p: &RUsmParameters) -> Result<Self> {
        Ok(UsmSecurityParameters {
            engine_id: p.authoritative_engine_id.to_vec(),
            engine_boots: int_to_u32(&p.authoritative_engine_boots)?,
            engine_time: int_to_u32(&p.authoritative_engine_time)?,
            user_name: p.user_name.to_vec(),
            auth_params: p.authentication_parameters.to_vec(),
            priv_params: p.privacy_parameters.to_vec(),
        })
    }

    /// BER-encode the USM SEQUENCE (the content of `msgSecurityParameters`).
    pub(super) fn to_ber(&self) -> Result<Vec<u8>> {
        Ok(rasn::ber::encode(&self.to_rasn())?)
    }

    /// Decode the USM SEQUENCE from `bytes`.
    pub(super) fn decode_ber(bytes: &[u8]) -> Result<Self> {
        Self::from_rasn(&rasn::ber::decode::<RUsmParameters>(bytes)?)
    }
}

/// A ScopedPDU: the context plus the carried PDU.
#[derive(Clone, Debug, PartialEq)]
pub struct ScopedPdu {
    /// `contextEngineID`.
    pub context_engine_id: Vec<u8>,
    /// `contextName`.
    pub context_name: Vec<u8>,
    /// The carried PDU.
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// Create a ScopedPDU for the given context and PDU.
    pub fn new(context_engine_id: Vec<u8>, context_name: Vec<u8>, pdu: Pdu) -> Self {
        ScopedPdu {
            context_engine_id,
            context_name,
            pdu,
        }
    }

    /// Convert into the `rasn-snmp` ScopedPDU.
    pub(super) fn to_rasn(&self) -> Result<RScopedPdu> {
        Ok(RScopedPdu {
            engine_id: octet_string(&self.context_engine_id),
            name: octet_string(&self.context_name),
            data: self.pdu.to_rasn()?,
        })
    }

    /// Build from a decoded `rasn-snmp` ScopedPDU.
    pub(super) fn from_rasn(s: RScopedPdu) -> Result<Self> {
        Ok(ScopedPdu {
            context_engine_id: s.engine_id.to_vec(),
            context_name: s.name.to_vec(),
            pdu: Pdu::from_rasn(s.data)?,
        })
    }

    /// BER-encode the ScopedPDU SEQUENCE.
    pub(super) fn to_ber(&self) -> Result<Vec<u8>> {
        Ok(rasn::ber::encode(&self.to_rasn()?)?)
    }

    /// Decode a ScopedPDU SEQUENCE from its full BER TLV `bytes`.
    pub(super) fn decode_ber(bytes: &[u8]) -> Result<Self> {
        Self::from_rasn(rasn::ber::decode::<RScopedPdu>(bytes)?)
    }
}

/// The authoritative engine parameters used when building authenticated/
/// encrypted messages (learned via discovery).
#[derive(Clone, Debug, Default)]
pub struct EngineParams {
    /// The authoritative `engineID`.
    pub engine_id: Vec<u8>,
    /// The authoritative `engineBoots`.
    pub engine_boots: u32,
    /// The authoritative `engineTime`.
    pub engine_time: u32,
}

impl EngineParams {
    /// The `engineID` rendered as a lowercase hex string (no separators), the
    /// conventional form for logging and display.
    pub fn engine_id_hex(&self) -> String {
        use itertools::Itertools;
        self.engine_id
            .iter()
            .format_with("", |b, g| g(&format_args!("{b:02x}")))
            .to_string()
    }
}

/// A fully parsed (and, if applicable, verified + decrypted) SNMPv3 message.
#[derive(Clone, Debug)]
pub struct V3Message {
    /// The message header.
    pub header: HeaderData,
    /// The USM security parameters.
    pub usm: UsmSecurityParameters,
    /// The recovered ScopedPDU.
    pub scoped: ScopedPdu,
}

impl V3Message {
    /// True when the report-PDU-expected flag was set.
    pub fn reportable(&self) -> bool {
        self.header.flags & FLAG_REPORTABLE != 0
    }
}
