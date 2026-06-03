//! The raw SNMPv3 message envelope used for assembly and verification.
//!
//! This mirrors [`rasn_snmp::v3::Message`] but captures the `msgData` field as a
//! raw [`Any`] rather than a typed `ScopedPduData`. Keeping the scoped payload
//! as opaque bytes lets us:
//!
//! * authenticate the message before parsing (or decrypting) attacker-supplied
//!   payload contents, and
//! * hash and re-emit the exact payload bytes, so HMAC verification does not
//!   depend on re-encoding the (already authenticated) ScopedPDU identically.
//!
//! Only the small, canonically-encoded envelope fields (version, header, and
//! the USM parameters octet string) are produced by `rasn`'s BER encoder.

use rasn::types::{Any, Integer, OctetString};
use rasn::{AsnType, Decode, Decoder, Encode};
use rasn_snmp::v3::HeaderData as RHeaderData;

/// The SNMPv3 message envelope with an opaque `msgData` payload.
#[derive(AsnType, Decode, Encode, Clone, Debug)]
pub(super) struct RawV3Message {
    /// `msgVersion` (always 3 here).
    pub version: Integer,
    /// `msgGlobalData`.
    pub global_data: RHeaderData,
    /// `msgSecurityParameters` (the BER of the USM parameters).
    pub security_parameters: OctetString,
    /// `msgData`: the cleartext ScopedPDU SEQUENCE or the encrypted OCTET STRING,
    /// captured verbatim as its raw BER TLV.
    pub scoped_data: Any,
}
