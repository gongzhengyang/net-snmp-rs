//! SNMP message framing for v1 and v2c (community-based models).
//!
//! Corresponds to the outermost message assembly/parse in `snmp_api.c`
//! (`snmp_build` / `snmp_parse`). SNMPv3's USM message format is intentionally
//! out of scope for this core layer; see `docs` in the workspace README.

use crate::convert::int_to_i64;
use crate::error::{Error, Result};
use crate::pdu::Pdu;
use rasn::types::Integer;
use rasn_snmp::v2::Pdus;
use rasn_snmp::v2c::Message as CommunityMessage;

/// Supported SNMP protocol versions (community-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// SNMPv1 (RFC 1157), wire value 0.
    V1,
    /// SNMPv2c (RFC 1901), wire value 1.
    V2c,
}

impl Version {
    /// The integer encoded in the message `version` field.
    pub fn code(self) -> i64 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
        }
    }

    /// Parse from the message `version` field.
    pub fn from_code(code: i64) -> Result<Version> {
        match code {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2c),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

/// A complete community-based SNMP message: version + community + PDU.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// Protocol version.
    pub version: Version,
    /// The community string (acts as a shared secret/identifier).
    pub community: Vec<u8>,
    /// The carried PDU.
    pub pdu: Pdu,
}

impl Message {
    /// Construct a message.
    pub fn new(version: Version, community: impl Into<Vec<u8>>, pdu: Pdu) -> Self {
        Message {
            version,
            community: community.into(),
            pdu,
        }
    }

    /// Serialize the whole message to BER bytes ready for the transport.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // SNMPv1 and SNMPv2c share the same outer envelope (version, community,
        // PDU); only the version integer differs. The PDU choice covers both.
        let message = CommunityMessage {
            version: Integer::from(self.version.code()),
            community: crate::convert::octet_string(&self.community),
            data: self.pdu.to_rasn()?,
        };
        Ok(rasn::ber::encode(&message)?)
    }

    /// Parse a message from raw BER bytes received from the transport.
    pub fn decode(bytes: &[u8]) -> Result<Message> {
        let message: CommunityMessage<Pdus> = rasn::ber::decode(bytes)?;
        let version = Version::from_code(int_to_i64(&message.version)?)?;
        let community = message.community.to_vec();
        let pdu = Pdu::from_rasn(message.data)?;
        Ok(Message {
            version,
            community,
            pdu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Pdu, PduType};
    use crate::value::Value;

    #[test]
    fn message_roundtrip_v2c() {
        let pdu = Pdu::new(PduType::Get, 999).with_null_var("1.3.6.1.2.1.1.1.0".parse().unwrap());
        let msg = Message::new(Version::V2c, b"public".to_vec(), pdu);

        let bytes = msg.encode().unwrap();
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.community, b"public");
    }

    #[test]
    fn message_roundtrip_v1_response() {
        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variables: vec![crate::pdu::VarBind::new(
                "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                Value::OctetString(b"router1".to_vec()),
            )],
        };
        let msg = Message::new(Version::V1, b"private".to_vec(), pdu);
        let bytes = msg.encode().unwrap();
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn rejects_unknown_version() {
        // A structurally valid community message but with version = 3.
        let message = CommunityMessage {
            version: Integer::from(3),
            community: crate::convert::octet_string(b"x"),
            data: Pdu::new(PduType::Get, 1)
                .with_null_var("1.3.6.1".parse().unwrap())
                .to_rasn()
                .unwrap(),
        };
        let bytes = rasn::ber::encode(&message).unwrap();
        let err = Message::decode(&bytes).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(3)));
    }
}
