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
use rasn_snmp::v1;

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
    ///
    /// SNMPv1 and SNMPv2c share the same outer envelope (version, community,
    /// PDU). The PDU choice differs: every PDU except the legacy SNMPv1 Trap-PDU
    /// uses the `rasn-snmp::v2` choice; a v1 Trap-PDU uses the structurally
    /// distinct `rasn-snmp::v1::Trap`. Both are wrapped in their respective
    /// `Message` envelope, which share the identical outer SEQUENCE form so the
    /// wire bytes are interchangeable between v1 and v2c peers for the non-trap
    /// PDUs.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.version == Version::V1 && self.pdu.pdu_type == crate::pdu::PduType::TrapV1 {
            // v1 Trap-PDU: distinct structure, encoded via the v1 codec.
            let message = v1::Message {
                version: Integer::from(self.version.code()),
                community: crate::convert::octet_string(&self.community),
                data: self.pdu.to_v1_rasn()?,
            };
            return Ok(rasn::ber::encode(&message)?);
        }
        let message = CommunityMessage {
            version: Integer::from(self.version.code()),
            community: crate::convert::octet_string(&self.community),
            data: self.pdu.to_rasn()?,
        };
        Ok(rasn::ber::encode(&message)?)
    }

    /// Parse a message from raw BER bytes received from the transport.
    ///
    /// The message is decoded as the v2 community form first; if the PDU tag is
    /// the SNMPv1 Trap-PDU tag (`0xA4`) — which the v2 `Pdus` choice cannot
    /// represent — it is re-decoded through the v1 codec so the structured trap
    /// fields are recovered. This mirrors upstream `snmp_parse`, which handles
    /// both shapes transparently for community messages.
    pub fn decode(bytes: &[u8]) -> Result<Message> {
        // Detect the v1 Trap-PDU by peeking at the PDU tag inside the message
        // SEQUENCE. The tag sits after version + community; rather than hand-
        // parse, attempt the v2 codec and fall back to v1 on the choice error.
        let v2_result: std::result::Result<CommunityMessage<Pdus>, _> =
            rasn::ber::decode(bytes);
        match v2_result {
            Ok(message) => {
                let version = Version::from_code(int_to_i64(&message.version)?)?;
                let community = message.community.to_vec();
                let pdu = Pdu::from_rasn(message.data)?;
                Ok(Message {
                    version,
                    community,
                    pdu,
                })
            }
            Err(_) => {
                // Fall back to the v1 codec, which is only reached for the v1
                // Trap-PDU tag (0xA4) — the one PDU the v2 `Pdus` choice cannot
                // represent. Every other v1 PDU shares a tag with its v2 form
                // and is decoded successfully by the v2 path above.
                let message: v1::Message<v1::Trap> = rasn::ber::decode(bytes)?;
                let version = Version::from_code(int_to_i64(&message.version)?)?;
                let community = message.community.to_vec();
                let pdu = Pdu::from_v1_rasn(message.data)?;
                Ok(Message {
                    version,
                    community,
                    pdu,
                })
            }
        }
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
            v1_trap: None,
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
