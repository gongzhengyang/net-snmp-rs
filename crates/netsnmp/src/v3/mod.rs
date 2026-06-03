//! SNMPv3 message processing (RFC 3412) over the User-based Security Model.
//!
//! Rust counterpart of `snmplib/snmpv3.c` (and the v3 message paths in
//! `snmp_api.c`). It assembles and parses the v3 message envelope:
//!
//! ```text
//! SNMPv3Message ::= SEQUENCE {
//!     msgVersion              INTEGER (3),
//!     msgGlobalData           HeaderData,
//!     msgSecurityParameters   OCTET STRING,   -- USM SEQUENCE, below
//!     msgData                 ScopedPduData    -- plaintext or encrypted
//! }
//! ```
//!
//! Authentication and privacy are performed by [`crate::usm`]. The HMAC is
//! handled per RFC 3414 §6.3: the message is serialized with a zeroed
//! authentication-parameters placeholder, the digest is computed over those
//! bytes, and the real HMAC is written back ([`build`](mod@self::build)); the
//! receiver re-emits the message with the field zeroed to verify
//! ([`parse`](mod@self::parse)). The domain wire types live in
//! [`types`](mod@self::types); the raw `rasn` envelope (whose `msgData` stays an
//! opaque payload until authenticated) lives in [`wire`](mod@self::wire).

mod build;
mod parse;
mod types;
mod wire;

pub use build::{UsmStat, build_discovery, build_report, build_request, build_response};
pub use parse::{parse, peek_security};
pub use types::{
    DEFAULT_MAX_SIZE, EngineParams, HeaderData, SECURITY_MODEL_USM, ScopedPdu,
    UsmSecurityParameters, V3Message, VERSION_V3,
};

#[cfg(test)]
mod tests {
    use super::types::{FLAG_AUTH, FLAG_PRIV};
    use super::*;
    use crate::error::Error;
    use crate::oid::Oid;
    use crate::pdu::{Pdu, PduType};
    use crate::usm::{AuthProtocol, PrivProtocol, UsmUser};
    use crate::value::Value;

    fn sample_pdu() -> Pdu {
        Pdu::new(PduType::Get, 0x0BAD).with_null_var("1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap())
    }

    fn engine() -> EngineParams {
        EngineParams {
            engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0x01],
            engine_boots: 5,
            engine_time: 1234,
        }
    }

    #[test]
    fn scoped_pdu_roundtrip() {
        let scoped = ScopedPdu::new(b"engine".to_vec(), b"ctx".to_vec(), sample_pdu());
        let bytes = scoped.to_ber().unwrap();
        assert_eq!(ScopedPdu::decode_ber(&bytes).unwrap(), scoped);
    }

    #[test]
    fn usm_params_roundtrip() {
        let usm = UsmSecurityParameters {
            engine_id: vec![1, 2, 3, 4],
            engine_boots: 7,
            engine_time: 99,
            user_name: b"alice".to_vec(),
            auth_params: vec![0u8; 12],
            priv_params: vec![9u8; 8],
        };
        let bytes = usm.to_ber().unwrap();
        assert_eq!(UsmSecurityParameters::decode_ber(&bytes).unwrap(), usm);
    }

    #[test]
    fn discovery_message_parses() {
        let bytes = build_discovery(42, 1).unwrap();
        let msg = parse(&bytes, None).unwrap();
        assert_eq!(msg.header.msg_id, 42);
        assert!(msg.reportable());
        assert!(msg.usm.engine_id.is_empty());
    }

    #[test]
    fn auth_no_priv_roundtrip() {
        let user = UsmUser::auth("bob", AuthProtocol::HmacSha1, "authpassword");
        let bytes = build_request(7, &user, &engine(), &[], sample_pdu()).unwrap();
        let msg = parse(&bytes, Some(&user)).unwrap();
        assert_eq!(msg.scoped.pdu, sample_pdu());
        assert_eq!(msg.header.flags & FLAG_AUTH, FLAG_AUTH);
        assert_eq!(msg.header.flags & FLAG_PRIV, 0);
    }

    #[test]
    fn auth_priv_roundtrip() {
        let user = UsmUser::auth_priv(
            "carol",
            AuthProtocol::HmacSha256,
            "authpassword",
            PrivProtocol::AesCfb128,
            "privpassword",
        );
        let pdu = Pdu::new(PduType::Response, 55).with_var(
            "1.3.6.1.2.1.1.5.0".parse::<Oid>().unwrap(),
            Value::OctetString(b"host-a".to_vec()),
        );
        let bytes = build_request(8, &user, &engine(), &[], pdu.clone()).unwrap();
        let msg = parse(&bytes, Some(&user)).unwrap();
        assert_eq!(msg.scoped.pdu, pdu);
        assert_eq!(msg.header.flags & FLAG_PRIV, FLAG_PRIV);
    }

    #[test]
    fn tampered_auth_is_rejected() {
        let user = UsmUser::auth("dave", AuthProtocol::HmacMd5, "authpassword");
        let mut bytes = build_request(9, &user, &engine(), &[], sample_pdu()).unwrap();
        // Flip a byte in the (plaintext) scoped PDU region near the end.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let err = parse(&bytes, Some(&user)).unwrap_err();
        assert!(matches!(err, Error::AuthFailure(_)), "got {err:?}");
    }

    #[test]
    fn wrong_password_fails_verification() {
        let sender = UsmUser::auth("erin", AuthProtocol::HmacSha1, "correct-password");
        let bytes = build_request(10, &sender, &engine(), &[], sample_pdu()).unwrap();
        let attacker = UsmUser::auth("erin", AuthProtocol::HmacSha1, "wrong-password");
        let err = parse(&bytes, Some(&attacker)).unwrap_err();
        assert!(matches!(err, Error::AuthFailure(_)));
    }
}
