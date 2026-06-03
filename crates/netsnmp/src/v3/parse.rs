//! Parsing SNMPv3 messages: peeking the security parameters and the full
//! verify-and-decrypt path.

use rasn::types::{Any, Integer, OctetString};

use crate::convert::{int_to_i64, octet_string};
use crate::error::{Error, Result};
use crate::usm::UsmUser;

use super::types::{
    FLAG_AUTH, FLAG_PRIV, HeaderData, ScopedPdu, UsmSecurityParameters, V3Message, VERSION_V3,
};
use super::wire::RawV3Message;

/// Peek at an SNMPv3 message's header and USM security parameters without
/// verifying authentication or decrypting. Used by the agent to look up the
/// named user (and detect engine discovery) before full processing.
///
/// Returns [`Error::UnsupportedVersion`] for non-v3 messages, which callers can
/// use to dispatch community (v1/v2c) messages down a different path.
pub fn peek_security(bytes: &[u8]) -> Result<(HeaderData, UsmSecurityParameters)> {
    // Read the leading `msgVersion` first — it occupies the same position in
    // SNMPv1/v2c and v3 — so community messages can be rejected with
    // `UnsupportedVersion` (and routed elsewhere) before committing to the v3
    // envelope layout.
    let version = message_version(bytes)?;
    if version != VERSION_V3 {
        return Err(Error::UnsupportedVersion(version));
    }
    let raw = rasn::ber::decode::<RawV3Message>(bytes)?;
    let header = HeaderData::from_rasn(&raw.global_data)?;
    let usm = UsmSecurityParameters::decode_ber(&raw.security_parameters)?;
    Ok((header, usm))
}

/// Read the `msgVersion` integer that leads any SNMP message SEQUENCE, by
/// decoding the outer SEQUENCE as a list of raw elements and parsing the first.
fn message_version(bytes: &[u8]) -> Result<i64> {
    let elements = rasn::ber::decode::<Vec<Any>>(bytes)?;
    let first = elements
        .first()
        .ok_or_else(|| Error::Protocol("empty SNMP message".into()))?;
    let version = rasn::ber::decode::<Integer>(first.as_bytes())?;
    int_to_i64(&version)
}

/// Parse an SNMPv3 message. When `user` is provided and the message is
/// authenticated, the HMAC is verified; when encrypted, the ScopedPDU is
/// decrypted. Discovery responses (Report PDUs) are typically `noAuthNoPriv`
/// and parse without a user.
pub fn parse(bytes: &[u8], user: Option<&UsmUser>) -> Result<V3Message> {
    let raw = rasn::ber::decode::<RawV3Message>(bytes)?;
    let version = int_to_i64(&raw.version)?;
    if version != VERSION_V3 {
        return Err(Error::UnsupportedVersion(version));
    }
    let header = HeaderData::from_rasn(&raw.global_data)?;
    let usm = UsmSecurityParameters::decode_ber(&raw.security_parameters)?;

    // Verify authentication (over the message with the auth parameters zeroed)
    // before trusting — or decrypting — the payload.
    if header.flags & FLAG_AUTH != 0 {
        let user =
            user.ok_or_else(|| Error::AuthFailure("authenticated message but no user".into()))?;
        let (auth_proto, _) = user
            .auth
            .as_ref()
            .ok_or_else(|| Error::AuthFailure("user has no auth protocol".into()))?;
        let auth_key = user
            .auth_key(&usm.engine_id)
            .ok_or_else(|| Error::AuthFailure("could not derive auth key".into()))?;
        let n = auth_proto.mac_len();
        if usm.auth_params.len() != n {
            return Err(Error::AuthFailure("malformed auth parameters".into()));
        }

        // Re-emit the message with zeroed auth parameters. Only the small,
        // canonically-encoded envelope fields are re-encoded; the (verbatim)
        // scoped payload bytes are preserved, so the digest input matches the
        // sender's regardless of the payload's exact encoding.
        let mut usm_zeroed = usm.clone();
        usm_zeroed.auth_params = vec![0u8; n];
        let zeroed = RawV3Message {
            version: raw.version.clone(),
            global_data: raw.global_data.clone(),
            security_parameters: octet_string(&usm_zeroed.to_ber()?),
            scoped_data: raw.scoped_data.clone(),
        };
        let to_hash = rasn::ber::encode(&zeroed)?;
        if !auth_proto.verify(&auth_key, &to_hash, &usm.auth_params) {
            return Err(Error::AuthFailure("HMAC mismatch".into()));
        }
    }

    // Recover the ScopedPDU (decrypting first when the priv flag is set).
    let scoped = if header.flags & FLAG_PRIV != 0 {
        let ct = rasn::ber::decode::<OctetString>(raw.scoped_data.as_bytes())?;
        let user =
            user.ok_or_else(|| Error::PrivFailure("encrypted message but no user".into()))?;
        let (priv_proto, _) = user
            .priv_
            .as_ref()
            .ok_or_else(|| Error::PrivFailure("user has no privacy protocol".into()))?;
        let priv_key = user
            .priv_key(&usm.engine_id)
            .ok_or_else(|| Error::PrivFailure("could not derive privacy key".into()))?;
        let plaintext = priv_proto.decrypt(
            &priv_key,
            usm.engine_boots,
            usm.engine_time,
            &usm.priv_params,
            ct.as_ref(),
        )?;
        ScopedPdu::decode_ber(&plaintext)?
    } else {
        ScopedPdu::decode_ber(raw.scoped_data.as_bytes())?
    };

    Ok(V3Message {
        header,
        usm,
        scoped,
    })
}
