//! Building SNMPv3 messages: discovery, request/response, and USM Report PDUs,
//! plus the low-level assembler that splices the HMAC into the serialized
//! envelope.

use rasn::types::{Any, Integer};

use crate::convert::octet_string;
use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, VarBind};
use crate::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use crate::value::Value;

use super::types::{
    DEFAULT_MAX_SIZE, EngineParams, FLAG_AUTH, FLAG_PRIV, FLAG_REPORTABLE, HeaderData,
    SECURITY_MODEL_USM, ScopedPdu, UsmSecurityParameters, VERSION_V3,
};
use super::wire::RawV3Message;

/// The base of the `usmStats` counter subtree (RFC 3414): `1.3.6.1.6.3.15.1.1`.
const USM_STATS_PREFIX: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1];

/// USM error counters reported back to a peer via a Report PDU (RFC 3414 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsmStat {
    /// `usmStatsUnsupportedSecLevels`.
    UnsupportedSecLevels,
    /// `usmStatsNotInTimeWindows`.
    NotInTimeWindows,
    /// `usmStatsUnknownUserNames`.
    UnknownUserNames,
    /// `usmStatsUnknownEngineIDs` (also used as the discovery response).
    UnknownEngineIDs,
    /// `usmStatsWrongDigests`.
    WrongDigests,
    /// `usmStatsDecryptionErrors`.
    DecryptionErrors,
}

impl UsmStat {
    /// The trailing sub-identifier of the counter object under `usmStats`.
    fn subid(self) -> u32 {
        match self {
            UsmStat::UnsupportedSecLevels => 1,
            UsmStat::NotInTimeWindows => 2,
            UsmStat::UnknownUserNames => 3,
            UsmStat::UnknownEngineIDs => 4,
            UsmStat::WrongDigests => 5,
            UsmStat::DecryptionErrors => 6,
        }
    }

    /// The full counter instance OID, e.g. `1.3.6.1.6.3.15.1.1.4.0`.
    fn oid(self) -> Oid {
        let mut parts = USM_STATS_PREFIX.to_vec();
        parts.push(self.subid());
        parts.push(0);
        Oid::new(parts)
    }
}

/// Build a discovery message: a `noAuthNoPriv` GET with an empty engine id and
/// user name, used to learn the remote's authoritative engine id / boots / time
/// (RFC 3414 §4). The peer responds with a Report PDU.
pub fn build_discovery(msg_id: i32, request_id: i32) -> Result<Vec<u8>> {
    let scoped = ScopedPdu::new(Vec::new(), Vec::new(), Pdu::new(PduType::Get, request_id));
    let usm = UsmSecurityParameters::default();
    let header = HeaderData {
        msg_id,
        max_size: DEFAULT_MAX_SIZE as i32,
        flags: FLAG_REPORTABLE,
        security_model: SECURITY_MODEL_USM as i32,
    };
    assemble(&header, &usm, Any::new(scoped.to_ber()?), None)
}

/// Build a request message for `user` at its configured security level, against
/// the discovered `engine`.
///
/// * `noAuthNoPriv` — neither auth nor priv applied.
/// * `authNoPriv`   — HMAC spliced over the whole message.
/// * `authPriv`     — ScopedPDU encrypted, then the message authenticated.
pub fn build_request(
    msg_id: i32,
    user: &UsmUser,
    engine: &EngineParams,
    context_engine_id: &[u8],
    pdu: Pdu,
) -> Result<Vec<u8>> {
    build_user_message(msg_id, true, user, engine, context_engine_id, pdu)
}

/// Build a response message for `user` against the authoritative `engine`. Same
/// as [`build_request`] but with the reportable flag cleared (responses do not
/// solicit Reports). Used by the agent (authoritative) side.
pub fn build_response(
    msg_id: i32,
    user: &UsmUser,
    engine: &EngineParams,
    context_engine_id: &[u8],
    pdu: Pdu,
) -> Result<Vec<u8>> {
    build_user_message(msg_id, false, user, engine, context_engine_id, pdu)
}

/// Build a USM Report message carrying a `usmStats` counter (RFC 3414 §3.2).
///
/// Engine-discovery and unknown-user reports are sent `noAuthNoPriv` (the peer
/// cannot or need not verify them); `notInTimeWindow` / decryption reports are
/// sent `authNoPriv` when `user` carries authentication credentials, so the
/// peer trusts the corrected engine time. `count` is the current counter value.
pub fn build_report(
    msg_id: i32,
    user: Option<&UsmUser>,
    engine: &EngineParams,
    stat: UsmStat,
    count: u32,
    request_id: i32,
) -> Result<Vec<u8>> {
    let mut pdu = Pdu::new(PduType::Report, request_id);
    pdu.variables
        .push(VarBind::new(stat.oid(), Value::Counter32(count)));

    match user {
        Some(u) if u.security_level().has_auth() => {
            let (proto, _) = u.auth.as_ref().unwrap();
            let key = u
                .auth_key(&engine.engine_id)
                .ok_or_else(|| Error::AuthFailure("could not derive auth key".into()))?;
            build_message(
                msg_id,
                false,
                SecurityLevel::AuthNoPriv,
                u.name.as_bytes(),
                engine,
                &engine.engine_id,
                Some((*proto, key)),
                None,
                pdu,
            )
        }
        _ => build_message(
            msg_id,
            false,
            SecurityLevel::NoAuthNoPriv,
            &[],
            engine,
            &engine.engine_id,
            None,
            None,
            pdu,
        ),
    }
}

/// Build a request/response message for `user`, sharing the auth/priv key
/// derivation between [`build_request`] and [`build_response`].
fn build_user_message(
    msg_id: i32,
    reportable: bool,
    user: &UsmUser,
    engine: &EngineParams,
    context_engine_id: &[u8],
    pdu: Pdu,
) -> Result<Vec<u8>> {
    let level = user.security_level();
    let auth = if level.has_auth() {
        let (proto, _) = user
            .auth
            .as_ref()
            .ok_or_else(|| Error::AuthFailure("auth requested but unconfigured".into()))?;
        let key = user
            .auth_key(&engine.engine_id)
            .ok_or_else(|| Error::AuthFailure("could not derive auth key".into()))?;
        Some((*proto, key))
    } else {
        None
    };
    let priv_ = if level.has_priv() {
        let (proto, _) = user
            .priv_
            .as_ref()
            .ok_or_else(|| Error::PrivFailure("privacy requested but unconfigured".into()))?;
        let key = user
            .priv_key(&engine.engine_id)
            .ok_or_else(|| Error::PrivFailure("could not derive privacy key".into()))?;
        Some((*proto, key))
    } else {
        None
    };
    build_message(
        msg_id,
        reportable,
        level,
        user.name.as_bytes(),
        engine,
        context_engine_id,
        auth,
        priv_,
        pdu,
    )
}

/// The low-level message builder shared by requests, responses and reports.
/// Encrypts the ScopedPDU when `level` requires privacy, reserves and splices
/// the HMAC when it requires authentication, and frames the v3 envelope.
#[allow(clippy::too_many_arguments)]
fn build_message(
    msg_id: i32,
    reportable: bool,
    level: SecurityLevel,
    user_name: &[u8],
    engine: &EngineParams,
    context_engine_id: &[u8],
    auth: Option<(AuthProtocol, Vec<u8>)>,
    priv_: Option<(PrivProtocol, Vec<u8>)>,
    pdu: Pdu,
) -> Result<Vec<u8>> {
    let ctx_engine = if context_engine_id.is_empty() {
        engine.engine_id.clone()
    } else {
        context_engine_id.to_vec()
    };
    let scoped = ScopedPdu::new(ctx_engine, Vec::new(), pdu);
    let scoped_bytes = scoped.to_ber()?;

    let mut flags = if reportable { FLAG_REPORTABLE } else { 0 };
    if level.has_auth() {
        flags |= FLAG_AUTH;
    }
    if level.has_priv() {
        flags |= FLAG_PRIV;
    }

    // Privacy: encrypt the ScopedPDU and carry the salt in msgPrivacyParameters.
    // The `msgData` field is the encrypted ScopedPDU wrapped in an OCTET STRING,
    // or the cleartext ScopedPDU SEQUENCE — captured here as its raw BER TLV.
    let (scoped_data, priv_params) = if level.has_priv() {
        let (priv_proto, priv_key) = priv_
            .as_ref()
            .ok_or_else(|| Error::PrivFailure("privacy requested but unconfigured".into()))?;
        let salt: [u8; 8] = rand::random();
        let ct = priv_proto.encrypt(
            priv_key,
            engine.engine_boots,
            engine.engine_time,
            &salt,
            &scoped_bytes,
        )?;
        let ct_tlv = rasn::ber::encode(&octet_string(&ct))?;
        (Any::new(ct_tlv), salt.to_vec())
    } else {
        (Any::new(scoped_bytes), Vec::new())
    };

    // Authentication: reserve a zeroed placeholder of the right length.
    let auth_placeholder = if level.has_auth() {
        let (auth_proto, _) = auth
            .as_ref()
            .ok_or_else(|| Error::AuthFailure("auth requested but unconfigured".into()))?;
        vec![0u8; auth_proto.mac_len()]
    } else {
        Vec::new()
    };

    let usm = UsmSecurityParameters {
        engine_id: engine.engine_id.clone(),
        engine_boots: engine.engine_boots,
        engine_time: engine.engine_time,
        user_name: user_name.to_vec(),
        auth_params: auth_placeholder,
        priv_params,
    };

    let header = HeaderData {
        msg_id,
        max_size: DEFAULT_MAX_SIZE as i32,
        flags,
        security_model: SECURITY_MODEL_USM as i32,
    };

    assemble(&header, &usm, scoped_data, auth)
}

/// Serialize the full v3 message. When `auth` is provided, the message is first
/// serialized with the authentication-parameters placeholder (already zeroed by
/// the caller), the HMAC is computed over those bytes, and the message is
/// re-serialized with the real HMAC in place (RFC 3414 §6.3.1).
fn assemble(
    header: &HeaderData,
    usm: &UsmSecurityParameters,
    scoped_data: Any,
    auth: Option<(AuthProtocol, Vec<u8>)>,
) -> Result<Vec<u8>> {
    let encode_with = |usm: &UsmSecurityParameters| -> Result<Vec<u8>> {
        let message = RawV3Message {
            version: Integer::from(VERSION_V3),
            global_data: header.to_rasn(),
            security_parameters: octet_string(&usm.to_ber()?),
            scoped_data: scoped_data.clone(),
        };
        Ok(rasn::ber::encode(&message)?)
    };

    let Some((proto, key)) = auth else {
        return encode_with(usm);
    };

    // `usm.auth_params` is the zeroed placeholder; hash, then patch in the MAC.
    let zeroed = encode_with(usm)?;
    let mac = proto.mac(&key, &zeroed);
    let n = proto.mac_len();
    let mut signed = usm.clone();
    signed.auth_params = mac[..n].to_vec();
    encode_with(&signed)
}
