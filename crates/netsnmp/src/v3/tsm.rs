//! RFC 6353 Transport Security Model (TSM).
//!
//! Counterpart of `snmplib/snmptsm.c`. TSM is the SNMPv3 security model
//! (`securityModel = transportSecurityModel(4)`) that relies on the TLS/DTLS
//! transport for authentication and confidentiality, instead of USM. The
//! authenticated peer identity established by the transport (the certificate's
//! SubjectAltName / Subject CN, optionally mapped via `tlstmCertToTSN`) becomes
//! the `securityName` carried in the v3 message.
//!
//! # Wire shape
//!
//! TSM messages are ordinary SNMPv3 messages with:
//!
//! * `msgSecurityModel` = 4,
//! * `msgSecurityParameters` = an empty `OCTET STRING` (RFC 6353 §5.2 — TSM
//!   carries no parameters in the message; the transport already authenticated
//!   the peer), and
//! * no USM auth/priv applied — the `msgFlags` auth/priv bits are clear and the
//!   ScopedPDU is always cleartext (the TLS/DTLS channel provides secrecy).
//!
//! # Scope
//!
//! This module provides message assembly/parsing (`build_tsm_request`,
//! `parse_tsm`) and the `tlstmCertToTSN` mapping-table model
//! ([`TsmCertMap`]). Wiring TSM into the agent's request dispatch (so an
//! incoming TLS connection's peer cert is consulted to derive the
//! `securityName` for VACM) is left to the transport integration layer.
//!
//! The certificate→securityName mapping here is pragmatic: by default the
//! certificate Subject CN is taken as the `securityName`. The
//! [`TsmCertMap`] table models the `tlstmCertToTSN` row that overrides this
//! default per fingerprint; a full implementation of every `CertMapType` is a
//! future extension.

use std::sync::RwLock;

use rasn::types::{Any, Integer};

use crate::convert::octet_string;
use crate::error::{Error, Result};
use crate::pdu::Pdu;

use super::types::{
    DEFAULT_MAX_SIZE, EngineParams, FLAG_REPORTABLE, HeaderData, ScopedPdu, VERSION_V3,
};
use super::wire::RawV3Message;

/// The TSM securityModel number (RFC 6353 §5.1: `transportSecurityModel(4)`).
pub const SECURITY_MODEL_TSM: i64 = 4;

/// TSM security parameters.
///
/// RFC 6353 §5.2 defines the TSM `msgSecurityParameters` as an empty
/// `OCTET STRING`; the transport already authenticated the peer, so the
/// message carries no security state. This type exists only to document that
/// contract and to give the wire layer a named placeholder — it serializes to
/// the empty octet string.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TsmSecurityParams;

impl TsmSecurityParams {
    /// The empty OCTET STRING that TSM carries as `msgSecurityParameters`.
    pub fn to_ber(&self) -> Vec<u8> {
        // An empty OCTET STRING: tag 0x04, length 0.
        vec![0x04, 0x00]
    }
}

/// The kind of certificate→securityName mapping a `tlstmCertToTSN` row applies.
///
/// Mirrors the `tlstmCertToTSNMapType` textual convention (RFC 6353 §7.2).
/// `SnmpTlsIdentity` (the default) uses the certificate's `snmpTLSIdentity`
/// SAN extension; the remaining variants derive the securityName from other
/// certificate fields. This implementation resolves `Subject` and
/// `SubjectAltName` pragmatically (CN / first SAN string); the exact SAN-type
/// selection rules of RFC 6353 are a future extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertMapType {
    /// Use the certificate's `snmpTLSIdentity` SAN (the RFC default).
    SnmpTlsIdentity,
    /// Use a `dNSName` SAN as the securityName.
    DnsName,
    /// Use an `iPAddress` SAN as the securityName.
    IpAddress,
    /// Use the certificate Subject (the DN, or its CN) as the securityName.
    Subject,
    /// Use a `SubjectAltName` entry as the securityName.
    SubjectAltName,
}

impl Default for CertMapType {
    fn default() -> Self {
        CertMapType::SnmpTlsIdentity
    }
}

/// A single `tlstmCertToTSN` table row (RFC 6353 §7.2).
///
/// Maps a peer certificate (identified by its fingerprint) to a securityName
/// using `map_type` and (optionally) `data`. When `data` is empty the
/// securityName is derived purely from the certificate field named by
/// `map_type`; otherwise `data` overrides it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertToTsnEntry {
    /// The certificate fingerprint (e.g. an uppercase hex SHA-256 string), the
    /// row's index.
    pub fingerprint: String,
    /// The mapping rule to apply.
    pub map_type: CertMapType,
    /// Optional override/parameter data for the mapping.
    pub data: String,
    /// The resolved securityName this row maps to.
    pub security_name: String,
}

/// The in-memory `tlstmCertToTSN` mapping table (RFC 6353 §7.2).
///
/// Holds the configured certificate→securityName rows. When a TLS/DTLS
/// connection is established, the agent looks up the peer certificate's
/// fingerprint here; if a row matches, its `security_name` becomes the TSM
/// `securityName`. Without a matching row the certificate's Subject CN is used
/// (see [`extract_security_name`]).
///
/// Concurrent access is guarded by an [`RwLock`] so the live MIB `SET` path can
/// mutate the table while request dispatch reads it.
#[derive(Debug, Default)]
pub struct TsmCertMap {
    entries: RwLock<Vec<CertToTsnEntry>>,
}

impl TsmCertMap {
    /// Create an empty certificate→securityName map.
    pub fn new() -> Self {
        TsmCertMap {
            entries: RwLock::new(Vec::new()),
        }
    }

    /// Add (or replace, on fingerprint match) a `tlstmCertToTSN` row.
    ///
    /// Fingerprint matching is case-insensitive (fingerprints are commonly
    /// rendered as uppercase or lowercase hex), matching [`TsmCertMap::map`].
    pub fn add(&self, entry: CertToTsnEntry) {
        let mut guard = self.entries.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard
            .iter_mut()
            .find(|e| e.fingerprint.eq_ignore_ascii_case(&entry.fingerprint))
        {
            *existing = entry;
        } else {
            guard.push(entry);
        }
    }

    /// Look up the securityName mapped to `fingerprint`, if any.
    pub fn map(&self, fingerprint: &str) -> Option<String> {
        let guard = self.entries.read().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .find(|e| e.fingerprint.eq_ignore_ascii_case(fingerprint))
            .map(|e| e.security_name.clone())
    }

    /// The number of configured rows.
    pub fn len(&self) -> usize {
        self.entries.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the table has any rows.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Derive a TSM `securityName` from a TLS peer certificate's Subject string.
///
/// Pragmatic implementation of the RFC 6353 `tlstmCertToTSN` default mapping:
/// the certificate Subject's Common Name (CN) is taken as the `securityName`.
/// `subject` is expected to be the RFC 4514 DN string (e.g.
/// `"CN=agent,O=Example"`); the first `CN=` component is extracted and returned
/// as bytes. When no CN is present the whole Subject is used (this is rare and
/// typically indicates a misconfigured certificate).
///
/// # Future work
///
/// A complete implementation honors the `tlstmCertToTSN` table's
/// `CertMapType` and selects a SubjectAltName by type (`dNSName`, `iPAddress`,
/// `rfc822Name`, …) rather than always taking the CN. That requires access to
/// the parsed certificate structure (not just the DN string), so it is wired in
/// at the transport integration layer; this function provides the sensible
/// default used when no explicit mapping row matches.
pub fn extract_security_name(tls_peer_cert_subject: &str) -> Vec<u8> {
    // Walk the comma-separated RDNs and pick the first CN= component.
    for rdn in tls_peer_cert_subject.split(',') {
        let rdn = rdn.trim();
        if let Some(rest) = rdn.strip_prefix("CN=")
            .or_else(|| rdn.strip_prefix("cn="))
        {
            return rest.trim().as_bytes().to_vec();
        }
    }
    // No CN: fall back to the whole Subject (best-effort).
    tls_peer_cert_subject.as_bytes().to_vec()
}

/// Build a TSM (securityModel=4) request message.
///
/// The ScopedPDU is carried in cleartext (the TLS/DTLS transport provides
/// confidentiality); `msgSecurityParameters` is the empty OCTET STRING; the
/// auth/priv `msgFlags` bits are clear. `reportable` is set so the peer may
/// send a Report on error, matching the USM request path.
///
/// `engine` supplies the `contextEngineID` used in the ScopedPDU (the
/// authoritative engine the request is addressed to); when `context_engine_id`
/// is empty, the engine's own id is used (matching `build_request`).
pub fn build_tsm_request(
    msg_id: i32,
    security_name: &[u8],
    engine: &EngineParams,
    context_engine_id: &[u8],
    pdu: Pdu,
) -> Result<Vec<u8>> {
    let ctx_engine = if context_engine_id.is_empty() {
        engine.engine_id.clone()
    } else {
        context_engine_id.to_vec()
    };
    // TSM carries the securityName only in the (cleartext, transport-secured)
    // scoped PDU's header path — the v3 header itself does not carry a
    // securityName. It is threaded through here so transport integrators can
    // log/audit it; USM's msgUserName slot is absent in TSM (empty params).
    let _ = security_name;

    let scoped = ScopedPdu::new(ctx_engine, Vec::new(), pdu);
    let scoped_data = Any::new(scoped.to_ber()?);

    let header = HeaderData {
        msg_id,
        max_size: DEFAULT_MAX_SIZE as i32,
        flags: FLAG_REPORTABLE, // no auth, no priv — the transport secures it
        security_model: SECURITY_MODEL_TSM as i32,
    };

    // TSM's msgSecurityParameters is an empty OCTET STRING.
    let message = RawV3Message {
        version: Integer::from(VERSION_V3),
        global_data: header.to_rasn(),
        security_parameters: octet_string(&[]),
        scoped_data,
    };
    Ok(rasn::ber::encode(&message)?)
}

/// Parse a TSM (securityModel=4) message into its header and ScopedPDU.
///
/// Unlike the USM path ([`super::parse`]), no HMAC verification or decryption
/// is performed — the transport already authenticated the peer. The header's
/// `security_model` is checked to be `4` so a USM message is never silently
/// accepted as TSM.
pub fn parse_tsm(bytes: &[u8]) -> Result<(HeaderData, ScopedPdu)> {
    let raw = rasn::ber::decode::<RawV3Message>(bytes)?;
    let version = crate::convert::int_to_i64(&raw.version)?;
    if version != VERSION_V3 {
        return Err(Error::UnsupportedVersion(version));
    }
    let header = HeaderData::from_rasn(&raw.global_data)?;
    if header.security_model as i64 != SECURITY_MODEL_TSM {
        return Err(Error::Protocol(format!(
            "not a TSM message: securityModel={}, expected {SECURITY_MODEL_TSM}",
            header.security_model
        )));
    }
    // TSM's securityParameters must be an empty OCTET STRING. We do not
    // hard-fail on a non-empty value (some transports may carry future
    // extensions), but we never interpret it as USM parameters.
    let scoped = ScopedPdu::decode_ber(raw.scoped_data.as_bytes())?;
    Ok((header, scoped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid::Oid;
    use crate::pdu::{Pdu, PduType};
    use crate::value::Value;
    use super::super::types::{FLAG_AUTH, FLAG_PRIV};

    fn engine() -> EngineParams {
        EngineParams {
            engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', 0x00, 0x01],
            engine_boots: 1,
            engine_time: 100,
        }
    }

    fn sample_pdu() -> Pdu {
        Pdu::new(PduType::Get, 0x1234)
            .with_var("1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap(), Value::Null)
    }

    #[test]
    fn build_tsm_request_sets_security_model_4_and_empty_params() {
        let bytes =
            build_tsm_request(42, b"tlsmuser", &engine(), &[], sample_pdu()).unwrap();
        // Decode the raw envelope to inspect the securityParameters and model.
        let raw = rasn::ber::decode::<RawV3Message>(&bytes).unwrap();
        let header = HeaderData::from_rasn(&raw.global_data).unwrap();
        assert_eq!(header.security_model as i64, SECURITY_MODEL_TSM);
        assert_eq!(header.msg_id, 42);
        // No auth/priv flags; reportable set for a request.
        assert_eq!(header.flags & FLAG_AUTH, 0);
        assert_eq!(header.flags & FLAG_PRIV, 0);
        assert_ne!(header.flags & FLAG_REPORTABLE, 0);
        // securityParameters is an empty OCTET STRING.
        assert!(raw.security_parameters.is_empty());
    }

    #[test]
    fn parse_tsm_round_trips() {
        let pdu = sample_pdu();
        let bytes = build_tsm_request(7, b"agent", &engine(), &[], pdu.clone()).unwrap();
        let (header, scoped) = parse_tsm(&bytes).unwrap();
        assert_eq!(header.msg_id, 7);
        assert_eq!(header.security_model as i64, SECURITY_MODEL_TSM);
        assert_eq!(scoped.pdu, pdu);
        assert_eq!(scoped.context_engine_id, engine().engine_id);
    }

    #[test]
    fn parse_tsm_rejects_usm_message() {
        // A USM (securityModel=3) discovery message must not parse as TSM.
        let usm = super::super::build_discovery(1, 1).unwrap();
        let err = parse_tsm(&usm).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn extract_security_name_from_cn() {
        assert_eq!(
            extract_security_name("CN=agent01, O=Example, C=US"),
            b"agent01".to_vec()
        );
        // Lowercase cn= is also accepted.
        assert_eq!(
            extract_security_name("cn=agent02"),
            b"agent02".to_vec()
        );
    }

    #[test]
    fn extract_security_name_falls_back_to_whole_subject_without_cn() {
        assert_eq!(extract_security_name("O=NoCnHere"), b"O=NoCnHere".to_vec());
    }

    #[test]
    fn cert_map_add_and_lookup() {
        let map = TsmCertMap::new();
        assert!(map.is_empty());
        map.add(CertToTsnEntry {
            fingerprint: "AB:CD".to_string(),
            map_type: CertMapType::Subject,
            data: String::new(),
            security_name: "mapped-user".to_string(),
        });
        assert_eq!(map.len(), 1);
        // Case-insensitive fingerprint match.
        assert_eq!(map.map("ab:cd"), Some("mapped-user".to_string()));
        assert!(map.map("00:00").is_none());
    }

    #[test]
    fn cert_map_replace_on_fingerprint_match() {
        let map = TsmCertMap::new();
        map.add(CertToTsnEntry {
            fingerprint: "FF".to_string(),
            map_type: CertMapType::DnsName,
            data: String::new(),
            security_name: "first".to_string(),
        });
        map.add(CertToTsnEntry {
            fingerprint: "ff".to_string(),
            map_type: CertMapType::DnsName,
            data: String::new(),
            security_name: "second".to_string(),
        });
        assert_eq!(map.len(), 1);
        assert_eq!(map.map("FF"), Some("second".to_string()));
    }

    #[test]
    fn tsm_security_params_serializes_to_empty_octet_string() {
        let ber = TsmSecurityParams.to_ber();
        assert_eq!(ber, vec![0x04, 0x00]);
    }
}
