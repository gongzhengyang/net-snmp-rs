//! Conversions between this crate's SNMP domain types and the `rasn` wire types.
//!
//! The domain types (`Oid`, `Value`, `Pdu`, `Message`, …) form the stable public
//! API; the `rasn`, `rasn-snmp` and `rasn-smi` crates provide the actual BER
//! (de)serialization. This module holds the small primitive bridges
//! (OID / OCTET STRING / INTEGER / Opaque) shared by the higher-level
//! conversions in `value`, `pdu`, `message` and `v3`.

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::v2::Opaque;

use crate::error::{Error, Result};
use crate::oid::Oid;

/// Convert a domain [`Oid`] into a `rasn` `ObjectIdentifier`.
///
/// X.690 requires an OID to carry at least two arcs (the first two are packed
/// into a single octet) with a first arc of 0, 1 or 2. A bare root arc such as
/// `.1` — commonly used to walk the entire tree (`snmpwalk host .1`) — is not
/// directly encodable. We pad such short OIDs with trailing `.0` arcs to the
/// minimum length so a GETNEXT/walk from the root still works: `GETNEXT(.1)` and
/// `GETNEXT(.1.0)` select the same first object in practice (no agent exposes an
/// object exactly at `.1.0`), and subsequent walk probes use the full-length
/// OIDs returned by the agent. The caller keeps the original (unpadded) root for
/// its own subtree/termination checks.
///
/// Returns [`Error::InvalidOid`] when the arcs still cannot form a valid ASN.1
/// OID (e.g. a first arc greater than 2).
pub(crate) fn oid_to_rasn(oid: &Oid) -> Result<ObjectIdentifier> {
    let mut arcs = oid.as_slice().to_vec();
    if arcs.len() < 2 {
        arcs.resize(2, 0);
    }
    ObjectIdentifier::new(arcs)
        .ok_or_else(|| Error::InvalidOid(format!("not encodable as ASN.1 OID: {oid}")))
}

/// Convert a `rasn` `ObjectIdentifier` back into a domain [`Oid`].
pub(crate) fn oid_from_rasn(oid: &ObjectIdentifier) -> Oid {
    Oid::new(oid.as_ref().to_vec())
}

/// Borrow `bytes` into a `rasn` `OctetString` (a reference-counted `Bytes`).
pub(crate) fn octet_string(bytes: &[u8]) -> OctetString {
    OctetString::from_slice(bytes)
}

/// Read a `rasn` `Integer` as an `i64`, erroring if it does not fit.
pub(crate) fn int_to_i64(value: &Integer) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::IntegerOverflow)
}

/// Read a `rasn` `Integer` as a `u32`, erroring if it does not fit.
pub(crate) fn int_to_u32(value: &Integer) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::IntegerOverflow)
}

/// Build an SMI `Opaque` carrying the given raw application content octets.
///
/// `rasn-smi`'s `Opaque` has a private field and no raw-bytes constructor, so we
/// frame `bytes` as a primitive OCTET STRING TLV, retag it to `[APPLICATION 4]`
/// (`Opaque`'s tag), and decode it back — reusing `rasn` for all length framing.
pub(crate) fn opaque_from_bytes(bytes: &[u8]) -> Result<Opaque> {
    let mut tlv = rasn::ber::encode(&octet_string(bytes))?;
    // Retag the universal primitive OCTET STRING (0x04) as Opaque (0x44).
    tlv[0] = 0x44;
    Ok(rasn::ber::decode::<Opaque>(&tlv)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_short_root_oids_to_encodable_form() {
        // `.1` (whole-tree walk root) pads to `.1.0` so it is BER-encodable.
        let got = oid_to_rasn(&Oid::new(vec![1])).expect("encodable");
        assert_eq!(got.as_ref(), &[1, 0]);

        // The empty root `.` pads to `.0.0`.
        let got = oid_to_rasn(&Oid::new(vec![])).expect("encodable");
        assert_eq!(got.as_ref(), &[0, 0]);
    }

    #[test]
    fn keeps_normal_oids_unchanged() {
        let arcs = vec![1, 3, 6, 1, 2, 1, 1, 1, 0];
        let got = oid_to_rasn(&Oid::new(arcs.clone())).expect("encodable");
        assert_eq!(got.as_ref(), arcs.as_slice());
    }

    #[test]
    fn rejects_oids_with_first_arc_above_two() {
        // A first arc > 2 is invalid even after padding.
        assert!(oid_to_rasn(&Oid::new(vec![3])).is_err());
    }
}
