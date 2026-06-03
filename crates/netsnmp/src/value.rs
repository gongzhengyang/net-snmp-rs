//! SNMP variable values and their BER (de)serialization.
//!
//! Combines the type system that C spreads across `asn1.c`, `snmp.c` and
//! `mib.c` into a single tagged `Value` enum. The wire (de)serialization maps
//! each variant onto the `rasn-smi` SMI object syntax and `rasn-snmp`
//! variable-binding value types.

use crate::convert::{int_to_i64, octet_string, oid_from_rasn, oid_to_rasn, opaque_from_bytes};
use crate::error::Result;
use crate::oid::Oid;
use itertools::Itertools;
use rasn::types::Integer;
use rasn_smi::v1::{Counter, Gauge, IpAddress, TimeTicks as SmiTimeTicks};
use rasn_smi::v2::{ApplicationSyntax, Counter64, SimpleSyntax};
use rasn_snmp::v2::{ObjectSyntax, VarBindValue};
use std::fmt;
use std::net::Ipv4Addr;

/// A typed SNMP value, as carried in a variable binding.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// INTEGER / Integer32.
    Integer(i64),
    /// OCTET STRING (arbitrary bytes).
    OctetString(Vec<u8>),
    /// OBJECT IDENTIFIER.
    Oid(Oid),
    /// IpAddress (4 octets).
    IpAddress(Ipv4Addr),
    /// Counter32 (wrapping unsigned, 0..2^32-1).
    Counter32(u32),
    /// Gauge32 / Unsigned32.
    Gauge32(u32),
    /// TimeTicks (hundredths of a second).
    TimeTicks(u32),
    /// Opaque (wrapped, application-specific bytes).
    Opaque(Vec<u8>),
    /// Counter64 (SNMPv2c+).
    Counter64(u64),
    /// ASN.1 NULL (used in request varbinds).
    Null,
    /// SNMPv2 exception: the object does not exist.
    NoSuchObject,
    /// SNMPv2 exception: the instance does not exist.
    NoSuchInstance,
    /// SNMPv2 exception: end of the MIB view reached (GETNEXT/GETBULK).
    EndOfMibView,
}

impl Value {
    /// A short human-readable type label, mirroring `snmptranslate` output.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Integer(_) => "INTEGER",
            Value::OctetString(_) => "STRING",
            Value::Oid(_) => "OID",
            Value::IpAddress(_) => "IpAddress",
            Value::Counter32(_) => "Counter32",
            Value::Gauge32(_) => "Gauge32",
            Value::TimeTicks(_) => "Timeticks",
            Value::Opaque(_) => "Opaque",
            Value::Counter64(_) => "Counter64",
            Value::Null => "Null",
            Value::NoSuchObject => "noSuchObject",
            Value::NoSuchInstance => "noSuchInstance",
            Value::EndOfMibView => "endOfMibView",
        }
    }

    /// Convert this value into a `rasn-snmp` variable-binding value, ready to be
    /// placed in a `VarBind` and BER-encoded.
    pub(crate) fn to_var_bind_value(&self) -> Result<VarBindValue> {
        let simple = |s| VarBindValue::Value(ObjectSyntax::Simple(s));
        let app = |a| VarBindValue::Value(ObjectSyntax::ApplicationWide(a));
        let value = match self {
            Value::Integer(v) => simple(SimpleSyntax::Integer(Integer::from(*v))),
            Value::OctetString(b) => simple(SimpleSyntax::String(octet_string(b))),
            Value::Oid(oid) => simple(SimpleSyntax::ObjectId(oid_to_rasn(oid)?)),
            Value::IpAddress(ip) => app(ApplicationSyntax::Address(IpAddress(ip.octets().into()))),
            Value::Counter32(v) => app(ApplicationSyntax::Counter(Counter(*v))),
            Value::Gauge32(v) => app(ApplicationSyntax::Unsigned(Gauge(*v))),
            Value::TimeTicks(v) => app(ApplicationSyntax::Ticks(SmiTimeTicks(*v))),
            Value::Opaque(b) => app(ApplicationSyntax::Arbitrary(opaque_from_bytes(b)?)),
            Value::Counter64(v) => app(ApplicationSyntax::BigCounter(Counter64(*v))),
            Value::Null => VarBindValue::Unspecified,
            Value::NoSuchObject => VarBindValue::NoSuchObject,
            Value::NoSuchInstance => VarBindValue::NoSuchInstance,
            Value::EndOfMibView => VarBindValue::EndOfMibView,
        };
        Ok(value)
    }

    /// Build a value from a decoded `rasn-snmp` variable-binding value.
    pub(crate) fn from_var_bind_value(value: VarBindValue) -> Result<Value> {
        let object = match value {
            VarBindValue::Unspecified => return Ok(Value::Null),
            VarBindValue::NoSuchObject => return Ok(Value::NoSuchObject),
            VarBindValue::NoSuchInstance => return Ok(Value::NoSuchInstance),
            VarBindValue::EndOfMibView => return Ok(Value::EndOfMibView),
            VarBindValue::Value(object) => object,
        };
        Value::from_object_syntax(object)
    }

    /// Build a value from a decoded SMI `ObjectSyntax`.
    pub(crate) fn from_object_syntax(object: ObjectSyntax) -> Result<Value> {
        let value = match object {
            ObjectSyntax::Simple(SimpleSyntax::Integer(i)) => Value::Integer(int_to_i64(&i)?),
            ObjectSyntax::Simple(SimpleSyntax::String(s)) => Value::OctetString(s.to_vec()),
            ObjectSyntax::Simple(SimpleSyntax::ObjectId(o)) => Value::Oid(oid_from_rasn(&o)),
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(IpAddress(b))) => {
                Value::IpAddress(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(Counter(v))) => {
                Value::Counter32(v)
            }
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(Gauge(v))) => {
                Value::Gauge32(v)
            }
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(SmiTimeTicks(v))) => {
                Value::TimeTicks(v)
            }
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(op)) => {
                Value::Opaque(op.as_ref().to_vec())
            }
            ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(Counter64(v))) => {
                Value::Counter64(v)
            }
        };
        Ok(value)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer(v) => write!(f, "INTEGER: {v}"),
            Value::OctetString(b) => match std::str::from_utf8(b) {
                Ok(s)
                    if b.iter()
                        .all(|c| !c.is_ascii_control() || *c == b'\n' || *c == b'\t') =>
                {
                    write!(f, "STRING: {s}")
                }
                _ => {
                    // Space-separated hex without an intermediate Vec<String>.
                    let hex = b.iter().format_with(" ", |c, g| g(&format_args!("{c:02X}")));
                    write!(f, "Hex-STRING: {hex}")
                }
            },
            Value::Oid(oid) => write!(f, "OID: {oid}"),
            Value::IpAddress(ip) => write!(f, "IpAddress: {ip}"),
            Value::Counter32(v) => write!(f, "Counter32: {v}"),
            Value::Gauge32(v) => write!(f, "Gauge32: {v}"),
            Value::TimeTicks(v) => {
                let secs = *v / 100;
                write!(
                    f,
                    "Timeticks: ({v}) {}d {}h {}m {}.{:02}s",
                    secs / 86400,
                    (secs % 86400) / 3600,
                    (secs % 3600) / 60,
                    secs % 60,
                    *v % 100
                )
            }
            Value::Opaque(b) => write!(f, "Opaque: {} bytes", b.len()),
            Value::Counter64(v) => write!(f, "Counter64: {v}"),
            Value::Null => write!(f, "NULL"),
            Value::NoSuchObject => write!(f, "No Such Object available on this agent at this OID"),
            Value::NoSuchInstance => write!(f, "No Such Instance currently exists at this OID"),
            Value::EndOfMibView => write!(f, "No more variables left in this MIB View"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: Value) {
        let vbv = value.to_var_bind_value().unwrap();
        let bytes = rasn::ber::encode(&vbv).unwrap();
        let decoded: VarBindValue = rasn::ber::decode(&bytes).unwrap();
        let back = Value::from_var_bind_value(decoded).unwrap();
        assert_eq!(back, value);
    }

    #[test]
    fn value_roundtrips() {
        roundtrip(Value::Integer(-42));
        roundtrip(Value::OctetString(b"public".to_vec()));
        roundtrip(Value::Oid("1.3.6.1.2.1".parse().unwrap()));
        roundtrip(Value::IpAddress(Ipv4Addr::new(192, 168, 0, 1)));
        roundtrip(Value::Counter32(4_000_000_000));
        roundtrip(Value::Gauge32(12345));
        roundtrip(Value::TimeTicks(99999));
        roundtrip(Value::Opaque(vec![0x9a, 0x01, 0x02, 0x03]));
        roundtrip(Value::Counter64(18_000_000_000_000_000_000));
        roundtrip(Value::Null);
        roundtrip(Value::NoSuchObject);
        roundtrip(Value::EndOfMibView);
    }
}
