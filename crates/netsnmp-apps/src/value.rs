//! Typed value parsing for `snmpset` / `snmptrap` `TYPE VALUE` arguments.

use std::net::Ipv4Addr;

use netsnmp::value::Value;

/// Parse a `snmpset`/`snmptrap` `TYPE VALUE` pair into a typed [`Value`].
///
/// TYPE is one of: `i` integer, `u` unsigned/gauge, `c` counter32,
/// `t` timeticks, `a` IPv4 address, `s` string, `x` hex string, `o` OID,
/// `n` null. Returns a human-readable error string on failure.
pub fn parse_typed_value(type_char: &str, raw: &str) -> Result<Value, String> {
    let value = match type_char {
        "i" => Value::Integer(raw.parse().map_err(|_| format!("bad integer '{raw}'"))?),
        "u" => Value::Gauge32(raw.parse().map_err(|_| format!("bad unsigned '{raw}'"))?),
        "c" => Value::Counter32(raw.parse().map_err(|_| format!("bad counter '{raw}'"))?),
        "t" => Value::TimeTicks(raw.parse().map_err(|_| format!("bad timeticks '{raw}'"))?),
        "a" => Value::IpAddress(
            raw.parse::<Ipv4Addr>()
                .map_err(|_| format!("bad IP '{raw}'"))?,
        ),
        "s" => Value::OctetString(raw.as_bytes().to_vec()),
        "x" => Value::OctetString(parse_hex_string(raw)?),
        "o" => Value::Oid(raw.parse().map_err(|_| format!("bad OID value '{raw}'"))?),
        "n" => Value::Null,
        other => return Err(format!("unknown type code '{other}'")),
    };
    Ok(value)
}

/// Parse a whitespace-tolerant hex string into bytes.
///
/// Shared by `snmpset`/`snmptrap` (`x` values) and the USM/VACM management
/// tools. Embedded whitespace is ignored; the remaining digits must form an
/// even number of hex characters.
pub fn parse_hex_string(raw: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = raw.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string '{raw}'"));
    }
    digits
        .chunks(2)
        .map(|pair| {
            // `pair` is two ASCII hex digits; from_utf8 cannot allocate here.
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| format!("bad hex byte in '{raw}'"))
        })
        .collect()
}
