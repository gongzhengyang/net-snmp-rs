//! Wire-level protocol work: build and parse real SNMP messages with the
//! `Message`/`Pdu`/`Value` types and inspect the BER bytes on the wire. The BER
//! (de)serialization itself is provided by the `rasn` / `rasn-snmp` codecs.
//!
//! Run:
//! ```text
//! cargo run -p netsnmp-examples --example asn1
//! ```

use netsnmp::{Message, Pdu, PduType, Value, Version};
use tracing::info;

fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    // ---- 1. A whole SNMP GET request, encoded and decoded ----------------
    let pdu = Pdu::new(PduType::Get, 1234).with_null_var("1.3.6.1.2.1.1.1.0".parse()?);
    let msg = Message::new(Version::V2c, b"public".to_vec(), pdu);
    let wire = msg.encode()?;
    info!("encoded SNMP GET ({} bytes) = {}", wire.len(), to_hex(&wire));

    let decoded = Message::decode(&wire)?;
    info!(
        "decoded: version={:?}, community={}, request_id={}, pdu_type={:?}",
        decoded.version,
        String::from_utf8_lossy(&decoded.community),
        decoded.pdu.request_id,
        decoded.pdu.pdu_type,
    );

    // ---- 2. A Response carrying a few typed values -----------------------
    let mut response = Pdu::new(PduType::Response, 1234);
    response = response
        .with_var("1.3.6.1.2.1.1.3.0".parse()?, Value::TimeTicks(987_654))
        .with_var(
            "1.3.6.1.2.1.1.1.0".parse()?,
            Value::OctetString(b"Net-SNMP rs".to_vec()),
        );
    let resp_msg = Message::new(Version::V2c, b"public".to_vec(), response);
    let resp_wire = resp_msg.encode()?;
    info!(
        "encoded SNMP RESPONSE ({} bytes) = {}",
        resp_wire.len(),
        to_hex(&resp_wire)
    );

    for vb in Message::decode(&resp_wire)?.pdu.variables {
        info!("  {} = {}", vb.oid, vb.value);
    }

    Ok(())
}

/// Render bytes as lowercase hex for logging.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
