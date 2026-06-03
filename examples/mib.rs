//! Use the MIB registry to translate between symbolic names and numeric OIDs,
//! and to pretty-print OIDs and enumerated values. No network is involved.
//!
//! Run (optionally pass a directory of `*.txt` MIB files to load):
//! ```text
//! cargo run -p netsnmp-examples --example mib -- ../mibs
//! ```

use netsnmp::{MibRegistry, Oid, Value};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    netsnmp_examples::init_tracing();

    // Start with the small set of built-in names, then optionally load real
    // MIB files from a directory for full symbolic coverage.
    let mut mib = MibRegistry::with_builtins();
    if let Some(dir) = std::env::args().nth(1) {
        let added = mib.load_dir(&dir).await?;
        info!("loaded {added} objects from {dir}");
    }

    // name -> OID
    for name in ["sysDescr", "ifTable", "ifOperStatus", "tcpConnState"] {
        match mib.name_to_oid(name) {
            Some(oid) => info!("name_to_oid  {name:14} = {oid}"),
            None => info!("name_to_oid  {name:14} = <unresolved> (load ../mibs for this one)"),
        }
    }

    // OID -> human-readable form (symbolic where known).
    let oid: Oid = "1.3.6.1.2.1.2.2.1.8.3".parse()?; // ifOperStatus.3
    info!("format_oid   {oid} = {}", mib.format_oid(&oid));

    // Render an enumerated INTEGER value using the MIB's enumeration labels
    // (ifOperStatus 2 == "down", when the IF-MIB is loaded).
    let formatted = mib.format_value(&oid, &Value::Integer(2));
    info!("format_value ifOperStatus.3 = 2 -> {formatted}");

    Ok(())
}
