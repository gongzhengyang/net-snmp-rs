//! GETBULK: retrieve many table rows per round-trip (SNMPv2c/v3), and a simple
//! bulk-walk loop built on top of it.
//!
//! Run:
//! ```text
//! cargo run -p netsnmp-examples --example bulkwalk -- 127.0.0.1:11611 public 1.3.6.1.2.1.2.2
//! ```

use netsnmp::{Oid, Session, SessionConfig, Value};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    let mut args = std::env::args().skip(1);
    let agent = args.next().unwrap_or_else(|| "127.0.0.1:11611".to_string());
    let community = args.next().unwrap_or_else(|| "public".to_string());
    let root: Oid = args
        .next()
        .unwrap_or_else(|| "1.3.6.1.2.1.2.2".to_string())
        .parse()?;

    let config = SessionConfig {
        community: community.into_bytes(),
        ..SessionConfig::default()
    };
    let session = Session::open_udp(&agent, config).await?;

    // A single GETBULK: 0 non-repeaters, up to 10 repetitions of `root`.
    info!("single GETBULK (max-repetitions=10) under {root}:");
    for vb in session.get_bulk(0, 10, std::slice::from_ref(&root)).await? {
        info!("    {} = {}", vb.oid, vb.value);
    }

    // A bulk-walk: keep issuing GETBULK from the last OID until we leave the
    // subtree or hit end-of-MIB-view. This is what `snmpbulkwalk` does.
    info!("bulk-walk of {root}:");
    let mut current = root.clone();
    let mut total = 0usize;
    'outer: loop {
        let vars = session.get_bulk(0, 20, std::slice::from_ref(&current)).await?;
        if vars.is_empty() {
            break;
        }
        for vb in vars {
            if matches!(vb.value, Value::EndOfMibView) || !root.is_prefix_of(&vb.oid) {
                break 'outer;
            }
            info!("    {} = {}", vb.oid, vb.value);
            current = vb.oid.clone();
            total += 1;
        }
    }
    info!("bulk-walk returned {total} rows");

    Ok(())
}
