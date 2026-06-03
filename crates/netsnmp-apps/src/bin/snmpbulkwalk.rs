//! `snmpbulkwalk` — walk a MIB subtree efficiently using SNMP GETBULK.
//!
//! Rust counterpart of `apps/snmpbulkwalk.c`. Behaves like `snmpwalk` but uses
//! GETBULK to fetch many variables per round-trip (falling back to GETNEXT on
//! SNMPv1, which has no GETBULK PDU).

use clap::Parser;
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Walk a MIB subtree using SNMP GETBULK.
///
/// Common usage (copy a whole line and run it):
///
///   snmpbulkwalk -v 2c -c public 127.0.0.1:161 ifTable
///
/// Typical output (same result as snmpwalk, but far fewer round-trips):
///
///   IF-MIB::ifIndex.1 = INTEGER: 1
///   IF-MIB::ifIndex.2 = INTEGER: 2
///   IF-MIB::ifDescr.1 = STRING: lo
///   IF-MIB::ifDescr.2 = STRING: eth0
///   IF-MIB::ifType.2 = INTEGER: ethernetCsmacd(6)
#[derive(Parser, Debug)]
#[command(
    name = "snmpbulkwalk",
    about = "Walk a MIB subtree using SNMP GETBULK (v2c/v3)"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Maximum repetitions per GETBULK request.
    #[arg(long = "max-repetitions", value_name = "N", default_value_t = 10)]
    max_repetitions: u32,
    /// Subtree root OID (symbolic or numeric). Defaults to `mib-2`.
    #[arg(value_name = "OID")]
    oid: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;

    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;
    let root = match &cli.oid {
        Some(token) => mib
            .translate(token)
            .ok_or_else(|| AppError::ParseOid(token.clone()))?,
        // Default subtree: mib-2 (1.3.6.1.2.1), matching the C tools.
        None => "1.3.6.1.2.1".parse().expect("valid default OID"),
    };

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    // Print each varbind as it arrives (per GETBULK round-trip) rather than
    // buffering the whole subtree.
    let count = client
        .bulk_walk_each(&root, cli.max_repetitions, |vb| {
            print_varbind(&mib, &vb.oid, &vb.value);
        })
        .await?;
    if count == 0 {
        info!(
            "{} = No more variables left in this MIB View (It is past the end of the MIB tree)",
            mib.format_oid(&root)
        );
    }
    Ok(())
}

fn print_varbind(mib: &MibRegistry, oid: &Oid, value: &netsnmp::value::Value) {
    info!("{} = {}", mib.format_oid(oid), mib.format_value(oid, value));
}
