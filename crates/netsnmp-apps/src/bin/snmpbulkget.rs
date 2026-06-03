//! `snmpbulkget` — retrieve many MIB objects in one round-trip via SNMP GETBULK.
//!
//! Rust counterpart of `apps/snmpbulkget.c`. GETBULK is a SNMPv2c/v3 PDU: the
//! first `--non-repeaters` OIDs are fetched once (like GETNEXT scalars) and the
//! remaining OIDs are each returned up to `--max-repetitions` times.

use clap::Parser;
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Retrieve MIB objects via a single SNMP GETBULK request.
///
/// Common usage (copy a whole line and run it):
///
///   snmpbulkget -v 2c -c public --non-repeaters 0 --max-repetitions 5 127.0.0.1:161 ifDescr
///
/// Typical output (up to max-repetitions successors in one round-trip):
///
///   IF-MIB::ifDescr.1 = STRING: lo
///   IF-MIB::ifDescr.2 = STRING: eth0
///   IF-MIB::ifType.1 = INTEGER: softwareLoopback(24)
///   IF-MIB::ifType.2 = INTEGER: ethernetCsmacd(6)
///   IF-MIB::ifMtu.1 = INTEGER: 65536
#[derive(Parser, Debug)]
#[command(
    name = "snmpbulkget",
    about = "Retrieve MIB objects via SNMP GETBULK (v2c/v3)"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Number of leading OIDs treated as non-repeaters (fetched once).
    #[arg(long = "non-repeaters", value_name = "N", default_value_t = 0)]
    non_repeaters: u32,
    /// Maximum repetitions for each repeating OID.
    #[arg(long = "max-repetitions", value_name = "N", default_value_t = 10)]
    max_repetitions: u32,
    /// One or more object identifiers (symbolic names or numeric OIDs).
    #[arg(value_name = "OID", required = true)]
    oids: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;

    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;
    let mut oids = Vec::new();
    for token in &cli.oids {
        let oid = mib
            .translate(token)
            .ok_or_else(|| AppError::ParseOid(token.clone()))?;
        oids.push(oid);
    }

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;
    if !client.supports_bulk() {
        return Err(AppError::msg(
            "GETBULK requires SNMPv2c or SNMPv3 (use -v 2c)",
        ));
    }

    let vars = client
        .get_bulk(cli.non_repeaters, cli.max_repetitions, &oids)
        .await?;
    for vb in vars {
        print_varbind(&mib, &vb.oid, &vb.value);
    }
    Ok(())
}

fn print_varbind(mib: &MibRegistry, oid: &Oid, value: &netsnmp::value::Value) {
    info!("{} = {}", mib.format_oid(oid), mib.format_value(oid, value));
}
