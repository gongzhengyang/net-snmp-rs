//! `snmpgetnext` — retrieve the lexicographic successor of each OID.
//!
//! Rust counterpart of `apps/snmpgetnext.c`.

use clap::Parser;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Retrieve the lexicographic successor of each given OID via SNMP GETNEXT.
///
/// Common usage (copy a whole line and run it):
///
///   snmpgetnext -v 2c -c public 127.0.0.1:161 sysDescr ifNumber
///
/// Typical output (each line is the *next* object after the one you asked for):
///
///   SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
///   IF-MIB::ifIndex.1 = INTEGER: 1
#[derive(Parser, Debug)]
#[command(
    name = "snmpgetnext",
    about = "Retrieve the next MIB object via SNMP GETNEXT"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
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
        .map_err(|e| AppError::msg(format!("cannot open session: {e}")))?;

    let vars = client.get_next(&oids).await?;
    for vb in vars {
        info!(
            "{} = {}",
            mib.format_oid(&vb.oid),
            mib.format_value(&vb.oid, &vb.value)
        );
    }
    Ok(())
}
