//! `snmpget` — retrieve one or more MIB object instances via SNMP GET.
//!
//! Rust counterpart of `apps/snmpget.c`.

use clap::Parser;
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Retrieve one or more MIB object instances via SNMP GET.
///
/// Common usage (copy a whole line and run it):
///
///   snmpget -v 2c -c public 127.0.0.1:161 sysDescr.0 sysName.0
///
/// Typical output:
///
///   SNMPv2-MIB::sysDescr.0 = STRING: Linux host 6.6.0 x86_64
///   SNMPv2-MIB::sysName.0 = STRING: host-a
///
/// SNMPv3 authPriv, by numeric OID:
///
///   snmpget -v 3 -u bob -a SHA -A authpass -x AES -X privpass -l authPriv 127.0.0.1:161 1.3.6.1.2.1.1.3.0
///
///   DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (123456) 0:20:34.56
#[derive(Parser, Debug)]
#[command(name = "snmpget", about = "Retrieve MIB object instances via SNMP GET")]
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
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let vars = client.get(&oids).await?;
    for vb in vars {
        print_varbind(&mib, &vb.oid, &vb.value);
    }
    Ok(())
}

fn print_varbind(mib: &MibRegistry, oid: &Oid, value: &netsnmp::value::Value) {
    info!("{} = {}", mib.format_oid(oid), mib.format_value(oid, value));
}
