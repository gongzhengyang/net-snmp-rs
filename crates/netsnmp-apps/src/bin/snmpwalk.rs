//! `snmpwalk` — walk a MIB subtree using repeated GETNEXT.
//!
//! Rust counterpart of `apps/snmpwalk.c`.

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Walk a MIB subtree using repeated SNMP GETNEXT.
///
/// Common usage (copy a whole line and run it):
///
///   snmpwalk -v 2c -c public 127.0.0.1:161 system
///
/// Typical output (one line per object in the subtree):
///
///   SNMPv2-MIB::sysDescr.0 = STRING: Linux host 6.6.0 x86_64
///   DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (123456) 0:20:34.56
///   SNMPv2-MIB::sysContact.0 = STRING: admin@example.com
///   SNMPv2-MIB::sysName.0 = STRING: host-a
///   SNMPv2-MIB::sysLocation.0 = STRING: Rack 9
#[derive(Parser, Debug)]
#[command(name = "snmpwalk", about = "Walk a MIB subtree via repeated GETNEXT")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Subtree root OID (defaults to the mib-2 subtree).
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
    // Default to the mib-2 subtree, like the C tool defaults to sysDescr's parent.
    let root: Oid = match cli.oid.as_deref() {
        Some(token) => mib
            .translate(token)
            .ok_or_else(|| AppError::ParseOid(token.to_string()))?,
        None => "1.3.6.1.2.1".parse().unwrap(),
    };

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session: {e}")))?;

    // Print each varbind as it arrives instead of buffering the whole subtree.
    let count = client
        .walk_each(&root, |vb| {
            info!(
                "{} = {}",
                mib.format_oid(&vb.oid),
                mib.format_value(&vb.oid, &vb.value)
            );
        })
        .await?;
    if count == 0 {
        info!(
            "{} = No more variables left in this MIB View",
            mib.format_oid(&root)
        );
    }
    Ok(())
}
