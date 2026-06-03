//! `snmpset` — set one or more MIB object instances via SNMP SET.
//!
//! Rust counterpart of `apps/snmpset.c`. Arguments after the agent come in
//! `OID TYPE VALUE` triples, where TYPE is one of:
//! `i` integer, `u` unsigned, `c` counter32, `t` timeticks, `a` ipaddress,
//! `s` string, `x` hex string, `o` oid, `n` null.

use clap::Parser;
use netsnmp::pdu::VarBind;
use netsnmp_apps::{AppError, CommonOpts, parse_typed_value};
use tracing::info;

/// Set one or more MIB object instances via SNMP SET.
///
/// Common usage (copy a whole line and run it):
///
///   snmpset -v 2c -c private 127.0.0.1:161 sysName.0 s host-a sysContact.0 s ops@example.com
///
/// Typical output (the agent echoes the new values it accepted):
///
///   SNMPv2-MIB::sysName.0 = STRING: host-a
///   SNMPv2-MIB::sysContact.0 = STRING: ops@example.com
#[derive(Parser, Debug)]
#[command(name = "snmpset", about = "Set MIB object instances via SNMP SET")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// `OID TYPE VALUE` triples. TYPE is one of i/u/c/t/a/s/x/o/n.
    #[arg(value_name = "OID TYPE VALUE", required = true)]
    bindings: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    if cli.bindings.is_empty() || cli.bindings.len() % 3 != 0 {
        return Err(AppError::msg("arguments must be OID TYPE VALUE triples"));
    }

    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;
    let mut bindings = Vec::new();
    for triple in cli.bindings.chunks(3) {
        let oid = mib
            .translate(&triple[0])
            .ok_or_else(|| AppError::ParseOid(triple[0].clone()))?;
        let value = parse_typed_value(&triple[1], &triple[2]).map_err(AppError::msg)?;
        bindings.push(VarBind::new(oid, value));
    }

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session: {e}")))?;

    let vars = client.set(bindings).await?;
    for vb in vars {
        info!("{} = {}", mib.format_oid(&vb.oid), vb.value);
    }
    Ok(())
}
