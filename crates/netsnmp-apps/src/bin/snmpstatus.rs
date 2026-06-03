//! `snmpstatus` — retrieve a concise device status summary.
//!
//! Rust counterpart of `apps/snmpstatus.c`. Issues a single GET for a handful
//! of well-known SNMPv2-MIB / IF-MIB / IP-MIB scalars and prints a two-line
//! summary: the system description and uptime, then interface and packet
//! counters. Missing objects are reported as `?`.

use std::collections::HashMap;

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Retrieve a concise device status summary.
///
/// Common usage (copy a whole line and run it):
///
///   snmpstatus -v 2c -c public 127.0.0.1:161
///
/// Typical output (system description + uptime, then interface/packet counters):
///
///   [127.0.0.1:161]=>[Linux host 6.6.0 x86_64] Up: Timeticks: (123456) 0:20:34.56
///   Interfaces: 2, Recv/Trans packets: 1048/972 | IP: 880/640
#[derive(Parser, Debug)]
#[command(
    name = "snmpstatus",
    about = "Retrieve a concise device status summary"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const IF_NUMBER: &str = "1.3.6.1.2.1.2.1.0";
const SNMP_IN_PKTS: &str = "1.3.6.1.2.1.11.1.0";
const SNMP_OUT_PKTS: &str = "1.3.6.1.2.1.11.2.0";
const IP_IN_RECEIVES: &str = "1.3.6.1.2.1.4.3.0";
const IP_OUT_REQUESTS: &str = "1.3.6.1.2.1.4.10.0";

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let oid_strs = [
        SYS_DESCR,
        SYS_UPTIME,
        IF_NUMBER,
        SNMP_IN_PKTS,
        SNMP_OUT_PKTS,
        IP_IN_RECEIVES,
        IP_OUT_REQUESTS,
    ];
    let oids: Vec<Oid> = oid_strs
        .iter()
        .map(|s| s.parse().expect("valid status OID"))
        .collect();

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let vars = client.get(&oids).await?;
    let mut values: HashMap<Oid, Value> = HashMap::new();
    for vb in vars {
        values.insert(vb.oid, vb.value);
    }
    let get = |key: &str| -> Option<&Value> {
        let oid: Oid = key.parse().ok()?;
        values.get(&oid).filter(|v| present(v))
    };

    let descr = get(SYS_DESCR)
        .map(|v| mib.format_value(&SYS_DESCR.parse().unwrap(), v))
        .unwrap_or_else(|| "?".to_string());
    let uptime = get(SYS_UPTIME)
        .map(|v| mib.format_value(&SYS_UPTIME.parse().unwrap(), v))
        .unwrap_or_else(|| "?".to_string());

    info!("[{}]=>[{descr}] Up: {uptime}", parsed.agent);
    info!(
        "Interfaces: {}, Recv/Trans packets: {}/{} | IP: {}/{}",
        scalar(get(IF_NUMBER)),
        scalar(get(SNMP_IN_PKTS)),
        scalar(get(SNMP_OUT_PKTS)),
        scalar(get(IP_IN_RECEIVES)),
        scalar(get(IP_OUT_REQUESTS)),
    );
    Ok(())
}

/// Whether a varbind value is a real reading (not an SNMPv2 exception/Null).
fn present(value: &Value) -> bool {
    !matches!(
        value,
        Value::Null | Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
    )
}

/// Render a counter/integer scalar, or `?` if absent.
fn scalar(value: Option<&Value>) -> String {
    match value.and_then(netsnmp_apps::table::value_as_i128) {
        Some(n) => n.to_string(),
        None => "?".to_string(),
    }
}
