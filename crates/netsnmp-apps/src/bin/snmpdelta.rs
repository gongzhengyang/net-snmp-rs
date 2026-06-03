//! `snmpdelta` — monitor the change in integer/counter objects over time.
//!
//! Rust counterpart of `apps/snmpdelta.c`. Periodically GETs the requested
//! objects and reports the difference from the previous poll (with Counter32
//! wrap handling), optionally as a per-second rate. Runs `--iterations` times
//! (0 = forever) at `--period` second intervals.

use std::collections::HashMap;
use std::time::Duration;

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_apps::table::value_as_i128;
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

const COUNTER32_MOD: i128 = 1 << 32;

/// Monitor the delta of counter/integer objects over time.
///
/// Common usage (copy a whole line and run it):
///
///   snmpdelta -v 2c -c public --period 5 --iterations 3 --rate 127.0.0.1:161 ifInOctets.2
///
/// Typical output (one block per polling period; here every 5 seconds):
///
///   IF-MIB::ifInOctets.2 = 1240 (248.00/sec)
///   IF-MIB::ifInOctets.2 = 980 (196.00/sec)
///   IF-MIB::ifInOctets.2 = 1503 (300.60/sec)
#[derive(Parser, Debug)]
#[command(name = "snmpdelta", about = "Monitor object value deltas over time")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Seconds between polls.
    #[arg(long = "period", value_name = "SECS", default_value_t = 1)]
    period: u64,
    /// Number of delta reports to print (0 = run until interrupted).
    #[arg(long = "iterations", value_name = "N", default_value_t = 0)]
    iterations: u64,
    /// Also print the per-second rate alongside each delta.
    #[arg(long = "rate")]
    rate: bool,
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
        oids.push(
            mib.translate(token)
                .ok_or_else(|| AppError::ParseOid(token.clone()))?,
        );
    }

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let period = Duration::from_secs(cli.period.max(1));
    let mut previous: HashMap<Oid, i128> = HashMap::new();

    // First poll establishes the baseline; subsequent polls report deltas.
    record_baseline(&client.get(&oids).await?, &mut previous);

    let mut reports = 0u64;
    loop {
        tokio::time::sleep(period).await;
        let vars = client.get(&oids).await?;
        for vb in &vars {
            let Some(now) = value_as_i128(&vb.value) else {
                continue;
            };
            if let Some(prev) = previous.get(&vb.oid) {
                let mut delta = now - prev;
                // Handle Counter32 wraparound.
                if delta < 0 && matches!(vb.value, Value::Counter32(_)) {
                    delta += COUNTER32_MOD;
                }
                let name = mib.format_oid(&vb.oid);
                if cli.rate {
                    let per_sec = delta as f64 / cli.period.max(1) as f64;
                    info!("{name} = {delta} ({per_sec:.2}/sec)");
                } else {
                    info!("{name} = {delta}");
                }
            }
            previous.insert(vb.oid.clone(), now);
        }
        reports += 1;
        if cli.iterations != 0 && reports >= cli.iterations {
            break;
        }
    }
    Ok(())
}

/// Seed the per-OID baseline from the first poll's varbinds.
fn record_baseline(vars: &[netsnmp::pdu::VarBind], previous: &mut HashMap<Oid, i128>) {
    for vb in vars {
        if let Some(now) = value_as_i128(&vb.value) {
            previous.insert(vb.oid.clone(), now);
        }
    }
}
