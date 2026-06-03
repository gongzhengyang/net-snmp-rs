//! `snmpdf` — display disk-space usage from the HOST-RESOURCES-MIB.
//!
//! Rust counterpart of `apps/snmpdf.c`. Walks `hrStorageTable` and prints, per
//! storage area, the total/used/available space (in KiB) and percent used,
//! mirroring the local `df` command.

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp_apps::table::{self, TableData, value_as_i128};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Display disk-space usage via the HOST-RESOURCES-MIB.
///
/// Common usage (copy a whole line and run it):
///
///   snmpdf -v 2c -c public 127.0.0.1:161
///
/// Typical output (one row per hrStorageTable entry, sizes in KiB):
///
///   Description  Size (kB)  Used     Available  Used%
///   /            10240000   5120000  5120000    50%
///   /boot        524288     131072   393216     25%
#[derive(Parser, Debug)]
#[command(name = "snmpdf", about = "Display disk-space usage (hrStorageTable)")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

// hrStorageEntry and the columns snmpdf needs.
const HR_STORAGE_ENTRY: &str = "1.3.6.1.2.1.25.2.3.1";
const COL_DESCR: u32 = 3;
const COL_ALLOC_UNITS: u32 = 4;
const COL_SIZE: u32 = 5;
const COL_USED: u32 = 6;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let entry: Oid = HR_STORAGE_ENTRY.parse().expect("valid hrStorageEntry OID");
    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let data = table::fetch_table(&mut client, &entry, 10).await?;
    if data.is_empty() {
        return Err(AppError::msg(
            "no hrStorageTable data returned (is HOST-RESOURCES-MIB supported?)",
        ));
    }
    for line in render(&mib, &entry, &data) {
        info!("{line}");
    }
    Ok(())
}

fn render(mib: &netsnmp::mib::MibRegistry, entry: &Oid, data: &TableData) -> Vec<String> {
    let header = vec![
        "Description".to_string(),
        "Size (kB)".to_string(),
        "Used".to_string(),
        "Available".to_string(),
        "Used%".to_string(),
    ];
    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let descr = cells
            .get(&COL_DESCR)
            .map(|v| table::cell_display(mib, entry, COL_DESCR, index, v))
            .unwrap_or_else(|| table::index_label(index));
        let units = cells
            .get(&COL_ALLOC_UNITS)
            .and_then(value_as_i128)
            .unwrap_or(1)
            .max(1);
        let size = cells
            .get(&COL_SIZE)
            .and_then(value_as_i128)
            .unwrap_or(0)
            .max(0);
        let used = cells
            .get(&COL_USED)
            .and_then(value_as_i128)
            .unwrap_or(0)
            .max(0);

        // Convert "units" to kibibytes; clamp used to size.
        let size_kb = size.saturating_mul(units) / 1024;
        let used_kb = used.min(size).saturating_mul(units) / 1024;
        let avail_kb = size_kb - used_kb;
        let pct = if size > 0 {
            (used.min(size) as f64 / size as f64 * 100.0).round() as i128
        } else {
            0
        };
        rows.push(vec![
            descr,
            size_kb.to_string(),
            used_kb.to_string(),
            avail_kb.to_string(),
            format!("{pct}%"),
        ]);
    }
    table::render_grid(&header, &rows)
}
