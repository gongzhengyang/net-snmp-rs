//! `snmptable` — fetch a conceptual MIB table and display it as a grid.
//!
//! Rust counterpart of `apps/snmptable.c`. Walks the table's entry, groups the
//! returned cells by row index, and prints one row per instance with a column
//! header. Without full INDEX metadata from the MIB, the row index is shown as
//! a leading `index` column.

use clap::Parser;
use netsnmp_apps::table::{self, TableData};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Display a MIB table in tabular form.
///
/// Common usage (copy a whole line and run it):
///
///   snmptable -v 2c -c public 127.0.0.1:161 ifTable
///
/// Typical output (one row per table index, columns aligned):
///
///   SNMP table: IF-MIB::ifTable
///   index  ifIndex  ifDescr  ifType
///   1      1        lo       softwareLoopback(24)
///   2      2        eth0     ethernetCsmacd(6)
#[derive(Parser, Debug)]
#[command(name = "snmptable", about = "Display a MIB table in tabular form")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Maximum repetitions per GETBULK request.
    #[arg(long = "max-repetitions", value_name = "N", default_value_t = 10)]
    max_repetitions: u32,
    /// Table object identifier (symbolic name such as `ifTable`, or numeric).
    #[arg(value_name = "TABLE")]
    table: String,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;

    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;
    let oid = mib
        .translate(&cli.table)
        .ok_or_else(|| AppError::ParseOid(cli.table.clone()))?;

    // If the user named a `*Table`, descend to its single `Entry` child (`.1`);
    // otherwise treat the given OID as the entry directly.
    let name = mib.format_oid(&oid);
    let entry = if name.to_ascii_lowercase().ends_with("table") {
        oid.child(1)
    } else {
        oid.clone()
    };

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let data = table::fetch_table(&mut client, &entry, cli.max_repetitions).await?;
    info!("SNMP table: {name}");
    if data.is_empty() {
        info!("(table is empty)");
        return Ok(());
    }
    for line in render(&mib, &data) {
        info!("{line}");
    }
    Ok(())
}

/// Build the header + body lines for the fetched table.
fn render(mib: &netsnmp::mib::MibRegistry, data: &TableData) -> Vec<String> {
    let mut header = vec!["index".to_string()];
    for &col in &data.columns {
        header.push(table::column_label(mib, &data.entry, col));
    }
    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let mut row = vec![table::index_label(index)];
        for &col in &data.columns {
            let cell = cells
                .get(&col)
                .map(|v| table::cell_display(mib, &data.entry, col, index, v))
                .unwrap_or_else(|| "?".to_string());
            row.push(cell);
        }
        rows.push(row);
    }
    table::render_grid(&header, &rows)
}
