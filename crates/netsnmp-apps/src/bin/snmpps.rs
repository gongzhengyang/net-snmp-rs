//! `snmpps` — list running processes from the HOST-RESOURCES-MIB.
//!
//! Rust counterpart of `apps/snmpps.c`. Walks `hrSWRunTable` and prints, per
//! process, its index (PID), name, run status and path, mirroring `ps`.

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp_apps::table::{self, TableData};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// List running processes via the HOST-RESOURCES-MIB.
///
/// Common usage (copy a whole line and run it):
///
///   snmpps -v 2c -c public 127.0.0.1:161
///
/// Typical output (one row per hrSWRunTable entry):
///
///   PID   Name  Status   Type            Path
///   1     init  running  application(4)  /sbin/init
///   842   sshd  running  application(4)  /usr/sbin/sshd
///   1001  bash  running  application(4)  /bin/bash
#[derive(Parser, Debug)]
#[command(name = "snmpps", about = "List running processes (hrSWRunTable)")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

const HR_SW_RUN_ENTRY: &str = "1.3.6.1.2.1.25.4.2.1";
const COL_NAME: u32 = 2;
const COL_PATH: u32 = 4;
const COL_TYPE: u32 = 6;
const COL_STATUS: u32 = 7;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let entry: Oid = HR_SW_RUN_ENTRY.parse().expect("valid hrSWRunEntry OID");
    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let data = table::fetch_table(&mut client, &entry, 10).await?;
    if data.is_empty() {
        return Err(AppError::msg(
            "no hrSWRunTable data returned (is HOST-RESOURCES-MIB supported?)",
        ));
    }
    for line in render(&mib, &entry, &data) {
        info!("{line}");
    }
    Ok(())
}

fn render(mib: &netsnmp::mib::MibRegistry, entry: &Oid, data: &TableData) -> Vec<String> {
    let header = vec![
        "PID".to_string(),
        "Name".to_string(),
        "Status".to_string(),
        "Type".to_string(),
        "Path".to_string(),
    ];
    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let cell = |col: u32| -> String {
            cells
                .get(&col)
                .map(|v| table::cell_display(mib, entry, col, index, v))
                .unwrap_or_default()
        };
        rows.push(vec![
            table::index_label(index),
            cell(COL_NAME),
            cell(COL_STATUS),
            cell(COL_TYPE),
            cell(COL_PATH),
        ]);
    }
    table::render_grid(&header, &rows)
}
