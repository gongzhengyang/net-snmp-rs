//! `snmpps` — list running processes from the HOST-RESOURCES-MIB.
//!
//! Rust counterpart of `apps/snmpps.c`. Walks `hrSWRunTable` and prints, per
//! process, its index (PID), name, run status and path, mirroring `ps`.
//!
//! Flags:
//!
//! * `-c/--cmdline` — include the full command line (`hrSWRunPath` +
//!   `hrSWRunParameters`).
//! * `-w/--wide` — wide output: include `hrSWRunPerfCPU` and `hrSWRunPerfMem`
//!   (CPU% and memory kB) from the `hrSWRunPerf` table.
//! * positional `pid` — restrict the listing to a single PID by fetching that
//!   one row's cells directly (GET) rather than walking the whole table.

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_apps::table::{self, TableData};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// List running processes via the HOST-RESOURCES-MIB.
///
/// Common usage (copy a whole line and run it):
///
///   snmpps -v 2c -c public 127.0.0.1:161
///   snmpps -v 2c -c public -w 127.0.0.1:161
///   snmpps -v 2c -c public 127.0.0.1:161 2
///
/// Typical output (one row per hrSWRunTable entry):
///
///   PID   Name  Status   Type            Path
///   1     init  running  application(4)  /sbin/init
///   842   sshd  running  application(4)  /usr/sbin/sshd
#[derive(Parser, Debug)]
#[command(name = "snmpps", about = "List running processes (hrSWRunTable)")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Show the full command line (path + parameters). (Long-only: `-c` is
    /// taken by the common `--community` option.)
    #[arg(long = "cmdline")]
    cmdline: bool,
    /// Wide output: include CPU% and memory (hrSWRunPerfCPU/Mem).
    #[arg(short = 'w', long = "wide")]
    wide: bool,
    /// Restrict the listing to this single PID (fetched via GET, not a walk).
    pid: Option<u32>,
}

const HR_SW_RUN_ENTRY: &str = "1.3.6.1.2.1.25.4.2.1";
const COL_NAME: u32 = 2;
const COL_PATH: u32 = 4;
const COL_PARAMS: u32 = 5;
const COL_TYPE: u32 = 6;
const COL_STATUS: u32 = 7;

/// `hrSWRunPerfEntry` root (`1.3.6.1.2.1.25.5.1.1`).
const HR_SW_RUN_PERF_ENTRY: &str = "1.3.6.1.2.1.25.5.1.1";
const COL_PERF_CPU: u32 = 1;
const COL_PERF_MEM: u32 = 2;

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

    // Fetch the perf table only when `-w` was requested.
    let perf_data = if cli.wide {
        let perf_entry: Oid = HR_SW_RUN_PERF_ENTRY.parse().expect("valid perf OID");
        Some(table::fetch_table(&mut client, &perf_entry, 10).await?)
    } else {
        None
    };

    let data = if let Some(pid) = cli.pid {
        fetch_single_pid(&mut client, &entry, pid).await?
    } else {
        table::fetch_table(&mut client, &entry, 10).await?
    };

    if data.is_empty() {
        if cli.pid.is_some() {
            return Err(AppError::msg(format!(
                "no hrSWRunTable row for pid {}",
                cli.pid.unwrap()
            )));
        }
        return Err(AppError::msg(
            "no hrSWRunTable data returned (is HOST-RESOURCES-MIB supported?)",
        ));
    }
    for line in render(&mib, &entry, &data, perf_data.as_ref(), cli.cmdline) {
        info!("{line}");
    }
    Ok(())
}

/// Fetch a single PID's row via GET (one request per column) rather than
/// walking the whole table. Builds a [`TableData`] with one row.
async fn fetch_single_pid(
    client: &mut netsnmp_apps::Client,
    entry: &Oid,
    pid: u32,
) -> Result<TableData, AppError> {
    let index = vec![pid];
    let columns = [COL_NAME, COL_PATH, COL_PARAMS, COL_TYPE, COL_STATUS];
    let oids: Vec<Oid> = columns
        .iter()
        .map(|col| table::cell_oid(entry, *col, &index))
        .collect();
    let vars = client
        .get(&oids)
        .await
        .map_err(|e| AppError::msg(format!("GET for pid {pid} failed: {e}")))?;
    let mut row: std::collections::BTreeMap<u32, Value> = std::collections::BTreeMap::new();
    for (vb, col) in vars.iter().zip(columns.iter()) {
        // Skip exception values so missing columns render as empty.
        if !matches!(
            vb.value,
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView | Value::Null
        ) {
            row.insert(*col, vb.value.clone());
        }
    }
    let mut rows: std::collections::BTreeMap<Vec<u32>, std::collections::BTreeMap<u32, Value>> =
        std::collections::BTreeMap::new();
    if !row.is_empty() {
        rows.insert(index, row);
    }
    Ok(TableData {
        entry: entry.clone(),
        columns: columns.to_vec(),
        rows,
    })
}

fn render(
    mib: &netsnmp::mib::MibRegistry,
    entry: &Oid,
    data: &TableData,
    perf: Option<&TableData>,
    cmdline: bool,
) -> Vec<String> {
    let mut header = vec![
        "PID".to_string(),
        "Name".to_string(),
        "Status".to_string(),
    ];
    if perf.is_some() {
        header.push("CPU%".to_string());
        header.push("MEM".to_string());
    }
    header.push("Type".to_string());
    if cmdline {
        header.push("Command".to_string());
    } else {
        header.push("Path".to_string());
    }

    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let cell = |col: u32| -> String {
            cells
                .get(&col)
                .map(|v| table::cell_display(mib, entry, col, index, v))
                .unwrap_or_default()
        };
        let mut row = vec![
            table::index_label(index),
            cell(COL_NAME),
            cell(COL_STATUS),
        ];
        if let Some(perf_data) = perf {
            row.push(perf_cell(perf_data, index, COL_PERF_CPU));
            row.push(perf_cell(perf_data, index, COL_PERF_MEM));
        }
        row.push(cell(COL_TYPE));
        if cmdline {
            row.push(command_line(cells, COL_PATH, COL_PARAMS));
        } else {
            row.push(cell(COL_PATH));
        }
        rows.push(row);
    }
    table::render_grid(&header, &rows)
}

/// Render a `hrSWRunPerf` cell for the given row index, looking it up in the
/// perf table data. Returns `?` when the perf row is absent.
fn perf_cell(perf: &TableData, index: &[u32], col: u32) -> String {
    perf.rows
        .get(index)
        .and_then(|cells| cells.get(&col))
        .and_then(table::value_as_i128)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Compose the full command line from `hrSWRunPath` and `hrSWRunParameters`.
fn command_line(
    cells: &std::collections::BTreeMap<u32, Value>,
    path_col: u32,
    params_col: u32,
) -> String {
    let path = match cells.get(&path_col) {
        Some(Value::OctetString(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    };
    let params = match cells.get(&params_col) {
        Some(Value::OctetString(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    };
    if params.is_empty() {
        path
    } else {
        format!("{path} {params}")
    }
}
