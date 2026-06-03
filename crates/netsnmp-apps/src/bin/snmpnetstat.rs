//! `snmpnetstat` — show network connections, netstat-style, over SNMP.
//!
//! Rust counterpart of `apps/snmpnetstat/`. Walks `tcpConnTable` and `udpTable`
//! from the TCP/UDP-MIB and prints active connections and listeners. Use
//! `--protocol tcp|udp` to restrict the output (default: both).

use clap::{Parser, ValueEnum};
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use netsnmp_apps::table::{self, TableData, value_as_i128};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Show network connections over SNMP (netstat-style).
///
/// Common usage (copy a whole line and run it):
///
///   snmpnetstat -v 2c -c public --protocol tcp 127.0.0.1:161
///
/// Typical output (TCP connection table; use --protocol udp for listeners):
///
///   Active Internet connections (tcp)
///   Proto  Local Address  Remote Address  State
///   tcp    127.0.0.1:22   0.0.0.0:0       2
///   tcp    127.0.0.1:80   10.0.0.5:51514  5
#[derive(Parser, Debug)]
#[command(
    name = "snmpnetstat",
    about = "Show network connections (tcp/udp tables)"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Which protocol's table to display.
    #[arg(short = 'p', long = "protocol", value_enum, default_value_t = Proto::All)]
    protocol: Proto,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Proto {
    Tcp,
    Udp,
    All,
}

const TCP_CONN_ENTRY: &str = "1.3.6.1.2.1.6.13.1";
const TCP_STATE: u32 = 1;
const TCP_LOCAL_ADDR: u32 = 2;
const TCP_LOCAL_PORT: u32 = 3;
const TCP_REM_ADDR: u32 = 4;
const TCP_REM_PORT: u32 = 5;

const UDP_ENTRY: &str = "1.3.6.1.2.1.7.5.1";
const UDP_LOCAL_ADDR: u32 = 1;
const UDP_LOCAL_PORT: u32 = 2;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let tcp_entry: Oid = TCP_CONN_ENTRY.parse().unwrap();
    let udp_entry: Oid = UDP_ENTRY.parse().unwrap();

    match cli.protocol {
        Proto::Tcp => {
            let mut client = open(&parsed).await?;
            let data = table::fetch_table(&mut client, &tcp_entry, 10).await?;
            for line in render_tcp(&mib, &tcp_entry, &data) {
                info!("{line}");
            }
        }
        Proto::Udp => {
            let mut client = open(&parsed).await?;
            let data = table::fetch_table(&mut client, &udp_entry, 10).await?;
            for line in render_udp(&data) {
                info!("{line}");
            }
        }
        // Default: the TCP and UDP walks are independent, so fetch them
        // concurrently over two sessions (SNMP over UDP is connectionless).
        Proto::All => {
            let (mut tcp_client, mut udp_client) = tokio::try_join!(open(&parsed), open(&parsed))?;
            let (tcp_data, udp_data) = tokio::try_join!(
                table::fetch_table(&mut tcp_client, &tcp_entry, 10),
                table::fetch_table(&mut udp_client, &udp_entry, 10),
            )?;
            for line in render_tcp(&mib, &tcp_entry, &tcp_data) {
                info!("{line}");
            }
            for line in render_udp(&udp_data) {
                info!("{line}");
            }
        }
    }
    Ok(())
}

/// Open a client session, mapping connection failure to a friendly error.
async fn open(parsed: &netsnmp_apps::CommonArgs) -> Result<netsnmp_apps::Client, AppError> {
    netsnmp_apps::connect(parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))
}

/// Format an `address:port` endpoint from a row's cells.
fn endpoint(
    cells: &std::collections::BTreeMap<u32, Value>,
    addr_col: u32,
    port_col: u32,
) -> String {
    let addr = match cells.get(&addr_col) {
        Some(Value::IpAddress(ip)) => ip.to_string(),
        Some(Value::OctetString(b)) if b.len() == 4 => {
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        _ => "*".to_string(),
    };
    let port = cells
        .get(&port_col)
        .and_then(value_as_i128)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "*".to_string());
    format!("{addr}:{port}")
}

fn render_tcp(mib: &netsnmp::mib::MibRegistry, entry: &Oid, data: &TableData) -> Vec<String> {
    let mut out = vec!["Active Internet connections (tcp)".to_string()];
    let header = vec![
        "Proto".to_string(),
        "Local Address".to_string(),
        "Remote Address".to_string(),
        "State".to_string(),
    ];
    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let state = cells
            .get(&TCP_STATE)
            .map(|v| table::cell_display(mib, entry, TCP_STATE, index, v))
            .unwrap_or_default();
        rows.push(vec![
            "tcp".to_string(),
            endpoint(cells, TCP_LOCAL_ADDR, TCP_LOCAL_PORT),
            endpoint(cells, TCP_REM_ADDR, TCP_REM_PORT),
            state,
        ]);
    }
    out.extend(table::render_grid(&header, &rows));
    out
}

fn render_udp(data: &TableData) -> Vec<String> {
    let mut out = vec!["Active Internet connections (udp)".to_string()];
    let header = vec!["Proto".to_string(), "Local Address".to_string()];
    let mut rows = Vec::new();
    for cells in data.rows.values() {
        rows.push(vec![
            "udp".to_string(),
            endpoint(cells, UDP_LOCAL_ADDR, UDP_LOCAL_PORT),
        ]);
    }
    out.extend(table::render_grid(&header, &rows));
    out
}
