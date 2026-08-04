//! `snmpnetstat` — show network connections, netstat-style, over SNMP.
//!
//! Rust counterpart of `apps/snmpnetstat/`. Walks the TCP/UDP-MIB connection
//! tables, the IF-MIB interface table, the IP-FORWARD-MIB route table and the
//! per-protocol statistics groups, printing them in `netstat`-style columns.
//!
//! Modes (mirroring `netstat`):
//!
//! * `-p/--protocol {tcp,udp,all}` — active TCP/UDP connections (default).
//! * `-i` — interface table (`ifTable`).
//! * `-r` — IPv4 routing table (`ipRouteTable`).
//! * `-a` — all sockets (TCP + UDP, including listeners).
//! * `-s` — per-protocol statistics (`ip`/`icmp`/`tcp`/`udp`/`snmp` groups).
//! * `-n` — numeric output (no DNS/port-name resolution; SNMP has no reverse
//!   DNS anyway, so this mainly suppresses the symbolic `State` column).
//! * `-P PROTO` — filter `-a`/`-s` to a single protocol.
//!
//! Missing MIB objects are rendered as `?` (or skipped) rather than crashing,
//! so the tool degrades gracefully against an agent that serves only a subset.

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
///   snmpnetstat -v 2c -c public -i 127.0.0.1:161
///   snmpnetstat -v 2c -c public -s 127.0.0.1:161
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
    about = "Show network connections, interfaces, routes and stats (netstat-style)"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Which protocol's connection table to display (with `-p`).
    #[arg(short = 'p', long = "protocol", value_enum, default_value_t = Proto::All)]
    protocol: Proto,
    /// Show the interface table (`ifTable`).
    #[arg(short = 'i', long = "interfaces")]
    interfaces: bool,
    /// Show the IPv4 routing table (`ipRouteTable`). (Long-only: `-r` is taken
    /// by the common `--retries` option.)
    #[arg(long = "route")]
    route: bool,
    /// Show all sockets (TCP + UDP, including listeners). (Long-only: `-a` is
    /// taken by the common `--auth-protocol` option.)
    #[arg(long = "all")]
    all: bool,
    /// Show per-protocol statistics (ip/icmp/tcp/udp/snmp). (Long-only: `-s` is
    /// taken by the common `--secname` option.)
    #[arg(long = "statistics")]
    statistics: bool,
    /// Numeric output: do not resolve names (SNMP has no reverse DNS; this
    /// mainly suppresses symbolic state labels).
    #[arg(short = 'n', long = "numeric")]
    numeric: bool,
    /// Restrict `-a`/`-s` output to a single protocol (ip/icmp/tcp/udp/snmp).
    #[arg(short = 'P', long = "filter")]
    filter: Option<String>,
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

/// `ifEntry` root (`1.3.6.1.2.1.2.2.1`).
const IF_ENTRY: &str = "1.3.6.1.2.1.2.2.1";
const IF_DESCR: u32 = 2;
const IF_MTU: u32 = 4;
const IF_SPEED: u32 = 5;
const IF_OPER_STATUS: u32 = 8;

/// `ipRouteEntry` root (`1.3.6.1.2.1.4.21.1`).
const IP_ROUTE_ENTRY: &str = "1.3.6.1.2.1.4.21.1";
const RT_DEST: u32 = 1;
const RT_IFINDEX: u32 = 2;
const RT_NEXTHOP: u32 = 7;
const RT_TYPE: u32 = 8;

/// `tcp` group root (`1.3.6.1.2.1.6`): scalar columns like tcpActiveOpens(5).
const TCP_GROUP: &str = "1.3.6.1.2.1.6";
/// `udp` group root (`1.3.6.1.2.1.7`): udpInDatagrams(1), udpOutDatagrams(4).
const UDP_GROUP: &str = "1.3.6.1.2.1.7";
/// `ip` group root (`1.3.6.1.2.1.4`): ipInReceives(3), ipOutRequests(10).
const IP_GROUP: &str = "1.3.6.1.2.1.4";
/// `icmp` group root (`1.3.6.1.2.1.5`): icmpInMsgs(1), icmpOutMsgs(14).
const ICMP_GROUP: &str = "1.3.6.1.2.1.5";
/// `snmp` group root (`1.3.6.1.2.1.11`): snmpInPkts(1), snmpOutPkts(2).
const SNMP_GROUP: &str = "1.3.6.1.2.1.11";

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

    // `-i`/`-r`/`-s` take precedence over the default `-p` connection view.
    if cli.interfaces {
        let mut client = open(&parsed).await?;
        let if_entry: Oid = IF_ENTRY.parse().unwrap();
        let data = table::fetch_table(&mut client, &if_entry, 10).await?;
        for line in render_interfaces(&mib, &if_entry, &data) {
            info!("{line}");
        }
        return Ok(());
    }

    if cli.route {
        let mut client = open(&parsed).await?;
        let rt_entry: Oid = IP_ROUTE_ENTRY.parse().unwrap();
        let data = table::fetch_table(&mut client, &rt_entry, 10).await?;
        for line in render_routes(&mib, &rt_entry, &data) {
            info!("{line}");
        }
        return Ok(());
    }

    if cli.statistics {
        let mut client = open(&parsed).await?;
        for line in render_statistics(&mut client, &cli.filter, cli.numeric).await? {
            info!("{line}");
        }
        return Ok(());
    }

    // Connection view: `-a` implies tcp+udp; otherwise honour `-p` (default All).
    let want_tcp = cli.all || matches!(cli.protocol, Proto::Tcp | Proto::All);
    let want_udp = cli.all || matches!(cli.protocol, Proto::Udp | Proto::All);
    // `-P` filters the connection view by protocol.
    let want_tcp = want_tcp
        && cli
            .filter
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case("tcp"))
            .unwrap_or(true);
    let want_udp = want_udp
        && cli
            .filter
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case("udp"))
            .unwrap_or(true);

    if want_tcp && want_udp {
        let (mut tcp_client, mut udp_client) = tokio::try_join!(open(&parsed), open(&parsed))?;
        let (tcp_data, udp_data) = tokio::try_join!(
            table::fetch_table(&mut tcp_client, &tcp_entry, 10),
            table::fetch_table(&mut udp_client, &udp_entry, 10),
        )?;
        for line in render_tcp(&mib, &tcp_entry, &tcp_data, cli.numeric) {
            info!("{line}");
        }
        for line in render_udp(&udp_data) {
            info!("{line}");
        }
    } else if want_tcp {
        let mut client = open(&parsed).await?;
        let data = table::fetch_table(&mut client, &tcp_entry, 10).await?;
        for line in render_tcp(&mib, &tcp_entry, &data, cli.numeric) {
            info!("{line}");
        }
    } else if want_udp {
        let mut client = open(&parsed).await?;
        let data = table::fetch_table(&mut client, &udp_entry, 10).await?;
        for line in render_udp(&data) {
            info!("{line}");
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

fn render_tcp(
    mib: &netsnmp::mib::MibRegistry,
    entry: &Oid,
    data: &TableData,
    numeric: bool,
) -> Vec<String> {
    let mut out = vec!["Active Internet connections (tcp)".to_string()];
    let header = vec![
        "Proto".to_string(),
        "Local Address".to_string(),
        "Remote Address".to_string(),
        "State".to_string(),
    ];
    let mut rows = Vec::new();
    for (index, cells) in &data.rows {
        let state = if numeric {
            cells
                .get(&TCP_STATE)
                .and_then(value_as_i128)
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string())
        } else {
            cells
                .get(&TCP_STATE)
                .map(|v| table::cell_display(mib, entry, TCP_STATE, index, v))
                .unwrap_or_default()
        };
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

/// Render the interface table (`-i`): Name / MTU / State / Speed. Missing
/// columns are shown as `?` / `0`.
fn render_interfaces(
    mib: &netsnmp::mib::MibRegistry,
    entry: &Oid,
    data: &TableData,
) -> Vec<String> {
    let _ = mib;
    let mut out = vec!["Kernel Interface table".to_string()];
    let header = vec![
        "Name".to_string(),
        "MTU".to_string(),
        "State".to_string(),
        "Speed".to_string(),
    ];
    let mut rows = Vec::new();
    for (_index, cells) in &data.rows {
        let name = cell_string(cells, IF_DESCR);
        let mtu = cells
            .get(&IF_MTU)
            .and_then(value_as_i128)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        let state = match cells.get(&IF_OPER_STATUS) {
            Some(Value::Integer(1)) => "up".to_string(),
            Some(Value::Integer(2)) => "down".to_string(),
            Some(Value::Integer(3)) => "testing".to_string(),
            Some(Value::Integer(n)) => format!("{n}"),
            Some(v) => table::cell_display(mib, entry, IF_OPER_STATUS, &[], v),
            None => "?".to_string(),
        };
        let speed = cells
            .get(&IF_SPEED)
            .and_then(value_as_i128)
            .map(|n| format!("{n}"))
            .unwrap_or_else(|| "?".to_string());
        rows.push(vec![name, mtu, state, speed]);
    }
    out.extend(table::render_grid(&header, &rows));
    out
}

/// Render the IPv4 routing table (`-r`): Destination / Gateway / Flags /
/// Interface. Missing columns are shown as `?`.
fn render_routes(
    mib: &netsnmp::mib::MibRegistry,
    entry: &Oid,
    data: &TableData,
) -> Vec<String> {
    let _ = mib;
    let mut out = vec!["Kernel IP routing table".to_string()];
    let header = vec![
        "Destination".to_string(),
        "Gateway".to_string(),
        "Flags".to_string(),
        "Interface".to_string(),
    ];
    let mut rows = Vec::new();
    for (_index, cells) in &data.rows {
        let dest = ip_cell_string(cells, RT_DEST);
        let gateway = ip_cell_string(cells, RT_NEXTHOP);
        let flags = match cells.get(&RT_TYPE) {
            Some(Value::Integer(3)) => "UG".to_string(), // remote + gateway
            Some(Value::Integer(4)) => "UH".to_string(), // local + host
            Some(Value::Integer(_)) => "U".to_string(),
            Some(v) => table::cell_display(mib, entry, RT_TYPE, &[], v),
            None => "?".to_string(),
        };
        let iface = cells
            .get(&RT_IFINDEX)
            .and_then(value_as_i128)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        rows.push(vec![dest, gateway, flags, iface]);
    }
    out.extend(table::render_grid(&header, &rows));
    out
}

/// Render per-protocol statistics (`-s`): Ip / Icmp / Tcp / Udp / Snmp
/// sections, each listing the scalar counters actually served by the agent.
/// Sections with no data are omitted (graceful degradation).
async fn render_statistics(
    client: &mut netsnmp_apps::Client,
    filter: &Option<String>,
    numeric: bool,
) -> Result<Vec<String>, AppError> {
    let _ = numeric;
    let mut out = Vec::new();
    let wants = |name: &str| -> bool {
        filter
            .as_deref()
            .map(|f| f.eq_ignore_ascii_case(name))
            .unwrap_or(true)
    };
    if wants("ip") {
        if let Some(lines) = stat_section(client, "Ip", IP_GROUP, &[
            (3, "total packets received"),
            (4, "received header errors"),
            (5, "delivered to upper layer"),
            (10, "requests sent out"),
        ])
        .await?
        {
            out.extend(lines);
        }
    }
    if wants("icmp") {
        if let Some(lines) = stat_section(client, "Icmp", ICMP_GROUP, &[
            (1, "input messages"),
            (14, "output messages"),
            (2, "input errors"),
        ])
        .await?
        {
            out.extend(lines);
        }
    }
    if wants("tcp") {
        if let Some(lines) = stat_section(client, "Tcp", TCP_GROUP, &[
            (5, "active opens"),
            (6, "passive opens"),
            (8, "attempt fails"),
            (9, "established resets"),
            (10, "current established conns"),
            (14, "segments received"),
            (15, "segments sent out"),
        ])
        .await?
        {
            out.extend(lines);
        }
    }
    if wants("udp") {
        if let Some(lines) = stat_section(client, "Udp", UDP_GROUP, &[
            (1, "datagrams received"),
            (4, "datagrams sent out"),
            (2, "datagrams to unknown port"),
            (3, "datagram receive errors"),
        ])
        .await?
        {
            out.extend(lines);
        }
    }
    if wants("snmp") {
        if let Some(lines) = stat_section(client, "Snmp", SNMP_GROUP, &[
            (1, "SnmpInPkts"),
            (2, "SnmpOutPkts"),
        ])
        .await?
        {
            out.extend(lines);
        }
    }
    Ok(out)
}

/// Fetch a scalar group (one column per row) and render it as a `Name:`
/// section followed by `    N counter-label` lines. Returns `None` when no
/// scalars were served (so the caller can omit the section).
async fn stat_section(
    client: &mut netsnmp_apps::Client,
    title: &str,
    root: &str,
    columns: &[(u32, &str)],
) -> Result<Option<Vec<String>>, AppError> {
    let root: Oid = root.parse().expect("valid group OID");
    let oids: Vec<Oid> = columns
        .iter()
        .map(|(col, _)| root.child(*col).child(0))
        .collect();
    let vars = client.get(&oids).await.map_err(|e| {
        AppError::msg(format!("statistics GET failed for {title}: {e}"))
    })?;
    let mut lines = vec![format!("{title}:")];
    let mut any = false;
    for (vb, (_, label)) in vars.iter().zip(columns.iter()) {
        if let Some(n) = value_as_i128(&vb.value) {
            lines.push(format!("    {n:>12} {label}"));
            any = true;
        }
    }
    if any {
        Ok(Some(lines))
    } else {
        Ok(None)
    }
}

/// Render an octet-string or integer cell as a display string.
fn cell_string(cells: &std::collections::BTreeMap<u32, Value>, col: u32) -> String {
    match cells.get(&col) {
        Some(Value::OctetString(b)) => String::from_utf8_lossy(b).into_owned(),
        Some(Value::Integer(n)) => n.to_string(),
        _ => "?".to_string(),
    }
}

/// Render an IpAddress / OctetString(4) cell as a dotted-quad, else `?`.
fn ip_cell_string(cells: &std::collections::BTreeMap<u32, Value>, col: u32) -> String {
    match cells.get(&col) {
        Some(Value::IpAddress(ip)) => ip.to_string(),
        Some(Value::OctetString(b)) if b.len() == 4 => {
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        _ => "?".to_string(),
    }
}
