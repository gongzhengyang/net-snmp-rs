//! Ad-hoc example: load the real mibs/ directory and probe resolution.
//!
//! Output goes through `tracing`; run with `RUST_LOG=info` (the default) to see
//! it, e.g. `RUST_LOG=info cargo run --example mibload -- ../../mibs`.
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .without_time()
        .with_target(false)
        .init();

    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/home/gong/work/github/net-snmp/mibs".to_string());
    let mut mib = MibRegistry::with_builtins();
    let n = mib.load_dir(&dir).await.expect("load dir");
    info!("objects added: {n}");
    for name in [
        "sysDescr",
        "ifTable",
        "ifEntry",
        "ifOperStatus",
        "ifInOctets",
        "tcpConnState",
        "hrSystemUptime",
        "ipAdEntAddr",
        "snmpInPkts",
        "ifPhysAddress",
        "dot1dBridge",
    ] {
        match mib.name_to_oid(name) {
            Some(oid) => info!("  {name:20} = {oid}"),
            None => info!("  {name:20} = <unresolved>"),
        }
    }
    let oid: Oid = "1.3.6.1.2.1.2.2.1.8.3".parse().unwrap();
    let formatted_oid = mib.format_oid(&oid);
    let formatted_val = mib.format_value(&oid, &Value::Integer(2));
    info!("format_oid  1.3.6.1.2.1.2.2.1.8.3 = {formatted_oid}");
    info!("format_val  ifOperStatus.3 = 2     = {formatted_val}");
}
