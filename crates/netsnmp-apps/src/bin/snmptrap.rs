//! `snmptrap` — send an SNMP notification (a v2c/v3 Trap, an InformRequest,
//! or a legacy SNMPv1 Trap-PDU).
//!
//! Rust counterpart of `apps/snmptrap.c` (and `snmpinform`).
//!
//! For SNMPv2c / SNMPv3 (the default form):
//!
//! ```text
//! snmptrap [-v 2c|3 ...] [--inform] RECEIVER UPTIME TRAP-OID [OID TYPE VALUE]...
//! ```
//!
//! `RECEIVER` is consumed by the shared `CommonOpts` AGENT positional (so it
//! can take the usual `host[:port]` + transport-prefix forms and defaults to
//! port 162 for notifications). The remaining positional `ARGS` are then
//! `UPTIME TRAP-OID [OID TYPE VALUE]...`. The first two notification varbinds
//! (`sysUpTime.0`, `snmpTrapOID.0`) are added automatically; `UPTIME` supplies
//! the former (an empty `''` means 0) and `TRAP-OID` the latter. Any trailing
//! `OID TYPE VALUE` triples are appended, using the same type codes as
//! `snmpset`.
//!
//! For SNMPv1 (the legacy Trap-PDU, RFC 1157):
//!
//! ```text
//! snmptrap -v 1 [-c COMM] RECEIVER ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...
//! ```
//!
//! After `RECEIVER`, the positional `ARGS` are
//! `ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...`.

use clap::Parser;
use netsnmp::pdu::VarBind;
use netsnmp_apps::{AppError, CommonArgs, CommonOpts, parse_typed_value};
use tracing::info;

/// Send an SNMP notification (trap or inform).
///
/// SNMPv2c/v3 common usage (copy a whole line and run it):
///
///   snmptrap -v 2c -c public 127.0.0.1:162 '' 1.3.6.1.6.3.1.1.5.1 sysName.0 s host-a
///   snmptrap -v 2c -c public --inform 127.0.0.1:162 2000 coldStart
///
/// SNMPv1 usage (legacy Trap-PDU):
///
///   snmptrap -v 1 -c public 127.0.0.1:162 1.3.6.1.4.1.8072.2 0.0.0.0 6 1 100 \
///       sysLocation.0 s rack-9
///
/// Typical output:
///
///   trap sent
///   inform acknowledged (request-id 42)
#[derive(Parser, Debug)]
#[command(
    name = "snmptrap",
    about = "Send an SNMP notification (trap or inform)"
)]
struct Cli {
    /// Send a confirmed InformRequest (await an acknowledgement) instead of an
    /// unconfirmed trap. (SNMPv2c/v3 only; ignored for `-v 1`.)
    #[arg(short = 'i', long = "inform")]
    inform: bool,
    #[command(flatten)]
    common: CommonOpts,
    /// Positional arguments. Their meaning depends on the SNMP version:
    ///
    /// * v2c/v3: `RECEIVER UPTIME TRAP-OID [OID TYPE VALUE]...`
    /// * v1: `RECEIVER ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...`
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    if parsed.config.version == netsnmp::Version::V1 {
        send_v1_trap(&cli, &parsed, &mib).await
    } else {
        send_v2_trap(&cli, &parsed, &mib).await
    }
}

/// Parse and send an SNMPv1 Trap-PDU.
///
/// `cli.args` holds everything after the common AGENT positional, i.e.
/// `ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...`; the
/// receiver/agent address itself lives in `parsed.agent` (the `CommonOpts`
/// positional that every network tool consumes first).
async fn send_v1_trap(
    cli: &Cli,
    parsed: &CommonArgs,
    mib: &netsnmp::MibRegistry,
) -> Result<(), AppError> {
    // ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...
    let args = &cli.args;
    if args.len() < 5 {
        return Err(AppError::msg(
            "v1 trap needs (after the AGENT): ENTERPRISE AGENT_ADDR GENERIC SPECIFIC UPTIME [OID TYPE VALUE]...",
        ));
    }
    let enterprise = mib
        .translate(&args[0])
        .ok_or_else(|| AppError::ParseOid(args[0].clone()))?;
    let agent_addr: std::net::Ipv4Addr = args[1]
        .parse()
        .map_err(|_| AppError::msg(format!("bad agent-addr '{}', expect an IPv4", args[1])))?;
    let generic: u8 = args[2]
        .parse()
        .map_err(|_| AppError::msg(format!("bad generic-trap '{}'", args[2])))?;
    let specific: u32 = args[3]
        .parse()
        .map_err(|_| AppError::msg(format!("bad specific-trap '{}'", args[3])))?;
    let uptime: u32 = if args[4].trim().is_empty() {
        0
    } else {
        args[4]
            .trim()
            .parse()
            .map_err(|_| AppError::msg(format!("bad uptime '{}'", args[4])))?
    };

    let triples = &args[5..];
    if triples.len() % 3 != 0 {
        return Err(AppError::msg(
            "trailing arguments must be OID TYPE VALUE triples",
        ));
    }
    let varbinds = parse_varbinds(triples, mib)?;

    let mut client = netsnmp_apps::connect_notifier(&parsed.agent, parsed, false)
        .await
        .map_err(|e| AppError::msg(format!("cannot open notification session: {e}")))?;
    client
        .send_trap_v1(&enterprise, agent_addr, generic, specific, uptime, varbinds)
        .await?;
    info!("v1 trap sent");
    Ok(())
}

/// Parse and send an SNMPv2c/v3 Trap or InformRequest.
///
/// `cli.args` holds everything after the common AGENT positional, i.e.
/// `UPTIME TRAP-OID [OID TYPE VALUE]...`; the receiver/agent address itself
/// lives in `parsed.agent` (the `CommonOpts` positional that every network
/// tool consumes first).
async fn send_v2_trap(
    cli: &Cli,
    parsed: &CommonArgs,
    mib: &netsnmp::MibRegistry,
) -> Result<(), AppError> {
    let args = &cli.args;
    if args.len() < 2 {
        return Err(AppError::msg(
            "trap needs (after the AGENT): UPTIME TRAP-OID [OID TYPE VALUE]...",
        ));
    }
    let sys_uptime: u32 = if args[0].trim().is_empty() {
        0
    } else {
        args[0]
            .trim()
            .parse()
            .map_err(|_| AppError::msg(format!("bad uptime '{}'", args[0])))?
    };
    let trap_oid = mib
        .translate(&args[1])
        .ok_or_else(|| AppError::ParseOid(args[1].clone()))?;

    let triples = &args[2..];
    if triples.len() % 3 != 0 {
        return Err(AppError::msg(
            "trailing arguments must be OID TYPE VALUE triples",
        ));
    }
    let varbinds = parse_varbinds(triples, mib)?;

    let mut client = netsnmp_apps::connect_notifier(&parsed.agent, parsed, cli.inform)
        .await
        .map_err(|e| AppError::msg(format!("cannot open notification session: {e}")))?;

    if cli.inform {
        let resp = client.send_inform(sys_uptime, &trap_oid, varbinds).await?;
        info!("inform acknowledged (request-id {})", resp.request_id);
    } else {
        client.send_trap(sys_uptime, &trap_oid, varbinds).await?;
        info!("trap sent");
    }
    Ok(())
}

/// Parse trailing `OID TYPE VALUE` triples into varbinds.
fn parse_varbinds(
    triples: &[String],
    mib: &netsnmp::MibRegistry,
) -> Result<Vec<VarBind>, AppError> {
    let mut varbinds = Vec::new();
    for triple in triples.chunks(3) {
        let oid = mib
            .translate(&triple[0])
            .ok_or_else(|| AppError::ParseOid(triple[0].clone()))?;
        let value = parse_typed_value(&triple[1], &triple[2]).map_err(AppError::msg)?;
        varbinds.push(VarBind::new(oid, value));
    }
    Ok(varbinds)
}
