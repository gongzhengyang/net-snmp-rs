//! `snmptrap` — send an SNMP notification (an SNMPv2-Trap or InformRequest).
//!
//! Rust counterpart of `apps/snmptrap.c` (and `snmpinform`). Usage mirrors the
//! v2c/v3 form of the C tool:
//!
//! ```text
//! snmptrap [-v 2c|3 ...] [--inform] RECEIVER UPTIME TRAP-OID [OID TYPE VALUE]...
//! ```
//!
//! The first two notification varbinds (`sysUpTime.0`, `snmpTrapOID.0`) are
//! added automatically; `UPTIME` supplies the former (an empty `''` means 0)
//! and `TRAP-OID` the latter. Any trailing `OID TYPE VALUE` triples are
//! appended, using the same type codes as `snmpset`. The receiver port
//! defaults to 162. SNMPv1 traps are not supported (use `-v 2c`).

use clap::Parser;
use netsnmp::pdu::VarBind;
use netsnmp_apps::{AppError, CommonOpts, parse_typed_value};
use tracing::info;

/// Send an SNMP notification (trap or inform).
///
/// Common usage (copy a whole line and run it):
///
///   snmptrap -v 2c -c public 127.0.0.1:162 '' 1.3.6.1.6.3.1.1.5.1 sysName.0 s host-a
///   snmptrap -v 2c -c public --inform 127.0.0.1:162 2000 coldStart
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
    /// unconfirmed trap.
    #[arg(short = 'i', long = "inform")]
    inform: bool,
    #[command(flatten)]
    common: CommonOpts,
    /// sysUpTime.0 value in timeticks; an empty string `''` means 0.
    #[arg(value_name = "UPTIME")]
    uptime: String,
    /// snmpTrapOID.0 — the notification's identity OID (symbolic or numeric).
    #[arg(value_name = "TRAP-OID")]
    trap_oid: String,
    /// Additional `OID TYPE VALUE` triples (TYPE is one of i/u/c/t/a/s/x/o/n).
    #[arg(value_name = "OID TYPE VALUE")]
    bindings: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let sys_uptime: u32 = if cli.uptime.trim().is_empty() {
        0
    } else {
        cli.uptime
            .trim()
            .parse()
            .map_err(|_| AppError::msg(format!("bad uptime '{}'", cli.uptime)))?
    };
    let trap_oid = mib
        .translate(&cli.trap_oid)
        .ok_or_else(|| AppError::ParseOid(cli.trap_oid.clone()))?;

    if cli.bindings.len() % 3 != 0 {
        return Err(AppError::msg(
            "trailing arguments must be OID TYPE VALUE triples",
        ));
    }
    let mut varbinds = Vec::new();
    for triple in cli.bindings.chunks(3) {
        let oid = mib
            .translate(&triple[0])
            .ok_or_else(|| AppError::ParseOid(triple[0].clone()))?;
        let value = parse_typed_value(&triple[1], &triple[2]).map_err(AppError::msg)?;
        varbinds.push(VarBind::new(oid, value));
    }

    let mut client = netsnmp_apps::connect_notifier(&cli.common.agent, &parsed, cli.inform)
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
