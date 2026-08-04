//! `agentxtrap` — send an AgentX Notify PDU to a master agent.
//!
//! Rust counterpart of `apps/agentxtrap.c`. Connects to an AgentX master agent
//! (default Unix socket `/var/agentx/master`, overridable with `-x`), opens a
//! session, sends a Notify PDU carrying the trap OID plus any trailing varbinds,
//! then closes the session and exits.
//!
//! ```text
//! agentxtrap [-x SOCK] OID [OID TYPE VALUE]...
//! ```
//!
//! The first positional `OID` is the notification's trap OID (it is *not*
//! auto-wrapped with `sysUpTime`/`snmpTrapOID`; that is the master agent's
//! responsibility when it forwards the notification to SNMP managers). Any
//! trailing `OID TYPE VALUE` triples are appended as additional varbinds, using
//! the same type codes as `snmpset`/`snmptrap` (`i`, `u`, `c`, `t`, `a`, `s`,
//! `x`, `o`, `n`).

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp_agent::agentx::{AgentxData, AgentxVarBind, Subagent};
use netsnmp_apps::{AppError, parse_typed_value};

/// Default AgentX master socket path (the net-snmp convention).
const DEFAULT_SOCKET: &str = "/var/agentx/master";

/// Send an AgentX notification to a master agent.
///
/// Typical usage:
///
///   agentxtrap -x /tmp/agentx.sock 1.3.6.1.6.3.1.1.5.1
///   agentxtrap 1.3.6.1.4.1.8072.2.3.0.1 sysLocation.0 s "server room B"
///
/// The tool prints `notification sent` on success and exits 0.
#[derive(Parser, Debug)]
#[command(
    name = "agentxtrap",
    about = "Send an AgentX notification (Notify PDU) to a master agent"
)]
struct Cli {
    /// The master agent's Unix socket path. Defaults to `/var/agentx/master`.
    #[arg(short = 'x', long = "sock", value_name = "SOCK", default_value = DEFAULT_SOCKET)]
    sock: String,
    /// Positional arguments: `TRAP_OID [OID TYPE VALUE]...`. The first OID is
    /// the trap OID; trailing `OID TYPE VALUE` triples are extra varbinds.
    #[arg(value_name = "ARGS")]
    args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();

    if cli.args.is_empty() {
        return Err(AppError::msg(
            "missing trap OID: usage: agentxtrap [-x SOCK] OID [OID TYPE VALUE]...",
        ));
    }

    let mut varbinds: Vec<AgentxVarBind> = Vec::new();
    let mut iter = cli.args.into_iter();
    // First positional is the trap OID, sent as a varbind bound to Null.
    let trap_oid: Oid = iter
        .next()
        .unwrap()
        .parse()
        .map_err(|_| AppError::ParseOid("trap OID".into()))?;
    varbinds.push(AgentxVarBind {
        name: trap_oid,
        data: AgentxData::Null,
    });

    // Trailing triples: OID TYPE VALUE.
    while let Some(oid_str) = iter.next() {
        let type_char = iter.next().ok_or_else(|| {
            AppError::msg(format!("missing TYPE for varbind '{oid_str}'"))
        })?;
        let value_str = iter.next().ok_or_else(|| {
            AppError::msg(format!("missing VALUE for varbind '{oid_str}'"))
        })?;
        let oid: Oid = oid_str
            .parse()
            .map_err(|_| AppError::ParseOid(oid_str.clone()))?;
        let value = parse_typed_value(&type_char, &value_str).map_err(AppError::msg)?;
        varbinds.push(AgentxVarBind {
            name: oid,
            data: data_from_value(&value),
        });
    }

    let mut sub = Subagent::connect_unix(&cli.sock)
        .await
        .map_err(|e| AppError::msg(format!("connect to {}: {e}", cli.sock)))?;
    sub.notify(varbinds)
        .await
        .map_err(|e| AppError::msg(format!("notify failed: {e}")))?;

    println!("notification sent");
    Ok(())
}

/// Map an SNMP [`netsnmp::value::Value`] onto the AgentX wire data type.
fn data_from_value(v: &netsnmp::value::Value) -> AgentxData {
    use netsnmp::value::Value as V;
    match v {
        V::Integer(n) => AgentxData::Integer(*n as i32),
        V::OctetString(b) => AgentxData::OctetString(b.clone()),
        V::Oid(o) => AgentxData::Oid(o.clone()),
        V::IpAddress(ip) => AgentxData::IpAddress(*ip),
        V::Counter32(n) => AgentxData::Counter32(*n),
        V::Gauge32(n) => AgentxData::Gauge32(*n),
        V::TimeTicks(n) => AgentxData::TimeTicks(*n),
        V::Opaque(b) => AgentxData::Opaque(b.clone()),
        V::Counter64(n) => AgentxData::Counter64(*n),
        V::Null => AgentxData::Null,
        // Exception markers have no AgentX representation; carry as Null.
        V::NoSuchObject | V::NoSuchInstance | V::EndOfMibView => AgentxData::Null,
    }
}
