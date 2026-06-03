//! `snmpusm` — manage USM users on a remote SNMPv3 agent.
//!
//! Rust counterpart of `apps/snmpusm.c`. Issues SNMP SETs against the
//! SNMP-USER-BASED-SM-MIB `usmUserTable`. Operations:
//!
//! - `create USER [TEMPLATE]`  — clone a new user from an existing template
//!   (default template: the session security name `-u`).
//! - `delete USER`             — destroy a user row.
//! - `activate USER`           — set RowStatus to active.
//! - `deactivate USER`         — set RowStatus to notInService.
//! - `changekey USER OLD NEW`  — change a user's authentication key (requires
//!   `-a` to select the auth protocol).
//!
//! Management normally requires a v3 admin session; the agent's engine ID is
//! taken from the v3 handshake, or supplied with `--engine-id <hex>`.

use clap::Parser;
use netsnmp::pdu::VarBind;
use netsnmp_apps::{AppError, CommonOpts, mgmt, parse_auth_proto};
use tracing::info;

/// Manage USM users on a remote agent.
///
/// Common usage (copy a whole line and run it):
///
///   snmpusm -v 3 -u admin -a SHA -A adminpass -l authNoPriv 127.0.0.1:161 create newuser admin
///   snmpusm -v 3 -u admin -a SHA -A adminpass -l authNoPriv 127.0.0.1:161 delete newuser
///
/// Typical output:
///
///   create OK (2 object(s) set)
///   delete OK (1 object(s) set)
#[derive(Parser, Debug)]
#[command(name = "snmpusm", about = "Manage USM users (usmUserTable)")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Override the authoritative engine ID (hex, e.g. `80001f88...`). Defaults
    /// to the engine ID discovered during the v3 handshake.
    #[arg(short = 'e', long = "engine-id", value_name = "HEX")]
    engine_id: Option<String>,
    /// Operation and its arguments: `create USER [TEMPLATE]`, `delete USER`,
    /// `activate USER`, `deactivate USER`, `changekey USER OLD NEW`.
    #[arg(value_name = "OP", required = true)]
    op: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let parsed = cli
        .common
        .resolve_with_defaults(&netsnmp_apps::load_client_defaults().await)?;

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let engine_id = match &cli.engine_id {
        Some(hex) => parse_hex(hex)?,
        None => client
            .engine_id()
            .ok_or_else(|| AppError::msg("engine ID required: use -v 3 or --engine-id <hex>"))?,
    };

    let op = cli.op[0].as_str();
    let rest = &cli.op[1..];
    let session_user = cli.common.user.clone().unwrap_or_default();

    let bindings: Vec<VarBind> = match op {
        "create" => {
            let user = arg(rest, 0, "create USER [TEMPLATE]")?;
            let template = rest.get(1).cloned().unwrap_or(session_user);
            if template.is_empty() {
                return Err(AppError::msg("create needs a TEMPLATE user (or set -u)"));
            }
            mgmt::usm_create(&engine_id, user, &template)
        }
        "delete" => {
            let user = arg(rest, 0, "delete USER")?;
            vec![mgmt::usm_set_status(
                &engine_id,
                user,
                mgmt::row_status::DESTROY,
            )]
        }
        "activate" => {
            let user = arg(rest, 0, "activate USER")?;
            vec![mgmt::usm_set_status(
                &engine_id,
                user,
                mgmt::row_status::ACTIVE,
            )]
        }
        "deactivate" => {
            let user = arg(rest, 0, "deactivate USER")?;
            vec![mgmt::usm_set_status(
                &engine_id,
                user,
                mgmt::row_status::NOT_IN_SERVICE,
            )]
        }
        "changekey" => {
            let user = arg(rest, 0, "changekey USER OLD NEW")?;
            let old = arg(rest, 1, "changekey USER OLD NEW")?;
            let new = arg(rest, 2, "changekey USER OLD NEW")?;
            let proto_token = cli
                .common
                .auth_protocol
                .clone()
                .ok_or_else(|| AppError::msg("changekey requires -a <auth protocol>"))?;
            let proto = parse_auth_proto(&proto_token)?;
            // Fresh random material for the KeyChange value.
            use rand::Rng;
            let mut random = vec![0u8; 32];
            rand::rng().fill_bytes(&mut random);
            let value = proto.key_change(old.as_bytes(), new.as_bytes(), &engine_id, &random);
            // usmUserAuthKeyChange is column 6.
            vec![mgmt::usm_key_change(&engine_id, user, 6, value)]
        }
        other => {
            return Err(AppError::msg(format!(
                "unknown operation '{other}' (create|delete|activate|deactivate|changekey)"
            )));
        }
    };

    let result = client.set(bindings).await?;
    info!("{op} OK ({} object(s) set)", result.len());
    Ok(())
}

/// Fetch a required positional argument or report the usage string.
fn arg<'a>(rest: &'a [String], i: usize, usage: &str) -> Result<&'a str, AppError> {
    rest.get(i)
        .map(String::as_str)
        .ok_or_else(|| AppError::msg(format!("usage: {usage}")))
}

/// Parse a hex string (optionally with whitespace) into bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, AppError> {
    netsnmp_apps::parse_hex_string(s).map_err(AppError::msg)
}
