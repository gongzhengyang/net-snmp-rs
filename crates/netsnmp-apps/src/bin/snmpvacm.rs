//! `snmpvacm` — manage VACM access control on a remote agent.
//!
//! Rust counterpart of `apps/snmpvacm.c`. Issues SNMP SETs against the
//! SNMP-VIEW-BASED-ACM-MIB tables. Operations:
//!
//! - `createview NAME SUBTREE [MASK] [included|excluded]`
//! - `deleteview NAME SUBTREE`
//! - `createsec2group MODEL SECNAME GROUP`
//! - `deletesec2group MODEL SECNAME`
//! - `createaccess GROUP CONTEXT MODEL LEVEL READ WRITE NOTIFY`
//! - `deleteaccess GROUP CONTEXT MODEL LEVEL`
//!
//! MODEL is a security model number (1=v1, 2=v2c, 3=usm) and LEVEL is a
//! security level (1=noAuthNoPriv, 2=authNoPriv, 3=authPriv).

use clap::Parser;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp_apps::mgmt::{self, ViewType};
use netsnmp_apps::{AppError, CommonOpts};
use tracing::info;

/// Manage VACM access control on a remote agent.
///
/// Common usage (copy a whole line and run it):
///
///   snmpvacm -v 3 -u admin -a SHA -A adminpass -l authNoPriv 127.0.0.1:161 createview allView 1.3.6.1.2.1 included
///   snmpvacm -v 3 -u admin -a SHA -A adminpass -l authNoPriv 127.0.0.1:161 createsec2group 3 alice readers
///
/// Typical output:
///
///   createview OK (3 object(s) set)
///   createsec2group OK (2 object(s) set)
#[derive(Parser, Debug)]
#[command(
    name = "snmpvacm",
    about = "Manage VACM views and access (SNMP-VIEW-BASED-ACM-MIB)"
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    /// Operation and its arguments (see the tool help for the full list).
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
    let mib = netsnmp_apps::load_mib_registry(&parsed.mib_dirs).await;

    let mut client = netsnmp_apps::connect(&parsed)
        .await
        .map_err(|e| AppError::msg(format!("cannot open session to {}: {e}", parsed.agent)))?;

    let op = cli.op[0].as_str();
    let rest = &cli.op[1..];

    let bindings: Vec<VarBind> = match op {
        "createview" => {
            let name = arg(
                rest,
                0,
                "createview NAME SUBTREE [MASK] [included|excluded]",
            )?;
            let subtree = resolve_oid(&mib, arg(rest, 1, "createview NAME SUBTREE")?)?;
            let mask = match rest.get(2) {
                Some(m) if !is_type_word(m) => parse_hex(m)?,
                _ => Vec::new(),
            };
            let view_type = rest
                .iter()
                .find_map(|w| match w.as_str() {
                    "excluded" => Some(ViewType::Excluded),
                    "included" => Some(ViewType::Included),
                    _ => None,
                })
                .unwrap_or(ViewType::Included);
            mgmt::vacm_create_view(name, &subtree, &mask, view_type)
        }
        "deleteview" => {
            let name = arg(rest, 0, "deleteview NAME SUBTREE")?;
            let subtree = resolve_oid(&mib, arg(rest, 1, "deleteview NAME SUBTREE")?)?;
            vec![mgmt::vacm_delete_view(name, &subtree)]
        }
        "createsec2group" => {
            let model = parse_i64(arg(rest, 0, "createsec2group MODEL SECNAME GROUP")?)?;
            let sec = arg(rest, 1, "createsec2group MODEL SECNAME GROUP")?;
            let group = arg(rest, 2, "createsec2group MODEL SECNAME GROUP")?;
            mgmt::vacm_create_sec2group(model, sec, group)
        }
        "deletesec2group" => {
            let model = parse_i64(arg(rest, 0, "deletesec2group MODEL SECNAME")?)?;
            let sec = arg(rest, 1, "deletesec2group MODEL SECNAME")?;
            vec![mgmt::vacm_delete_sec2group(model, sec)]
        }
        "createaccess" => {
            let group = arg(
                rest,
                0,
                "createaccess GROUP CONTEXT MODEL LEVEL READ WRITE NOTIFY",
            )?;
            let context = arg(rest, 1, "createaccess GROUP CONTEXT MODEL LEVEL ...")?;
            let model = parse_i64(arg(rest, 2, "createaccess ... MODEL ...")?)?;
            let level = parse_i64(arg(rest, 3, "createaccess ... LEVEL ...")?)?;
            let read = arg(rest, 4, "createaccess ... READ WRITE NOTIFY")?;
            let write = arg(rest, 5, "createaccess ... READ WRITE NOTIFY")?;
            let notify = arg(rest, 6, "createaccess ... READ WRITE NOTIFY")?;
            mgmt::vacm_create_access(group, context, model, level, read, write, notify)
        }
        "deleteaccess" => {
            let group = arg(rest, 0, "deleteaccess GROUP CONTEXT MODEL LEVEL")?;
            let context = arg(rest, 1, "deleteaccess GROUP CONTEXT MODEL LEVEL")?;
            let model = parse_i64(arg(rest, 2, "deleteaccess GROUP CONTEXT MODEL LEVEL")?)?;
            let level = parse_i64(arg(rest, 3, "deleteaccess GROUP CONTEXT MODEL LEVEL")?)?;
            vec![mgmt::vacm_delete_access(group, context, model, level)]
        }
        other => {
            return Err(AppError::msg(format!(
                "unknown operation '{other}' (createview|deleteview|createsec2group|\
                 deletesec2group|createaccess|deleteaccess)"
            )));
        }
    };

    let result = client.set(bindings).await?;
    info!("{op} OK ({} object(s) set)", result.len());
    Ok(())
}

fn arg<'a>(rest: &'a [String], i: usize, usage: &str) -> Result<&'a str, AppError> {
    rest.get(i)
        .map(String::as_str)
        .ok_or_else(|| AppError::msg(format!("usage: {usage}")))
}

fn is_type_word(w: &str) -> bool {
    matches!(w, "included" | "excluded")
}

fn parse_i64(s: &str) -> Result<i64, AppError> {
    s.parse()
        .map_err(|_| AppError::msg(format!("expected an integer, got '{s}'")))
}

fn resolve_oid(mib: &netsnmp::mib::MibRegistry, token: &str) -> Result<Oid, AppError> {
    mib.translate(token)
        .ok_or_else(|| AppError::ParseOid(token.to_string()))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, AppError> {
    netsnmp_apps::parse_hex_string(s).map_err(AppError::msg)
}
