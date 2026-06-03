//! `snmptest` — interactive SNMP request console.
//!
//! Rust counterpart of `apps/snmptest.c`. Reads commands from standard input,
//! one per line, and issues the corresponding SNMP request against the agent.
//! Supported line forms:
//!
//! - `OID [OID...]`   — issue the current request type (GET by default).
//! - `$G`             — switch to GET mode.
//! - `$N`             — switch to GETNEXT mode.
//! - `$S OID TYPE VALUE` — issue a SET (TYPE is the `snmpset` type code).
//! - `$q` / `quit`    — exit.
//!
//! On end-of-input the console exits cleanly.

use std::io::Write;

use clap::Parser;
use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp_apps::{AppError, Client, CommonOpts, parse_typed_value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{error, info};

/// Interactive SNMP request console.
///
/// Common usage (pipe commands in, or type them at the prompt):
///
///   printf 'sysDescr.0\n$N\nifDescr\n$q\n' | snmptest -v 2c -c public 127.0.0.1:161
///
/// Typical output ($N switches to GETNEXT; $S sets; $q quits):
///
///   SNMPv2-MIB::sysDescr.0 = STRING: Linux host 6.6.0 x86_64
///   IF-MIB::ifDescr.1 = STRING: lo
#[derive(Parser, Debug)]
#[command(name = "snmptest", about = "Interactive SNMP request console")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
}

#[derive(Copy, Clone, PartialEq)]
enum Mode {
    Get,
    GetNext,
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

    // Read commands asynchronously so waiting for input never blocks the tokio
    // runtime worker (which also drives the SNMP request futures).
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut mode = Mode::Get;
    let mut line = String::new();
    loop {
        prompt(mode);
        line.clear();
        let n = stdin
            .read_line(&mut line)
            .await
            .map_err(|e| AppError::msg(e.to_string()))?;
        if n == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed {
            "$q" | "quit" | "exit" => break,
            "$G" => {
                mode = Mode::Get;
                continue;
            }
            "$N" => {
                mode = Mode::GetNext;
                continue;
            }
            _ => {}
        }
        if let Some(rest) = trimmed.strip_prefix("$S") {
            if let Err(e) = do_set(&mut client, &mib, rest.trim()).await {
                error!("{e}");
            }
            continue;
        }
        if let Err(e) = do_query(&mut client, &mib, mode, trimmed).await {
            error!("{e}");
        }
    }
    Ok(())
}

fn prompt(mode: Mode) {
    let label = match mode {
        Mode::Get => "GET",
        Mode::GetNext => "GETNEXT",
    };
    // Prompt to stderr so piped result parsing on stdout stays clean.
    let _ = write!(std::io::stderr(), "[{label}]> ");
    let _ = std::io::stderr().flush();
}

/// Resolve whitespace-separated tokens to OIDs and run a GET or GETNEXT.
async fn do_query(
    client: &mut Client,
    mib: &MibRegistry,
    mode: Mode,
    line: &str,
) -> Result<(), AppError> {
    let mut oids = Vec::new();
    for token in line.split_whitespace() {
        oids.push(
            mib.translate(token)
                .ok_or_else(|| AppError::ParseOid(token.to_string()))?,
        );
    }
    let vars = match mode {
        Mode::Get => client.get(&oids).await?,
        Mode::GetNext => client.get_next(&oids).await?,
    };
    for vb in vars {
        print_varbind(mib, &vb);
    }
    Ok(())
}

/// Parse `OID TYPE VALUE` and issue a SET.
async fn do_set(client: &mut Client, mib: &MibRegistry, line: &str) -> Result<(), AppError> {
    let mut parts = line.splitn(3, char::is_whitespace);
    let oid_token = parts.next().filter(|s| !s.is_empty());
    let type_code = parts.next();
    let value = parts.next().unwrap_or("");
    let (Some(oid_token), Some(type_code)) = (oid_token, type_code) else {
        return Err(AppError::msg("usage: $S OID TYPE VALUE"));
    };
    let oid: Oid = mib
        .translate(oid_token)
        .ok_or_else(|| AppError::ParseOid(oid_token.to_string()))?;
    let parsed_value = parse_typed_value(type_code, value).map_err(AppError::msg)?;
    let vars = client.set(vec![VarBind::new(oid, parsed_value)]).await?;
    for vb in vars {
        print_varbind(mib, &vb);
    }
    Ok(())
}

fn print_varbind(mib: &MibRegistry, vb: &VarBind) {
    info!(
        "{} = {}",
        mib.format_oid(&vb.oid),
        mib.format_value(&vb.oid, &vb.value)
    );
}
