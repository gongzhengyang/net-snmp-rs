//! `snmptrapd` — receive and display SNMP notifications (traps and informs).
//!
//! Rust counterpart of `apps/snmptrapd*.c`. It binds a UDP socket and prints
//! every SNMPv2-Trap and InformRequest it receives, acknowledging informs.
//! Community (v1/v2c) notifications are accepted for the configured community;
//! SNMPv3/USM notifications are authenticated/decrypted against a configured
//! user. The default bind address is `127.0.0.1:1162` (the privileged port 162
//! requires elevated rights).

use chrono::Local;
use clap::Parser;
use netsnmp::usm::UsmUser;
use netsnmp_agent::{ReceivedNotification, TrapReceiver, TrapReceiverConfig};
use netsnmp_apps::{AppError, parse_auth_proto, parse_priv_proto};
use std::net::SocketAddr;
use tracing::info;

/// Receive and display SNMP notifications (traps and informs).
///
/// Common usage (copy a whole line and run it; stays in the foreground):
///
///   snmptrapd -c public 127.0.0.1:1162
///
/// Typical output (one block per received notification):
///
///   listening for SNMP notifications on 127.0.0.1:1162
///   notification from 127.0.0.1: v2c community=public
///     DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (2000) 0:00:20.00
///     SNMPv2-MIB::snmpTrapOID.0 = OID: SNMPv2-MIB::coldStart
#[derive(Parser, Debug)]
#[command(
    name = "snmptrapd",
    about = "Receive and display SNMP traps and informs"
)]
struct Cli {
    /// Accepted community string for v1/v2c notifications.
    #[arg(short, long, default_value = "public", env = "SNMP_COMMUNITY")]
    community: String,
    /// SNMPv3/USM user name to accept (enables SNMPv3).
    #[arg(short = 'u', long = "user", env = "SNMP_SECNAME")]
    v3_user: Option<String>,
    /// USM authentication protocol: MD5, SHA or SHA-256.
    #[arg(short = 'a', long = "auth-protocol")]
    auth_protocol: Option<String>,
    /// USM authentication passphrase.
    #[arg(short = 'A', long = "auth-passphrase", env = "SNMP_AUTH_PASSPHRASE")]
    auth_pass: Option<String>,
    /// USM privacy protocol: AES.
    #[arg(short = 'x', long = "priv-protocol")]
    priv_protocol: Option<String>,
    /// USM privacy passphrase.
    #[arg(short = 'X', long = "priv-passphrase", env = "SNMP_PRIV_PASSPHRASE")]
    priv_pass: Option<String>,
    /// MIB directories to load for symbolic output (repeatable / `:`-separated).
    #[arg(short = 'M', long = "mib-dirs", env = "MIBDIRS")]
    mib_dirs: Vec<String>,
    /// Address to bind, e.g. `127.0.0.1:1162` or `0.0.0.0:162`.
    #[arg(value_name = "BIND_ADDR")]
    bind_addr: Option<String>,
}

impl Cli {
    /// Assemble the configured SNMPv3/USM user, if `-u` was given.
    fn v3_user(&self) -> Result<Option<UsmUser>, AppError> {
        let Some(name) = &self.v3_user else {
            return Ok(None);
        };
        let Some(auth_pass) = &self.auth_pass else {
            return Ok(Some(UsmUser::noauth(name)));
        };
        let auth_proto = match &self.auth_protocol {
            Some(p) => parse_auth_proto(p).map_err(|e| AppError::msg(e.to_string()))?,
            None => netsnmp::usm::AuthProtocol::HmacSha1,
        };
        let Some(priv_pass) = &self.priv_pass else {
            return Ok(Some(UsmUser::auth(name, auth_proto, auth_pass)));
        };
        let priv_proto = match &self.priv_protocol {
            Some(p) => parse_priv_proto(p).map_err(|e| AppError::msg(e.to_string()))?,
            None => netsnmp::usm::PrivProtocol::AesCfb128,
        };
        Ok(Some(UsmUser::auth_priv(
            name, auth_proto, auth_pass, priv_proto, priv_pass,
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let v3_user = cli.v3_user()?;
    let mib_dirs: Vec<String> = cli
        .mib_dirs
        .iter()
        .flat_map(|d| netsnmp_apps::split_dir_list(d))
        .collect();
    let mib = netsnmp_apps::load_mib_registry(&mib_dirs).await;

    let mut config = TrapReceiverConfig {
        community: Some(cli.community.clone().into_bytes()),
        users: v3_user.iter().cloned().collect(),
        ..TrapReceiverConfig::default()
    };
    if let Some(addr) = &cli.bind_addr {
        config.bind_addr = addr.clone();
    }

    let receiver = TrapReceiver::new(config.clone());
    let socket = receiver
        .bind()
        .await
        .map_err(|e| AppError::msg(format!("cannot bind {}: {e}", config.bind_addr)))?;

    let community_label = config
        .community
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or(std::borrow::Cow::Borrowed("<any>"));
    info!(
        "net-snmp-rs snmptrapd listening on {} (community '{community_label}')",
        config.bind_addr,
    );
    if let Some(user) = &v3_user {
        info!(
            "SNMPv3 enabled for user '{}' ({:?})",
            user.name,
            user.security_level()
        );
    }

    receiver
        .serve_on(socket, |note, peer| print_notification(&mib, note, peer))
        .await?;
    Ok(())
}

/// Print a received notification in a human-readable, log-style form.
fn print_notification(
    mib: &netsnmp::mib::MibRegistry,
    note: &ReceivedNotification,
    peer: SocketAddr,
) {
    // Local wall-clock receipt time, e.g. "2026-06-03 13:54:07.123".
    let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let kind = if note.confirmed { "INFORM" } else { "TRAP" };
    let security = match &note.security_name {
        Some(name) => format!("v3 user={name}"),
        None => "v1/v2c".to_string(),
    };
    println!("[{now}] {kind} from {peer} [{security}]");
    println!(
        "    sysUpTime.0 = Timeticks: ({})",
        note.notification.sys_uptime
    );
    println!(
        "    snmpTrapOID.0 = {}",
        mib.format_oid(&note.notification.trap_oid)
    );
    for vb in &note.notification.varbinds {
        println!("    {} = {}", mib.format_oid(&vb.oid), vb.value);
    }
}
