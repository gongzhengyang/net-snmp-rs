//! `snmpd` — a minimal SNMP agent daemon serving live system data.
//!
//! Rust counterpart of `agent/snmpd.c`. It registers the mibII system group,
//! IF-MIB interfaces and a HOST-RESOURCES subset, all backed by real
//! operating-system data (`/proc`, `/sys`), and serves community-based and
//! SNMPv3/USM requests over UDP. Settings come from `snmpd.conf`
//! (`rocommunity`, `sysLocation`, `createUser`, …) and may be overridden on the
//! command line.

use clap::Parser;
use netsnmp::usm::UsmUser;
use netsnmp_agent::{Agent, AgentConfig, Registry, SystemMibConfig};
use netsnmp_apps::{AppError, SnmpdSettings, parse_auth_proto, parse_priv_proto};
use std::time::Instant;
use tracing::{info, warn};

/// A minimal SNMP agent daemon serving live system data.
///
/// Common usage (copy a whole line and run it; stays in the foreground):
///
///   snmpd -c public --sys-location 'Rack 9' 127.0.0.1:1161
///
/// Typical output, then query it from another shell with snmpget/snmpwalk:
///
///   snmpd listening on 127.0.0.1:1161 (community-based v1/v2c)
///   registered mibII system / IF-MIB / HOST-RESOURCES modules
///   $ snmpget -c public 127.0.0.1:1161 sysLocation.0
///   SNMPv2-MIB::sysLocation.0 = STRING: Rack 9
#[derive(Parser, Debug)]
#[command(
    name = "snmpd",
    about = "Minimal SNMP agent serving live mibII/IF-MIB/HOST-RESOURCES data"
)]
struct Cli {
    /// Read/write community (overrides snmpd.conf rocommunity/rwcommunity).
    #[arg(short, long, env = "SNMP_COMMUNITY")]
    community: Option<String>,
    /// Value to report for sysContact.0 (overrides snmpd.conf sysContact).
    #[arg(long = "sys-contact")]
    sys_contact: Option<String>,
    /// Value to report for sysLocation.0 (overrides snmpd.conf sysLocation).
    #[arg(long = "sys-location")]
    sys_location: Option<String>,
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
    /// Address to bind, e.g. `127.0.0.1:1161` or `0.0.0.0:161` (overrides
    /// snmpd.conf agentAddress).
    #[arg(value_name = "BIND_ADDR")]
    bind_addr: Option<String>,
}

impl Cli {
    /// Assemble the configured SNMPv3/USM user, if `-u` was given.
    fn v3_user(&self) -> Result<Option<UsmUser>, AppError> {
        let Some(name) = &self.v3_user else {
            return Ok(None);
        };
        // No auth passphrase: a noAuthNoPriv user.
        let Some(auth_pass) = &self.auth_pass else {
            return Ok(Some(UsmUser::noauth(name)));
        };
        let auth_proto = match &self.auth_protocol {
            Some(p) => parse_auth_proto(p).map_err(|e| AppError::msg(e.to_string()))?,
            None => netsnmp::usm::AuthProtocol::HmacSha1,
        };
        // No privacy passphrase: authNoPriv.
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

fn build_registry(mib_config: SystemMibConfig) -> Registry {
    let mut reg = Registry::new();
    netsnmp_agent::register_system_mibs(&mut reg, &mib_config);
    reg
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();

    // snmpd.conf provides the baseline; command-line options override it.
    let settings = netsnmp_apps::load_snmpd_settings().await.unwrap_or_else(|e| {
        warn!("ignoring snmpd.conf: {e}");
        SnmpdSettings::default()
    });

    let cli_user = cli.v3_user()?;

    // Defaults: CLI > snmpd.conf > built-in.
    let defaults = AgentConfig::default();
    let community = cli
        .community
        .clone()
        .or_else(|| settings.community.clone())
        .map(String::into_bytes)
        .unwrap_or(defaults.community);
    let contact = cli
        .sys_contact
        .clone()
        .or_else(|| settings.sys_contact.clone())
        .unwrap_or_else(|| "Me <me@example.org>".to_string());
    let location = cli
        .sys_location
        .clone()
        .or_else(|| settings.sys_location.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let bind_addr = cli
        .bind_addr
        .clone()
        .or_else(|| settings.agent_address.clone())
        .unwrap_or(defaults.bind_addr);

    // USM users: those from snmpd.conf `createUser` plus the CLI `-u` user.
    let mut users = settings.users.clone();
    users.extend(cli_user.iter().cloned());

    let mib_config = SystemMibConfig {
        contact,
        location,
        start: Instant::now(),
    };
    let config = AgentConfig {
        community,
        users: users.clone(),
        bind_addr,
        ..AgentConfig::default()
    };

    let agent = Agent::new(build_registry(mib_config), config.clone());
    info!(
        "net-snmp-rs snmpd listening on {} (community '{}'), serving live mibII/IF-MIB/HOST-RESOURCES data",
        config.bind_addr,
        String::from_utf8_lossy(&config.community)
    );
    for user in &users {
        info!(
            "SNMPv3 user '{}' enabled ({:?})",
            user.name,
            user.security_level()
        );
    }
    agent.serve_forever().await?;
    Ok(())
}
