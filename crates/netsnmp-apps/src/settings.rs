//! Configuration parsed from `snmp.conf` (client defaults) and `snmpd.conf`
//! (agent settings).
//!
//! Counterpart of the `read_config.c` handling in `snmplib/snmp_api.c` and the
//! agent's `agent_read_config.c` / `mibgroup/mibII/system_mib.c`. Command-line
//! options override every value parsed here.

use netsnmp::usm::UsmUser;

use crate::addr::normalize_bind_addr;
use crate::error::ArgError;
use crate::mib::split_dir_list;
use crate::usm::{parse_auth_proto, parse_priv_proto};

/// Client-side defaults parsed from `snmp.conf` (the `def*` tokens and
/// `mibdirs`). Command-line options override these; see
/// [`CommonOpts::resolve_with_defaults`](crate::CommonOpts::resolve_with_defaults).
#[derive(Debug, Default, Clone)]
pub struct ClientDefaults {
    /// `defVersion` — 1, 2c or 3.
    pub version: Option<String>,
    /// `defCommunity` — community string.
    pub community: Option<String>,
    /// `defSecurityName` — USM security name (`-u`).
    pub sec_name: Option<String>,
    /// `defAuthType` — USM auth protocol (`-a`).
    pub auth_protocol: Option<String>,
    /// `defAuthPassphrase` — USM auth passphrase (`-A`).
    pub auth_pass: Option<String>,
    /// `defPrivType` — USM privacy protocol (`-x`).
    pub priv_protocol: Option<String>,
    /// `defPrivPassphrase` — USM privacy passphrase (`-X`).
    pub priv_pass: Option<String>,
    /// `defSecurityLevel` — noAuthNoPriv / authNoPriv / authPriv (`-l`).
    pub level: Option<String>,
    /// `mibdirs` — MIB directories to load.
    pub mib_dirs: Vec<String>,
}

impl ClientDefaults {
    /// Extract the recognized client tokens from parsed `snmp.conf` directives.
    /// Later occurrences override earlier ones (matching read order).
    pub fn from_directives(directives: &[netsnmp::config::Directive]) -> Self {
        let mut d = ClientDefaults::default();
        for dir in directives {
            // Only honor the default (global) or [snmp] context.
            if let Some(section) = &dir.section
                && !section.eq_ignore_ascii_case("snmp")
            {
                continue;
            }
            let value = || dir.rest.trim().to_string();
            match dir.token.to_ascii_lowercase().as_str() {
                "defversion" => d.version = dir.arg(0).map(str::to_string),
                "defcommunity" => d.community = Some(value()),
                "defsecurityname" | "defsecname" => d.sec_name = dir.arg(0).map(str::to_string),
                "defauthtype" => d.auth_protocol = dir.arg(0).map(str::to_string),
                "defauthpassphrase" => d.auth_pass = Some(value()),
                "defprivtype" => d.priv_protocol = dir.arg(0).map(str::to_string),
                "defprivpassphrase" => d.priv_pass = Some(value()),
                "defseclevel" | "defsecuritylevel" => d.level = dir.arg(0).map(str::to_string),
                "mibdirs" => {
                    for entry in &dir.args {
                        // Honor net-snmp's optional leading '+'/'-' by stripping it.
                        let cleaned = entry.trim_start_matches(['+', '-']);
                        d.mib_dirs.extend(split_dir_list(cleaned));
                    }
                }
                _ => {}
            }
        }
        d
    }
}

/// Load client defaults from the standard `snmp.conf` search path.
///
/// The config-file search and parsing are blocking filesystem operations, so
/// they run on tokio's blocking pool via [`tokio::task::spawn_blocking`] rather
/// than stalling the async runtime worker.
pub async fn load_client_defaults() -> ClientDefaults {
    tokio::task::spawn_blocking(|| {
        ClientDefaults::from_directives(&netsnmp::config::read_app_config("snmp"))
    })
    .await
    .expect("client config load task panicked")
}

/// Agent settings parsed from `snmpd.conf`.
///
/// Counterpart of the agent's `snmpd.conf` handlers (`agent_read_config.c`,
/// `mibgroup/mibII/system_mib.c`, `mibgroup/snmp_mib*`). Command-line options
/// override these values.
#[derive(Debug, Default, Clone)]
pub struct SnmpdSettings {
    /// Community string from `rwcommunity` (preferred) or `rocommunity`.
    pub community: Option<String>,
    /// `sysLocation` value.
    pub sys_location: Option<String>,
    /// `sysContact` value.
    pub sys_contact: Option<String>,
    /// Listen address from `agentAddress`, normalized to `host:port`.
    pub agent_address: Option<String>,
    /// USM users created via `createUser`.
    pub users: Vec<UsmUser>,
}

impl SnmpdSettings {
    /// Parse recognized `snmpd.conf` tokens from the directive list.
    pub fn from_directives(directives: &[netsnmp::config::Directive]) -> Result<Self, ArgError> {
        let mut settings = SnmpdSettings::default();
        let mut ro = None;
        let mut rw = None;
        for dir in directives {
            if let Some(section) = &dir.section
                && !section.eq_ignore_ascii_case("snmpd")
            {
                continue;
            }
            match dir.token.to_ascii_lowercase().as_str() {
                "rocommunity" | "rocommunity6" => ro = dir.arg(0).map(str::to_string),
                "rwcommunity" | "rwcommunity6" => rw = dir.arg(0).map(str::to_string),
                "syslocation" => settings.sys_location = Some(freeform_value(dir)),
                "syscontact" => settings.sys_contact = Some(freeform_value(dir)),
                "agentaddress" => {
                    settings.agent_address = dir.arg(0).map(normalize_bind_addr);
                }
                "createuser" => settings.users.push(build_create_user(&dir.args)?),
                _ => {}
            }
        }
        settings.community = rw.or(ro);
        Ok(settings)
    }
}

/// Load agent settings from the standard `snmpd.conf` search path.
///
/// The config-file search and parsing are blocking filesystem operations, so
/// they run on tokio's blocking pool via [`tokio::task::spawn_blocking`] rather
/// than stalling the async runtime worker.
pub async fn load_snmpd_settings() -> Result<SnmpdSettings, ArgError> {
    tokio::task::spawn_blocking(|| {
        SnmpdSettings::from_directives(&netsnmp::config::read_app_config("snmpd"))
    })
    .await
    .expect("snmpd config load task panicked")
}

/// The value of a free-form directive (`sysLocation`/`sysContact`): a single
/// quoted token is taken verbatim, otherwise the rest of the line is used.
fn freeform_value(dir: &netsnmp::config::Directive) -> String {
    if dir.args.len() == 1 {
        dir.args[0].clone()
    } else {
        dir.rest.trim().to_string()
    }
}

/// Build a [`UsmUser`] from the arguments of a `createUser` directive.
///
/// Accepts `createUser NAME [auth AUTHPASS [priv PRIVPASS]]`, plus an optional
/// leading `-e ENGINEID` (which is ignored, as our agent is authoritative).
fn build_create_user(args: &[String]) -> Result<UsmUser, ArgError> {
    let mut args = args;
    if args.first().map(String::as_str) == Some("-e") {
        args = args.get(2..).unwrap_or(&[]);
    }
    let name = args
        .first()
        .ok_or_else(|| ArgError("createUser requires a username".into()))?
        .clone();

    match args.len() {
        0 | 1 => Ok(UsmUser::noauth(name)),
        2 => Err(ArgError(format!(
            "createUser '{name}': auth type without a passphrase"
        ))),
        3 => {
            let proto = parse_auth_proto(&args[1])?;
            Ok(UsmUser::auth(name, proto, args[2].clone()))
        }
        4 => Err(ArgError(format!(
            "createUser '{name}': privacy type without a passphrase"
        ))),
        _ => {
            let auth = parse_auth_proto(&args[1])?;
            let priv_proto = parse_priv_proto(&args[3])?;
            Ok(UsmUser::auth_priv(
                name,
                auth,
                args[2].clone(),
                priv_proto,
                args[4].clone(),
            ))
        }
    }
}
