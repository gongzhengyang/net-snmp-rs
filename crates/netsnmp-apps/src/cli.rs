//! Shared command-line options ([`CommonOpts`]) and their validated form
//! ([`CommonArgs`]).
//!
//! Counterpart of `snmplib/snmp_parse_args.c`. Options are declared with
//! `clap`'s derive API; network tools embed [`CommonOpts`] via
//! `#[command(flatten)]`. [`CommonOpts::resolve`] turns the raw clap values into
//! a validated [`CommonArgs`] (version → enum, agent normalization, USM user
//! assembly).

use std::time::Duration;

use clap::Args;
use netsnmp::message::Version;
use netsnmp::session::SessionConfig;
use netsnmp::usm::UsmUser;

use crate::addr::normalize_agent;
use crate::error::ArgError;
use crate::mib::split_dir_list;
use crate::settings::ClientDefaults;
use crate::usm::{build_usm_user, parse_auth_proto, parse_priv_proto};

/// Common options shared by every client tool, declared for `clap`'s derive
/// API. Network tools embed this with `#[command(flatten)]`; call
/// [`CommonOpts::resolve`] to obtain a validated [`CommonArgs`].
#[derive(Args, Debug, Clone)]
pub struct CommonOpts {
    /// SNMP protocol version: 1, 2c or 3. Defaults to `snmp.conf`'s
    /// `defVersion`, or `2c` if not set.
    #[arg(short, long, env = "SNMP_VERSION")]
    pub version: Option<String>,

    /// Community string (SNMPv1/v2c). Defaults to `snmp.conf`'s `defCommunity`,
    /// or `public` if not set.
    #[arg(short, long, env = "SNMP_COMMUNITY")]
    pub community: Option<String>,

    /// USM security name (SNMPv3).
    #[arg(short, long, env = "SNMP_SECNAME")]
    pub user: Option<String>,

    /// USM authentication protocol: MD5, SHA or SHA-256 (SNMPv3).
    #[arg(short, long)]
    pub auth_protocol: Option<String>,

    /// USM authentication passphrase (SNMPv3).
    #[arg(short = 'A', long = "auth-passphrase", env = "SNMP_AUTH_PASSPHRASE")]
    pub auth_pass: Option<String>,

    /// USM privacy protocol: AES (SNMPv3).
    #[arg(short = 'x', long = "priv-protocol")]
    pub priv_protocol: Option<String>,

    /// USM privacy passphrase (SNMPv3).
    #[arg(short = 'X', long = "priv-passphrase", env = "SNMP_PRIV_PASSPHRASE")]
    pub priv_pass: Option<String>,

    /// Security level: noAuthNoPriv, authNoPriv or authPriv (SNMPv3).
    #[arg(short, long)]
    pub level: Option<String>,

    /// Per-request timeout in seconds.
    #[arg(short, long, default_value_t = 5.0, env = "SNMP_TIMEOUT")]
    pub timeout: f64,

    /// Number of retries after the first attempt.
    #[arg(short, long, default_value_t = 2, env = "SNMP_RETRIES")]
    pub retries: u32,

    /// MIB directories to load (repeatable; also `:`/`,` separated lists).
    #[arg(short = 'M', long = "mib-dirs", env = "MIBDIRS")]
    pub mib_dirs: Vec<String>,

    /// Agent address (`host`, `host:port`, or `udp:host`).
    #[arg(value_name = "AGENT")]
    pub agent: String,
}

impl CommonOpts {
    /// Validate and normalize the raw options into a [`CommonArgs`], using only
    /// the built-in defaults (no `snmp.conf`). Used by tests and callers that
    /// do not want file-based configuration.
    pub fn resolve(&self) -> Result<CommonArgs, ArgError> {
        self.resolve_with_defaults(&ClientDefaults::default())
    }

    /// Validate and normalize the options, applying `defaults` (typically loaded
    /// from `snmp.conf` via [`load_client_defaults`](crate::load_client_defaults))
    /// wherever a command-line value was not given. Precedence is
    /// **CLI > snmp.conf > built-in**.
    pub fn resolve_with_defaults(&self, defaults: &ClientDefaults) -> Result<CommonArgs, ArgError> {
        let version = self
            .version
            .clone()
            .or_else(|| defaults.version.clone())
            .unwrap_or_else(|| "2c".to_string());

        let mut config = SessionConfig::default();
        let want_v3 = match version.as_str() {
            "1" => {
                config.version = Version::V1;
                false
            }
            "2c" | "2" => {
                config.version = Version::V2c;
                false
            }
            "3" => true,
            other => {
                return Err(ArgError(format!(
                    "unsupported version '{other}' (use 1, 2c or 3)"
                )));
            }
        };

        let community = self
            .community
            .clone()
            .or_else(|| defaults.community.clone())
            .unwrap_or_else(|| "public".to_string());
        config.community = community.into_bytes();
        config.timeout = Duration::from_secs_f64(self.timeout);
        config.retries = self.retries;

        // MIB directories: command-line first, then any from snmp.conf.
        let mut mib_dirs = Vec::new();
        for entry in &self.mib_dirs {
            mib_dirs.extend(split_dir_list(entry));
        }
        mib_dirs.extend(defaults.mib_dirs.iter().cloned());

        let v3_user = if want_v3 {
            Some(self.build_v3_user(defaults)?)
        } else {
            None
        };

        Ok(CommonArgs {
            agent: normalize_agent(&self.agent),
            config,
            mib_dirs,
            v3_user,
        })
    }

    /// Assemble the USM user for a v3 session, merging CLI options with
    /// `snmp.conf` defaults.
    fn build_v3_user(&self, defaults: &ClientDefaults) -> Result<UsmUser, ArgError> {
        let auth_token = self
            .auth_protocol
            .clone()
            .or_else(|| defaults.auth_protocol.clone());
        let priv_token = self
            .priv_protocol
            .clone()
            .or_else(|| defaults.priv_protocol.clone());
        let auth_proto = match &auth_token {
            Some(p) => Some(parse_auth_proto(p)?),
            None => None,
        };
        let priv_proto = match &priv_token {
            Some(p) => Some(parse_priv_proto(p)?),
            None => None,
        };
        build_usm_user(
            self.user.clone().or_else(|| defaults.sec_name.clone()),
            auth_proto,
            self.auth_pass
                .clone()
                .or_else(|| defaults.auth_pass.clone()),
            priv_proto,
            self.priv_pass
                .clone()
                .or_else(|| defaults.priv_pass.clone()),
            self.level.clone().or_else(|| defaults.level.clone()),
        )
    }
}

/// Validated, ready-to-use common arguments for a client tool.
#[derive(Debug, Clone)]
pub struct CommonArgs {
    /// The agent address (`host:port`); port defaults to 161.
    pub agent: String,
    /// Session configuration derived from the options.
    pub config: SessionConfig,
    /// MIB directories to load.
    pub mib_dirs: Vec<String>,
    /// When `-v 3` is selected, the assembled USM user; `None` for v1/v2c.
    pub v3_user: Option<UsmUser>,
}
