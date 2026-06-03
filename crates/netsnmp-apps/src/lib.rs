//! Shared building blocks for the SNMP command-line tools.
//!
//! This crate factors out everything the `snmp*` binaries have in common:
//!
//! - [`CommonOpts`] / [`CommonArgs`] — shared `clap` options and their
//!   validated form (counterpart of `snmplib/snmp_parse_args.c`).
//! - [`ClientDefaults`] / [`SnmpdSettings`] — `snmp.conf` / `snmpd.conf` parsing.
//! - [`Client`] — a version-agnostic async session over v1/v2c/v3.
//! - value/OID/MIB/address helpers and the shared [`AppError`].
//!
//! The functionality lives in focused submodules; the most commonly used items
//! are re-exported here so callers can keep using `netsnmp_apps::Foo`.

use tracing_subscriber::{EnvFilter, fmt};

mod addr;
mod cli;
mod client;
mod error;
pub mod mgmt;
mod mib;
mod settings;
pub mod table;
mod usm;
mod value;

pub use addr::{normalize_agent, normalize_agent_port, normalize_bind_addr};
pub use cli::{CommonArgs, CommonOpts};
pub use client::{Client, connect, connect_notifier};
pub use error::{AppError, ArgError};
pub use mib::{load_mib_registry, split_dir_list};
pub use settings::{ClientDefaults, SnmpdSettings, load_client_defaults, load_snmpd_settings};
pub use usm::{parse_auth_proto, parse_priv_proto};
pub use value::{parse_hex_string, parse_typed_value};

/// Initialize the global `tracing` subscriber for a CLI tool.
///
/// Output goes through `tracing` rather than `println!`/`eprintln!`: tool
/// results and status are emitted at `info`, protocol detail at `debug`/`trace`,
/// and failures at `error`. The level is controlled by the `RUST_LOG`
/// environment variable (e.g. `RUST_LOG=debug`), defaulting to `info`. The
/// format is compact (no timestamp/target) so result lines read cleanly. Safe
/// to call more than once; a second call is a no-op.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A tiny test harness command embedding the shared options + trailing OIDs.
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        common: CommonOpts,
        #[arg(value_name = "OID")]
        oids: Vec<String>,
    }

    fn parse(args: &[&str]) -> Result<TestCli, clap::Error> {
        let mut argv = vec!["test"];
        argv.extend_from_slice(args);
        TestCli::try_parse_from(argv)
    }

    #[test]
    fn normalize_defaults_port() {
        assert_eq!(normalize_agent("localhost"), "localhost:161");
        assert_eq!(normalize_agent("127.0.0.1:1161"), "127.0.0.1:1161");
        assert_eq!(normalize_agent("udp:10.0.0.1"), "10.0.0.1:161");
    }

    #[test]
    fn parse_version_and_community() {
        let cli = parse(&["-v", "2c", "-c", "secret", "host", "sysDescr.0"]).unwrap();
        let common = cli.common.resolve().unwrap();
        assert_eq!(common.agent, "host:161");
        assert_eq!(common.config.community, b"secret");
        assert!(common.v3_user.is_none());
        assert_eq!(cli.oids, vec!["sysDescr.0".to_string()]);
    }

    #[test]
    fn missing_agent_errors() {
        // No positional AGENT: clap rejects the invocation.
        assert!(parse(&["-c", "public"]).is_err());
    }

    #[test]
    fn repeatable_and_split_mib_dirs() {
        let cli = parse(&["-M", "/a:/b", "-M", "/c", "host", "sysDescr.0"]).unwrap();
        let common = cli.common.resolve().unwrap();
        assert_eq!(common.mib_dirs, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn v3_authpriv_user_assembled() {
        let cli = parse(&[
            "-v",
            "3",
            "-u",
            "alice",
            "-a",
            "SHA",
            "-A",
            "authpass",
            "-x",
            "AES",
            "-X",
            "privpass",
            "-l",
            "authPriv",
            "host",
            "sysDescr.0",
        ])
        .unwrap();
        let common = cli.common.resolve().unwrap();
        let user = common.v3_user.expect("v3 user");
        assert_eq!(user.name, "alice");
        assert_eq!(user.security_level(), netsnmp::usm::SecurityLevel::AuthPriv);
    }

    #[test]
    fn bad_version_errors() {
        let cli = parse(&["-v", "9", "host", "sysDescr.0"]).unwrap();
        assert!(cli.common.resolve().is_err());
    }

    #[test]
    fn client_defaults_parsed_from_snmp_conf() {
        let conf = "\
defVersion 2c
defCommunity s3cr3t
defSecurityName alice
defAuthType SHA
defAuthPassphrase authpass
mibdirs +/opt/mibs:/more/mibs
";
        let d = ClientDefaults::from_directives(&netsnmp::config::parse_str(conf));
        assert_eq!(d.version.as_deref(), Some("2c"));
        assert_eq!(d.community.as_deref(), Some("s3cr3t"));
        assert_eq!(d.sec_name.as_deref(), Some("alice"));
        assert_eq!(d.auth_protocol.as_deref(), Some("SHA"));
        assert_eq!(d.auth_pass.as_deref(), Some("authpass"));
        assert_eq!(d.mib_dirs, vec!["/opt/mibs", "/more/mibs"]);
    }

    #[test]
    fn config_defaults_used_when_cli_absent() {
        // No -c on the command line: snmp.conf's defCommunity applies.
        let cli = parse(&["host", "sysDescr.0"]).unwrap();
        let defaults = ClientDefaults {
            community: Some("fromfile".to_string()),
            ..ClientDefaults::default()
        };
        let common = cli.common.resolve_with_defaults(&defaults).unwrap();
        assert_eq!(common.config.community, b"fromfile");
    }

    #[test]
    fn cli_overrides_config_defaults() {
        // -c on the command line wins over snmp.conf.
        let cli = parse(&["-c", "fromcli", "host", "sysDescr.0"]).unwrap();
        let defaults = ClientDefaults {
            community: Some("fromfile".to_string()),
            ..ClientDefaults::default()
        };
        let common = cli.common.resolve_with_defaults(&defaults).unwrap();
        assert_eq!(common.config.community, b"fromcli");
    }

    #[test]
    fn snmpd_settings_parsed() {
        let conf = r#"
rocommunity public 10.0.0.0/8
syslocation "Server Room 1"
syscontact admin@example.org
agentAddress udp:10161
createUser bob SHA authpass AES privpass
"#;
        let s = SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf)).unwrap();
        assert_eq!(s.community.as_deref(), Some("public"));
        assert_eq!(s.sys_location.as_deref(), Some("Server Room 1"));
        assert_eq!(s.sys_contact.as_deref(), Some("admin@example.org"));
        assert_eq!(s.agent_address.as_deref(), Some("0.0.0.0:10161"));
        assert_eq!(s.users.len(), 1);
        assert_eq!(s.users[0].name, "bob");
        assert_eq!(
            s.users[0].security_level(),
            netsnmp::usm::SecurityLevel::AuthPriv
        );
    }

    #[test]
    fn rwcommunity_preferred_over_ro() {
        let conf = "rocommunity readonly\nrwcommunity readwrite\n";
        let s = SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf)).unwrap();
        assert_eq!(s.community.as_deref(), Some("readwrite"));
    }

    #[test]
    fn normalizes_agent_address() {
        assert_eq!(normalize_bind_addr("udp:161"), "0.0.0.0:161");
        assert_eq!(normalize_bind_addr("udp:127.0.0.1:1161"), "127.0.0.1:1161");
        assert_eq!(normalize_bind_addr("0.0.0.0:161"), "0.0.0.0:161");
        assert_eq!(normalize_bind_addr("localhost"), "localhost:161");
    }

    #[test]
    fn config_v3_defaults_build_user() {
        // SNMPv3 user assembled entirely from snmp.conf defaults.
        let cli = parse(&["-v", "3", "host", "sysDescr.0"]).unwrap();
        let defaults = ClientDefaults {
            sec_name: Some("bob".to_string()),
            auth_protocol: Some("SHA".to_string()),
            auth_pass: Some("authpass".to_string()),
            level: Some("authNoPriv".to_string()),
            ..ClientDefaults::default()
        };
        let common = cli.common.resolve_with_defaults(&defaults).unwrap();
        let user = common.v3_user.expect("v3 user from config");
        assert_eq!(user.name, "bob");
        assert_eq!(
            user.security_level(),
            netsnmp::usm::SecurityLevel::AuthNoPriv
        );
    }
}
