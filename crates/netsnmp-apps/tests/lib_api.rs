//! Integration tests for the public `netsnmp_apps` library API: argument
//! resolution, value parsing, address normalization, and config mapping.

use clap::Parser;
use netsnmp::usm::SecurityLevel;
use netsnmp::value::Value;
use netsnmp_apps::{
    ClientDefaults, CommonOpts, SnmpdSettings, normalize_agent, normalize_agent_port,
    normalize_bind_addr, parse_auth_proto, parse_priv_proto, parse_typed_value, split_dir_list,
};

/// A clap harness embedding the shared options plus trailing OIDs, mirroring
/// how the real network tools assemble their command lines.
#[derive(Parser, Debug)]
struct Harness {
    #[command(flatten)]
    common: CommonOpts,
    #[arg(value_name = "OID")]
    oids: Vec<String>,
}

fn parse(args: &[&str]) -> Harness {
    let mut argv = vec!["tool"];
    argv.extend_from_slice(args);
    Harness::try_parse_from(argv).expect("parse")
}

#[test]
fn typed_values_cover_every_type_code() {
    assert_eq!(parse_typed_value("i", "-5").unwrap(), Value::Integer(-5));
    assert_eq!(parse_typed_value("u", "42").unwrap(), Value::Gauge32(42));
    assert_eq!(parse_typed_value("c", "7").unwrap(), Value::Counter32(7));
    assert_eq!(
        parse_typed_value("t", "100").unwrap(),
        Value::TimeTicks(100)
    );
    assert_eq!(
        parse_typed_value("a", "10.0.0.1").unwrap(),
        Value::IpAddress("10.0.0.1".parse().unwrap())
    );
    assert_eq!(
        parse_typed_value("s", "hello").unwrap(),
        Value::OctetString(b"hello".to_vec())
    );
    assert_eq!(
        parse_typed_value("x", "de ad be ef").unwrap(),
        Value::OctetString(vec![0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(
        parse_typed_value("o", "1.3.6.1").unwrap(),
        Value::Oid("1.3.6.1".parse().unwrap())
    );
    assert_eq!(parse_typed_value("n", "").unwrap(), Value::Null);
}

#[test]
fn typed_values_reject_bad_input() {
    assert!(parse_typed_value("i", "notanint").is_err());
    assert!(parse_typed_value("a", "999.1.1.1").is_err());
    assert!(parse_typed_value("x", "abc").is_err()); // odd length
    assert!(parse_typed_value("z", "x").is_err()); // unknown type code
}

#[test]
fn agent_address_normalization() {
    assert_eq!(normalize_agent("localhost"), "localhost:161");
    assert_eq!(normalize_agent("127.0.0.1:1161"), "127.0.0.1:1161");
    assert_eq!(normalize_agent("udp:10.0.0.1"), "10.0.0.1:161");
    // Notification receivers default to port 162.
    assert_eq!(normalize_agent_port("host", 162), "host:162");
    // Raw IPv6 gets bracketed.
    assert_eq!(normalize_agent("::1"), "[::1]:161");
    assert_eq!(normalize_agent("[2001:db8::1]:5000"), "[2001:db8::1]:5000");
}

#[test]
fn bind_address_normalization() {
    assert_eq!(normalize_bind_addr("udp:161"), "0.0.0.0:161");
    assert_eq!(normalize_bind_addr("udp:127.0.0.1:1161"), "127.0.0.1:1161");
    assert_eq!(normalize_bind_addr("0.0.0.0:161"), "0.0.0.0:161");
    assert_eq!(normalize_bind_addr("localhost"), "localhost:161");
    // A comma-separated list keeps only the first entry.
    assert_eq!(normalize_bind_addr("udp:1161,tcp:1162"), "0.0.0.0:1161");
}

#[test]
fn usm_protocol_parsing() {
    use netsnmp::usm::{AuthProtocol, PrivProtocol};
    assert_eq!(parse_auth_proto("MD5").unwrap(), AuthProtocol::HmacMd5);
    assert_eq!(parse_auth_proto("sha").unwrap(), AuthProtocol::HmacSha1);
    assert_eq!(
        parse_auth_proto("SHA-256").unwrap(),
        AuthProtocol::HmacSha256
    );
    assert!(parse_auth_proto("bogus").is_err());
    assert_eq!(parse_priv_proto("AES").unwrap(), PrivProtocol::AesCfb128);
    assert!(parse_priv_proto("DES").is_err());
}

#[test]
fn dir_list_splitting() {
    assert_eq!(split_dir_list("/a:/b,/c"), vec!["/a", "/b", "/c"]);
    assert!(split_dir_list("  ").is_empty());
}

#[test]
fn cli_overrides_then_config_then_builtin() {
    // 1) Built-in default (no CLI, no config): version 2c, community public.
    let args = parse(&["host", "sysDescr.0"]).common.resolve().unwrap();
    assert_eq!(args.config.community, b"public");
    assert!(args.v3_user.is_none());

    // 2) Config supplies a community when the CLI omits `-c`.
    let defaults = ClientDefaults {
        community: Some("fromconf".into()),
        ..ClientDefaults::default()
    };
    let args = parse(&["host", "sysDescr.0"])
        .common
        .resolve_with_defaults(&defaults)
        .unwrap();
    assert_eq!(args.config.community, b"fromconf");

    // 3) The CLI wins over config.
    let args = parse(&["-c", "fromcli", "host", "sysDescr.0"])
        .common
        .resolve_with_defaults(&defaults)
        .unwrap();
    assert_eq!(args.config.community, b"fromcli");
}

#[test]
fn v3_user_assembled_from_options() {
    let args = parse(&[
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
    .common
    .resolve()
    .unwrap();
    let user = args.v3_user.expect("v3 user");
    assert_eq!(user.name, "alice");
    assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
}

#[test]
fn snmp_conf_maps_to_client_defaults() {
    let conf = "\
defVersion 3
defSecurityName bob
defAuthType SHA-256
defAuthPassphrase secretpass
defSecurityLevel authNoPriv
mibdirs +/opt/mibs:/more
";
    let defaults = ClientDefaults::from_directives(&netsnmp::config::parse_str(conf));
    assert_eq!(defaults.version.as_deref(), Some("3"));
    assert_eq!(defaults.sec_name.as_deref(), Some("bob"));
    assert_eq!(defaults.auth_protocol.as_deref(), Some("SHA-256"));
    assert_eq!(defaults.mib_dirs, vec!["/opt/mibs", "/more"]);

    // And those defaults flow through into a fully-built v3 session.
    let args = parse(&["host", "sysDescr.0"])
        .common
        .resolve_with_defaults(&defaults)
        .unwrap();
    let user = args.v3_user.expect("v3 user from config");
    assert_eq!(user.name, "bob");
    assert_eq!(user.security_level(), SecurityLevel::AuthNoPriv);
}

#[test]
fn snmpd_conf_maps_to_settings() {
    let conf = r#"
rocommunity readonly
rwcommunity readwrite
syslocation "Server Room 1"
syscontact ops@example.org
agentAddress udp:1610
createUser carol MD5 carolpass
"#;
    let settings = SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf)).unwrap();
    // rwcommunity is preferred for the agent's single community.
    assert_eq!(settings.community.as_deref(), Some("readwrite"));
    assert_eq!(settings.sys_location.as_deref(), Some("Server Room 1"));
    assert_eq!(settings.sys_contact.as_deref(), Some("ops@example.org"));
    assert_eq!(settings.agent_address.as_deref(), Some("0.0.0.0:1610"));
    assert_eq!(settings.users.len(), 1);
    assert_eq!(settings.users[0].name, "carol");
    assert_eq!(
        settings.users[0].security_level(),
        SecurityLevel::AuthNoPriv
    );
}

#[test]
fn createuser_without_passphrase_errors() {
    // `createUser name MD5` is missing the passphrase.
    let conf = "createUser dave MD5\n";
    let err = SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf));
    assert!(err.is_err());
}
