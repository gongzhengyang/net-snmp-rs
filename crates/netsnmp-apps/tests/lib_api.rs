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
    assert_eq!(settings.agent_address.first().map(String::as_str), Some("0.0.0.0:1610"));
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

#[test]
fn full_snmpd_conf_directives_parsed() {
    let conf = r#"
# VACM
com2sec readonly default public
com2sec6 readonly6 default public
group mygroup v2c public
view all included .1.3.6.1.2.1
view system included .1.3.6.1.2.1.1
access mygroup "" any noauth prefix all NULL all

# community + system
rocommunity rocomm
rwcommunity rwcomm
syslocation "Server Room 1"
syscontact ops@example.org
agentAddress udp:1610,tcp:1162
agentAddress udp:1163

# notifications
trapsink trap.example.com public 162
trap2sink trap2.example.com
informsink inform.example.com
trapsess -v 2c -c public sess.example.com

# proxy
proxy -Cn ctx proxied 10.0.0.1 .1.3.6.1.4.1.8072

# exec/extend/pass/disk/proc/load/file/logmatch
exec check_load /usr/local/bin/check_load
extend .1.3.6.1.4.1.8072.999 myname /bin/echo hello
pass .1.3.6.1.4.1.8072.1 /usr/local/bin/passscript
pass_persist .1.3.6.1.4.1.8072.2 /usr/local/bin/persistscript
disk / 10%
disk /var
proc sendmail 10 1
load 12 10 5
file /var/log/messages 1000000
logmatch mymatch /var/log/syslog "error"

# master / smux / iquery / persistentDir
master agentx
agentXSocket /tmp/agentx
smuxpeer .1.3.6.1.4.1.8072 secret
smuxsocket 161
iquery internaluser
persistentDir /var/lib/snmp

createUser carol SHA carolpass AES privpass
"#;
    let settings =
        SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf)).expect("parse");

    // Community: rwcommunity wins over rocommunity.
    assert_eq!(settings.community.as_deref(), Some("rwcomm"));
    assert_eq!(settings.sys_location.as_deref(), Some("Server Room 1"));
    assert_eq!(settings.sys_contact.as_deref(), Some("ops@example.org"));

    // agentAddress: comma- and space-separated lists expanded across directives.
    assert_eq!(settings.agent_address.len(), 3);
    assert_eq!(settings.agent_address[0], "0.0.0.0:1610");
    assert_eq!(settings.agent_address[1], "0.0.0.0:1162");
    assert_eq!(settings.agent_address[2], "0.0.0.0:1163");

    // VACM entries.
    assert_eq!(settings.com2sec.len(), 2);
    assert_eq!(settings.com2sec[0].name, "readonly");
    assert_eq!(settings.com2sec[0].community, "public");
    assert_eq!(settings.groups.len(), 1);
    assert_eq!(settings.groups[0].name, "mygroup");
    assert_eq!(settings.views.len(), 2);
    assert_eq!(settings.views[0].name, "all");
    assert_eq!(settings.access.len(), 1);
    assert_eq!(settings.access[0].name, "mygroup");
    assert_eq!(settings.access[0].read_view, "all");
    // A Vacm was built from the directives.
    assert!(settings.has_vacm());
    assert!(settings.vacm.is_some());

    // Trap sinks.
    assert_eq!(settings.trapsinks.len(), 3);
    assert_eq!(settings.trapsinks[0].host, "trap.example.com");
    assert_eq!(settings.trapsinks[0].community, "public");
    assert_eq!(settings.trapsinks[0].port, Some(162));
    assert_eq!(settings.trapsinks[2].host, "inform.example.com");
    assert_eq!(settings.trapsesses.len(), 1);
    assert_eq!(settings.trapsesses[0].host, "sess.example.com");

    // Proxy.
    assert_eq!(settings.proxy.len(), 1);
    assert_eq!(settings.proxy[0].context.as_deref(), Some("ctx"));
    assert_eq!(settings.proxy[0].community, "proxied");
    assert_eq!(settings.proxy[0].host, "10.0.0.1");

    // exec/extend/pass/disk/proc/load/file/logmatch.
    assert_eq!(settings.exec.len(), 2);
    assert_eq!(settings.exec[0].name, "check_load");
    assert_eq!(settings.exec[0].program, "/usr/local/bin/check_load");
    assert_eq!(settings.exec[1].mib_oid.as_deref(), Some(".1.3.6.1.4.1.8072.999"));
    assert_eq!(settings.exec[1].name, "myname");
    assert_eq!(settings.pass.len(), 2);
    assert!(!settings.pass[0].persist);
    assert!(settings.pass[1].persist);
    assert_eq!(settings.disk.len(), 2);
    assert_eq!(settings.disk[0].min.as_deref(), Some("10%"));
    assert_eq!(settings.disk[1].min, None);
    assert_eq!(settings.proc.len(), 1);
    assert_eq!(settings.proc[0].max.as_deref(), Some("10"));
    assert_eq!(settings.proc[0].min.as_deref(), Some("1"));
    assert!(settings.load.is_some());
    assert_eq!(settings.load.as_ref().unwrap().one.as_deref(), Some("12"));
    assert_eq!(settings.file.len(), 1);
    assert_eq!(settings.logmatch.len(), 1);
    assert_eq!(settings.logmatch[0].file, "/var/log/syslog");

    // master / smux / iquery / persistentDir.
    assert!(settings.master.is_some());
    assert_eq!(settings.master.as_ref().unwrap().typ, "agentx");
    assert_eq!(
        settings.master.as_ref().unwrap().socket.as_deref(),
        Some("/tmp/agentx")
    );
    assert_eq!(settings.smuxpeer.len(), 1);
    assert_eq!(settings.smuxsocket.as_deref(), Some("161"));
    assert_eq!(settings.iquery.as_deref(), Some("internaluser"));
    assert_eq!(
        settings.persistent_dir.as_deref(),
        Some(std::path::Path::new("/var/lib/snmp"))
    );

    // createUser still flows through.
    assert_eq!(settings.users.len(), 1);
    assert_eq!(settings.users[0].name, "carol");
}

#[test]
fn vacm_directives_build_a_vacm() {
    use netsnmp_agent::{AccessView, Vacm};
    let conf = "\
com2sec sec default public
group g v2c public
view all included .1.3.6.1.2.1
access g \"\" any noauth prefix all NULL all
";
    let dirs = netsnmp::config::parse_str(conf);
    let settings = SnmpdSettings::from_directives(&dirs).expect("parse");
    let vacm = settings.vacm.expect("vacm built");
    // `public` can read the system group; an unknown community cannot.
    assert!(vacm.is_view_accessible(
        AccessView::Read,
        2,
        &b"public".to_vec(),
        0,
        &Vec::new(),
        &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
    ));
    assert!(!vacm.is_view_accessible(
        AccessView::Read,
        2,
        &b"other".to_vec(),
        0,
        &Vec::new(),
        &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
    ));
    // No write view (NULL) -> SET denied.
    assert!(!vacm.is_view_accessible(
        AccessView::Write,
        2,
        &b"public".to_vec(),
        0,
        &Vec::new(),
        &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
    ));
    // The Vacm is reusable: feeding the same directives reproduces the state.
    let _again = Vacm::from_config_directives(&dirs);
}

#[test]
fn docker_snmpd_conf_parses_without_error() {
    // The shipped example snmpd.conf must parse cleanly.
    let conf = std::include_str!("../../../docker/etc-snmp/snmpd.conf");
    let settings =
        SnmpdSettings::from_directives(&netsnmp::config::parse_str(conf)).expect("parse example");
    assert_eq!(settings.community.as_deref(), Some("public"));
    assert_eq!(settings.agent_address.len(), 1);
    assert_eq!(settings.users.len(), 1);
    assert_eq!(settings.users[0].name, "bob");
}
