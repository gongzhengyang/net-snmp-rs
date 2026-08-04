//! Integration test: parse the real Net-SNMP `mibs/*.txt` distribution and
//! verify symbolic resolution of well-known objects across modules.
//!
//! The test locates the MIB directory relative to the crate; if it is not
//! present (e.g. the crate was vendored on its own) the test is skipped.

use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::value::Value;
use std::path::PathBuf;

fn mib_dir() -> Option<PathBuf> {
    // crates/netsnmp -> ../../../mibs  (the upstream net-snmp mibs directory)
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../mibs");
    if dir.join("SNMPv2-MIB.txt").exists() {
        Some(dir)
    } else {
        None
    }
}

#[tokio::test]
async fn parses_real_mib_distribution() {
    let Some(dir) = mib_dir() else {
        tracing::warn!("skipping: mibs/ directory not found");
        return;
    };

    let mut mib = MibRegistry::with_builtins();
    let count = mib.load_dir(&dir).await.expect("load mibs dir");
    // The real distribution defines thousands of objects.
    assert!(count > 1000, "expected >1000 objects, got {count}");

    // Cross-module resolution of well-known objects (defined across SMI files).
    let expectations = [
        ("sysDescr", ".1.3.6.1.2.1.1.1"),
        ("ifEntry", ".1.3.6.1.2.1.2.2.1"),
        ("ifOperStatus", ".1.3.6.1.2.1.2.2.1.8"),
        ("ifInOctets", ".1.3.6.1.2.1.2.2.1.10"),
        ("tcpConnState", ".1.3.6.1.2.1.6.13.1.1"),
        ("hrSystemUptime", ".1.3.6.1.2.1.25.1.1"),
        ("ipAdEntAddr", ".1.3.6.1.2.1.4.20.1.1"),
        ("snmpInPkts", ".1.3.6.1.2.1.11.1"),
    ];
    for (name, oid) in expectations {
        assert_eq!(
            mib.name_to_oid(name).map(|o| o.to_string()).as_deref(),
            Some(oid),
            "name {name} should resolve to {oid}"
        );
    }
}

#[tokio::test]
async fn symbolic_formatting_with_real_mibs() {
    let Some(dir) = mib_dir() else {
        return;
    };
    let mut mib = MibRegistry::with_builtins();
    mib.load_dir(&dir).await.expect("load");

    // ifOperStatus.3 with value down(2) should render symbolically.
    let oid: Oid = "1.3.6.1.2.1.2.2.1.8.3".parse().unwrap();
    assert_eq!(mib.format_oid(&oid), "ifOperStatus.3");
    assert_eq!(
        mib.format_value(&oid, &Value::Integer(2)),
        "INTEGER: down(2)"
    );

    // Numeric -> symbolic for a scalar instance.
    let sys: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    assert_eq!(mib.format_oid(&sys), "sysDescr.0");
}

#[tokio::test]
async fn semantic_object_defs_from_real_mibs() {
    // Task 5.17: the structured OBJECT-TYPE definitions must be parsed and
    // registered alongside the OID path. Skipped when the mibs/ fixture is
    // absent (same guard as the other tests in this file).
    let Some(dir) = mib_dir() else {
        tracing::warn!("skipping: mibs/ directory not found");
        return;
    };

    let mut mib = MibRegistry::with_builtins();
    mib.load_dir(&dir).await.expect("load mibs dir");

    // ifIndex (1.3.6.1.2.1.2.2.1.1) is read-only with SYNTAX InterfaceIndex.
    let if_index: Oid = "1.3.6.1.2.1.2.2.1.1".parse().unwrap();
    let def = mib.object_def(&if_index).expect("ifIndex object def");
    assert_eq!(def.name, "ifIndex");
    assert_eq!(def.max_access, netsnmp::smi::Access::ReadOnly);
    assert_eq!(def.status, netsnmp::smi::Status::Current);
    // It should not be writable.
    assert!(!mib.is_writable(&if_index));

    // ifAdminStatus is read-write and enumerated.
    let if_admin: Oid = "1.3.6.1.2.1.2.2.1.7".parse().unwrap();
    let admin_def = mib.object_def(&if_admin).expect("ifAdminStatus object def");
    assert_eq!(admin_def.max_access, netsnmp::smi::Access::ReadWrite);
    assert!(admin_def.enums.iter().any(|(_, n)| n == "up"));
    assert!(mib.is_writable(&if_admin));

    // The DisplayString textual convention must be registered.
    let ds = mib
        .textual_convention("DisplayString")
        .expect("DisplayString TC");
    assert_eq!(ds.display_hint.as_deref(), Some("255a"));
}
