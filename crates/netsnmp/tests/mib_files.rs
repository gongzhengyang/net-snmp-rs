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
