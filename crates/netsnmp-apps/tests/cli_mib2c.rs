//! Integration test for the `mib2c` code generator binary.
//!
//! Runs `mib2c -M <mibs> ifTable` against the real Net-SNMP `mibs/` tree (when
//! present) and asserts the generated output contains the expected table
//! handler structure. Skipped when the MIB directory is not vendored.

use std::path::PathBuf;

fn mib_dir() -> Option<PathBuf> {
    // crates/netsnmp-apps -> ../../../mibs  (the upstream net-snmp mibs directory)
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../mibs");
    if dir.join("IF-MIB.txt").exists() {
        Some(dir)
    } else {
        None
    }
}

/// Locate the built `mib2c` binary for the current target/profile.
fn mib2c_bin() -> Option<PathBuf> {
    // CARGO_BIN_EXE_mib2c is set by `cargo test` for binaries in the same crate.
    std::option_env!("CARGO_BIN_EXE_mib2c").map(PathBuf::from)
}

#[test]
fn mib2c_generates_iftable_handler() {
    let (Some(mibs), Some(bin)) = (mib_dir(), mib2c_bin()) else {
        eprintln!("skipping: mibs/ or mib2c binary not found");
        return;
    };

    let output = std::process::Command::new(bin)
        .arg("-M")
        .arg(&mibs)
        .arg("ifTable")
        .output()
        .expect("run mib2c");

    if !output.status.success() {
        panic!(
            "mib2c failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let code = String::from_utf8_lossy(&output.stdout);
    assert!(
        code.contains("fn ifTable_handlers"),
        "missing handler fn in output:\n{code}"
    );
    assert!(
        code.contains("TableHandler"),
        "missing TableHandler in output:\n{code}"
    );
    assert!(
        code.contains("IFTABLE_OID"),
        "missing OID constant in output:\n{code}"
    );
}

#[test]
fn mib2c_generates_scalar_handler() {
    let (Some(mibs), Some(bin)) = (mib_dir(), mib2c_bin()) else {
        eprintln!("skipping: mibs/ or mib2c binary not found");
        return;
    };

    // sysDescr is a well-known scalar in SNMPv2-MIB.
    let output = std::process::Command::new(bin)
        .arg("-M")
        .arg(&mibs)
        .arg("sysDescr")
        .output()
        .expect("run mib2c");

    if !output.status.success() {
        panic!(
            "mib2c failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let code = String::from_utf8_lossy(&output.stdout);
    assert!(
        code.contains("fn sysDescr_handlers"),
        "missing handler fn in output:\n{code}"
    );
    assert!(
        code.contains("ScalarHandler"),
        "missing ScalarHandler in output:\n{code}"
    );
}

#[test]
fn mib2c_writes_to_output_dir() {
    let (Some(mibs), Some(bin)) = (mib_dir(), mib2c_bin()) else {
        eprintln!("skipping: mibs/ or mib2c binary not found");
        return;
    };

    let tmp = std::env::temp_dir().join(format!(
        "netsnmp-rs-mib2c-test-{}",
        std::process::id()
    ));
    let output = std::process::Command::new(bin)
        .arg("-M")
        .arg(&mibs)
        .arg("-o")
        .arg(&tmp)
        .arg("ifTable")
        .output()
        .expect("run mib2c");
    assert!(output.status.success(), "mib2c -o failed: {}", String::from_utf8_lossy(&output.stderr));
    let written = std::fs::read_to_string(tmp.join("ifTable.rs")).expect("output file written");
    assert!(written.contains("fn ifTable_handlers"));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn mib2c_unknown_node_errors() {
    let (Some(mibs), Some(bin)) = (mib_dir(), mib2c_bin()) else {
        eprintln!("skipping: mibs/ or mib2c binary not found");
        return;
    };

    let output = std::process::Command::new(bin)
        .arg("-M")
        .arg(&mibs)
        .arg("doesNotExistXYZ")
        .output()
        .expect("run mib2c");
    assert!(
        !output.status.success(),
        "expected non-zero exit for unknown node"
    );
}
