//! Integration tests for `snmptranslate` — the offline name<->OID converter.
//! These need no agent and no network.

mod common;

use common::run;
use std::path::PathBuf;

/// Absolute path to the workspace `mibs/` tree (where the real IF-MIB /
/// SNMPv2-MIB modules live), located relative to this crate's manifest.
fn workspace_mibs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../mibs")
}

/// `true` when the workspace `mibs/` tree ships the file named `name` (e.g.
/// `"SNMPv2-MIB.txt"`). Used to skip tests that need real MIB modules when the
/// tree is absent (e.g. a minimal CI checkout).
fn mib_present(name: &str) -> bool {
    workspace_mibs().join(name).exists()
}

/// Build the standard `-M <mibs>` argument plus a `MIBDIRS` env entry. Pass
/// both so the loader sees the directory whether the binary consults `-M` or
/// the `MIBDIRS` env var.
fn mib_args() -> (Vec<&'static str>, Vec<(&'static str, &'static str)>) {
    let path = workspace_mibs();
    let path_str = match path.to_str() {
        Some(s) => s,
        None => "",
    };
    // Leak stable &'static strs for the arg/env vectors.
    let leaked: &'static str = Box::leak(path_str.to_string().into_boxed_str());
    (vec!["-M", leaked], vec![("MIBDIRS", leaked)])
}

#[test]
fn name_to_symbolic_form() {
    let out = run("snmptranslate", &["sysDescr.0"], &[]);
    out.assert_success("translate name");
    assert!(
        out.combined().contains("sysDescr"),
        "unexpected: {}",
        out.combined()
    );
}

#[test]
fn name_to_numeric_with_dash_o_n() {
    let out = run("snmptranslate", &["-On", "sysName.0"], &[]);
    out.assert_success("translate -On");
    assert!(
        out.combined().contains("1.3.6.1.2.1.1.5.0"),
        "unexpected: {}",
        out.combined()
    );
}

#[test]
fn numeric_oid_back_to_name() {
    let out = run("snmptranslate", &["1.3.6.1.2.1.1.1.0"], &[]);
    out.assert_success("translate numeric");
    assert!(out.combined().contains("sysDescr"));
}

#[test]
fn multiple_tokens_in_one_invocation() {
    let out = run("snmptranslate", &["-On", "sysDescr.0", "ifDescr"], &[]);
    out.assert_success("translate multiple");
    let text = out.combined();
    assert!(text.contains("1.3.6.1.2.1.1.1.0"));
    assert!(text.contains("1.3.6.1.2.1.2.2.1.2"));
}

#[test]
fn unknown_name_is_an_error() {
    let out = run("snmptranslate", &["thisIsNotAKnownObject"], &[]);
    out.assert_failure("translate unknown");
    assert!(
        out.combined().contains("unknown object"),
        "unexpected: {}",
        out.combined()
    );
}

#[test]
fn missing_argument_is_rejected_by_clap() {
    // `tokens` is `required = true`, so clap exits non-zero with usage text.
    let out = run("snmptranslate", &[], &[]);
    out.assert_failure("translate no args");
}

// ---------------------------------------------------------------------------
// Task 5.2 — extended -O* / -T* output modes.
//
// These tests require the real MIB modules under `mibs/`. They follow the
// skip-on-missing pattern: if the relevant `.txt` is absent the test is
// skipped rather than failing.
// ---------------------------------------------------------------------------

#[test]
fn translate_full_mode() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Of", "ifIndex"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Of");
    let text = out.combined();
    assert!(
        text.contains("ifIndex"),
        "-Of should contain the leaf name, got: {text}"
    );
}

#[test]
fn translate_short_mode() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Os", "ifIndex"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Os");
    let text = out.combined();
    // The short form is the last name segment, which for ifIndex is `ifIndex`.
    assert!(
        text.contains("ifIndex"),
        "-Os should print the short name, got: {text}"
    );
}

#[test]
fn translate_numeric_and_suffix() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    // `-On` dominates over `-OS`: the dotted numeric form is printed.
    args.extend_from_slice(&["-On", "-OS", "ifTable.ifEntry.ifIndex"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -On -OS");
    assert!(
        out.combined().contains(".1.3.6.1.2.1.2.2.1.1"),
        "-On -OS should print the numeric form, got: {}",
        out.combined()
    );
}

#[test]
fn translate_suffix_mode_alone() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-OS", "ifTable.ifEntry.ifIndex"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -OS");
    let text = out.combined();
    // Suffix mode starts at the entry node, so it should include both the
    // entry and the leaf name.
    assert!(
        text.contains("ifIndex"),
        "-OS should contain the leaf, got: {text}"
    );
}

#[test]
fn translate_tree_print() {
    if !mib_present("SNMPv2-MIB.txt") {
        eprintln!("skipping: SNMPv2-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Tp", "system"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Tp");
    let text = out.combined();
    assert!(text.contains("system"), "-Tp should include root, got: {text}");
    assert!(
        text.contains("+- "),
        "-Tp should use +- connectors, got: {text}"
    );
}

#[test]
fn translate_tree_ascii() {
    if !mib_present("SNMPv2-MIB.txt") {
        eprintln!("skipping: SNMPv2-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Ta", "system"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Ta");
    let text = out.combined();
    assert!(text.contains("system"), "-Ta should include root, got: {text}");
}

#[test]
fn translate_enum() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Oe", "ifAdminStatus"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Oe");
    let text = out.combined();
    assert!(
        text.contains("up") || text.contains("down"),
        "-Oe should mention an enum label, got: {text}"
    );
}

#[test]
fn translate_detailed() {
    if !mib_present("IF-MIB.txt") {
        eprintln!("skipping: IF-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Td", "ifIndex"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Td");
    let text = out.combined();
    assert!(
        text.contains("OBJECT-TYPE"),
        "-Td should print the OBJECT-TYPE header, got: {text}"
    );
    assert!(
        text.contains("SYNTAX"),
        "-Td should print a SYNTAX line, got: {text}"
    );
}

#[test]
fn translate_table_mode() {
    if !mib_present("SNMPv2-MIB.txt") {
        eprintln!("skipping: SNMPv2-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Tt", "system"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Tt");
    let text = out.combined();
    // The table has 5 tab-separated columns. Pick a known system object line
    // and verify the column count.
    let sys_line = text
        .lines()
        .find(|l| l.contains("sysDescr"))
        .unwrap_or_else(|| panic!("-Tt should list sysDescr, got: {text}"));
    assert!(
        sys_line.split('\t').count() >= 5,
        "-Tt row should have >=5 columns: {sys_line}"
    );
}

#[test]
fn translate_list_all_still_works() {
    if !mib_present("SNMPv2-MIB.txt") {
        eprintln!("skipping: SNMPv2-MIB.txt not found");
        return;
    }
    let (mut args, envs) = mib_args();
    args.extend_from_slice(&["-Tl"]);
    let out = run("snmptranslate", &args, &envs);
    out.assert_success("translate -Tl");
    let text = out.combined();
    assert!(text.contains("sysDescr"), "-Tl should list sysDescr, got: {text}");
}

