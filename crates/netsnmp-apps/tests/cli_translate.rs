//! Integration tests for `snmptranslate` — the offline name<->OID converter.
//! These need no agent and no network.

mod common;

use common::run;

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
