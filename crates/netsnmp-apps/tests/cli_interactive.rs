//! Integration tests for the interactive/periodic tools `snmptest` and
//! `snmpdelta`.

mod common;

use common::{run_async, run_async_stdin, spawn_rich_agent};

const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const IF_DESCR_COL: &str = "1.3.6.1.2.1.2.2.1.2";
const SNMP_IN_PKTS: &str = "1.3.6.1.2.1.11.1.0";

#[tokio::test]
async fn snmptest_get_from_stdin() {
    let addr = spawn_rich_agent("public").await;
    let stdin = format!("{SYS_DESCR}\n$q\n");
    let out = run_async_stdin(
        "snmptest",
        &["-v", "2c", "-c", "public", &addr],
        &[],
        &stdin,
    )
    .await;
    out.assert_success("snmptest get");
    assert!(
        out.combined().contains("rich test agent"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmptest_getnext_mode() {
    let addr = spawn_rich_agent("public").await;
    // Switch to GETNEXT, then query the ifDescr column (no instance): the agent
    // returns the first instance, `lo`.
    let stdin = format!("$N\n{IF_DESCR_COL}\n$q\n");
    let out = run_async_stdin(
        "snmptest",
        &["-v", "2c", "-c", "public", &addr],
        &[],
        &stdin,
    )
    .await;
    out.assert_success("snmptest getnext");
    assert!(out.combined().contains("lo"), "got: {}", out.combined());
}

#[tokio::test]
async fn snmptest_exits_on_eof() {
    let addr = spawn_rich_agent("public").await;
    // No commands, just EOF: should exit cleanly.
    let out = run_async_stdin("snmptest", &["-v", "2c", "-c", "public", &addr], &[], "").await;
    out.assert_success("snmptest eof");
}

#[tokio::test]
async fn snmpdelta_reports_zero_delta_for_static_counter() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpdelta",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--period",
            "1",
            "--iterations",
            "1",
            &addr,
            SNMP_IN_PKTS,
        ],
        &[],
    )
    .await;
    out.assert_success("snmpdelta one iteration");
    // The counter is static in the test agent, so the delta is zero.
    assert!(out.combined().contains("= 0"), "got: {}", out.combined());
}
