//! Integration tests for the GETBULK tools `snmpbulkget` and `snmpbulkwalk`,
//! driven against an in-process agent.

mod common;

use common::{run_async, spawn_rich_agent};

const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const IF_ENTRY: &str = "1.3.6.1.2.1.2.2.1";

#[tokio::test]
async fn bulkget_returns_multiple_repetitions() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpbulkget",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--max-repetitions",
            "5",
            &addr,
            IF_DESCR,
        ],
        &[],
    )
    .await;
    out.assert_success("bulkget ifDescr");
    let combined = out.combined();
    assert!(combined.contains("lo"), "want lo, got: {combined}");
    assert!(combined.contains("eth0"), "want eth0, got: {combined}");
}

#[tokio::test]
async fn bulkget_with_non_repeaters() {
    let addr = spawn_rich_agent("public").await;
    // sysUpTime is a non-repeater (fetched once); ifDescr repeats.
    let out = run_async(
        "snmpbulkget",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--non-repeaters",
            "1",
            "--max-repetitions",
            "3",
            &addr,
            "1.3.6.1.2.1.1.3.0",
            IF_DESCR,
        ],
        &[],
    )
    .await;
    out.assert_success("bulkget with non-repeaters");
    assert!(out.combined().contains("eth0"), "got: {}", out.combined());
}

#[tokio::test]
async fn bulkget_rejected_on_v1() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpbulkget",
        &["-v", "1", "-c", "public", &addr, IF_DESCR],
        &[],
    )
    .await;
    out.assert_failure("bulkget should reject v1");
    assert!(
        out.combined().to_lowercase().contains("getbulk"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn bulkwalk_collects_whole_subtree() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpbulkwalk",
        &["-v", "2c", "-c", "public", &addr, IF_ENTRY],
        &[],
    )
    .await;
    out.assert_success("bulkwalk ifEntry");
    let combined = out.combined();
    assert!(combined.contains("lo"), "got: {combined}");
    assert!(combined.contains("eth0"), "got: {combined}");
}

#[tokio::test]
async fn bulkwalk_falls_back_to_getnext_on_v1() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpbulkwalk",
        &["-v", "1", "-c", "public", &addr, IF_ENTRY],
        &[],
    )
    .await;
    out.assert_success("bulkwalk v1 fallback");
    assert!(out.combined().contains("eth0"), "got: {}", out.combined());
}

#[tokio::test]
async fn bulkwalk_empty_subtree_reports_end() {
    let addr = spawn_rich_agent("public").await;
    // A subtree the agent does not serve: expect a clean, successful no-op.
    let out = run_async(
        "snmpbulkwalk",
        &["-v", "2c", "-c", "public", &addr, "1.3.6.1.4.1.99999"],
        &[],
    )
    .await;
    out.assert_success("bulkwalk empty subtree");
}
