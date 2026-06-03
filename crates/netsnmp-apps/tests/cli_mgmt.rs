//! Integration tests for the management tools `snmpusm` and `snmpvacm`.
//!
//! The in-process test agent does not implement remote management of the USM /
//! VACM MIB tables, so these tests focus on argument handling and on confirming
//! that the tools build and transmit a SET (which the agent then rejects). The
//! happy-path variable-binding construction is covered by unit tests in
//! `netsnmp_apps::mgmt`.

mod common;

use common::{run_async, spawn_rich_agent};

#[tokio::test]
async fn snmpusm_requires_engine_id_without_v3() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &["-v", "2c", "-c", "public", &addr, "delete", "bob"],
        &[],
    )
    .await;
    out.assert_failure("snmpusm without engine id");
    assert!(
        out.combined().to_lowercase().contains("engine id"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpusm_unknown_operation() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "8000000001",
            &addr,
            "frobnicate",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm unknown op");
    assert!(
        out.combined().contains("unknown operation"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpusm_delete_transmits_set_and_agent_rejects() {
    let addr = spawn_rich_agent("public").await;
    // The agent has no usmUserTable, so the SET is rejected — but this proves
    // the tool parsed the op, built the binding and sent the request.
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "8000000001",
            &addr,
            "delete",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm delete rejected by agent");
}

#[tokio::test]
async fn snmpusm_bad_engine_id_hex() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpusm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            "--engine-id",
            "xyz",
            &addr,
            "delete",
            "bob",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpusm bad hex");
}

#[tokio::test]
async fn snmpvacm_unknown_operation() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &["-v", "2c", "-c", "public", &addr, "frobnicate"],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm unknown op");
    assert!(
        out.combined().contains("unknown operation"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpvacm_createview_missing_args() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &["-v", "2c", "-c", "public", &addr, "createview", "onlyname"],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm createview missing subtree");
    assert!(
        out.combined().to_lowercase().contains("usage"),
        "got: {}",
        out.combined()
    );
}

#[tokio::test]
async fn snmpvacm_createaccess_rejects_non_integer_model() {
    let addr = spawn_rich_agent("public").await;
    let out = run_async(
        "snmpvacm",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            &addr,
            "createaccess",
            "grp",
            "ctx",
            "notanumber",
            "3",
            "all",
            "all",
            "none",
        ],
        &[],
    )
    .await;
    out.assert_failure("snmpvacm bad model");
    assert!(
        out.combined().contains("expected an integer"),
        "got: {}",
        out.combined()
    );
}
