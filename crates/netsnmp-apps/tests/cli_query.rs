//! Integration tests for the query/set CLI tools (`snmpget`, `snmpgetnext`,
//! `snmpwalk`, `snmpset`) driven against an in-process agent over UDP, plus the
//! common error paths and `snmp.conf` default-community handling.

mod common;

use common::{
    IF_DESCR, SYS_DESCR, SYS_DESCR_VALUE, SYS_NAME, SYS_NAME_VALUE, SYS_SERVICES, run_async,
    spawn_agent,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpget_scalar_by_numeric_oid() {
    let addr = spawn_agent("public").await;
    let out = run_async(
        "snmpget",
        &["-c", "public", "-v", "2c", &addr, SYS_DESCR],
        &[],
    )
    .await;
    out.assert_success("snmpget numeric");
    assert!(
        out.combined().contains(SYS_DESCR_VALUE),
        "missing value: {}",
        out.combined()
    );
    assert!(out.combined().contains("STRING:"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpget_scalar_by_symbolic_name() {
    let addr = spawn_agent("public").await;
    let out = run_async("snmpget", &["-c", "public", &addr, "sysDescr.0"], &[]).await;
    out.assert_success("snmpget symbolic");
    assert!(out.combined().contains(SYS_DESCR_VALUE));
    // The numeric OID is rendered back symbolically using the built-in registry.
    assert!(out.combined().contains("sysDescr"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpget_multiple_oids_in_one_request() {
    let addr = spawn_agent("public").await;
    let out = run_async(
        "snmpget",
        &["-c", "public", &addr, SYS_DESCR, SYS_NAME],
        &[],
    )
    .await;
    out.assert_success("snmpget multi");
    assert!(out.combined().contains(SYS_DESCR_VALUE));
    assert!(out.combined().contains(SYS_NAME_VALUE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpget_works_over_v1() {
    let addr = spawn_agent("public").await;
    let out = run_async(
        "snmpget",
        &["-v", "1", "-c", "public", &addr, SYS_DESCR],
        &[],
    )
    .await;
    out.assert_success("snmpget v1");
    assert!(out.combined().contains(SYS_DESCR_VALUE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpgetnext_returns_successor() {
    let addr = spawn_agent("public").await;
    // GETNEXT of the column object (no instance) yields the first instance.
    let out = run_async(
        "snmpgetnext",
        &["-c", "public", &addr, "1.3.6.1.2.1.1.1"],
        &[],
    )
    .await;
    out.assert_success("snmpgetnext");
    assert!(out.combined().contains(SYS_DESCR_VALUE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpwalk_enumerates_table_column() {
    let addr = spawn_agent("public").await;
    let out = run_async("snmpwalk", &["-c", "public", &addr, IF_DESCR], &[]).await;
    out.assert_success("snmpwalk table");
    let text = out.combined();
    assert!(text.contains("lo"), "missing lo: {text}");
    assert!(text.contains("eth0"), "missing eth0: {text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpwalk_empty_subtree_reports_no_variables() {
    let addr = spawn_agent("public").await;
    // Nothing is registered under this subtree.
    let out = run_async("snmpwalk", &["-c", "public", &addr, "1.3.6.1.2.1.99"], &[]).await;
    out.assert_success("snmpwalk empty");
    assert!(
        out.combined().contains("No more variables"),
        "expected end-of-MIB note: {}",
        out.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpset_string_then_get_roundtrip() {
    let addr = spawn_agent("public").await;
    let set = run_async(
        "snmpset",
        &["-c", "public", &addr, "sysName.0", "s", "renamed-host"],
        &[],
    )
    .await;
    set.assert_success("snmpset string");

    let get = run_async("snmpget", &["-c", "public", &addr, SYS_NAME], &[]).await;
    get.assert_success("snmpget after set");
    assert!(
        get.combined().contains("renamed-host"),
        "value not persisted: {}",
        get.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpset_integer_then_get_roundtrip() {
    let addr = spawn_agent("public").await;
    let set = run_async(
        "snmpset",
        &["-c", "public", &addr, SYS_SERVICES, "i", "5"],
        &[],
    )
    .await;
    set.assert_success("snmpset integer");

    let get = run_async("snmpget", &["-c", "public", &addr, SYS_SERVICES], &[]).await;
    get.assert_success("snmpget integer");
    assert!(
        get.combined().contains("INTEGER: 5"),
        "integer not persisted: {}",
        get.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmpset_rejects_incomplete_triple() {
    let addr = spawn_agent("public").await;
    // Two args instead of OID TYPE VALUE.
    let out = run_async("snmpset", &["-c", "public", &addr, "sysName.0", "s"], &[]).await;
    out.assert_failure("snmpset bad triple");
    assert!(out.combined().contains("triple"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unresolvable_oid_token_is_reported() {
    let addr = spawn_agent("public").await;
    let out = run_async(
        "snmpget",
        &["-c", "public", &addr, "definitely.not.an.oid"],
        &[],
    )
    .await;
    out.assert_failure("bad oid token");
    assert!(
        out.combined().contains("cannot parse OID"),
        "missing parse error: {}",
        out.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_version_is_rejected() {
    let addr = spawn_agent("public").await;
    let out = run_async("snmpget", &["-v", "9", &addr, SYS_DESCR], &[]).await;
    out.assert_failure("bad version");
    assert!(
        out.combined().contains("unsupported version"),
        "missing version error: {}",
        out.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_community_times_out() {
    let addr = spawn_agent("public").await;
    // The agent silently drops mismatched-community requests, so the client
    // exhausts its (zero) retries and times out.
    let out = run_async(
        "snmpget",
        &["-c", "wrong", "-t", "1", "-r", "0", &addr, SYS_DESCR],
        &[],
    )
    .await;
    out.assert_failure("wrong community");
    assert!(
        out.combined().contains("timed out"),
        "expected timeout: {}",
        out.combined()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_agent_fails_fast() {
    // No agent is bound at this reserved address.
    let dead = common::reserve_udp_addr();
    let out = run_async(
        "snmpget",
        &["-c", "public", "-t", "1", "-r", "0", &dead, SYS_DESCR],
        &[],
    )
    .await;
    out.assert_failure("unreachable agent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn community_taken_from_snmp_conf_default() {
    // Agent expects a non-default community.
    let addr = spawn_agent("s3cr3t").await;

    // Fixture snmp.conf supplying defCommunity; no `-c` on the command line.
    let dir = std::env::temp_dir().join(format!(
        "netsnmp-apps-conf-{}-{}",
        std::process::id(),
        now_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("snmp.conf"),
        "defCommunity s3cr3t\ndefVersion 2c\n",
    )
    .unwrap();
    let confpath = dir.to_string_lossy().into_owned();

    let with_conf = run_async(
        "snmpget",
        &[&addr, SYS_DESCR],
        &[("SNMPCONFPATH", &confpath)],
    )
    .await;
    with_conf.assert_success("snmpget via snmp.conf defCommunity");
    assert!(with_conf.combined().contains(SYS_DESCR_VALUE));

    // Control: without the config, the built-in default community "public"
    // does not match, so the request is dropped.
    let no_conf = run_async("snmpget", &["-t", "1", "-r", "0", &addr, SYS_DESCR], &[]).await;
    no_conf.assert_failure("snmpget without matching community");

    let _ = std::fs::remove_dir_all(&dir);
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
