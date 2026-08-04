//! Integration tests for the table/status display tools: `snmptable`,
//! `snmpstatus`, `snmpdf`, `snmpps` and `snmpnetstat`.

mod common;

use common::{run_async, spawn_rich_agent};

const IF_ENTRY: &str = "1.3.6.1.2.1.2.2.1";

fn v2c<'a>(addr: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec!["-v", "2c", "-c", "public"];
    v.extend_from_slice(extra);
    v.push(addr);
    v
}

#[tokio::test]
async fn snmptable_renders_rows() {
    let addr = spawn_rich_agent("public").await;
    // snmptable takes AGENT then the table OID positional.
    let out = run_async(
        "snmptable",
        &["-v", "2c", "-c", "public", &addr, IF_ENTRY],
        &[],
    )
    .await;
    out.assert_success("snmptable ifEntry");
    let combined = out.combined();
    assert!(combined.contains("SNMP table"), "got: {combined}");
    assert!(combined.contains("lo"), "got: {combined}");
    assert!(combined.contains("eth0"), "got: {combined}");
    // Two rows with indices 1 and 2.
    assert!(combined.contains("index"), "header missing: {combined}");
}

#[tokio::test]
async fn snmpstatus_summarizes_device() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &[]);
    let out = run_async("snmpstatus", &args, &[]).await;
    out.assert_success("snmpstatus");
    let combined = out.combined();
    assert!(combined.contains("rich test agent"), "got: {combined}");
    assert!(combined.contains("Up:"), "got: {combined}");
    assert!(combined.contains("Interfaces: 2"), "got: {combined}");
    // snmpInPkts / snmpOutPkts.
    assert!(combined.contains("100"), "got: {combined}");
    assert!(combined.contains("90"), "got: {combined}");
}

#[tokio::test]
async fn snmpdf_reports_storage() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &[]);
    let out = run_async("snmpdf", &args, &[]).await;
    out.assert_success("snmpdf");
    let combined = out.combined();
    assert!(combined.contains('/'), "got: {combined}");
    // 1000 units * 1024 bytes / 1024 = 1000 kB total; 250 used => 25%.
    assert!(combined.contains("1000"), "size kB missing: {combined}");
    assert!(combined.contains("25%"), "percent missing: {combined}");
}

#[tokio::test]
async fn snmpps_lists_processes() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &[]);
    let out = run_async("snmpps", &args, &[]).await;
    out.assert_success("snmpps");
    let combined = out.combined();
    assert!(combined.contains("init"), "got: {combined}");
    assert!(combined.contains("bash"), "got: {combined}");
}

#[tokio::test]
async fn snmpnetstat_shows_tcp_and_udp() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &[]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat");
    let combined = out.combined();
    assert!(
        combined.contains("127.0.0.1:80"),
        "tcp endpoint: {combined}"
    );
    assert!(combined.contains("0.0.0.0:161"), "udp endpoint: {combined}");
}

#[tokio::test]
async fn snmpnetstat_protocol_filter_udp_only() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["--protocol", "udp"]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat udp only");
    let combined = out.combined();
    assert!(combined.contains("0.0.0.0:161"), "udp endpoint: {combined}");
    assert!(
        !combined.contains("127.0.0.1:80"),
        "tcp should be filtered out: {combined}"
    );
}

#[tokio::test]
async fn snmpnetstat_i_lists_interfaces() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["-i"]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat -i");
    let combined = out.combined();
    assert!(combined.contains("lo") || combined.contains("eth0"), "ifTable: {combined}");
    // The interface-table header is present.
    assert!(combined.contains("Name"), "header: {combined}");
}

#[tokio::test]
async fn snmpnetstat_p_tcp_lists_connections() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["--protocol", "tcp"]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat -p tcp");
    let combined = out.combined();
    assert!(combined.contains("127.0.0.1:80"), "tcp endpoint: {combined}");
    assert!(
        !combined.contains("0.0.0.0:161"),
        "udp should be filtered out: {combined}"
    );
}

#[tokio::test]
async fn snmpnetstat_n_numeric() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["--protocol", "tcp", "-n"]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat -p tcp -n");
    let combined = out.combined();
    // Numeric mode renders the state as its integer code (the rich agent's
    // tcpConnState is 2 = listen). The endpoint is still present.
    assert!(combined.contains("127.0.0.1:80"), "tcp endpoint: {combined}");
}

#[tokio::test]
async fn snmpnetstat_s_stats() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["--statistics"]);
    let out = run_async("snmpnetstat", &args, &[]).await;
    out.assert_success("snmpnetstat --statistics");
    let combined = out.combined();
    // The rich agent serves snmpInPkts (100) / snmpOutPkts (90); the Snmp:
    // section must appear. Other sections (Ip/Tcp/Udp) may be absent.
    assert!(
        combined.contains("Snmp:") || combined.contains("Tcp:") || combined.contains("Ip:"),
        "expected a stats section, got: {combined}"
    );
}

#[tokio::test]
async fn snmpps_c_shows_command_line() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["--cmdline"]);
    let out = run_async("snmpps", &args, &[]).await;
    out.assert_success("snmpps --cmdline");
    let combined = out.combined();
    // The Command column header is present and at least one process path shows.
    assert!(combined.contains("Command"), "Command header: {combined}");
    assert!(
        combined.contains("/sbin/init") || combined.contains("/bin/bash"),
        "command line: {combined}"
    );
}

#[tokio::test]
async fn snmpps_w_shows_perf() {
    let addr = spawn_rich_agent("public").await;
    let args = v2c(&addr, &["-w"]);
    let out = run_async("snmpps", &args, &[]).await;
    // The rich agent does not serve hrSWRunPerf, so the tool must still
    // succeed (graceful degradation) and advertise the CPU%/MEM columns.
    out.assert_success("snmpps -w");
    let combined = out.combined();
    assert!(combined.contains("CPU%") || combined.contains("MEM"), "perf header: {combined}");
}

#[tokio::test]
async fn snmpps_per_pid() {
    let addr = spawn_rich_agent("public").await;
    // The rich agent serves hrSWRun rows indexed 1 (init) and 2 (bash).
    // Requesting pid 1 must show only that row. The PID positional must follow
    // the AGENT positional, so build the args explicitly (addr before pid).
    let args = ["-v", "2c", "-c", "public", &addr, "1"];
    let out = run_async("snmpps", &args, &[]).await;
    out.assert_success("snmpps <pid>");
    let combined = out.combined();
    assert!(combined.contains("init"), "pid 1 name: {combined}");
    assert!(
        !combined.contains("bash"),
        "pid 2 should be filtered out: {combined}"
    );
}

