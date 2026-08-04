//! Integration tests for the `agentxtrap` tool.
//!
//! Drives the actual compiled `agentxtrap` binary against an in-process
//! [`AgentxMaster`] listening on a temporary Unix socket, verifying the Open →
//! Notify → close handshake completes and the master acknowledges the
//! notification.

mod common;

use std::sync::Arc;
use std::time::Duration;

use netsnmp_agent::agentx::AgentxMaster;
use tokio::time::sleep;

use common::{bin, run};

/// A unique temp socket path for this test process.
fn temp_sock(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "/tmp/agentx-it-{}-{nanos}-{label}.sock",
        std::process::id()
    )
}

/// Spawn an in-process AgentX master on a temp socket. Returns the socket path.
async fn spawn_master(label: &str) -> String {
    let sock = temp_sock(label);
    let _ = std::fs::remove_file(&sock);
    let master = Arc::new(AgentxMaster::new());
    let m = Arc::clone(&master);
    let path = sock.clone();
    tokio::spawn(async move {
        let _ = m.serve_unix(&path).await;
    });
    // Give the listener a moment to come up.
    sleep(Duration::from_millis(100)).await;
    sock
}

#[tokio::test(flavor = "multi_thread")]
async fn agentxtrap_sends_notification_to_master() {
    let sock = spawn_master("notify").await;

    // Run the agentxtrap binary: trap OID + one extra varbind.
    let out = run(
        "agentxtrap",
        &[
            "-x",
            &sock,
            "1.3.6.1.6.3.1.1.5.1",
            "1.3.6.1.2.1.1.5.0",
            "s",
            "host-a",
        ],
        &[],
    );
    out.assert_success("agentxtrap notify");
    assert!(
        out.combined().contains("notification sent"),
        "expected 'notification sent' in output, got: {}",
        out.combined()
    );

    let _ = std::fs::remove_file(&sock);
}

#[tokio::test(flavor = "multi_thread")]
async fn agentxtrap_missing_oid_errors() {
    let sock = spawn_master("noargs").await;
    let out = run("agentxtrap", &["-x", &sock], &[]);
    out.assert_failure("agentxtrap without OID should fail");
    assert!(out.combined().contains("missing trap OID"));
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test(flavor = "multi_thread")]
async fn agentxtrap_unreachable_master_errors() {
    // A socket path that does not exist: must fail with a connect error.
    let out = run(
        "agentxtrap",
        &["-x", "/nonexistent-agentx-test.sock", "1.3.6.1.6.3.1.1.5.1"],
        &[],
    );
    out.assert_failure("agentxtrap to nonexistent socket should fail");
    assert!(out.combined().contains("connect to"));
}

#[tokio::test(flavor = "multi_thread")]
async fn agentxtrap_default_socket_flag_present() {
    // `--help` confirms the binary is wired into the test `bin()` helper and
    // that the default socket is /var/agentx/master.
    let _ = bin("agentxtrap");
    let out = run("agentxtrap", &["--help"], &[]);
    out.assert_success("agentxtrap --help");
    assert!(out.combined().contains("/var/agentx/master"));
}
