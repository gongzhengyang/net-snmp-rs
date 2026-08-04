//! Integration tests for the notification tools.
//!
//! * `snmptrap` (sender) is driven against an in-process [`TrapReceiver`].
//! * `snmptrapd` (receiver) is launched as a child process and fed a trap from
//!   an in-process [`Session`].

// Test names mirror upstream tool/flag names (e.g. `snmptrapd_format_F_...`),
// which are not snake_case; allow that here rather than mangle the names.
#![allow(non_snake_case)]

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

use netsnmp::message::Version;
use netsnmp::oid::Oid;
use netsnmp::session::{Session, SessionConfig};
use netsnmp_agent::{ReceivedNotification, TrapReceiver, TrapReceiverConfig};
use tokio::sync::mpsc;
use tokio::time::timeout;

use common::{bin, reserve_udp_addr, run_async};

const COLD_START: &str = "1.3.6.1.6.3.1.1.5.1";

/// A flattened copy of a received notification, sendable across a channel.
#[derive(Debug)]
struct Got {
    uptime: u32,
    trap_oid: String,
    confirmed: bool,
    varbinds: usize,
    security: Option<String>,
}

impl Got {
    fn capture(note: &ReceivedNotification) -> Self {
        Got {
            uptime: note.notification.sys_uptime,
            trap_oid: note.notification.trap_oid.to_string(),
            confirmed: note.confirmed,
            varbinds: note.notification.varbinds.len(),
            security: note.security_name.clone(),
        }
    }
}

/// Bind an in-process trap receiver and stream captured notifications.
async fn spawn_receiver(community: &str) -> (String, mpsc::UnboundedReceiver<Got>) {
    let config = TrapReceiverConfig {
        community: Some(community.as_bytes().to_vec()),
        bind_addr: "127.0.0.1:0".to_string(),
        ..TrapReceiverConfig::default()
    };
    let receiver = TrapReceiver::new(config);
    let socket = receiver.bind().await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let _ = receiver
            .serve_on(socket, move |note, _peer| {
                let _ = tx.send(Got::capture(note));
            })
            .await;
    });
    (addr, rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrap_sends_v2c_trap_with_varbind() {
    let (addr, mut rx) = spawn_receiver("public").await;

    let out = run_async(
        "snmptrap",
        &[
            "-v",
            "2c",
            "-c",
            "public",
            &addr,
            "123",
            COLD_START,
            "1.3.6.1.2.1.1.6.0",
            "s",
            "rack-9",
        ],
        &[],
    )
    .await;
    out.assert_success("snmptrap trap");
    assert!(out.combined().contains("trap sent"));

    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for trap")
        .expect("receiver channel closed");
    assert_eq!(got.uptime, 123);
    assert!(!got.confirmed);
    // `Oid`'s Display renders a leading dot (`.1.3.6...`).
    assert!(
        got.trap_oid.ends_with(COLD_START),
        "unexpected trap OID: {}",
        got.trap_oid
    );
    assert!(got.varbinds >= 1, "expected the extra varbind: {got:?}");
    assert!(got.security.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrap_inform_is_acknowledged() {
    let (addr, mut rx) = spawn_receiver("public").await;

    let out = run_async(
        "snmptrap",
        &[
            "-v", "2c", "-c", "public", "--inform", &addr, "456", COLD_START,
        ],
        &[],
    )
    .await;
    out.assert_success("snmptrap inform");
    assert!(
        out.combined().contains("inform acknowledged"),
        "expected ack: {}",
        out.combined()
    );

    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for inform")
        .expect("receiver channel closed");
    assert!(got.confirmed);
    assert_eq!(got.uptime, 456);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrap_sends_v1_trap() {
    // SNMPv1 Trap-PDU end-to-end: the CLI builds the legacy Trap-PDU and the
    // in-process receiver decodes it, translating enterprise-specific traps to
    // snmpTrapOID = enterprise.0.<specific> per RFC 3584.
    let (addr, mut rx) = spawn_receiver("public").await;

    let enterprise = "1.3.6.1.4.1.8072.2";
    let out = run_async(
        "snmptrap",
        &[
            "-v",
            "1",
            "-c",
            "public",
            &addr,
            enterprise,
            "127.0.0.1",
            "6", // enterpriseSpecific
            "1", // specific trap number
            "300", // uptime
        ],
        &[],
    )
    .await;
    out.assert_success("snmptrap v1");
    assert!(out.combined().contains("v1 trap sent"), "output: {}", out.combined());

    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for v1 trap")
        .expect("receiver channel closed");
    assert_eq!(got.uptime, 300);
    assert!(!got.confirmed);
    // enterpriseSpecific(6) → enterprise.0.<specific>
    assert!(
        got.trap_oid.ends_with(&format!("{enterprise}.0.1")),
        "unexpected translated trap OID: {}",
        got.trap_oid
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrap_sends_v1_generic_trap_maps_to_snmpTraps() {
    // A v1 generic trap (linkDown = 2) maps to snmpTraps.2 (coldStart is .1).
    let (addr, mut rx) = spawn_receiver("public").await;
    let out = run_async(
        "snmptrap",
        &[
            "-v",
            "1",
            "-c",
            "public",
            &addr,
            "1.3.6.1.4.1.8072.2", // enterprise (irrelevant for a generic trap)
            "0.0.0.0",
            "2", // linkDown
            "0",
            "99",
        ],
        &[],
    )
    .await;
    out.assert_success("snmptrap v1 generic");
    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for v1 generic trap")
        .expect("receiver channel closed");
    // linkDown → 1.3.6.1.6.3.1.1.5.2
    assert!(got.trap_oid.ends_with("1.3.6.1.6.3.1.1.5.2"), "got: {}", got.trap_oid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrapd_receives_and_prints_trap() {
    let addr = reserve_udp_addr();

    // Launch the real snmptrapd, capturing both streams as line events.
    let mut child = Command::new(bin("snmptrapd"))
        .args(["-c", "public", &addr])
        .env("RUST_LOG", "info")
        .env("MIBDIRS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn snmptrapd");

    let mut lines = line_stream(&mut child);

    // Wait until it reports the socket is bound before sending anything.
    assert!(
        wait_for(&mut lines, "listening", Duration::from_secs(5)).await,
        "snmptrapd did not report listening"
    );

    // Send a trap from an in-process session.
    let session = Session::open_udp(
        &addr,
        SessionConfig {
            version: Version::V2c,
            community: b"public".to_vec(),
            timeout: Duration::from_secs(2),
            retries: 1,
        },
    )
    .await
    .expect("open session to snmptrapd");
    let trap_oid: Oid = COLD_START.parse().unwrap();
    session
        .send_trap(789, &trap_oid, Vec::new())
        .await
        .expect("send trap");

    let saw_trap = wait_for(&mut lines, "TRAP from", Duration::from_secs(5)).await;

    let _ = child.kill();
    let _ = child.wait();

    assert!(saw_trap, "snmptrapd did not print the received trap");
}

/// Run the real `snmptrapd` with `-F FORMAT` and confirm the formatted output
/// appears. Sends a coldStart trap and asserts the output contains the trap OID
/// (numeric, via `%q`) and the varbind list (via `%v`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrapd_format_F_outputs_custom_format() {
    let addr = reserve_udp_addr();

    let mut child = Command::new(bin("snmptrapd"))
        .args(["-c", "public", "-F", "%q %v", &addr])
        .env("RUST_LOG", "info")
        .env("MIBDIRS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn snmptrapd");

    let mut lines = line_stream(&mut child);
    assert!(
        wait_for(&mut lines, "listening", Duration::from_secs(5)).await,
        "snmptrapd did not report listening"
    );

    let session = Session::open_udp(
        &addr,
        SessionConfig {
            version: Version::V2c,
            community: b"public".to_vec(),
            timeout: Duration::from_secs(2),
            retries: 1,
        },
    )
    .await
    .expect("open session");
    let trap_oid: Oid = COLD_START.parse().unwrap();
    let extra = vec![netsnmp::pdu::VarBind::new(
        "1.3.6.1.2.1.1.5.0".parse().unwrap(),
        netsnmp::value::Value::OctetString(b"format-host".to_vec()),
    )];
    session.send_trap(789, &trap_oid, extra).await.unwrap();

    // The formatted line is "<trap-oid-numeric> <varbinds>". With an empty MIB
    // the trap OID renders numerically (`.1.3.6.1.6.3.1.1.5.1`) and the varbind
    // as `name = value`.
    let saw = wait_for(&mut lines, "1.3.6.1.6.3.1.1.5.1", Duration::from_secs(5)).await;

    let _ = child.kill();
    let _ = child.wait();

    assert!(saw, "snmptrapd -F did not print the formatted trap OID");
}

/// Run the real `snmptrapd` with `--traphandle OID SCRIPT` and confirm the
/// script is invoked when a matching trap arrives. The script writes a marker
/// file whose contents are the varbinds it received on stdin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snmptrapd_traphandle_invokes_script() {
    let addr = reserve_udp_addr();
    let marker = std::env::temp_dir().join(format!(
        "netsnmp-rs-traphandle-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_str = marker.to_string_lossy().to_string();
    // The script reads stdin, writes it to the marker file, then exits.
    let script = format!("cat > {marker_str}");

    let mut child = Command::new(bin("snmptrapd"))
        .args([
            "-c",
            "public",
            "--traphandle",
            COLD_START,
            &script,
            &addr,
        ])
        .env("RUST_LOG", "info")
        .env("MIBDIRS", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn snmptrapd");

    let mut lines = line_stream(&mut child);
    assert!(
        wait_for(&mut lines, "listening", Duration::from_secs(5)).await,
        "snmptrapd did not report listening"
    );

    let session = Session::open_udp(
        &addr,
        SessionConfig {
            version: Version::V2c,
            community: b"public".to_vec(),
            timeout: Duration::from_secs(2),
            retries: 1,
        },
    )
    .await
    .expect("open session");
    let trap_oid: Oid = COLD_START.parse().unwrap();
    let extra = vec![netsnmp::pdu::VarBind::new(
        "1.3.6.1.2.1.1.5.0".parse().unwrap(),
        netsnmp::value::Value::OctetString(b"handle-host".to_vec()),
    )];
    session.send_trap(42, &trap_oid, extra).await.unwrap();

    // Poll for the marker file (the traphandle runs asynchronously).
    let mut saw = false;
    for _ in 0..100 {
        if let Ok(content) = std::fs::read_to_string(&marker) {
            // The script receives the varbinds on stdin as `name = value`.
            if content.contains("handle-host") {
                saw = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&marker);

    assert!(
        saw,
        "traphandle script was not invoked or did not receive the varbinds"
    );
}

/// Merge a child's stdout and stderr into a single stream of text lines.
fn line_stream(child: &mut std::process::Child) -> mpsc::UnboundedReceiver<String> {
    use std::io::BufRead;
    let (tx, rx) = mpsc::unbounded_channel();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stream);
            for line in reader.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    rx
}

/// Wait up to `budget` for a line containing `needle`.
async fn wait_for(
    rx: &mut mpsc::UnboundedReceiver<String>,
    needle: &str,
    budget: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match timeout(remaining, rx.recv()).await {
            Ok(Some(line)) if line.contains(needle) => return true,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return false,
        }
    }
}
