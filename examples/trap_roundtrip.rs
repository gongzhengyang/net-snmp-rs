//! Notifications end-to-end in one process: run a `TrapReceiver` (the core of
//! `snmptrapd`) in the background, then send it a v2c trap and a confirmed
//! inform from a client `Session`.
//!
//! Run:
//! ```text
//! cargo run -p netsnmp-examples --example trap_roundtrip
//! ```

use std::time::Duration;

use netsnmp::{Oid, Session, SessionConfig, VarBind, Value};
use netsnmp_agent::{ReceivedNotification, TrapReceiver, TrapReceiverConfig};
use tokio::sync::mpsc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), netsnmp::Error> {
    netsnmp_examples::init_tracing();

    // ---- 1. Start a receiver on an ephemeral port -----------------------
    let config = TrapReceiverConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        community: Some(b"public".to_vec()),
        ..TrapReceiverConfig::default()
    };
    let receiver = TrapReceiver::new(config);
    let socket = receiver.bind().await?;
    let recv_addr = socket.local_addr()?;
    info!("trap receiver listening on {recv_addr}");

    // The serve loop calls our closure for each valid notification; forward
    // them to `main` over a channel.
    let (tx, mut rx) = mpsc::unbounded_channel::<ReceivedNotification>();
    tokio::spawn(async move {
        let _ = receiver
            .serve_on(socket, move |note, _peer| {
                let _ = tx.send(note.clone());
            })
            .await;
    });

    // ---- 2. Send a trap and an inform from a client session -------------
    let session = Session::open_udp(&recv_addr.to_string(), SessionConfig::default()).await?;
    let cold_start: Oid = "1.3.6.1.6.3.1.1.5.1".parse()?;
    let sys_name: Oid = "1.3.6.1.2.1.1.5.0".parse()?;

    // Unconfirmed SNMPv2-Trap with one extra varbind (fire-and-forget).
    session
        .send_trap(
            1000, // sysUpTime.0 (centiseconds)
            &cold_start,
            vec![VarBind::new(
                sys_name.clone(),
                Value::OctetString(b"sensor-A".to_vec()),
            )],
        )
        .await?;

    // Confirmed InformRequest — awaits the receiver's acknowledgement.
    let ack = session.send_inform(2000, &cold_start, vec![]).await?;
    info!("inform acknowledged (request_id={})", ack.request_id);

    // ---- 3. Print what the receiver surfaced ----------------------------
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(note)) => print_notification(&note),
            _ => warn!("timed out waiting for a notification"),
        }
    }
    Ok(())
}

fn print_notification(note: &ReceivedNotification) {
    info!(
        "received {:?} notification (confirmed={}): trapOID={}, uptime={}",
        note.version,
        note.confirmed,
        note.notification.trap_oid,
        note.notification.sys_uptime,
    );
    for vb in &note.notification.varbinds {
        info!("    varbind {} = {}", vb.oid, vb.value);
    }
}
