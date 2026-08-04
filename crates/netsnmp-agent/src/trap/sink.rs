//! Output backends for the trap receiver (`snmptrapd`'s `-o`/`-O`/`--traphandle`
//! /`--forward` options).
//!
//! Each backend implements [`TrapSink`]: given a formatted notification string
//! (produced by [`format::format_notification`](super::format::format_notification)
//! when a `-F` format is given, or the default human-readable form otherwise)
//! and the parsed notification, it records/dispatches/forwards the event.
//!
//! The provided sinks mirror upstream `snmptrapd`:
//!
//! | Sink          | Upstream option                |
//! |---------------|--------------------------------|
//! | [`StdoutSink`]| default (logs via `tracing`)   |
//! | [`FileSink`]  | `-o FILE` / `-Lf FILE`         |
//! | [`HandleSink`]| `--traphandle OID CMD`         |
//! | [`ForwardSink`]| `--forward COMMUNITY HOST`    |

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use netsnmp::mib::MibRegistry;
use netsnmp::oid::Oid;
use netsnmp::trap::Notification;
use tracing::{info, warn};

use super::format::format_notification;
use super::ReceivedNotification;

/// A notification output backend. Each received notification is passed to every
/// registered sink via [`TrapSink::log`].
///
/// Implementations receive both the parsed notification (for matching and
/// forwarding) and the already-formatted line (the `-F` expansion or the
/// default human-readable form), so a sink that just appends text does not
/// need its own MIB handle.
///
/// `Debug` is a supertrait so that [`super::TrapReceiverConfig`] (which holds
/// `Vec<Arc<dyn TrapSink>>`) can derive `Debug`.
pub trait TrapSink: Send + Sync + std::fmt::Debug {
    /// Record or dispatch one notification. `line` is the formatted output
    /// (what `-F` produced, or the default form); `notif` is the parsed
    /// notification; `peer` is the source transport address.
    fn log(&self, line: &str, notif: &ReceivedNotification, peer: SocketAddr) -> io::Result<()>;
}

/// The default sink: emits the formatted line through `tracing::info!` (which
/// the `snmptrapd` binary routes to stdout via its `tracing` subscriber).
#[derive(Debug, Default)]
pub struct StdoutSink;

impl StdoutSink {
    /// Create a stdout sink.
    pub fn new() -> Self {
        Self
    }
}

impl TrapSink for StdoutSink {
    fn log(&self, line: &str, _notif: &ReceivedNotification, _peer: SocketAddr) -> io::Result<()> {
        info!("{line}");
        Ok(())
    }
}

/// An append-to-file sink (`-o FILE` / `-Lf FILE`). Each notification line is
/// appended to the configured file; the file is kept open across writes so the
/// per-notification cost is a single `write_all`. No rotation is performed
/// (matching the minimal `-F` path here; upstream's rotation is not modelled).
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl FileSink {
    /// Open (or create) `path` for appending. The file is created if it does
    /// not exist; existing content is preserved.
    pub fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(FileSink {
            path,
            file: Mutex::new(file),
        })
    }

    /// The file path this sink appends to.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl TrapSink for FileSink {
    fn log(&self, line: &str, _notif: &ReceivedNotification, _peer: SocketAddr) -> io::Result<()> {
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

/// One `--traphandle OID CMD` rule: when a notification whose trap OID is under
/// `oid_prefix` arrives, `command` is spawned with the varbinds fed on stdin
/// (one `name = value` per line), mirroring upstream `traphandle`.
#[derive(Clone, Debug)]
pub struct HandleRule {
    /// The OID prefix that selects this rule (e.g. `1.3.6.1.6.3.1.1.5.1` for
    /// `coldStart`).
    pub oid_prefix: Oid,
    /// The command line to execute (shell-split by the caller; passed to
    /// `tokio::process::Command` verbatim via `sh -c`).
    pub command: String,
}

impl HandleRule {
    /// Create a new rule.
    pub fn new(oid_prefix: Oid, command: String) -> Self {
        Self { oid_prefix, command }
    }

    /// Whether `trap_oid` falls under this rule's prefix.
    fn matches(&self, trap_oid: &Oid) -> bool {
        self.oid_prefix.is_prefix_of(trap_oid)
    }
}

/// A `traphandle` sink: spawns a subprocess for each matching notification,
/// feeding the varbinds as text on stdin (one `name = value` per line). Mirrors
/// upstream `snmptrapd`'s `traphandle` directive.
#[derive(Debug, Default)]
pub struct HandleSink {
    rules: Vec<HandleRule>,
}

impl HandleSink {
    /// Create an empty handle sink.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule (builder style).
    pub fn with_rule(mut self, rule: HandleRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Whether any rules are configured.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Add a rule at runtime.
    pub fn add_rule(&self, _rule: HandleRule) {
        // Rules are immutable after build for simplicity; the binary rebuilds
        // the sink from CLI args. This method is a no-op placeholder kept for
        // API symmetry with the other sinks.
    }
}

impl TrapSink for HandleSink {
    fn log(&self, _line: &str, notif: &ReceivedNotification, _peer: SocketAddr) -> io::Result<()> {
        for rule in &self.rules {
            if !rule.matches(&notif.notification.trap_oid) {
                continue;
            }
            // Build the stdin payload: one varbind per line as `name = value`.
            let stdin = format_varbinds_plain(&notif.notification);
            let command = rule.command.clone();
            // Spawn the command via `sh -c` so shell features (pipes, quotes)
            // work as in upstream `traphandle`. The child runs independently of
            // the receiver; the spawn+write+wait happens in a background task
            // so this sync `log` call never blocks.
            tokio::spawn(async move {
                let mut cmd = tokio::process::Command::new("sh");
                cmd.arg("-c").arg(&command);
                cmd.stdin(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::null());
                match cmd.spawn() {
                    Ok(mut child) => {
                        if let Some(mut stdin_handle) = child.stdin.take() {
                            use tokio::io::AsyncWriteExt;
                            let _ = stdin_handle.write_all(stdin.as_bytes()).await;
                            // Dropping stdin_handle closes the pipe.
                        }
                        let _ = child.wait().await;
                    }
                    Err(e) => {
                        warn!(
                            command = %command,
                            error = %e,
                            "traphandle: failed to spawn command"
                        );
                    }
                }
            });
        }
        Ok(())
    }
}

/// Format the notification's varbinds as `name = value` lines (one per line),
/// matching the upstream `traphandle` stdin format. Uses numeric OIDs (no MIB
/// handle is available to the sink at this layer).
fn format_varbinds_plain(notification: &Notification) -> String {
    let mut out = String::new();
    for vb in &notification.varbinds {
        out.push_str(&format!("{} = {}\n", vb.oid, vb.value));
    }
    out
}

/// A forwarding sink (`--forward COMMUNITY HOST`): re-sends each received
/// notification to another host as a v2c trap. Kept minimal: only v2c
/// community forwarding is supported (no v3 re-encryption).
#[derive(Clone, Debug)]
pub struct ForwardSink {
    community: Vec<u8>,
    target: String,
}

impl ForwardSink {
    /// Create a forwarder that re-sends to `target` (`host:port`) using
    /// `community`.
    pub fn new(community: Vec<u8>, target: String) -> Self {
        Self { community, target }
    }
}

impl TrapSink for ForwardSink {
    fn log(&self, _line: &str, notif: &ReceivedNotification, _peer: SocketAddr) -> io::Result<()> {
        let community = self.community.clone();
        let target = self.target.clone();
        let notification = notif.notification.clone();
        // Forwarding is fire-and-forget; do it in a background task so the
        // receiver is never blocked on a slow/dead forwarder.
        tokio::spawn(async move {
            let config = netsnmp::session::SessionConfig {
                version: netsnmp::message::Version::V2c,
                community,
                timeout: std::time::Duration::from_secs(2),
                retries: 1,
            };
            let session = match netsnmp::session::Session::open_udp(&target, config).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(target = %target, error = %e, "forward: cannot open session");
                    return;
                }
            };
            if let Err(e) = session
                .send_trap(
                    notification.sys_uptime,
                    &notification.trap_oid,
                    notification.varbinds,
                )
                .await
            {
                warn!(target = %target, error = %e, "forward: send_trap failed");
            }
        });
        Ok(())
    }
}

/// Render the default (no `-F`) human-readable form for one notification,
/// mirroring the existing `print_notification` output. Used when no format
/// string is supplied so the sinks still receive a sensible `line`.
pub fn default_line(notif: &ReceivedNotification, mib: &MibRegistry, peer: SocketAddr) -> String {
    // The default form is the historical multi-line block; collapse to a
    // single line for sink consumption by joining with " | ".
    let kind = if notif.confirmed { "INFORM" } else { "TRAP" };
    let security = match &notif.security_name {
        Some(name) => format!("v3 user={name}"),
        None => "v1/v2c".to_string(),
    };
    let mut parts = vec![
        format!("{kind} from {peer} [{security}]"),
        format!("sysUpTime.0 = Timeticks: ({})", notif.notification.sys_uptime),
        format!(
            "snmpTrapOID.0 = {}",
            mib.format_oid(&notif.notification.trap_oid)
        ),
    ];
    for vb in &notif.notification.varbinds {
        parts.push(format!("{} = {}", mib.format_oid(&vb.oid), vb.value));
    }
    parts.join(" | ")
}

/// Produce the output line for a notification: the `-F` format expansion if a
/// format is given, otherwise the default human-readable form.
pub fn render_line(
    format: Option<&str>,
    notif: &ReceivedNotification,
    mib: &MibRegistry,
    peer: SocketAddr,
) -> String {
    match format {
        Some(fmt) => format_notification(fmt, notif, mib, peer),
        None => default_line(notif, mib, peer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::pdu::VarBind;
    use netsnmp::value::Value;
    use crate::trap::NotifyVersion;

    fn cold_start() -> Oid {
        "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
    }

    fn sample_notif(trap_oid: Oid) -> ReceivedNotification {
        ReceivedNotification {
            version: NotifyVersion::Community,
            security_name: None,
            confirmed: false,
            notification: Notification {
                sys_uptime: 100,
                trap_oid,
                varbinds: vec![VarBind::new(
                    "1.3.6.1.2.1.1.5.0".parse().unwrap(),
                    Value::OctetString(b"host-a".to_vec()),
                )],
            },
        }
    }

    #[test]
    fn handle_rule_matches_prefix() {
        let rule = HandleRule::new(cold_start(), "true".to_string());
        assert!(rule.matches(&cold_start()));
        // A longer OID under the prefix matches.
        let sub: Oid = "1.3.6.1.6.3.1.1.5.1.0".parse().unwrap();
        assert!(rule.matches(&sub));
        // A different OID does not.
        let other: Oid = "1.3.6.1.6.3.1.1.5.2".parse().unwrap();
        assert!(!rule.matches(&other));
    }

    #[test]
    fn default_line_includes_trap_oid_and_varbinds() {
        let mib = MibRegistry::new();
        let notif = sample_notif(cold_start());
        let line = default_line(&notif, &mib, "127.0.0.1:1234".parse().unwrap());
        assert!(line.contains("TRAP from 127.0.0.1:1234"));
        assert!(line.contains("snmpTrapOID.0"));
        assert!(line.contains("STRING: host-a"));
    }

    #[test]
    fn render_line_uses_format_when_given() {
        let mib = MibRegistry::new();
        let notif = sample_notif(cold_start());
        let line = render_line(Some("%q"), &notif, &mib, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(line, ".1.3.6.1.6.3.1.1.5.1");
    }

    #[test]
    fn render_line_falls_back_to_default() {
        let mib = MibRegistry::new();
        let notif = sample_notif(cold_start());
        let line = render_line(None, &notif, &mib, "127.0.0.1:1234".parse().unwrap());
        assert!(line.contains("TRAP from"));
    }
}
