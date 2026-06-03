//! The integration test suite: the full set of checks plus the special trap
//! send/receive orchestration.
//!
//! Every shipped CLI tool is exercised. Checks are classified as
//! required / expect-fail / best-effort (see [`Category`](crate::check::Category))
//! and grouped into thematic submodules, each of which contributes its checks
//! via `checks()`.

mod bulk;
mod core;
mod help;
mod mgmt;
mod monitor;
mod tables;
mod translate;
mod v3;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::check::{Check, Outcome, Status};
use crate::runner::{self, CommandResult};

/// Every binary the suite touches (also used for `--help` smoke checks and the
/// preflight existence check). `snmpd` is included for the help check only.
pub const TOOLS: &[&str] = &[
    "snmpget",
    "snmpgetnext",
    "snmpwalk",
    "snmpset",
    "snmpbulkget",
    "snmpbulkwalk",
    "snmptable",
    "snmpstatus",
    "snmpdelta",
    "snmpdf",
    "snmpps",
    "snmpnetstat",
    "snmptest",
    "snmptranslate",
    "snmptrap",
    "snmptrapd",
    "snmpusm",
    "snmpvacm",
    "snmpd",
];

/// Runtime parameters used to build concrete command lines.
pub struct Params {
    pub agent: String,
    pub community: String,
    /// The complete SNMPv3 flag set (e.g. `-v 3 -u bob -l authPriv -a SHA ...`).
    pub v3: Vec<String>,
}

/// SNMPv2c flags + agent + extra positional args. Shared by the submodules.
fn v2(p: &Params, extra: &[&str]) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-v".into(),
        "2c".into(),
        "-c".into(),
        p.community.clone(),
        p.agent.clone(),
    ];
    a.extend(extra.iter().map(|s| (*s).to_string()));
    a
}

/// SNMPv3 flags + agent + extra positional args. Shared by the submodules.
fn v3(p: &Params, extra: &[&str]) -> Vec<String> {
    let mut a = p.v3.clone();
    a.push(p.agent.clone());
    a.extend(extra.iter().map(|s| (*s).to_string()));
    a
}

/// Build the full, ordered list of checks for the given parameters.
pub fn build(p: &Params) -> Vec<Check> {
    let mut c = Vec::new();
    c.extend(help::checks());
    c.extend(core::checks(p));
    c.extend(bulk::checks(p));
    c.extend(tables::checks(p));
    c.extend(monitor::checks(p));
    c.extend(translate::checks(p));
    c.extend(mgmt::checks(p));
    c.extend(v3::checks(p));
    c
}

/// Orchestrated trap test: start `snmptrapd` on loopback, fire one v2c trap at
/// it with `snmptrap`, then confirm the listener captured it.
pub fn run_trap(paths: &HashMap<String, PathBuf>, community: &str, timeout: Duration) -> Outcome {
    let check = Check::new("snmptrap", "send + receive a v2c notification", "snmptrap")
        .args([
            "-v",
            "2c",
            "-c",
            community,
            "127.0.0.1:1162",
            "''",
            "1.3.6.1.6.3.1.1.5.1",
            "sysName.0",
            "s",
            "trap-from-itest",
        ])
        .offline()
        .hint("Ensure snmptrap/snmptrapd are present and UDP/1162 on loopback is free.");

    let Some(trapd_path) = paths.get("snmptrapd") else {
        return fail_outcome(check, "snmptrapd binary not found");
    };
    let Some(trap_path) = paths.get("snmptrap") else {
        return fail_outcome(check, "snmptrap binary not found");
    };

    // Start the listener with piped output.
    let mut trapd = match Command::new(trapd_path)
        .args(["-c", community, "127.0.0.1:1162"])
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return fail_outcome(check, &format!("could not start snmptrapd: {e}")),
    };

    use std::io::Read;
    let mut tout = trapd.stdout.take().expect("trapd stdout");
    let mut terr = trapd.stderr.take().expect("trapd stderr");
    let oh = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = tout.read_to_string(&mut s);
        s
    });
    let eh = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = terr.read_to_string(&mut s);
        s
    });

    // Give the listener a moment to bind.
    std::thread::sleep(Duration::from_millis(1500));

    let send_args: Vec<String> = vec![
        "-v".into(),
        "2c".into(),
        "-c".into(),
        community.into(),
        "127.0.0.1:1162".into(),
        String::new(), // empty uptime -> 0
        "1.3.6.1.6.3.1.1.5.1".into(),
        "sysName.0".into(),
        "s".into(),
        "trap-from-itest".into(),
    ];
    let send = runner::run(
        trap_path,
        &send_args,
        None,
        &[("RUST_LOG", "info")],
        timeout,
    );

    // Let the datagram arrive, then stop the listener and gather its output.
    std::thread::sleep(Duration::from_millis(800));
    let _ = trapd.kill();
    let _ = trapd.wait();
    let trapd_out = format!(
        "{}\n{}",
        oh.join().unwrap_or_default(),
        eh.join().unwrap_or_default()
    );
    let trapd_lower = trapd_out.to_lowercase();

    let received = trapd_lower.contains("trap") && trapd_lower.contains("trap-from-itest");
    let sent_ok = send.exit_code == Some(0) && !send.timed_out;

    // Fold both sides into one result for reporting.
    let combined = CommandResult {
        exit_code: send.exit_code,
        timed_out: send.timed_out,
        stdout: format!(
            "snmptrap exit: {:?}\n--- snmptrapd captured ---\n{}",
            send.exit_code, trapd_out
        ),
        stderr: send.stderr.clone(),
        duration: send.duration,
        spawn_error: send.spawn_error.clone(),
    };

    let (status, detail) = if sent_ok && received {
        (Status::Pass, String::new())
    } else if !sent_ok {
        (
            Status::Fail,
            format!("snmptrap did not succeed (exit {:?})", send.exit_code),
        )
    } else {
        (
            Status::Fail,
            "snmptrapd did not report the expected trap".to_string(),
        )
    };

    Outcome {
        check,
        status,
        detail,
        result: combined,
    }
}

fn fail_outcome(check: Check, detail: &str) -> Outcome {
    Outcome {
        check,
        status: Status::Fail,
        detail: detail.to_string(),
        result: CommandResult {
            exit_code: None,
            timed_out: false,
            stdout: String::new(),
            stderr: String::new(),
            duration: Duration::ZERO,
            spawn_error: None,
        },
    }
}
