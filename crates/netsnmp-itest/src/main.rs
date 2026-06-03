//! `snmp-itest` — end-to-end integration test runner for the net-snmp-rs CLI
//! tools.
//!
//! It drives the real compiled `snmp*` binaries against a running agent (the
//! `snmpd` started by docker-compose, or any reachable SNMP agent), classifies
//! each result, and prints a colored report with actionable hints on failure.
//!
//! This replaces the previous `docker/integration-test.sh` shell script with a
//! broader, friendlier, and more maintainable Rust harness.
//!
//! Configuration is taken from flags or the environment:
//!   AGENT, COMMUNITY, SNMP_V3_USER, SNMP_V3_AUTH_PROTO, SNMP_V3_AUTH_PASS,
//!   SNMP_V3_PRIV_PROTO, SNMP_V3_PRIV_PASS, NETSNMP_BIN_DIR.

mod check;
mod json;
mod report;
mod runner;
mod suite;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use check::{Outcome, Status};
use report::{Palette, Totals};
use suite::Params;

/// Integration test runner for the net-snmp-rs command-line tools.
#[derive(Parser, Debug)]
#[command(name = "snmp-itest", version, about, long_about = None)]
struct Config {
    /// Agent address as host:port.
    #[arg(long, env = "AGENT", default_value = "127.0.0.1:161")]
    agent: String,

    /// SNMPv1/v2c community string.
    #[arg(long, env = "COMMUNITY", default_value = "public")]
    community: String,

    /// SNMPv3 user name.
    #[arg(long, env = "SNMP_V3_USER", default_value = "bob")]
    v3_user: String,
    /// SNMPv3 authentication protocol (MD5/SHA/...).
    #[arg(long, env = "SNMP_V3_AUTH_PROTO", default_value = "SHA")]
    v3_auth_proto: String,
    /// SNMPv3 authentication passphrase.
    #[arg(long, env = "SNMP_V3_AUTH_PASS", default_value = "authpassword")]
    v3_auth_pass: String,
    /// SNMPv3 privacy protocol (DES/AES/...).
    #[arg(long, env = "SNMP_V3_PRIV_PROTO", default_value = "AES")]
    v3_priv_proto: String,
    /// SNMPv3 privacy passphrase.
    #[arg(long, env = "SNMP_V3_PRIV_PASS", default_value = "privpassword")]
    v3_priv_pass: String,

    /// Directory holding the snmp* binaries. Defaults to PATH lookup, then
    /// ./target/{release,debug}.
    #[arg(long, env = "NETSNMP_BIN_DIR")]
    bin_dir: Option<PathBuf>,

    /// Per-check timeout, in seconds.
    #[arg(long, default_value_t = 20)]
    timeout: u64,

    /// Only run checks whose group or name contains this substring.
    #[arg(long)]
    filter: Option<String>,

    /// Run only checks that do not need a remote agent.
    #[arg(long)]
    offline: bool,

    /// List the checks that would run, then exit.
    #[arg(long)]
    list: bool,

    /// Emit a machine-readable JSON report on stdout instead of the colored,
    /// human-oriented report (progress is routed to stderr). Ideal for CI.
    #[arg(long)]
    json: bool,

    /// Disable colored output (also honors the NO_COLOR environment variable).
    #[arg(long)]
    no_color: bool,
}

impl Config {
    /// Build the SNMPv3 flag set used for v3 checks.
    fn v3_flags(&self) -> Vec<String> {
        vec![
            "-v".into(),
            "3".into(),
            "-u".into(),
            self.v3_user.clone(),
            "-l".into(),
            "authPriv".into(),
            "-a".into(),
            self.v3_auth_proto.clone(),
            "-A".into(),
            self.v3_auth_pass.clone(),
            "-x".into(),
            self.v3_priv_proto.clone(),
            "-X".into(),
            self.v3_priv_pass.clone(),
        ]
    }
}

fn main() {
    let cfg = Config::parse();
    let palette = Palette {
        enabled: !cfg.no_color && !cfg.json && std::env::var_os("NO_COLOR").is_none(),
    };
    let timeout = Duration::from_secs(cfg.timeout);

    let params = Params {
        agent: cfg.agent.clone(),
        community: cfg.community.clone(),
        v3: cfg.v3_flags(),
    };

    // Build and filter the suite.
    let mut checks = suite::build(&params);
    if cfg.offline {
        checks.retain(|c| !c.needs_agent);
    }
    if let Some(f) = &cfg.filter {
        let f = f.to_lowercase();
        checks
            .retain(|c| c.group.to_lowercase().contains(&f) || c.name.to_lowercase().contains(&f));
    }
    // The trap orchestration runs unless filtered out or offline-excluded.
    let run_trap = match &cfg.filter {
        Some(f) => "snmptrap".contains(&f.to_lowercase()) || f.to_lowercase().contains("trap"),
        None => true,
    };

    if cfg.list {
        list_checks(&palette, &checks, run_trap);
        return;
    }

    // ---- Preflight: locate every binary we need. ----
    let (paths, missing) = runner::resolve_all(cfg.bin_dir.as_deref(), suite::TOOLS);
    if !missing.is_empty() {
        eprintln!(
            "{}",
            palette.red(&format!(
                "Could not find {} required binar{}: {}",
                missing.len(),
                if missing.len() == 1 { "y" } else { "ies" },
                missing.join(", ")
            ))
        );
        eprintln!(
            "{}",
            palette.yellow(
                "hint: build the workspace first (`cargo build --release`) and either run from \
                 the workspace root or pass --bin-dir <dir> / set NETSNMP_BIN_DIR. Inside the \
                 container the tools live in /usr/local/bin."
            )
        );
        std::process::exit(2);
    }

    if !cfg.json {
        report::banner(
            &palette,
            &cfg.agent,
            &cfg.community,
            checks.len() + run_trap as usize,
            cfg.offline,
        );
    }

    // ---- Preflight: confirm the agent is reachable (unless offline). ----
    let need_agent = !cfg.offline && checks.iter().any(|c| c.needs_agent);
    if need_agent && !wait_for_agent(&palette, &cfg, &paths["snmpget"], cfg.json) {
        agent_unreachable_help(&palette, &cfg);
        std::process::exit(3);
    }

    // ---- Run all checks, grouped, streaming results as we go. ----
    let mut totals = Totals::default();
    let mut outcomes: Vec<Outcome> = Vec::new();
    let mut current_group = "";

    for check in checks {
        if !cfg.json && check.group != current_group {
            current_group = check.group;
            report::group_header(&palette, current_group);
        }
        let tool_path = &paths[&check.tool];
        let ck_timeout = check.timeout.unwrap_or(timeout);
        let result = runner::run(
            tool_path,
            &check.args,
            check.stdin.as_deref(),
            &[("RUST_LOG", "info")],
            ck_timeout,
        );
        let (status, detail) = check.evaluate(&result);
        let outcome = Outcome {
            check,
            status,
            detail,
            result,
        };
        totals.record(status);
        if !cfg.json {
            report::outcome_line(&palette, &outcome);
        }
        outcomes.push(outcome);
    }

    // ---- Special: trap send/receive orchestration. ----
    if run_trap {
        if !cfg.json {
            report::group_header(&palette, "snmptrap");
        }
        let outcome = suite::run_trap(&paths, &cfg.community, timeout);
        totals.record(outcome.status);
        if !cfg.json {
            report::outcome_line(&palette, &outcome);
        }
        outcomes.push(outcome);
    }

    // ---- Summary + exit code. ----
    let code = if cfg.json {
        json::emit(&cfg.agent, &cfg.community, cfg.offline, totals, &outcomes)
    } else {
        let failures: Vec<&Outcome> = outcomes
            .iter()
            .filter(|o| o.status == Status::Fail)
            .collect();
        report::summary(&palette, totals, &failures)
    };
    std::process::exit(code);
}

/// Poll the agent with `snmpget sysDescr.0` until it responds or we give up.
/// When `quiet` (JSON mode) progress is routed to stderr to keep stdout clean.
fn wait_for_agent(p: &Palette, cfg: &Config, snmpget: &std::path::Path, quiet: bool) -> bool {
    if quiet {
        eprint!("waiting for agent ... ");
    } else {
        print!("{}", p.dim("waiting for agent ... "));
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let args: Vec<String> = vec![
        "-v".into(),
        "2c".into(),
        "-c".into(),
        cfg.community.clone(),
        cfg.agent.clone(),
        "sysDescr.0".into(),
    ];
    for attempt in 1..=30 {
        let r = runner::run(
            snmpget,
            &args,
            None,
            &[("RUST_LOG", "error")],
            Duration::from_secs(3),
        );
        if r.exit_code == Some(0) {
            if quiet {
                eprintln!("ready (attempt {attempt})");
            } else {
                println!("{}", p.green(&format!("ready (attempt {attempt})")));
                println!();
            }
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if quiet {
        eprintln!("no response");
    } else {
        println!("{}", p.red("no response"));
    }
    false
}

/// Print actionable advice when the agent cannot be reached.
fn agent_unreachable_help(p: &Palette, cfg: &Config) {
    eprintln!();
    eprintln!(
        "{}",
        p.red(&format!("The agent at {} is not responding.", cfg.agent))
    );
    eprintln!("{}", p.yellow("Things to check:"));
    eprintln!("  - Is the snmpd agent actually running and bound to that address?");
    eprintln!("    (with docker-compose: `just docker-up` or `docker compose up -d snmpd`)");
    eprintln!(
        "  - Does AGENT ({}) point at the right host:port? On the compose network",
        cfg.agent
    );
    eprintln!("    the agent's hostname is `snmpd` and the port is 161.");
    eprintln!(
        "  - Does the community string ({}) match the agent's `rocommunity`?",
        cfg.community
    );
    eprintln!("  - Is a firewall or NAT dropping UDP to that port?");
    eprintln!(
        "{}",
        p.dim("Run with --offline to exercise only the checks that need no agent.")
    );
}

/// Print the checks that would run (for `--list`).
fn list_checks(p: &Palette, checks: &[check::Check], run_trap: bool) {
    let groups: BTreeSet<&str> = checks.iter().map(|c| c.group).collect();
    println!("{}", p.bold("checks:"));
    for group in groups {
        println!("{}", p.cyan(group));
        for c in checks.iter().filter(|c| c.group == group) {
            println!(
                "  [{}] {}  {}",
                c.category.label(),
                c.name,
                p.dim(&c.command_line())
            );
        }
    }
    if run_trap {
        println!("{}", p.cyan("snmptrap"));
        println!("  [required] send + receive a v2c notification");
    }
}
