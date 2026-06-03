//! Terminal reporting: colored per-check lines, failure diagnostics with
//! actionable hints, and a final summary.

use crate::check::{Outcome, Status};

/// ANSI color helper. Colors are disabled when `enabled` is false (e.g. when
/// `--no-color` is passed or `NO_COLOR` is set, or output is not a TTY).
#[derive(Clone, Copy)]
pub struct Palette {
    pub enabled: bool,
}

impl Palette {
    pub fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    pub fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    pub fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    pub fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    pub fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
    pub fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    pub fn cyan(&self, t: &str) -> String {
        self.paint("36", t)
    }
}

/// Aggregate counts of a run.
#[derive(Default, Clone, Copy)]
pub struct Totals {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl Totals {
    pub fn record(&mut self, status: Status) {
        match status {
            Status::Pass => self.passed += 1,
            Status::Fail => self.failed += 1,
            Status::Skip => self.skipped += 1,
        }
    }
}

/// Print the banner shown before checks run.
pub fn banner(p: &Palette, agent: &str, community: &str, total: usize, offline: bool) {
    println!("{}", p.bold("net-snmp-rs integration test"));
    if offline {
        println!("  mode    : {}", p.cyan("offline (no agent)"));
    } else {
        println!("  agent   : {}", p.cyan(agent));
        println!("  community: {community}");
    }
    println!("  checks  : {total}");
    println!();
}

/// Print a group header.
pub fn group_header(p: &Palette, group: &str) {
    println!("{}", p.bold(&format!("── {group} ──")));
}

/// Print a single outcome line (and, on failure, diagnostics + hint).
pub fn outcome_line(p: &Palette, o: &Outcome) {
    let secs = o.result.duration.as_secs_f64();
    let timing = p.dim(&format!("({secs:.2}s)"));
    match o.status {
        Status::Pass => {
            println!("  {} {} {timing}", p.green("✔ PASS"), o.check.name);
        }
        Status::Skip => {
            println!("  {} {} {timing}", p.yellow("• SKIP"), o.check.name);
            if !o.detail.is_empty() {
                println!("        {}", p.dim(&o.detail));
            }
        }
        Status::Fail => {
            println!("  {} {} {timing}", p.red("✘ FAIL"), o.check.name);
            println!("        {}", p.red(&format!("reason : {}", o.detail)));
            println!(
                "        {}",
                p.dim(&format!("command: {}", o.check.command_line()))
            );
            print_excerpt(p, o);
            if !o.check.hint.is_empty() {
                println!("        {} {}", p.yellow("hint   :"), o.check.hint);
            }
        }
    }
}

/// Print a short excerpt of stderr (preferred) or stdout for a failed check.
fn print_excerpt(p: &Palette, o: &Outcome) {
    let source = if !o.result.stderr.trim().is_empty() {
        ("stderr", &o.result.stderr)
    } else {
        ("stdout", &o.result.stdout)
    };
    let lines: Vec<&str> = source
        .1
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(6)
        .collect();
    if lines.is_empty() {
        return;
    }
    println!("        {}", p.dim(&format!("{}:", source.0)));
    for line in lines {
        println!("        {}", p.dim(&format!("  | {line}")));
    }
}

/// Print the closing summary and return the process exit code (0 = success).
pub fn summary(p: &Palette, totals: Totals, failures: &[&Outcome]) -> i32 {
    println!();
    println!("{}", p.bold("── summary ──"));
    println!(
        "  {}   {}   {}",
        p.green(&format!("{} passed", totals.passed)),
        p.red(&format!("{} failed", totals.failed)),
        p.yellow(&format!("{} skipped", totals.skipped)),
    );

    if failures.is_empty() {
        println!("\n{}", p.green("All required checks passed."));
        return 0;
    }

    println!("\n{}", p.red("Some required checks failed:"));
    for o in failures {
        println!("  - [{}] {}", o.check.group, o.check.name);
        if !o.check.hint.is_empty() {
            println!("      {} {}", p.yellow("→"), o.check.hint);
        }
    }
    println!(
        "\n{}",
        p.dim("Re-run a single group with --filter <name>, or inspect a tool directly using the printed command line.")
    );
    1
}
