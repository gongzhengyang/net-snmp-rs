//! Machine-readable (`--json`) report.
//!
//! The human report in [`crate::report`] is colored and stream-oriented; this
//! module emits a single, stable JSON document instead, suitable for CI
//! artifacts, `jq` filtering, or IDE integration. The domain types
//! (`Outcome`, `CommandResult`, …) are deliberately kept serde-free; we map
//! them onto purpose-built DTOs here so the wire format stays decoupled from
//! the internal representation.

use serde::Serialize;

use crate::check::{Outcome, Status};
use crate::report::Totals;

#[derive(Serialize)]
struct Report<'a> {
    agent: &'a str,
    community: &'a str,
    offline: bool,
    summary: Summary,
    results: Vec<ResultEntry<'a>>,
}

#[derive(Serialize)]
struct Summary {
    passed: usize,
    failed: usize,
    skipped: usize,
    ok: bool,
}

#[derive(Serialize)]
struct ResultEntry<'a> {
    group: &'a str,
    name: &'a str,
    category: &'a str,
    status: &'a str,
    duration_secs: f64,
    command: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    detail: &'a str,
    exit_code: Option<i32>,
    timed_out: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'a str>,
}

/// Serialize the run as JSON to stdout. Returns the process exit code
/// (0 = no required failures).
pub fn emit(
    agent: &str,
    community: &str,
    offline: bool,
    totals: Totals,
    outcomes: &[Outcome],
) -> i32 {
    let results = outcomes
        .iter()
        .map(|o| ResultEntry {
            group: o.check.group,
            name: &o.check.name,
            category: o.check.category.label(),
            status: o.status.label(),
            duration_secs: o.result.duration.as_secs_f64(),
            command: o.check.command_line(),
            detail: &o.detail,
            exit_code: o.result.exit_code,
            timed_out: o.result.timed_out,
            hint: (o.status == Status::Fail && !o.check.hint.is_empty())
                .then_some(o.check.hint.as_str()),
        })
        .collect();

    let report = Report {
        agent,
        community,
        offline,
        summary: Summary {
            passed: totals.passed,
            failed: totals.failed,
            skipped: totals.skipped,
            ok: totals.failed == 0,
        },
        results,
    };

    match serde_json::to_string_pretty(&report) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("failed to serialize JSON report: {e}"),
    }
    i32::from(totals.failed != 0)
}
