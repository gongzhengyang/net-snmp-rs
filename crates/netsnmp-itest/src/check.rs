//! The declarative `Check` type and its evaluation logic.
//!
//! A [`Check`] describes one invocation of a CLI tool and what a correct result
//! looks like. Checks are built with a fluent API in `suite.rs`. Evaluation
//! turns a [`CommandResult`](crate::runner::CommandResult) into a [`Status`]
//! plus a human-readable detail string.

use std::time::Duration;

use crate::runner::CommandResult;

/// How a check's result is interpreted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    /// Must succeed (exit 0 and satisfy all content expectations).
    Required,
    /// Must be rejected (non-zero exit). Used for unsupported operations and
    /// malformed input, verifying graceful error handling.
    ExpectFail,
    /// Optional: passes if it works, otherwise skipped (never fails the run).
    /// Used for objects an agent may legitimately not serve.
    BestEffort,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Required => "required",
            Category::ExpectFail => "expect-fail",
            Category::BestEffort => "best-effort",
        }
    }
}

/// Final status of an evaluated check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Skip => "skip",
        }
    }
}

/// One declarative integration check.
#[derive(Clone, Debug)]
pub struct Check {
    pub group: &'static str,
    pub name: String,
    pub category: Category,
    /// Whether this check needs a reachable remote agent.
    pub needs_agent: bool,
    pub tool: String,
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub timeout: Option<Duration>,
    /// All of these substrings must appear (case-insensitive) in stdout+stderr.
    pub contains_all: Vec<String>,
    /// At least one of these substrings must appear.
    pub contains_any: Vec<String>,
    /// Minimum number of non-empty stdout lines.
    pub min_lines: usize,
    /// Actionable advice shown when the check does not behave as expected.
    pub hint: String,
}

impl Check {
    pub fn new(group: &'static str, name: impl Into<String>, tool: impl Into<String>) -> Self {
        Check {
            group,
            name: name.into(),
            category: Category::Required,
            needs_agent: true,
            tool: tool.into(),
            args: Vec::new(),
            stdin: None,
            timeout: None,
            contains_all: Vec::new(),
            contains_any: Vec::new(),
            min_lines: 0,
            hint: String::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn stdin(mut self, input: impl Into<String>) -> Self {
        self.stdin = Some(input.into());
        self
    }

    pub fn expect_fail(mut self) -> Self {
        self.category = Category::ExpectFail;
        self
    }

    pub fn best_effort(mut self) -> Self {
        self.category = Category::BestEffort;
        self
    }

    /// Mark a check as not requiring the remote agent (offline-capable).
    pub fn offline(mut self) -> Self {
        self.needs_agent = false;
        self
    }

    pub fn contains(mut self, needle: impl Into<String>) -> Self {
        self.contains_all.push(needle.into());
        self
    }

    pub fn contains_any<I, S>(mut self, needles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.contains_any = needles.into_iter().map(Into::into).collect();
        self
    }

    pub fn min_lines(mut self, n: usize) -> Self {
        self.min_lines = n;
        self
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout = Some(Duration::from_secs(secs));
        self
    }

    /// The full command line as a copy-pasteable string.
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.tool.clone()];
        for a in &self.args {
            if a.is_empty() {
                parts.push("''".to_string());
            } else if a.contains(' ') {
                parts.push(format!("'{a}'"));
            } else {
                parts.push(a.clone());
            }
        }
        parts.join(" ")
    }

    /// Check the content expectations against a successful result.
    /// Returns `Some(reason)` if an expectation is not met.
    fn unmet_content(&self, r: &CommandResult) -> Option<String> {
        let hay = r.haystack_lower();
        for needle in &self.contains_all {
            if !hay.contains(&needle.to_lowercase()) {
                return Some(format!("output did not contain expected text {needle:?}"));
            }
        }
        if !self.contains_any.is_empty()
            && !self
                .contains_any
                .iter()
                .any(|n| hay.contains(&n.to_lowercase()))
        {
            return Some(format!(
                "output contained none of the expected alternatives {:?}",
                self.contains_any
            ));
        }
        let lines = r.stdout_lines();
        if lines < self.min_lines {
            return Some(format!(
                "expected at least {} output line(s), got {lines}",
                self.min_lines
            ));
        }
        None
    }

    /// Evaluate a result for this check, producing a status and a detail string.
    pub fn evaluate(&self, r: &CommandResult) -> (Status, String) {
        if let Some(err) = &r.spawn_error {
            return (
                Status::Fail,
                format!("could not start `{}`: {err}", self.tool),
            );
        }

        match self.category {
            Category::Required => {
                if r.timed_out {
                    return (
                        Status::Fail,
                        format!("timed out after {:.1}s", r.duration.as_secs_f64()),
                    );
                }
                if r.exit_code != Some(0) {
                    return (Status::Fail, exit_detail(r));
                }
                if let Some(reason) = self.unmet_content(r) {
                    return (Status::Fail, reason);
                }
                (Status::Pass, String::new())
            }
            Category::ExpectFail => {
                if r.timed_out {
                    return (
                        Status::Fail,
                        "expected a prompt rejection, but the command hung".to_string(),
                    );
                }
                match r.exit_code {
                    Some(0) => (
                        Status::Fail,
                        "expected a non-zero exit (rejection) but the command succeeded"
                            .to_string(),
                    ),
                    _ => {
                        // For negative tests, contains_all/any are matched against
                        // the error text to confirm the *right* failure.
                        if let Some(reason) = self.unmet_content(r) {
                            return (Status::Fail, format!("rejected, but {reason}"));
                        }
                        (Status::Pass, String::new())
                    }
                }
            }
            Category::BestEffort => {
                let ok = !r.timed_out && r.exit_code == Some(0) && self.unmet_content(r).is_none();
                if ok {
                    (Status::Pass, String::new())
                } else {
                    (
                        Status::Skip,
                        "optional data not provided by this agent".to_string(),
                    )
                }
            }
        }
    }
}

fn exit_detail(r: &CommandResult) -> String {
    match r.exit_code {
        Some(c) => format!("exited with code {c}"),
        None => "process terminated without an exit code".to_string(),
    }
}

/// A check paired with its evaluated result, ready for reporting.
pub struct Outcome {
    pub check: Check,
    pub status: Status,
    pub detail: String,
    pub result: CommandResult,
}
