//! Subprocess execution with a hard timeout, plus binary discovery.
//!
//! The integration suite drives the real, compiled `snmp*` binaries as child
//! processes; this module is responsible for locating them and running them
//! without ever hanging the whole run.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Outcome of running a single command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Process exit code, or `None` if the process was killed / had no code.
    pub exit_code: Option<i32>,
    /// Whether the command was killed because it exceeded the timeout.
    pub timed_out: bool,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Set when the process could not even be spawned (e.g. binary missing).
    pub spawn_error: Option<String>,
}

impl CommandResult {
    /// Combined stdout + stderr, lowercased, for lenient substring matching.
    pub fn haystack_lower(&self) -> String {
        let mut s = self.stdout.to_lowercase();
        s.push('\n');
        s.push_str(&self.stderr.to_lowercase());
        s
    }

    /// Number of non-empty stdout lines.
    pub fn stdout_lines(&self) -> usize {
        self.stdout.lines().filter(|l| !l.trim().is_empty()).count()
    }
}

/// Run `program` with `args`, optionally feeding `stdin`, killing it after
/// `timeout`. Extra environment variables in `env` are applied on top of the
/// inherited environment.
pub fn run(
    program: &Path,
    args: &[String],
    stdin: Option<&str>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> CommandResult {
    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return CommandResult {
                exit_code: None,
                timed_out: false,
                stdout: String::new(),
                stderr: String::new(),
                duration: start.elapsed(),
                spawn_error: Some(e.to_string()),
            };
        }
    };

    // Feed stdin from a separate thread so a full pipe buffer cannot deadlock us.
    if let Some(input) = stdin
        && let Some(mut sink) = child.stdin.take()
    {
        let data = input.to_owned();
        std::thread::spawn(move || {
            let _ = sink.write_all(data.as_bytes());
        });
    }

    // Drain stdout/stderr concurrently to avoid pipe back-pressure deadlocks.
    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let out_handle = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_handle = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err.read_to_string(&mut s);
        s
    });

    let deadline = start + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(_) => break None,
        }
    };

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();
    CommandResult {
        exit_code: status.and_then(|s| s.code()),
        timed_out,
        stdout,
        stderr,
        duration: start.elapsed(),
        spawn_error: None,
    }
}

/// Locate the `snmp*` binary `name`.
///
/// Resolution order:
/// 1. `bin_dir/name` if `bin_dir` is provided,
/// 2. the first match on `PATH`,
/// 3. `target/release/name` then `target/debug/name` relative to the current
///    directory (developer convenience when run from the workspace root).
pub fn resolve_tool(bin_dir: Option<&Path>, name: &str) -> Option<PathBuf> {
    if let Some(dir) = bin_dir {
        let p = dir.join(name);
        return p.is_file().then_some(p);
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for profile in ["release", "debug"] {
        let p = PathBuf::from("target").join(profile).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Resolve every tool in `names`, returning a `name -> path` map and the list
/// of names that could not be found.
pub fn resolve_all(
    bin_dir: Option<&Path>,
    names: &[&str],
) -> (HashMap<String, PathBuf>, Vec<String>) {
    let mut found = HashMap::new();
    let mut missing = Vec::new();
    for &name in names {
        match resolve_tool(bin_dir, name) {
            Some(p) => {
                found.insert(name.to_string(), p);
            }
            None => missing.push(name.to_string()),
        }
    }
    (found, missing)
}
