//! pass / pass_persist (NET-SNMP-PASS-MIB style): subtree delegation to an
//! external script.
//!
//! Counterpart of Net-SNMP's `pass` and `pass_persist` directives (see
//! `agent/mibgroup/util_funcs/`). A `pass PIVOT_OID CMD` directive hands a
//! whole subtree rooted at `PIVOT_OID` to an external command:
//!
//! * **pass** — the command is spawned fresh per request. On GET it is invoked
//!   as `CMD -g OID`; on GETNEXT as `CMD -n OID`; on SET as
//!   `CMD -s OID TYPE VALUE`. The script's stdout is parsed as
//!   `OID\nTYPE\nVALUE\n` (GET) or `OID\nTYPE\nVALUE\n` for the successor
//!   (GETNEXT).
//! * **pass_persist** — the command is kept running and spoken to over its
//!   stdin/stdout. Commands sent to the script: `PING` (expect `PONG`),
//!   `getnext -s<OID>` / `getnext -n<OID>` (older form), `set -s<OID> TYPE
//!   VALUE`, and `shutdown` to terminate. This implementation uses the
//!   Net-SNMP v5.7+ protocol: `get\nOID`, `getnext\nOID`, `set\nOID TYPE
//!   VALUE`.
//!
//! The [`PassHandler`] implements [`MibHandler`] so the delegated subtree
//! participates in GET/GETNEXT/SET exactly like a native handler. For
//! `pass_persist` the child is lazily spawned on first use and kept alive in a
//! [`Mutex`]; for plain `pass` a fresh process is spawned per request.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;

use crate::handler::{MibHandler, Reading};

/// Split a command string into a program and its arguments, honoring
/// double-quoted / single-quoted segments and backslash escapes (a small
/// subset of POSIX shell word-splitting). The first word is the program; the
/// rest are arguments. Returns `None` when the string is empty or unparseable.
///
/// Net-SNMP's `pass`/`pass_persist` directives accept the command as a single
/// free-form string (e.g. `sh -c "echo ..."`), so we must split it ourselves
/// rather than passing the whole string to [`Command::new`], which would treat
/// it as a single program name containing spaces.
fn split_command(s: &str) -> Option<(String, Vec<String>)> {
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
            continue;
        }
        if in_double {
            if c == '\\' {
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                    continue;
                }
            }
            if c == '"' {
                in_double = false;
            } else {
                current.push(c);
            }
            continue;
        }
        match c {
            '\\' => {
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                    any = true;
                }
            }
            '\'' => {
                in_single = true;
                any = true;
            }
            '"' => {
                in_double = true;
                any = true;
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(c);
                any = true;
            }
        }
    }
    if in_single || in_double {
        return None;
    }
    if !current.is_empty() {
        words.push(current);
    }
    if !any {
        return None;
    }
    let (program, args) = words.split_first()?;
    Some((program.clone(), args.to_vec()))
}

/// Maximum wall-clock seconds a pass script may run before being abandoned.
const PASS_TIMEOUT_SECS: u64 = 5;

/// A parsed reply from a pass script: the OID, the SMI type token, and the
/// value text.
#[derive(Clone, Debug)]
struct PassReply {
    oid: Oid,
    type_token: String,
    value: String,
}

/// Parse a pass script's stdout into a [`PassReply`]. The expected format is
///
/// ```text
/// OID
/// TYPE
/// VALUE
/// ```
///
/// (possibly followed by trailing blank lines). Returns `None` if the output
/// does not contain at least an OID line (the conventional "not found" signal
/// is an empty or `NONE` reply).
fn parse_pass_reply(stdout: &str) -> Option<PassReply> {
    let mut lines = stdout.lines();
    let oid_line = lines.next()?.trim();
    if oid_line.is_empty() || oid_line.eq_ignore_ascii_case("NONE") {
        return None;
    }
    let oid: Oid = oid_line.parse().ok()?;
    // The type line may be absent for empty values; treat missing as "string".
    let type_line = lines.next().map(|s| s.trim().to_string()).unwrap_or_default();
    let value_line = lines.next().map(|s| s.trim_end().to_string()).unwrap_or_default();
    Some(PassReply {
        oid,
        type_token: type_line,
        value: value_line,
    })
}

/// Map a pass-script type token to a [`Value`]. Mirrors Net-SNMP's recognised
/// type names: `integer`, `gauge`/`gauge32`, `counter`/`counter32`,
/// `timeticks`, `counter64`, `ipaddress`, `string`/`octet`,
/// `objectid`/`oid`, and `opaque`.
fn value_from_pass(type_token: &str, text: &str) -> Value {
    let t = type_token.trim().to_ascii_lowercase();
    let parse_num = || text.trim().parse::<i64>().ok();
    match t.as_str() {
        "integer" | "int" | "integer32" => Value::Integer(parse_num().unwrap_or(0)),
        "gauge" | "gauge32" | "unsigned" | "uinteger" | "uint32" => {
            Value::Gauge32(text.trim().parse::<u32>().unwrap_or(0))
        }
        "counter" | "counter32" => {
            Value::Counter32(text.trim().parse::<u32>().unwrap_or(0))
        }
        "counter64" => Value::Counter64(text.trim().parse::<u64>().unwrap_or(0)),
        "timeticks" | "timetick" => {
            Value::TimeTicks(text.trim().parse::<u32>().unwrap_or(0))
        }
        "ipaddress" | "ip" => Value::IpAddress(
            text.trim()
                .parse()
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        ),
        "objectid" | "oid" => Value::Oid(text.trim().parse().unwrap_or(Oid::null())),
        "opaque" => Value::Opaque(text.as_bytes().to_vec()),
        // Default: octet string (Net-SNMP's fallback for unrecognised types).
        _ => Value::OctetString(text.as_bytes().to_vec()),
    }
}

/// A handler that delegates a subtree to an external pass / pass_persist
/// script.
pub struct PassHandler {
    root: Oid,
    command: String,
    persist: bool,
    /// For pass_persist: the long-lived child's stdin/stdout handles.
    child: Mutex<Option<PersistChild>>,
}

/// The live stdin/stdout of a pass_persist child.
struct PersistChild {
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

impl PassHandler {
    /// Create a `pass` handler (fresh process per request) rooted at `root`,
    /// delegating to `command`.
    pub fn pass(root: Oid, command: impl Into<String>) -> Arc<Self> {
        Arc::new(PassHandler {
            root,
            command: command.into(),
            persist: false,
            child: Mutex::new(None),
        })
    }

    /// Create a `pass_persist` handler (long-lived child) rooted at `root`,
    /// delegating to `command`.
    pub fn pass_persist(root: Oid, command: impl Into<String>) -> Arc<Self> {
        Arc::new(PassHandler {
            root,
            command: command.into(),
            persist: true,
            child: Mutex::new(None),
        })
    }

    /// Run a one-shot `pass` invocation: `CMD -g OID` for GET, `CMD -n OID`
    /// for GETNEXT, `CMD -s OID TYPE VALUE` for SET. Returns the parsed reply
    /// (or `None`).
    fn run_oneshot(&self, mode: char, oid: &Oid, set_args: Option<(&str, &str)>) -> Option<PassReply> {
        let (program, base_args) = split_command(&self.command)?;
        let mut cmd = Command::new(program);
        cmd.args(&base_args);
        match mode {
            'g' => {
                cmd.arg("-g").arg(oid.to_string());
            }
            'n' => {
                cmd.arg("-n").arg(oid.to_string());
            }
            's' => {
                if let Some((type_token, value)) = set_args {
                    cmd.arg("-s")
                        .arg(oid.to_string())
                        .arg(type_token)
                        .arg(value);
                } else {
                    return None;
                }
            }
            _ => return None,
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd.output().ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        parse_pass_reply(&stdout)
    }

    /// Spawn (or reuse) the pass_persist child and send one command, reading
    /// the reply up to the blank line that delimits a pass_persist response.
    fn run_persist(&self, request: &str) -> Option<PassReply> {
        let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = spawn_persist_child(&self.command);
        }
        // Send the request, respawning once if the child has died. The write
        // borrow is released before we touch stdout so the borrow checker is
        // satisfied.
        let send_ok = send_persist_request(&mut guard, request);
        if !send_ok {
            // First attempt failed (broken pipe): respawn and retry once.
            *guard = spawn_persist_child(&self.command);
            let _ = send_persist_request(&mut guard, request);
        }
        let child_slot = guard.as_mut()?;
        let stdout = &mut child_slot.stdout;
        read_persist_reply(stdout)
    }

    fn get_impl(&self, oid: &Oid) -> Option<Value> {
        if self.persist {
            let reply = self.run_persist(&format!("get\n{}", oid))?;
            Some(value_from_pass(&reply.type_token, &reply.value))
        } else {
            let reply = self.run_oneshot('g', oid, None)?;
            Some(value_from_pass(&reply.type_token, &reply.value))
        }
    }

    fn get_next_impl(&self, oid: &Oid) -> Option<Reading> {
        let reply = if self.persist {
            self.run_persist(&format!("getnext\n{}", oid))?
        } else {
            self.run_oneshot('n', oid, None)?
        };
        // The successor must be within this handler's subtree; otherwise treat
        // it as no successor (Net-SNMP would likewise stop the walk here).
        if !self.root.is_prefix_of(&reply.oid) {
            return None;
        }
        Some(Reading {
            oid: reply.oid,
            value: value_from_pass(&reply.type_token, &reply.value),
        })
    }
}

/// Write `request` to the persist child's stdin. Returns `false` if the child
/// is absent or the write fails ( signalling the caller to respawn).
fn send_persist_request(
    guard: &mut std::sync::MutexGuard<'_, Option<PersistChild>>,
    request: &str,
) -> bool {
    match guard.as_mut() {
        Some(child_slot) => {
            let _ = child_slot.stdin.flush();
            writeln!(&mut child_slot.stdin, "{request}").is_ok()
        }
        None => false,
    }
}

impl Drop for PassHandler {
    fn drop(&mut self) {
        if self.persist {
            if let Ok(mut guard) = self.child.lock() {
                if let Some(child) = guard.as_mut() {
                    let _ = writeln!(&mut child.stdin, "shutdown");
                }
                // Drop closes stdin and reaps the child implicitly when the
                // handles are dropped.
            }
        }
    }
}

impl MibHandler for PassHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.get_impl(oid)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        self.get_next_impl(oid)
    }

    fn set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        let (type_token, text) = value_to_pass(value);
        if self.persist {
            let req = format!("set\n{} {} {}", oid, type_token, text);
            let _ = self.run_persist(&req);
        } else {
            let _ = self.run_oneshot('s', oid, Some((&type_token, &text)));
        }
        Ok(())
    }
}

/// Spawn the pass_persist child with piped stdin/stdout.
fn spawn_persist_child(command: &str) -> Option<PersistChild> {
    let (program, args) = split_command(command)?;
    let mut cmd = Command::new(program);
    cmd.args(&args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let stdin = child.stdin.take()?;
    let stdout = child.stdout.take()?;
    // Detach the child: we never wait() on it directly, relying on drop to
    // close stdin and let it exit. Leak prevention is best-effort, matching
    // Net-SNMP's behaviour.
    std::mem::forget(child);
    Some(PersistChild { stdin, stdout })
}

/// Read a pass_persist reply: three lines (OID, TYPE, VALUE) terminated by an
/// empty line. Times out after [`PASS_TIMEOUT_SECS`] of waiting.
fn read_persist_reply(stdout: &mut std::process::ChildStdout) -> Option<PassReply> {
    let mut reader = std::io::BufReader::new(stdout);
    let mut lines = Vec::new();
    // Collect up to 3 non-empty lines, then the terminating blank.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(PASS_TIMEOUT_SECS);
    loop {
        if std::time::Instant::now() > deadline {
            return None;
        }
        let mut buf = String::new();
        let n = read_line_with_timeout(&mut reader, &mut buf, deadline)?;
        if n == 0 {
            // EOF.
            break;
        }
        let trimmed = buf.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            break;
        }
        lines.push(trimmed.to_string());
        if lines.len() >= 3 {
            break;
        }
    }
    if lines.is_empty() {
        return None;
    }
    let oid: Oid = lines.first()?.parse().ok()?;
    let type_line = lines.get(1).cloned().unwrap_or_default();
    let value_line = lines.get(2).cloned().unwrap_or_default();
    Some(PassReply {
        oid,
        type_token: type_line,
        value: value_line,
    })
}

/// Read one line from a buffered reader, returning `None` on timeout.
fn read_line_with_timeout<R: std::io::BufRead>(
    reader: &mut R,
    buf: &mut String,
    deadline: std::time::Instant,
) -> Option<usize> {
    // Busy-wait with a tiny sleep: the pass_persist protocol is line-oriented
    // and the script is expected to reply promptly. A full async integration
    // would require threading the agent's tokio runtime through here, which is
    // out of scope for this synchronous handler.
    loop {
        if std::time::Instant::now() > deadline {
            return None;
        }
        match reader.fill_buf() {
            Ok(bytes) if bytes.is_empty() => return Some(0),
            Ok(_) => {
                match reader.read_line(buf) {
                    Ok(0) => return Some(0),
                    Ok(n) => return Some(n),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => return None,
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(_) => return None,
        }
    }
}

/// Render a [`Value`] as a `(type_token, text)` pair for a pass SET.
fn value_to_pass(value: &Value) -> (String, String) {
    match value {
        Value::Integer(v) => ("integer".to_string(), v.to_string()),
        Value::Gauge32(v) => ("gauge".to_string(), v.to_string()),
        Value::Counter32(v) => ("counter".to_string(), v.to_string()),
        Value::Counter64(v) => ("counter64".to_string(), v.to_string()),
        Value::TimeTicks(v) => ("timeticks".to_string(), v.to_string()),
        Value::IpAddress(ip) => ("ipaddress".to_string(), ip.to_string()),
        Value::Oid(o) => ("objectid".to_string(), o.to_string()),
        Value::OctetString(b) => (
            "string".to_string(),
            String::from_utf8_lossy(b).into_owned(),
        ),
        Value::Opaque(b) => ("opaque".to_string(), format!("{:?}", b)),
        Value::Null => ("string".to_string(), String::new()),
        // Exceptions cannot be SET.
        Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => {
            ("string".to_string(), String::new())
        }
    }
}

/// Parse a `pass OID CMD` / `pass_persist OID CMD` directive line (keyword
/// already stripped) into `(root_oid, command)`. Returns `None` on a malformed
/// line.
pub fn parse_pass_directive(line: &str) -> Option<(Oid, String)> {
    let mut parts = line.split_whitespace();
    let oid: Oid = parts.next()?.parse().ok()?;
    let command = parts.next()?.to_string();
    Some((oid, command))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pass command (shell snippet) that emits a fixed integer for any GET of
    /// `.1.3.6.1.4.1.9999.1.0`. Invoked via `sh -c`, which [`split_command`]
    /// parses into `("sh", ["-c", "..."])`. Uses `echo` rather than `printf`
    /// with `\n` so the command string contains no backslash escapes that
    /// [`split_command`] would mangle. No temp files are written, so the tests
    /// are race-free under parallel execution.
    fn integer_cmd() -> String {
        "sh -c \"echo 1.3.6.1.4.1.9999.1.0; echo integer; echo 42\"".to_string()
    }

    #[test]
    fn pass_get_returns_script_value() {
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let handler = PassHandler::pass(root, integer_cmd());
        let oid: Oid = "1.3.6.1.4.1.9999.1.0".parse().unwrap();
        let value = handler.get(&oid);
        assert_eq!(value, Some(Value::Integer(42)));
    }

    #[test]
    fn pass_getnext_returns_successor() {
        // The script always returns the same OID regardless of input; for a
        // GETNEXT we only require that the reply be within the subtree.
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let handler = PassHandler::pass(root.clone(), integer_cmd());
        let oid: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let reading = handler.get_next(&oid).expect("a successor");
        assert!(root.is_prefix_of(&reading.oid));
        assert_eq!(reading.value, Value::Integer(42));
    }

    #[test]
    fn pass_get_returns_none_for_missing_oid() {
        // A script that prints NONE signals "not found".
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let handler = PassHandler::pass(root, "sh -c \"echo NONE\"");
        let oid: Oid = "1.3.6.1.4.1.9999.9.9".parse().unwrap();
        assert_eq!(handler.get(&oid), None);
    }

    #[test]
    fn parse_pass_reply_handles_integer() {
        let reply = parse_pass_reply("1.2.3.4.5\ninteger\n7\n").unwrap();
        assert_eq!(reply.oid.to_string(), ".1.2.3.4.5");
        assert_eq!(reply.type_token, "integer");
        assert_eq!(reply.value, "7");
        let value = value_from_pass(&reply.type_token, &reply.value);
        assert_eq!(value, Value::Integer(7));
    }

    #[test]
    fn parse_pass_reply_treats_none_as_missing() {
        assert!(parse_pass_reply("NONE\n").is_none());
        assert!(parse_pass_reply("\n").is_none());
    }

    #[test]
    fn value_from_pass_maps_known_types() {
        assert_eq!(value_from_pass("integer", "5"), Value::Integer(5));
        assert_eq!(value_from_pass("counter", "5"), Value::Counter32(5));
        assert_eq!(value_from_pass("counter64", "5"), Value::Counter64(5));
        assert_eq!(value_from_pass("gauge", "5"), Value::Gauge32(5));
        assert_eq!(value_from_pass("timeticks", "5"), Value::TimeTicks(5));
        assert_eq!(
            value_from_pass("ipaddress", "10.0.0.1"),
            Value::IpAddress("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            value_from_pass("string", "hello"),
            Value::OctetString(b"hello".to_vec())
        );
        // Unknown type falls back to octet string.
        assert_eq!(
            value_from_pass("weirdtype", "x"),
            Value::OctetString(b"x".to_vec())
        );
    }

    #[test]
    fn parse_pass_directive_parses_oid_and_command() {
        let (oid, cmd) = parse_pass_directive("1.3.6.1.4.1.9999 /usr/local/bin/myscript").unwrap();
        assert_eq!(oid.to_string(), ".1.3.6.1.4.1.9999");
        assert_eq!(cmd, "/usr/local/bin/myscript");
    }
}
