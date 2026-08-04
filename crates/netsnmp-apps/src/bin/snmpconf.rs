//! `snmpconf` — interactive generator for `snmp.conf` / `snmpd.conf` /
//! `snmptrapd.conf`.
//!
//! Rust counterpart of `apps/snmpconf.c`. Rather than driving Net-SNMP's
//! per-token handler registration, this implementation asks a fixed, compact
//! set of questions per config type (with sensible defaults), then emits one
//! line per collected directive. The output is parseable verbatim by
//! [`netsnmp::config::parse_str`] into `Vec<Directive>` with matching tokens
//! and arguments, so it round-trips cleanly into [`ClientDefaults`] /
//! [`SnmpdSettings`].
//!
//! Two modes:
//! - **Interactive** (default when `-f` is absent): prompts on stderr, reads
//!   answers from stdin, writes the resulting config to stdout (or `OUTPUT`).
//! - **Non-interactive** (`-f FILE`): reads a `key=value` answers file and
//!   emits the merged config to stdout. Unknown keys are passed through
//!   verbatim; empty values for recognized keys are skipped.
//!
//! Synchronous throughout — the tool is pure stdin/stdout I/O, so there is no
//! async runtime.

use clap::Parser;
use netsnmp_apps::AppError;
use std::fs;
use std::io::{BufRead, Write, stdin};
use std::path::PathBuf;

/// Generate `snmp.conf` / `snmpd.conf` / `snmptrapd.conf` interactively or
/// from an answers file.
///
/// Examples:
///
///   snmpconf                       # interactive, all defaults prompted
///   snmpconf -t snmpd              # interactive, snmpd.conf questions
///   snmpconf -f answers.txt -t snmp   # merge an answers file to stdout
///   snmpconf -t snmp snmp.conf     # interactive, write to snmp.conf
#[derive(Parser, Debug)]
#[command(
    name = "snmpconf",
    about = "Generate snmp.conf / snmpd.conf / snmptrapd.conf interactively or from an answers file"
)]
struct Cli {
    /// Interactive mode (default when --file is not given).
    #[arg(short = 'i', long = "interactive")]
    interactive: bool,

    /// Read a `key=value` answers file and emit the merged config to stdout
    /// (non-interactive).
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: Option<PathBuf>,

    /// Config type: `snmp`, `snmpd` or `snmptrapd`. If omitted in interactive
    /// mode, a menu prompts for it.
    #[arg(short = 't', long = "type", value_name = "TYPE")]
    conf_type: Option<ConfType>,

    /// Output file. If absent, the config is written to stdout.
    #[arg(value_name = "OUTPUT")]
    output: Option<PathBuf>,
}

/// The kind of config file being generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ConfType {
    /// `snmp.conf` — client defaults (`defVersion`, `defCommunity`, …).
    Snmp,
    /// `snmpd.conf` — agent settings (`rocommunity`, `sysLocation`, …).
    Snmpd,
    /// `snmptrapd.conf` — trap daemon settings (`authCommunity`, …).
    Snmptrapd,
}

impl ConfType {
    /// The set of questions to ask for this config type, in order: `(directive
    /// token, prompt label, default value)`. A `None` default means the value
    /// is optional and is skipped when left blank.
    fn questions(self) -> &'static [(&'static str, &'static str, Option<&'static str>)] {
        match self {
            ConfType::Snmp => &[
                ("defVersion", "default SNMP version", Some("2c")),
                ("defCommunity", "default community string", Some("public")),
                ("defSecurityName", "default v3 security name", None),
                ("defAuthType", "default auth type", Some("SHA")),
                ("defAuthPassphrase", "default auth passphrase", None),
                ("defPrivType", "default privacy type", Some("AES")),
                ("defPrivPassphrase", "default privacy passphrase", None),
                ("defSecurityLevel", "default security level", Some("noAuthNoPriv")),
                ("mibdirs", "MIB directories (colon-separated)", None),
            ],
            ConfType::Snmpd => &[
                ("rocommunity", "read-only community", Some("public")),
                ("rwcommunity", "read-write community", None),
                ("sysLocation", "system location", Some("Unknown")),
                ("sysContact", "system contact", Some("Me <me@example.org>")),
                ("agentAddress", "agent listen address", Some("udp:161")),
                ("createUser", "createUser line (name [auth pass [priv pass]])", None),
                ("trapsink", "trap sink (host [community])", None),
            ],
            ConfType::Snmptrapd => &[
                ("authCommunity", "community to accept traps from", Some("public")),
                ("traphandle", "trap handler command", None),
                ("outputOption", "log output option", Some("p")),
            ],
        }
    }
}

fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();

    let conf_type = match cli.conf_type {
        Some(t) => t,
        None => {
            if cli.file.is_some() {
                return Err(AppError::msg(
                    "--type is required when using --file (no interactive menu)",
                ));
            }
            prompt_conf_type()?
        }
    };

    let lines: Vec<String> = if let Some(path) = &cli.file {
        from_answers_file(path, conf_type)?
    } else {
        let mut out = std::io::stderr();
        let mut stdin = stdin().lock();
        interactive(conf_type, &mut out, &mut stdin)?
    };

    let body = lines.join("\n");

    match &cli.output {
        Some(path) => {
            fs::write(path, format!("{body}\n"))
                .map_err(|e| AppError::msg(format!("cannot write {}: {e}", path.display())))?;
        }
        None => {
            // stdout: emit the config followed by a trailing newline.
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            write!(handle, "{body}\n")
                .map_err(|e| AppError::msg(format!("cannot write stdout: {e}")))?;
            handle
                .flush()
                .map_err(|e| AppError::msg(format!("cannot flush stdout: {e}")))?;
        }
    }

    Ok(())
}

/// Print the type-selection menu to `out` and read a `1`/`2`/`3` choice from
/// stdin, re-prompting on invalid input.
fn prompt_conf_type() -> Result<ConfType, AppError> {
    let mut out = std::io::stderr();
    let mut stdin = stdin().lock();
    loop {
        writeln!(out, "Select the type of configuration file to generate:")
            .map_err(io_err)?;
        writeln!(out, "  1) snmp      (snmp.conf — client defaults)")
            .map_err(io_err)?;
        writeln!(out, "  2) snmpd     (snmpd.conf — agent settings)")
            .map_err(io_err)?;
        writeln!(out, "  3) snmptrapd (snmptrapd.conf — trap daemon)")
            .map_err(io_err)?;
        write!(out, "Enter choice [1-3]: ").map_err(io_err)?;
        out.flush().map_err(io_err)?;
        let line = read_line(&mut stdin)?;
        match line.trim() {
            "1" => return Ok(ConfType::Snmp),
            "2" => return Ok(ConfType::Snmpd),
            "3" => return Ok(ConfType::Snmptrapd),
            _ => continue,
        }
    }
}

/// Run the interactive question loop for `conf_type`, prompting on `out` and
/// reading answers from `stdin`. Returns one formatted directive line per
/// non-skipped answer.
fn interactive(
    conf_type: ConfType,
    out: &mut impl Write,
    stdin: &mut impl BufRead,
) -> Result<Vec<String>, AppError> {
    let mut lines = Vec::new();
    for (token, label, default) in conf_type.questions() {
        let value = ask(out, stdin, label, *default)?;
        if let Some(value) = value {
            lines.push(format_directive(token, &value));
        }
    }
    Ok(lines)
}

/// Ask a single question. Returns `Ok(None)` when the answer is empty with no
/// default, or literally `skip`. A non-empty answer overrides the default.
fn ask(
    out: &mut impl Write,
    stdin: &mut impl BufRead,
    label: &str,
    default: Option<&str>,
) -> Result<Option<String>, AppError> {
    loop {
        match default {
            Some(d) => write!(out, "{label} (default: {d}): ").map_err(io_err)?,
            None => write!(out, "{label}: ").map_err(io_err)?,
        }
        out.flush().map_err(io_err)?;
        let line = read_line(stdin)?;
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("skip") {
            return Ok(None);
        }
        if trimmed.is_empty() {
            // Empty answer: use the default if any, otherwise skip.
            return Ok(default.map(str::to_string));
        }
        return Ok(Some(trimmed.to_string()));
    }
}

/// Read a single line from `stdin`, stripping a trailing newline (any of `\n`,
/// `\r\n`, `\r`). Returns an empty string on EOF.
fn read_line(stdin: &mut impl BufRead) -> Result<String, AppError> {
    let mut buf = String::new();
    let n = stdin.read_line(&mut buf).map_err(io_err)?;
    if n == 0 {
        return Ok(String::new());
    }
    // Strip any trailing line terminator.
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    } else if buf.ends_with('\r') {
        buf.pop();
    }
    Ok(buf)
}

/// Build the directive lines from a `key=value` / `key:value` answers file for
/// `conf_type`.
///
/// - Blank lines and lines whose first non-blank character is `#` are ignored.
/// - A recognized key whose value is empty is skipped.
/// - A recognized key is split into words with [`netsnmp::config::parse_words`]
///   so a multi-word value yields the correct argument list (e.g. `createUser`
///   or `mibdirs` with multiple entries).
/// - An unknown key is emitted verbatim (its value, if present, is word-split
///   and re-quoted; a bare key is emitted as-is).
fn from_answers_file(path: &PathBuf, conf_type: ConfType) -> Result<Vec<String>, AppError> {
    let content =
        fs::read_to_string(path).map_err(|e| AppError::msg(format!("cannot read {}: {e}", path.display())))?;

    let known: Vec<&'static str> = conf_type
        .questions()
        .iter()
        .map(|(t, _, _)| *t)
        .collect();

    let mut lines = Vec::new();
    for raw in content.lines() {
        let trimmed = raw.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Split on the first `=` or `:`.
        let (key, value, has_value) = match split_kv(raw) {
            Some((k, v, hv)) => (k, v, hv),
            None => (raw.trim().to_string(), String::new(), false),
        };

        if known.iter().any(|k| k.eq_ignore_ascii_case(&key)) {
            if value.trim().is_empty() {
                // Recognized but empty: skip.
                continue;
            }
            lines.push(format_directive(&key, &value));
        } else {
            // Pass through verbatim: re-quote so it survives round-trip.
            if has_value {
                lines.push(format_directive(&key, &value));
            } else {
                lines.push(key.clone());
            }
        }
    }
    Ok(lines)
}

/// Split a `key=value` or `key:value` line into `(key, value, has_value)`. The
/// first `=` or `:` separates key from value; the value retains any interior
/// whitespace and quotes. Returns `None` if there is no separator.
fn split_kv(line: &str) -> Option<(String, String, bool)> {
    let eq = line.find('=');
    let colon = line.find(':');
    let sep = match (eq, colon) {
        (Some(e), Some(c)) => e.min(c),
        (Some(e), None) => e,
        (None, Some(c)) => c,
        (None, None) => return None,
    };
    let key = line[..sep].trim().to_string();
    let value = line[sep + 1..].trim().to_string();
    Some((key, value, true))
}

/// Format a directive line: `<token> <arg1> <arg2> ...` where each arg is
/// quoted with [`quote_arg`]. The value is split into words using Net-SNMP's
/// own [`parse_words`] so quoting is normalized and the line round-trips.
fn format_directive(token: &str, value: &str) -> String {
    let words = netsnmp::config::parse_words(value);
    let mut out = String::from(token);
    for w in &words {
        out.push(' ');
        out.push_str(&quote_arg(w));
    }
    out
}

/// Quote a single argument for emission in a config line.
///
/// An argument is wrapped in double quotes when it is empty, contains
/// whitespace, `#` or `"`. Inside the quotes, `\` and `"` are escaped. Bare
/// arguments (no special characters) are returned unchanged.
fn quote_arg(s: &str) -> String {
    // A backslash is also a trigger: a bare `\` is an escape sequence under
    // `parse_words`, so an argument containing one must be quoted (and the `\`
    // doubled) to round-trip verbatim.
    let needs_quotes = s.is_empty()
        || s.chars()
            .any(|c| c.is_whitespace() || c == '#' || c == '"' || c == '\\');
    if !needs_quotes {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Helper: lift an `io::Error` into an [`AppError`] message.
fn io_err(e: std::io::Error) -> AppError {
    AppError::msg(format!("I/O error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netsnmp::config::parse_str;

    /// A simple value with no special chars is emitted bare.
    #[test]
    fn quote_arg_bare_value_unchanged() {
        assert_eq!(quote_arg("public"), "public");
        assert_eq!(quote_arg("2c"), "2c");
        assert_eq!(quote_arg("udp:161"), "udp:161");
    }

    /// Values with whitespace, `#` or quotes get wrapped and escaped.
    #[test]
    fn quote_arg_wraps_and_escapes_special() {
        assert_eq!(quote_arg("Me <me@example.org>"), "\"Me <me@example.org>\"");
        assert_eq!(quote_arg("a#b"), "\"a#b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("a\\b"), "\"a\\\\b\"");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("with space"), "\"with space\"");
    }

    /// The generated config round-trips through `parse_str` into directives
    /// with the expected tokens and argument lists.
    #[test]
    fn round_trip_defversion_and_community() {
        let lines = vec![
            format_directive("defVersion", "2c"),
            format_directive("defCommunity", "public"),
        ];
        let conf = lines.join("\n");
        let dirs = parse_str(&conf);
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].token, "defVersion");
        assert_eq!(dirs[0].args, vec!["2c"]);
        assert_eq!(dirs[1].token, "defCommunity");
        assert_eq!(dirs[1].args, vec!["public"]);
    }

    /// A quoted multi-word value round-trips back to its parts.
    #[test]
    fn round_trip_quoted_syscontact() {
        let line = format_directive("sysContact", "\"Me <me@example.org>\"");
        let dirs = parse_str(&line);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].token, "sysContact");
        assert_eq!(dirs[0].args, vec!["Me <me@example.org>"]);
    }

    /// File mode: a recognized key with an empty value is dropped; an unknown
    /// key passes through. Uses a temp file so the file-reading path is real.
    #[test]
    fn file_mode_drops_empty_recognized_and_passes_through_unknown() {
        let dir = std::env::temp_dir().join(format!(
            "snmpconf-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("answers.txt");
        fs::write(
            &path,
            "defVersion=2c\ndefCommunity=\n# a comment\nfrobnicate=yes\nbareToken\n",
        )
        .unwrap();

        let lines = from_answers_file(&path, ConfType::Snmp).unwrap();
        fs::remove_dir_all(&dir).ok();
        // defVersion kept; defCommunity dropped (empty recognized); frobnicate
        // and bareToken passed through.
        assert!(lines.iter().any(|l| l == "defVersion 2c"), "got {lines:?}");
        assert!(
            !lines.iter().any(|l| l.starts_with("defCommunity")),
            "empty recognized key should be dropped: {lines:?}"
        );
        assert!(lines.iter().any(|l| l == "frobnicate yes"), "got {lines:?}");
        assert!(lines.iter().any(|l| l == "bareToken"), "got {lines:?}");
    }

    /// File mode accepts both `=` and `:` separators and word-splits values.
    #[test]
    fn file_mode_accepts_colon_and_equal_separators() {
        let dir = std::env::temp_dir().join(format!(
            "snmpconf-colon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("answers.txt");
        fs::write(&path, "defVersion=3\ndefSecurityName:alice\n").unwrap();

        let lines = from_answers_file(&path, ConfType::Snmp).unwrap();
        fs::remove_dir_all(&dir).ok();
        assert!(lines.iter().any(|l| l == "defVersion 3"), "got {lines:?}");
        assert!(
            lines.iter().any(|l| l == "defSecurityName alice"),
            "got {lines:?}"
        );
    }

    /// `ConfType` parses from the clap value-enum strings.
    #[test]
    fn conf_type_value_enum_variants() {
        use clap::ValueEnum;
        assert_eq!(
            ConfType::from_str("snmp", true).unwrap(),
            ConfType::Snmp
        );
        assert_eq!(
            ConfType::from_str("snmpd", true).unwrap(),
            ConfType::Snmpd
        );
        assert_eq!(
            ConfType::from_str("snmptrapd", true).unwrap(),
            ConfType::Snmptrapd
        );
        assert!(ConfType::from_str("bogus", true).is_err());
    }

    /// The per-type question tables cover the directives named in the spec.
    #[test]
    fn question_tables_cover_expected_directives() {
        let snmp_tokens: Vec<&str> =
            ConfType::Snmp.questions().iter().map(|(t, _, _)| *t).collect();
        assert!(snmp_tokens.contains(&"defVersion"));
        assert!(snmp_tokens.contains(&"defCommunity"));
        assert!(snmp_tokens.contains(&"mibdirs"));

        let snmpd_tokens: Vec<&str> =
            ConfType::Snmpd.questions().iter().map(|(t, _, _)| *t).collect();
        assert!(snmpd_tokens.contains(&"rocommunity"));
        assert!(snmpd_tokens.contains(&"sysLocation"));
        assert!(snmpd_tokens.contains(&"agentAddress"));

        let trapd_tokens: Vec<&str> = ConfType::Snmptrapd
            .questions()
            .iter()
            .map(|(t, _, _)| *t)
            .collect();
        assert!(trapd_tokens.contains(&"authCommunity"));
        assert!(trapd_tokens.contains(&"outputOption"));
    }
}
