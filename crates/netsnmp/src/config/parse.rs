//! Line classification and directive parsing, including `include*` resolution.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::Directive;
use super::search::config_directories;
use super::word::{parse_words, read_word};

/// Maximum nesting depth for `includeFile`/`includeDir` to guard against loops.
const MAX_INCLUDE_DEPTH: usize = 32;

/// The kind of `include*` directive encountered while parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IncludeKind {
    File,
    Dir,
    Search,
}

/// One classified configuration line.
enum Classified {
    /// `[name]` on its own — switch the active section.
    Section(String),
    /// An `include*` directive with its single path/name argument.
    Include(IncludeKind, String),
    /// A normal directive (possibly with a one-line `[section]` override).
    Entry {
        section: Option<String>,
        token: String,
        args: Vec<String>,
        rest: String,
    },
}

/// Classify a single raw line.
fn classify_line(raw: &str) -> Option<Classified> {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let (mut token, mut rest) = read_word(raw)?;
    let mut section_override = None;

    // Section header: `[name]` or `[name] token args...`.
    if token.starts_with('[') {
        if !token.ends_with(']') || token.len() < 2 {
            return None; // malformed header; ignore the line
        }
        let name = token[1..token.len() - 1].to_string();
        if rest.is_empty() {
            return Some(Classified::Section(name));
        }
        section_override = Some(name);
        let (t2, r2) = read_word(rest)?;
        token = t2;
        rest = r2;
    }

    let lower = token.to_ascii_lowercase();
    match lower.as_str() {
        "includefile" => {
            let arg = read_word(rest).map(|(w, _)| w).unwrap_or_default();
            return Some(Classified::Include(IncludeKind::File, arg));
        }
        "includedir" => {
            let arg = read_word(rest).map(|(w, _)| w).unwrap_or_default();
            return Some(Classified::Include(IncludeKind::Dir, arg));
        }
        "includesearch" => {
            let arg = read_word(rest).map(|(w, _)| w).unwrap_or_default();
            return Some(Classified::Include(IncludeKind::Search, arg));
        }
        // The bare `include` token is ambiguous in Net-SNMP; ignore it.
        "include" => return None,
        _ => {}
    }

    let args = parse_words(rest);
    Some(Classified::Entry {
        section: section_override,
        token,
        args,
        rest: rest.to_string(),
    })
}

/// Parse configuration directives from an in-memory string. `include*`
/// directives are *not* resolved (there is no base path); use [`parse_file`]
/// for include support.
pub fn parse_str(content: &str) -> Vec<Directive> {
    let mut out = Vec::new();
    let mut section: Option<String> = None;
    for (idx, raw) in content.lines().enumerate() {
        match classify_line(raw) {
            None => {}
            Some(Classified::Section(name)) => section = Some(name),
            Some(Classified::Include(..)) => {}
            Some(Classified::Entry {
                section: ov,
                token,
                args,
                rest,
            }) => out.push(Directive {
                token,
                args,
                rest,
                section: ov.or_else(|| section.clone()),
                source: None,
                line_no: idx + 1,
            }),
        }
    }
    out
}

/// Parse a configuration file, resolving `include*` directives relative to it.
pub fn parse_file(path: impl AsRef<Path>) -> io::Result<Vec<Directive>> {
    parse_file_inner(path.as_ref(), 0)
}

fn parse_file_inner(path: &Path, depth: usize) -> io::Result<Vec<Directive>> {
    if depth > MAX_INCLUDE_DEPTH {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut section: Option<String> = None;
    for (idx, raw) in content.lines().enumerate() {
        match classify_line(raw) {
            None => {}
            Some(Classified::Section(name)) => section = Some(name),
            Some(Classified::Include(kind, arg)) => {
                resolve_include(path, kind, &arg, depth, &mut out);
            }
            Some(Classified::Entry {
                section: ov,
                token,
                args,
                rest,
            }) => out.push(Directive {
                token,
                args,
                rest,
                section: ov.or_else(|| section.clone()),
                source: Some(path.to_path_buf()),
                line_no: idx + 1,
            }),
        }
    }
    Ok(out)
}

/// Resolve one `include*` directive, appending the parsed directives to `out`.
/// Errors (missing files, unreadable dirs) are silently skipped, matching the
/// best-effort behavior of `read_config.c`.
fn resolve_include(
    base: &Path,
    kind: IncludeKind,
    arg: &str,
    depth: usize,
    out: &mut Vec<Directive>,
) {
    match kind {
        IncludeKind::File => {
            let target = resolve_relative(base, arg);
            if let Ok(d) = parse_file_inner(&target, depth + 1) {
                out.extend(d);
            }
        }
        IncludeKind::Dir => {
            if let Ok(entries) = fs::read_dir(arg) {
                let mut files: Vec<PathBuf> = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| !n.starts_with('.') && n.ends_with(".conf"))
                            .unwrap_or(false)
                    })
                    .collect();
                files.sort();
                for f in files {
                    if let Ok(d) = parse_file_inner(&f, depth + 1) {
                        out.extend(d);
                    }
                }
            }
        }
        IncludeKind::Search => {
            let header = arg.strip_suffix(".conf").unwrap_or(arg);
            for dir in config_directories() {
                let candidate = dir.join(format!("{header}.conf"));
                if candidate.is_file()
                    && let Ok(d) = parse_file_inner(&candidate, depth + 1)
                {
                    out.extend(d);
                }
            }
        }
    }
}

/// Resolve `arg` relative to the directory containing `base` (absolute paths
/// are returned unchanged).
fn resolve_relative(base: &Path, arg: &str) -> PathBuf {
    let p = Path::new(arg);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    match base.parent() {
        Some(dir) => dir.join(arg),
        None => p.to_path_buf(),
    }
}
