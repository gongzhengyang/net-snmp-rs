//! `snmptranslate` — translate between symbolic MIB names and numeric OIDs.
//!
//! Rust counterpart of `apps/snmptranslate.c` (offline; no network access).
//!
//! Output-format family (`-O<letters>`):
//!   - `n` numeric dotted form          `-On`
//!   - `f` fully-qualified symbolic     `-Of`
//!   - `s` short (last segment)         `-Os`
//!   - `S` suffix (from entry node)     `-OS`
//!   - `v` value-only (N/A offline)     ignored
//!   - `d` detailed OBJECT-TYPE block   `-Od`
//!   - `e` print enum labels            `-Oe` (orthogonal to the print mode)
//!
//! Tree-format family (`-T<letters>`):
//!   - `l` list every loaded OID        `-Tl`  (existing)
//!   - `p` indented subtree             `-Tp`
//!   - `a` ASCII-safe subtree           `-Ta`
//!   - `t` table `oid\tname\taccess\tstatus\tmodule`  `-Tt`
//!   - `d` detailed def per token       `-Td`
//!
//! `-M DIR[:DIR]` / `MIBDIRS` load MIB files.
//! `-m LIST`  module whitelist (best-effort; accepted but currently a no-op
//!            because the registry does not yet track module names).

use clap::Parser;
use netsnmp_apps::translate_fmt;
use netsnmp_apps::AppError;
use tracing::info;

/// Translate between symbolic MIB names and numeric OIDs (offline).
///
/// Common usage (copy a whole line and run it; no network needed):
///
///   snmptranslate -On sysName.0
///   snmptranslate -M ./mibs 1.3.6.1.2.1.2.2.1.8
///   snmptranslate -Tl -M ./mibs        # dump every loaded OID
///   snmptranslate -Of -M ./mibs ifIndex
///   snmptranslate -Tp -M ./mibs system
///
/// Typical output:
///
///   .1.3.6.1.2.1.1.5.0
///   IF-MIB::ifOperStatus
#[derive(Parser, Debug)]
#[command(
    name = "snmptranslate",
    about = "Translate between MIB names and numeric OIDs"
)]
struct Cli {
    /// Output options string (stack of letters): `n` numeric, `f` full, `s`
    /// short, `S` suffix, `d` detailed, `e` enum labels, `v` value-only.
    /// Repeatable; letters from every `-O` are concatenated (e.g.
    /// `-On -OS` is equivalent to `-OnS`).
    #[arg(short = 'O', long = "out-opts")]
    output: Vec<String>,
    /// Tree options string (stack of letters): `l` list all, `p` subtree,
    /// `a` ASCII-safe subtree, `t` table, `d` detailed per token. Repeatable;
    /// letters from every `-T` are concatenated.
    #[arg(short = 'T', long = "tree-opts")]
    tree: Vec<String>,
    /// Module whitelist (comma-separated); best-effort, no-op until the
    /// registry tracks module names.
    #[arg(short = 'm', long = "module")]
    module: Option<String>,
    /// MIB directories to load (repeatable; also `:`/`,` separated lists).
    #[arg(short = 'M', long = "mib-dirs", env = "MIBDIRS")]
    mib_dirs: Vec<String>,
    /// Names or OIDs to translate (omitted when listing with `-Tl`).
    #[arg(value_name = "NAME-OR-OID")]
    tokens: Vec<String>,
}

/// Resolved output mode selected by the active `-O` letter (last one wins for
/// the print mode; `e` is orthogonal).
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutMode {
    /// Default: symbolic form via `format_oid`.
    Symbolic,
    /// `-On`: numeric dotted form.
    Numeric,
    /// `-Of`: fully-qualified symbolic path.
    Full,
    /// `-Os`: short / last segment.
    Short,
    /// `-OS`: suffix from entry node.
    Suffix,
    /// `-Od`: detailed OBJECT-TYPE block.
    Detailed,
}

/// Parsed combination of `-O` letters.
struct OutOpts {
    mode: OutMode,
    enum_labels: bool,
}

impl OutOpts {
    fn parse(parts: &[String]) -> Self {
        let mut mode = OutMode::Symbolic;
        let mut numeric_seen = false;
        let mut enum_labels = false;
        for s in parts {
            for ch in s.chars() {
                match ch {
                    'n' => {
                        mode = OutMode::Numeric;
                        numeric_seen = true;
                    }
                    'f' => mode = OutMode::Full,
                    's' => mode = OutMode::Short,
                    'S' => mode = OutMode::Suffix,
                    'd' => mode = OutMode::Detailed,
                    'e' => enum_labels = true,
                    // `v` (value-only) is meaningful only for live tools; we
                    // accept it silently to mirror upstream parsing.
                    'v' => {}
                    // Unknown letters are ignored, matching upstream's lenient
                    // `-O` parsing.
                    _ => {}
                }
            }
        }
        // Upstream short-circuits: when `n` is present anywhere in `-O`, the
        // numeric form wins over any symbolic mode requested by other letters.
        if numeric_seen {
            mode = OutMode::Numeric;
        }
        OutOpts { mode, enum_labels }
    }
}

/// Parsed combination of `-T` letters. Each flag is independent and combinable.
struct TreeOpts {
    list: bool,
    print: bool,
    ascii: bool,
    table: bool,
    detailed: bool,
}

impl TreeOpts {
    fn parse(parts: &[String]) -> Self {
        let mut o = TreeOpts {
            list: false,
            print: false,
            ascii: false,
            table: false,
            detailed: false,
        };
        for s in parts {
            for ch in s.chars() {
                match ch {
                    'l' => o.list = true,
                    'p' => o.print = true,
                    'a' => o.ascii = true,
                    't' => o.table = true,
                    'd' => o.detailed = true,
                    _ => {}
                }
            }
        }
        o
    }

    fn any(&self) -> bool {
        self.list || self.print || self.ascii || self.table || self.detailed
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();

    let out_opts = OutOpts::parse(&cli.output);
    let tree_opts = TreeOpts::parse(&cli.tree);

    // The `-m` module whitelist is accepted but currently a no-op (the registry
    // does not yet expose module names). Documented best-effort.
    #[allow(unused_variables)]
    let module_whitelist = cli.module.as_deref();

    let mut mib_dirs: Vec<String> = Vec::new();
    for entry in &cli.mib_dirs {
        mib_dirs.extend(netsnmp_apps::split_dir_list(entry));
    }

    let mib = netsnmp_apps::load_mib_registry(&mib_dirs).await;

    // `-T` modes win over per-token formatting when both are supplied.
    if tree_opts.any() {
        run_tree_modes(&mib, &tree_opts, &cli.tokens, &out_opts)?;
        return Ok(());
    }

    if cli.tokens.is_empty() {
        return Err(AppError::msg(
            "no objects to translate (pass a NAME-OR-OID, or use -Tl to list all)",
        ));
    }

    let mut unknown = Vec::new();
    for token in &cli.tokens {
        match translate_fmt::resolve_token(&mib, token) {
            Some(oid) => print_oid(&mib, &oid, &out_opts),
            None => unknown.push(token.clone()),
        }
    }
    if !unknown.is_empty() {
        return Err(AppError::msg(format!(
            "unknown object(s): {}",
            unknown.join(", ")
        )));
    }
    Ok(())
}

/// Emit a single OID according to the active output mode.
fn print_oid(mib: &netsnmp::mib::MibRegistry, oid: &netsnmp::oid::Oid, opts: &OutOpts) {
    match opts.mode {
        OutMode::Numeric => info!("{oid}"),
        OutMode::Symbolic => info!("{}", mib.format_oid(oid)),
        OutMode::Full => info!("{}", translate_fmt::format_full(mib, oid)),
        OutMode::Short => info!("{}", translate_fmt::format_short(mib, oid)),
        OutMode::Suffix => info!("{}", translate_fmt::format_suffix(mib, oid)),
        OutMode::Detailed => {
            // Print without the trailing newline; tracing::info! adds one.
            let block = translate_fmt::format_detailed(mib, oid);
            for line in block.trim_end_matches('\n').split('\n') {
                info!("{line}");
            }
        }
    }
    if opts.enum_labels {
        if let Some(listing) = translate_fmt::enum_listing(mib, oid) {
            info!("ENUMS: {listing}");
        }
    }
}

/// Dispatch the `-T*` family: list / print / ascii / table / detailed.
fn run_tree_modes(
    mib: &netsnmp::mib::MibRegistry,
    tree: &TreeOpts,
    tokens: &[String],
    out: &OutOpts,
) -> Result<(), AppError> {
    // `-Tl` lists every loaded OID, ordered by OID, ignoring tokens.
    if tree.list {
        let mut count = 0usize;
        for (oid, name) in mib.iter_oids() {
            if out.mode == OutMode::Numeric {
                info!("{oid}");
            } else {
                info!("{name} = {oid}");
            }
            count += 1;
        }
        if count == 0 {
            return Err(AppError::msg(
                "no MIB objects loaded (use -M DIR to point at a MIB folder)",
            ));
        }
        return Ok(());
    }

    // `-Tt`: tab-separated table of every loaded OID (or descendants of the
    // single supplied token).
    if tree.table {
        let root = single_root(mib, tokens)?;
        let text = translate_fmt::render_table(mib, root.as_ref());
        for line in text.trim_end_matches('\n').split('\n') {
            if line.is_empty() {
                continue;
            }
            info!("{line}");
        }
        return Ok(());
    }

    // `-Td`: detailed def block per token.
    if tree.detailed {
        if tokens.is_empty() {
            return Err(AppError::msg(
                "-Td requires one or more NAME-OR-OID tokens",
            ));
        }
        let mut unknown = Vec::new();
        for token in tokens {
            match translate_fmt::resolve_token(mib, token) {
                Some(oid) => {
                    let block = translate_fmt::format_detailed(mib, &oid);
                    for line in block.trim_end_matches('\n').split('\n') {
                        info!("{line}");
                    }
                }
                None => unknown.push(token.clone()),
            }
        }
        if !unknown.is_empty() {
            return Err(AppError::msg(format!(
                "unknown object(s): {}",
                unknown.join(", ")
            )));
        }
        return Ok(());
    }

    // `-Tp` / `-Ta`: indented subtree rooted at each token.
    if tree.print || tree.ascii {
        if tokens.is_empty() {
            return Err(AppError::msg(
                "-Tp/-Ta require a NAME-OR-OID root token",
            ));
        }
        let ascii_safe = tree.ascii;
        let mut unknown = Vec::new();
        for token in tokens {
            match translate_fmt::resolve_token(mib, token) {
                Some(oid) => {
                    let text = translate_fmt::render_tree(mib, &oid, ascii_safe);
                    for line in text.trim_end_matches('\n').split('\n') {
                        info!("{line}");
                    }
                }
                None => unknown.push(token.clone()),
            }
        }
        if !unknown.is_empty() {
            return Err(AppError::msg(format!(
                "unknown object(s): {}",
                unknown.join(", ")
            )));
        }
        return Ok(());
    }

    // No recognised `-T` letter: fall through to the per-token path.
    Err(AppError::msg(
        "no recognised -T option (use -Tl, -Tp, -Ta, -Tt, or -Td)",
    ))
}

/// Resolve the first token to a root OID, if any. Returns `None` when no token
/// was given (whole registry).
fn single_root(
    mib: &netsnmp::mib::MibRegistry,
    tokens: &[String],
) -> Result<Option<netsnmp::oid::Oid>, AppError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    match translate_fmt::resolve_token(mib, &tokens[0]) {
        Some(oid) => Ok(Some(oid)),
        None => Err(AppError::msg(format!(
            "unknown object(s): {}",
            tokens[0]
        ))),
    }
}
