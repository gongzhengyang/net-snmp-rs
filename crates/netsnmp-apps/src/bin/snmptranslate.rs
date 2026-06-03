//! `snmptranslate` — translate between symbolic MIB names and numeric OIDs.
//!
//! Rust counterpart of `apps/snmptranslate.c` (offline; no network access).
//! With `-On` it prints numeric form; otherwise it prints the symbolic form.
//! `-M DIR[:DIR]` loads MIB files (also honours the `MIBDIRS` env var).
//!
//! With `-Tl` it dumps **every** object loaded from the given MIB folder(s),
//! one per line, instead of translating individual tokens.

use clap::Parser;
use netsnmp_apps::AppError;
use tracing::info;

/// Translate between symbolic MIB names and numeric OIDs (offline).
///
/// Common usage (copy a whole line and run it; no network needed):
///
///   snmptranslate -On sysName.0
///   snmptranslate -M ./mibs 1.3.6.1.2.1.2.2.1.8
///   snmptranslate -Tl -M ./mibs        # dump every loaded OID
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
    /// Output options string; include `n` for numeric form (e.g. `-On`).
    #[arg(short = 'O', long = "out-opts")]
    output: Option<String>,
    /// Tree options string; include `l` to list every loaded object (`-Tl`).
    #[arg(short = 'T', long = "tree-opts")]
    tree: Option<String>,
    /// MIB directories to load (repeatable; also `:`/`,` separated lists).
    #[arg(short = 'M', long = "mib-dirs", env = "MIBDIRS")]
    mib_dirs: Vec<String>,
    /// Names or OIDs to translate (omitted when listing with `-Tl`).
    #[arg(value_name = "NAME-OR-OID")]
    tokens: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();
    let numeric = cli.output.as_deref().is_some_and(|o| o.contains('n'));
    let list_all = cli.tree.as_deref().is_some_and(|t| t.contains('l'));

    let mut mib_dirs: Vec<String> = Vec::new();
    for entry in &cli.mib_dirs {
        mib_dirs.extend(netsnmp_apps::split_dir_list(entry));
    }

    let mib = netsnmp_apps::load_mib_registry(&mib_dirs).await;

    // `-Tl`: dump every object loaded from the MIB folder(s), ordered by OID.
    if list_all {
        let mut count = 0usize;
        for (oid, name) in mib.iter_oids() {
            if numeric {
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

    if cli.tokens.is_empty() {
        return Err(AppError::msg(
            "no objects to translate (pass a NAME-OR-OID, or use -Tl to list all)",
        ));
    }

    let mut unknown = Vec::new();
    for token in &cli.tokens {
        match mib.translate(token) {
            Some(oid) => {
                if numeric {
                    info!("{oid}");
                } else {
                    info!("{}", mib.format_oid(&oid));
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
    Ok(())
}
