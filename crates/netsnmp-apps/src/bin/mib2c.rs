//! `mib2c` — generate Rust handler skeletons from MIB definitions.
//!
//! Rust counterpart of Net-SNMP's `local/mib2c` (the `mib2c/*.c.conf`
//! templates). It is offline (no agent/network): it loads MIB files, resolves
//! the named node to its [`ObjectDef`](netsnmp::smi::ObjectDef), and emits a
//! Rust handler skeleton that compiles against the `netsnmp-agent` crate.
//!
//! # Usage
//!
//! ```text
//! mib2c [-c CONFIG] [-M MIBDIRS] [-o DIR] NODE
//! ```
//!
//! * `-c/--config <NAME>` — config name (`scalar`/`table`/`notification`);
//!   default auto-detect from NODE's syntax.
//! * `-M/--mib-dirs` — colon/comma-separated MIB directories (env `MIBDIRS`).
//! * `-o/--output <DIR>` — output directory (else stdout).
//! * `NODE` — the MIB node name to generate for (e.g. `ifTable`).
//!
//! Generated code is `cargo fmt`-able and targets the `netsnmp-agent`
//! [`ScalarHandler`]/[`TableHandler`]/notification APIs.

use clap::Parser;
use netsnmp_apps::codegen::{self, GenKind, ResolvedNode};
use netsnmp_apps::{AppError, ArgError, load_mib_registry};
use tracing::info;

/// Generate Rust handler skeletons from MIB definitions (offline).
#[derive(Parser, Debug)]
#[command(name = "mib2c", version, about, long_about = None)]
struct Args {
    /// Config name: `scalar`, `table`, or `notification`. Default: auto-detect
    /// from the node's SYNTAX/INDEX.
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// MIB directories (`DIR:DIR:...` or comma-separated). Defaults to the
    /// `MIBDIRS` environment variable.
    #[arg(short = 'M', long = "mib-dirs", env = "MIBDIRS")]
    mib_dirs: Option<String>,

    /// Output directory. When set, writes `<DIR>/<node>.rs`; otherwise prints
    /// to stdout.
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// The MIB node name to generate for (e.g. `ifTable`, `sysDescr`).
    node: String,
}

/// Parse a `-c` config name into a [`GenKind`].
fn parse_config(name: &str) -> Result<GenKind, AppError> {
    match name.to_ascii_lowercase().as_str() {
        "scalar" => Ok(GenKind::Scalar),
        "table" => Ok(GenKind::Table),
        "notification" | "notify" => Ok(GenKind::Notification),
        other => Err(ArgError(format!("unknown config '{other}'")).into()),
    }
}

/// Resolve the args into a [`ResolvedNode`] suitable for code generation.
async fn resolve(args: &Args) -> Result<ResolvedNode, AppError> {
    let dirs: Vec<String> = args
        .mib_dirs
        .as_deref()
        .map(netsnmp_apps::split_dir_list)
        .unwrap_or_default();
    let registry = load_mib_registry(&dirs).await;
    let node = codegen::resolve_node(&registry, &args.node).ok_or_else(|| {
        AppError::msg(format!(
            "could not resolve MIB node '{}' (loaded {} names)",
            args.node,
            registry.len()
        ))
    })?;
    // Override the detected kind when -c is given.
    let kind = match &args.config {
        Some(c) => parse_config(c)?,
        None => node.kind.clone(),
    };
    Ok(ResolvedNode {
        kind,
        ..node
    })
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let args = Args::parse();
    let node = resolve(&args).await?;
    let code = codegen::generate(&node);
    match &args.output {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .map_err(|e| AppError::msg(format!("create output dir: {e}")))?;
            let path = std::path::Path::new(dir).join(format!("{}.rs", node.name));
            std::fs::write(&path, &code)
                .map_err(|e| AppError::msg(format!("write output: {e}")))?;
            info!("wrote {}", path.display());
        }
        None => {
            print!("{code}");
        }
    }
    Ok(())
}
