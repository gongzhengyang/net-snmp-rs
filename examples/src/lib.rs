//! Shared helpers for the `netsnmp-examples` programs.
//!
//! Every example links against this tiny support crate for one thing: a
//! consistent `tracing` setup so example output (and library `debug`/`trace`
//! logs, when `RUST_LOG` asks for them) is rendered the same way.

/// Initialize a `tracing` subscriber that prints to stderr, honoring `RUST_LOG`
/// (defaulting to `info`). Safe to call once at the start of an example's
/// `main`; subsequent calls are ignored.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}
