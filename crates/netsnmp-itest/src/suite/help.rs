//! Offline smoke checks: every binary must print help and exit cleanly.

use crate::check::Check;

use super::TOOLS;

/// One `--help` smoke check per shipped binary.
pub(super) fn checks() -> Vec<Check> {
    TOOLS
        .iter()
        .map(|&tool| {
            Check::new("help", format!("{tool} --help"), tool)
                .args(["--help"])
                .offline()
                .contains_any(["usage", "options"])
                .hint("The binary may be a stale build; rebuild with `cargo build --release`.")
        })
        .collect()
}
