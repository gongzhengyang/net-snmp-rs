//! MIB directory-list parsing and registry construction.

/// Split a `-M`/`MIBDIRS` style path list on `:` and `,` separators.
pub fn split_dir_list(list: &str) -> Vec<String> {
    list.split([':', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Build a MIB registry: built-in names plus every MIB file found in the given
/// directories. If `dirs` is empty, the `MIBDIRS` environment variable is
/// consulted. Mirrors the C tools' `-M`/`MIBDIRS` behaviour (we always load all
/// modules in the directories, equivalent to `-m ALL`).
///
/// The directory listing and file reads go through [`tokio::fs`] (see
/// [`netsnmp::mib::MibRegistry::load_dir`]), so the (potentially large) MIB tree
/// is loaded on tokio's blocking pool without stalling the async runtime worker.
pub async fn load_mib_registry(dirs: &[String]) -> netsnmp::mib::MibRegistry {
    let mut reg = netsnmp::mib::MibRegistry::with_builtins();
    let mut all: Vec<String> = dirs.to_vec();
    if all.is_empty()
        && let Ok(env_dirs) = std::env::var("MIBDIRS")
    {
        all = split_dir_list(&env_dirs);
    }
    for dir in all {
        // Best-effort: ignore unreadable directories, like the C tools.
        let _ = reg.load_dir(&dir).await;
    }
    reg
}
