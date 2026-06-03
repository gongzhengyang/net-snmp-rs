//! Configuration search-path resolution (`SNMPCONFPATH` and the compiled
//! defaults) plus the per-application file lookup.

use std::path::{Path, PathBuf};

use super::Directive;
use super::parse::parse_file;

/// Default configuration directories used when `SNMPCONFPATH` is unset.
const DEFAULT_CONF_DIRS: &[&str] = &["/etc/snmp", "/usr/share/snmp", "/usr/lib/snmp"];

/// Default persistent-data directory (`get_persistent_directory` fallback).
const DEFAULT_PERSISTENT_DIR: &str = "/var/lib/snmp";

/// The ordered list of configuration directories to search, reproducing
/// `get_configuration_directory` + the persistent directory:
///
/// * If `SNMPCONFPATH` is set, its `:`-separated entries are used verbatim.
/// * Otherwise the compiled defaults (`/etc/snmp`, `/usr/share/snmp`,
///   `/usr/lib/snmp`) plus `$HOME/.snmp` are used.
/// * The persistent directory (`SNMP_PERSISTENT_DIR`, else `/var/lib/snmp`) is
///   appended.
pub fn config_directories() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    if let Ok(path) = std::env::var("SNMPCONFPATH") {
        dirs.extend(path.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
    } else {
        dirs.extend(DEFAULT_CONF_DIRS.iter().map(PathBuf::from));
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            dirs.push(Path::new(&home).join(".snmp"));
        }
    }

    let persistent =
        std::env::var("SNMP_PERSISTENT_DIR").unwrap_or_else(|_| DEFAULT_PERSISTENT_DIR.to_string());
    let persistent = PathBuf::from(persistent);
    if !dirs.contains(&persistent) {
        dirs.push(persistent);
    }
    dirs
}

/// The candidate file list for an application type, e.g. `"snmp"` or `"snmpd"`:
/// `<dir>/<app>.conf` and `<dir>/<app>.local.conf` for each search directory.
pub fn config_files(app_type: &str) -> Vec<PathBuf> {
    config_files_in(&config_directories(), app_type)
}

/// Like [`config_files`] but over an explicit directory list (testable without
/// touching the real system paths).
pub fn config_files_in(dirs: &[PathBuf], app_type: &str) -> Vec<PathBuf> {
    let mut files = Vec::with_capacity(dirs.len() * 2);
    for dir in dirs {
        files.push(dir.join(format!("{app_type}.conf")));
        files.push(dir.join(format!("{app_type}.local.conf")));
    }
    files
}

/// Read and parse every existing configuration file for `app_type` across the
/// standard search path, concatenating the directives in read order.
pub fn read_app_config(app_type: &str) -> Vec<Directive> {
    read_app_config_in(&config_directories(), app_type)
}

/// Like [`read_app_config`] but over an explicit directory list.
pub fn read_app_config_in(dirs: &[PathBuf], app_type: &str) -> Vec<Directive> {
    let mut out = Vec::new();
    for file in config_files_in(dirs, app_type) {
        if file.is_file()
            && let Ok(directives) = parse_file(&file)
        {
            out.extend(directives);
        }
    }
    out
}
