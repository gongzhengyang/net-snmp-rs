//! Configuration parsed from `snmp.conf` (client defaults) and `snmpd.conf`
//! (agent settings).
//!
//! Counterpart of the `read_config.c` handling in `snmplib/snmp_api.c` and the
//! agent's `agent_read_config.c` / `mibgroup/mibII/system_mib.c`. Command-line
//! options override every value parsed here.

use std::path::PathBuf;
use std::sync::Arc;

use netsnmp::usm::UsmUser;
use tracing::warn;

use crate::addr::normalize_bind_addr;
use crate::error::ArgError;
use crate::mib::split_dir_list;
use crate::usm::{parse_auth_proto, parse_priv_proto};

/// Client-side defaults parsed from `snmp.conf` (the `def*` tokens and
/// `mibdirs`). Command-line options override these; see
/// [`CommonOpts::resolve_with_defaults`](crate::CommonOpts::resolve_with_defaults).
#[derive(Debug, Default, Clone)]
pub struct ClientDefaults {
    /// `defVersion` — 1, 2c or 3.
    pub version: Option<String>,
    /// `defCommunity` — community string.
    pub community: Option<String>,
    /// `defSecurityName` — USM security name (`-u`).
    pub sec_name: Option<String>,
    /// `defAuthType` — USM auth protocol (`-a`).
    pub auth_protocol: Option<String>,
    /// `defAuthPassphrase` — USM auth passphrase (`-A`).
    pub auth_pass: Option<String>,
    /// `defPrivType` — USM privacy protocol (`-x`).
    pub priv_protocol: Option<String>,
    /// `defPrivPassphrase` — USM privacy passphrase (`-X`).
    pub priv_pass: Option<String>,
    /// `defSecurityLevel` — noAuthNoPriv / authNoPriv / authPriv (`-l`).
    pub level: Option<String>,
    /// `mibdirs` — MIB directories to load.
    pub mib_dirs: Vec<String>,
}

impl ClientDefaults {
    /// Extract the recognized client tokens from parsed `snmp.conf` directives.
    /// Later occurrences override earlier ones (matching read order).
    pub fn from_directives(directives: &[netsnmp::config::Directive]) -> Self {
        let mut d = ClientDefaults::default();
        for dir in directives {
            // Only honor the default (global) or [snmp] context.
            if let Some(section) = &dir.section
                && !section.eq_ignore_ascii_case("snmp")
            {
                continue;
            }
            let value = || dir.rest.trim().to_string();
            match dir.token.to_ascii_lowercase().as_str() {
                "defversion" => d.version = dir.arg(0).map(str::to_string),
                "defcommunity" => d.community = Some(value()),
                "defsecurityname" | "defsecname" => d.sec_name = dir.arg(0).map(str::to_string),
                "defauthtype" => d.auth_protocol = dir.arg(0).map(str::to_string),
                "defauthpassphrase" => d.auth_pass = Some(value()),
                "defprivtype" => d.priv_protocol = dir.arg(0).map(str::to_string),
                "defprivpassphrase" => d.priv_pass = Some(value()),
                "defseclevel" | "defsecuritylevel" => d.level = dir.arg(0).map(str::to_string),
                "mibdirs" => {
                    for entry in &dir.args {
                        // Honor net-snmp's optional leading '+'/'-' by stripping it.
                        let cleaned = entry.trim_start_matches(['+', '-']);
                        d.mib_dirs.extend(split_dir_list(cleaned));
                    }
                }
                _ => {}
            }
        }
        d
    }
}

/// Load client defaults from the standard `snmp.conf` search path.
///
/// The config-file search and parsing are blocking filesystem operations, so
/// they run on tokio's blocking pool via [`tokio::task::spawn_blocking`] rather
/// than stalling the async runtime worker.
pub async fn load_client_defaults() -> ClientDefaults {
    tokio::task::spawn_blocking(|| {
        ClientDefaults::from_directives(&netsnmp::config::read_app_config("snmp"))
    })
    .await
    .expect("client config load task panicked")
}

/// One `com2sec` / `com2sec6` directive: `com2sec [-C] NAME SOURCE COMMUNITY`.
///
/// Maps a source/community pair to a security name. The optional `-C` flag
/// (context) is parsed but not yet wired to VACM contexts. Parsed and stored
/// here; [`SnmpdSettings::vacm`] consumes them via
/// [`Vacm::from_config_directives`](netsnmp_agent::Vacm::from_config_directives).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Com2Sec {
    /// The security/group name (`NAME`).
    pub name: String,
    /// The source network (`SOURCE`, e.g. `default` or `10.0.0.0/8`).
    pub source: String,
    /// The community string (`COMMUNITY`).
    pub community: String,
}

/// One `group NAME MODEL SECURITYNAME` directive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupEntry {
    /// The group name (`NAME`).
    pub name: String,
    /// The security model keyword (`v1`/`v2c`/`usm`/`any`) verbatim.
    pub model: String,
    /// The security name mapped into the group.
    pub security_name: String,
}

/// One `view NAME TYPE SUBTREE [MASK]` directive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewEntry {
    /// The view name (`NAME`).
    pub name: String,
    /// `included` or `excluded` (verbatim).
    pub typ: String,
    /// The subtree OID as a string (validated lazily by VACM).
    pub subtree: String,
    /// The optional hex mask (verbatim, e.g. `0xfe`), if present.
    pub mask: Option<String>,
}

/// One `access` / `access2` directive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessEntry {
    /// The group name.
    pub name: String,
    /// The context prefix (`""` for the default).
    pub context_prefix: String,
    /// The security model keyword (verbatim).
    pub model: String,
    /// The security level keyword (verbatim).
    pub level: String,
    /// The optional context-match keyword (`exact`/`prefix`) — present in the
    /// `access2` 8-arg form, absent in the 7-arg `access` form.
    pub context_match: Option<String>,
    /// The read view name (or `NULL`).
    pub read_view: String,
    /// The write view name (or `NULL`).
    pub write_view: String,
    /// The notify view name (or `NULL`).
    pub notify_view: String,
}

/// One `trapsink`/`trap2sink`/`informsink` directive:
/// `<token> HOST [COMMUNITY] [PORT]`.
///
/// Parsed and stored; wiring the notification originator to actually send is
/// Task 5.12's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrapSink {
    /// The directive kind: `trapsink` (v1), `trap2sink` (v2c) or `informsink`
    /// (v2c inform).
    pub kind: TrapSinkKind,
    /// The destination host (verbatim — may include a port).
    pub host: String,
    /// The community string (defaults to `public`).
    pub community: String,
    /// The destination port (defaults to 162).
    pub port: Option<u16>,
}

/// Which kind of trap sink a [`TrapSink`] represents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrapSinkKind {
    /// `trapsink` — SNMPv1 trap.
    #[default]
    TrapSink,
    /// `trap2sink` — SNMPv2c notification.
    Trap2Sink,
    /// `informsink` — SNMPv2c inform (acknowledged).
    InformSink,
}

/// One `trapsess` directive: a full notification session with explicit
/// version/security parameters. Parsed and stored; wiring is Task 5.12.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrapSession {
    /// The SNMP version keyword (`1`/`2c`/`3`) verbatim.
    pub version: String,
    /// The destination host (verbatim).
    pub host: String,
    /// Remaining arguments (community, security params, port, …) verbatim —
    /// the shape varies by version, so they are kept raw for 5.12 to interpret.
    pub args: Vec<String>,
}

/// One `proxy [-Cn CTX] COMMUNITY HOST OID` directive. Parsed and stored;
/// wiring the proxy handler is Task 5.19's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyEntry {
    /// The optional context name (`-Cn CTX`).
    pub context: Option<String>,
    /// The community string forwarded to the proxied agent.
    pub community: String,
    /// The proxied agent's host (verbatim).
    pub host: String,
    /// The OID subtree delegated to the proxy (verbatim).
    pub oid: String,
}

/// One `exec`/`extend` directive: `[exec|extend] [MIBOID] NAME PROG ARGS...`.
/// Parsed and stored; wiring the `exec` handler is Task 5.23's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecEntry {
    /// The directive kind (`exec` or `extend`).
    pub kind: String,
    /// The optional MIB OID prefix (verbatim), if the first arg parses as one.
    pub mib_oid: Option<String>,
    /// The symbolic name given to the entry.
    pub name: String,
    /// The program path.
    pub program: String,
    /// The program arguments (after the program path).
    pub args: Vec<String>,
}

/// One `pass`/`pass_persist` directive: `pass[-persist] MIBOID PROG`. Parsed
/// and stored; wiring is Task 5.23's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassEntry {
    /// Whether this is `pass_persist` (true) or `pass` (false).
    pub persist: bool,
    /// The MIB OID prefix delegated to the pass-through program.
    pub mib_oid: String,
    /// The program path.
    pub program: String,
}

/// One `disk` directive: `disk PATH [MINSPACE]` (or `disk PATH %MIN`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskEntry {
    /// The mount point or device path.
    pub path: String,
    /// The minimum free space threshold (verbatim: a number or `%N`).
    pub min: Option<String>,
}

/// One `proc` directive: `proc NAME [MAX] [MIN]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcEntry {
    /// The process name to monitor.
    pub name: String,
    /// The maximum count (verbatim).
    pub max: Option<String>,
    /// The minimum count (verbatim).
    pub min: Option<String>,
}

/// One `load` directive: `load [1] [5] [15]` — load-average thresholds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadEntry {
    /// The 1-minute threshold (verbatim).
    pub one: Option<String>,
    /// The 5-minute threshold (verbatim).
    pub five: Option<String>,
    /// The 15-minute threshold (verbatim).
    pub fifteen: Option<String>,
}

/// One `file` directive: `file PATH [MAXSIZE]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileEntry {
    /// The file path to monitor.
    pub path: String,
    /// The maximum size threshold (verbatim).
    pub max: Option<String>,
}

/// One `logmatch` directive. The full grammar is
/// `logmatch NAME FILE [REGEX [DISKTAG]]`; arguments beyond the file are kept
/// verbatim for Task 5.24 to interpret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogMatchEntry {
    /// The symbolic name.
    pub name: String,
    /// The log file path.
    pub file: String,
    /// The remaining arguments (regex, disk tag, …).
    pub args: Vec<String>,
}

/// `master agentx` plus an optional `agentXSocket PATH`. Parsed and stored;
/// wiring the AgentX master is Task 5.18's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MasterConfig {
    /// The sub-agent protocol (currently only `agentx`).
    pub typ: String,
    /// The AgentX socket path (from a separate `agentXSocket` directive).
    pub socket: Option<String>,
}

/// One `smuxpeer OID PASS` directive. Parsed and stored; wiring the SMUX peer
/// is Task 5.20's job.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmuxPeerEntry {
    /// The peer's OID identity (verbatim).
    pub oid: String,
    /// The SMUX password.
    pub password: String,
}

/// Agent settings parsed from `snmpd.conf`.
///
/// Counterpart of the agent's `snmpd.conf` handlers (`agent_read_config.c`,
/// `mibgroup/mibII/system_mib.c`, `mibgroup/snmp_mib*`). Command-line options
/// override these values.
///
/// The full upstream directive set is parsed here: VACM (`com2sec`/`group`/
/// `view`/`access`), trap sinks, proxy, `exec`/`extend`/`pass`/`disk`/`proc`/
/// `load`/`file`/`logmatch`, `master`/`agentXSocket`, `smuxpeer`/`smuxsocket`,
/// `iquery`/`agentSecName` and `persistentDir`. Directives whose wiring belongs
/// to a later task (5.12/5.18/5.19/5.20/5.23/5.24/5.25) are *parsed and
/// stored* here; the binary consumes them as structured data when those tasks
/// land.
#[derive(Debug, Default, Clone)]
pub struct SnmpdSettings {
    /// Community string from `rwcommunity` (preferred) or `rocommunity`.
    pub community: Option<String>,
    /// `sysLocation` value.
    pub sys_location: Option<String>,
    /// `sysContact` value.
    pub sys_contact: Option<String>,
    /// Listen addresses from one or more `agentAddress` directives, each
    /// normalized to `host:port`. A single directive may carry a
    /// comma/space-separated list, all of which are expanded here. Empty when
    /// no `agentAddress` directive is present (the binary falls back to its
    /// built-in default).
    pub agent_address: Vec<String>,
    /// USM users created via `createUser`.
    pub users: Vec<UsmUser>,
    /// `persistentDir` — where the agent writes its persistent state.
    pub persistent_dir: Option<PathBuf>,
    /// `com2sec` / `com2sec6` entries.
    pub com2sec: Vec<Com2Sec>,
    /// `group` entries.
    pub groups: Vec<GroupEntry>,
    /// `view` entries.
    pub views: Vec<ViewEntry>,
    /// `access` / `access2` entries.
    pub access: Vec<AccessEntry>,
    /// A built [`Vacm`] derived from the VACM directives above, if any were
    /// present. `None` when no VACM directives appeared (the agent stays
    /// permissive / falls back to the community ACL).
    pub vacm: Option<Arc<netsnmp_agent::Vacm>>,
    /// `trapsink` / `trap2sink` / `informsink` entries.
    pub trapsinks: Vec<TrapSink>,
    /// `trapsess` entries.
    pub trapsesses: Vec<TrapSession>,
    /// `proxy` entries.
    pub proxy: Vec<ProxyEntry>,
    /// `exec` / `extend` entries.
    pub exec: Vec<ExecEntry>,
    /// `pass` / `pass_persist` entries.
    pub pass: Vec<PassEntry>,
    /// `disk` entries.
    pub disk: Vec<DiskEntry>,
    /// `proc` entries.
    pub proc: Vec<ProcEntry>,
    /// `load` directive (only the last one is honoured upstream).
    pub load: Option<LoadEntry>,
    /// `file` entries.
    pub file: Vec<FileEntry>,
    /// `logmatch` entries.
    pub logmatch: Vec<LogMatchEntry>,
    /// `master agentx` + `agentXSocket`.
    pub master: Option<MasterConfig>,
    /// `smuxpeer` entries.
    pub smuxpeer: Vec<SmuxPeerEntry>,
    /// `smuxsocket` directive.
    pub smuxsocket: Option<String>,
    /// `iquery` / `agentSecName` — the internal-query security identity.
    pub iquery: Option<String>,
}

impl SnmpdSettings {
    /// Parse recognized `snmpd.conf` tokens from the directive list.
    ///
    /// Unknown directives are skipped. Malformed directives emit a
    /// `tracing::warn!` and are skipped (they do *not* abort the whole parse);
    /// only a malformed `createUser` — which the caller likely cares about —
    /// returns `Err`.
    pub fn from_directives(directives: &[netsnmp::config::Directive]) -> Result<Self, ArgError> {
        let mut settings = SnmpdSettings::default();
        let mut ro = None;
        let mut rw = None;
        // Track whether agentXSocket was seen so it attaches to a master block.
        let mut agentx_socket: Option<String> = None;
        for dir in directives {
            if let Some(section) = &dir.section
                && !section.eq_ignore_ascii_case("snmpd")
            {
                continue;
            }
            match dir.token.to_ascii_lowercase().as_str() {
                "rocommunity" | "rocommunity6" => ro = dir.arg(0).map(str::to_string),
                "rwcommunity" | "rwcommunity6" => rw = dir.arg(0).map(str::to_string),
                "syslocation" => settings.sys_location = Some(freeform_value(dir)),
                "syscontact" => settings.sys_contact = Some(freeform_value(dir)),
                "agentaddress" => {
                    for addr in expand_address_list(&dir.args) {
                        settings.agent_address.push(normalize_bind_addr(&addr));
                    }
                }
                "createuser" => settings.users.push(build_create_user(&dir.args)?),
                "persistentdir" => {
                    if let Some(p) = dir.arg(0) {
                        settings.persistent_dir = Some(PathBuf::from(p));
                    }
                }
                "com2sec" | "com2sec6" => {
                    if let Some(e) = parse_com2sec(dir) {
                        settings.com2sec.push(e);
                    }
                }
                "group" => {
                    if let Some(e) = parse_group(dir) {
                        settings.groups.push(e);
                    }
                }
                "view" => {
                    if let Some(e) = parse_view(dir) {
                        settings.views.push(e);
                    }
                }
                "access" | "access2" => {
                    if let Some(e) = parse_access(dir) {
                        settings.access.push(e);
                    }
                }
                "trapsink" => settings.trapsinks.push(parse_trap_sink(dir, TrapSinkKind::TrapSink)),
                "trap2sink" => settings
                    .trapsinks
                    .push(parse_trap_sink(dir, TrapSinkKind::Trap2Sink)),
                "informsink" => settings
                    .trapsinks
                    .push(parse_trap_sink(dir, TrapSinkKind::InformSink)),
                "trapsess" => {
                    if let Some(e) = parse_trapsess(dir) {
                        settings.trapsesses.push(e);
                    }
                }
                "proxy" => {
                    if let Some(e) = parse_proxy(dir) {
                        settings.proxy.push(e);
                    }
                }
                "exec" | "extend" | "sh" => settings.exec.push(parse_exec(dir)),
                "pass" => {
                    if let Some(e) = parse_pass(dir, false) {
                        settings.pass.push(e);
                    }
                }
                "pass_persist" | "passpersist" => {
                    if let Some(e) = parse_pass(dir, true) {
                        settings.pass.push(e);
                    }
                }
                "disk" => {
                    if let Some(e) = parse_disk(dir) {
                        settings.disk.push(e);
                    }
                }
                "proc" => {
                    if let Some(e) = parse_proc(dir) {
                        settings.proc.push(e);
                    }
                }
                "load" => settings.load = parse_load(dir),
                "file" => {
                    if let Some(e) = parse_file(dir) {
                        settings.file.push(e);
                    }
                }
                "logmatch" => {
                    if let Some(e) = parse_logmatch(dir) {
                        settings.logmatch.push(e);
                    }
                }
                "master" => {
                    if let Some(e) = parse_master(dir) {
                        // Attach any previously-seen agentXSocket, or leave it
                        // to be attached below if it comes later.
                        let mut m = e;
                        m.socket = agentx_socket.clone().or(m.socket.take());
                        settings.master = Some(m);
                    }
                }
                "agentxsocket" => {
                    agentx_socket = dir.arg(0).map(str::to_string);
                    if let Some(m) = settings.master.as_mut() {
                        m.socket = agentx_socket.clone();
                    }
                }
                "smuxpeer" => {
                    if let Some(e) = parse_smuxpeer(dir) {
                        settings.smuxpeer.push(e);
                    }
                }
                "smuxsocket" => settings.smuxsocket = dir.arg(0).map(str::to_string),
                "iquery" | "agentsecname" => settings.iquery = dir.arg(0).map(str::to_string),
                _ => {}
            }
        }
        settings.community = rw.or(ro);
        // Build a Vacm from the VACM directives when any were present.
        if !settings.com2sec.is_empty()
            || !settings.groups.is_empty()
            || !settings.views.is_empty()
            || !settings.access.is_empty()
        {
            settings.vacm = Some(netsnmp_agent::Vacm::from_config_directives(directives));
        }
        Ok(settings)
    }

    /// The first `agentAddress` value, if any — convenience for binaries that
    /// only bind a single listener. Returns `None` when `agentAddress` was
    /// absent.
    pub fn first_agent_address(&self) -> Option<&str> {
        self.agent_address.first().map(String::as_str)
    }

    /// Whether any VACM directives were parsed (and thus [`Self::vacm`] is
    /// `Some`).
    pub fn has_vacm(&self) -> bool {
        self.vacm.is_some()
    }
}

/// Expand a `agentAddress` argument list into individual address specs.
///
/// Net-SNMP accepts both space- and comma-separated lists (e.g.
/// `udp:161,tcp:1161` or `udp:161 tcp:1161`); a single spec with no separator
/// yields a one-element vec. Empty tokens (from trailing commas) are dropped.
fn expand_address_list(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for arg in args {
        for part in arg.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

/// Parse a `com2sec [-C] NAME SOURCE COMMUNITY` directive. Returns `None` and
/// warns on a malformed line.
fn parse_com2sec(dir: &netsnmp::config::Directive) -> Option<Com2Sec> {
    let mut args = dir.args.iter().skip_while(|a| a.starts_with('-'));
    let name = args.next().map(String::as_str);
    let source = args.next().map(String::as_str);
    let community = args.next().map(String::as_str);
    match (name, source, community) {
        (Some(name), Some(source), Some(community)) => Some(Com2Sec {
            name: name.to_string(),
            source: source.to_string(),
            community: community.to_string(),
        }),
        _ => {
            warn!(line = dir.line_no, "com2sec: need NAME SOURCE COMMUNITY");
            None
        }
    }
}

/// Parse a `group NAME MODEL SECURITYNAME` directive.
fn parse_group(dir: &netsnmp::config::Directive) -> Option<GroupEntry> {
    match (dir.arg(0), dir.arg(1), dir.arg(2)) {
        (Some(name), Some(model), Some(security_name)) => Some(GroupEntry {
            name: name.to_string(),
            model: model.to_string(),
            security_name: security_name.to_string(),
        }),
        _ => {
            warn!(line = dir.line_no, "group: need NAME MODEL SECURITYNAME");
            None
        }
    }
}

/// Parse a `view NAME TYPE SUBTREE [MASK]` directive.
fn parse_view(dir: &netsnmp::config::Directive) -> Option<ViewEntry> {
    let name = dir.arg(0)?;
    let typ = dir.arg(1)?;
    let subtree = dir.arg(2)?;
    Some(ViewEntry {
        name: name.to_string(),
        typ: typ.to_string(),
        subtree: subtree.to_string(),
        mask: dir.arg(3).map(str::to_string),
    })
}

/// Parse an `access` / `access2` directive. The 7-arg `access` form has no
/// context-match word; the 8-arg `access2` form inserts `exact`/`prefix`
/// between LEVEL and READ.
fn parse_access(dir: &netsnmp::config::Directive) -> Option<AccessEntry> {
    let args: Vec<&str> = dir.args.iter().map(String::as_str).collect();
    if args.len() < 7 {
        warn!(line = dir.line_no, "access: need at least 7 args");
        return None;
    }
    let (context_match, read_idx) = if args.len() >= 8
        && matches!(args[4].to_ascii_lowercase().as_str(), "exact" | "prefix")
    {
        (Some(args[4].to_string()), 5)
    } else {
        (None, 4)
    };
    Some(AccessEntry {
        name: args[0].to_string(),
        context_prefix: args[1].to_string(),
        model: args[2].to_string(),
        level: args[3].to_string(),
        context_match,
        read_view: args[read_idx].to_string(),
        write_view: args[read_idx + 1].to_string(),
        notify_view: args[read_idx + 2].to_string(),
    })
}

/// Parse a `trapsink`/`trap2sink`/`informsink HOST [COMMUNITY] [PORT]`
/// directive. Missing community defaults to `public`; a non-numeric community
/// leaves the port unset.
fn parse_trap_sink(dir: &netsnmp::config::Directive, kind: TrapSinkKind) -> TrapSink {
    let host = dir.arg(0).unwrap_or("localhost").to_string();
    let community = dir.arg(1).unwrap_or("public").to_string();
    let port = dir.arg(2).and_then(|p| p.parse::<u16>().ok());
    TrapSink {
        kind,
        host,
        community,
        port,
    }
}

/// Parse a `trapsess` directive. The grammar mirrors `snmptrap`'s options
/// (`-v <ver> -c <comm> HOST` for v1/v2c, or `-v 3 -u <user> ... HOST` for v3),
/// but older forms also accept a bare version keyword as the first token. The
/// host is the first argument that is not a flag and not a flag's value. The
/// version comes from `-v` when present, else defaults to `2c`. All arguments
/// are kept verbatim in [`TrapSession::args`] for the notification originator
/// (Task 5.12) to interpret fully.
fn parse_trapsess(dir: &netsnmp::config::Directive) -> Option<TrapSession> {
    if dir.args.is_empty() {
        warn!(line = dir.line_no, "trapsess: need at least a version/host");
        return None;
    }
    // Flags that consume the following argument as their value.
    const VALUE_FLAGS: &[&str] = &["-v", "-c", "-u", "-a", "-A", "-x", "-X", "-l", "-e", "-E", "-r", "-t"];
    let mut version = String::from("2c");
    let mut host: Option<String> = None;
    let mut i = 0;
    while i < dir.args.len() {
        let arg = &dir.args[i];
        if arg == "-v" {
            if let Some(v) = dir.args.get(i + 1) {
                version = v.clone();
                i += 2;
                continue;
            }
        } else if VALUE_FLAGS.contains(&arg.as_str()) {
            // Skip the flag and its value.
            i += 2;
            continue;
        } else if arg.starts_with('-') && arg.len() == 2 {
            // A bare boolean flag (e.g. -Ci, -Cf) consuming no value.
            i += 1;
            continue;
        } else if host.is_none() {
            // The first non-flag token is the destination host.
            host = Some(arg.clone());
        }
        i += 1;
    }
    let host = host?;
    Some(TrapSession {
        version,
        host,
        args: dir.args.clone(),
    })
}

/// Parse a `proxy [-Cn CTX] COMMUNITY HOST OID` directive.
fn parse_proxy(dir: &netsnmp::config::Directive) -> Option<ProxyEntry> {
    let mut args = dir.args.iter();
    let mut context = None;
    // Optional `-Cn CTX`.
    if args.next().map(String::as_str) == Some("-Cn") {
        context = args.next().cloned();
    } else {
        // Rewind: re-create the iterator without consuming the first token.
        args = dir.args.iter();
    }
    let community = args.next()?;
    let host = args.next()?;
    let oid = args.next()?;
    Some(ProxyEntry {
        context,
        community: community.clone(),
        host: host.clone(),
        oid: oid.clone(),
    })
}

/// Parse an `exec`/`extend`/`sh` directive. The optional leading MIB OID is
/// detected by trying to parse the first arg as an OID.
fn parse_exec(dir: &netsnmp::config::Directive) -> ExecEntry {
    let kind = dir.token.to_ascii_lowercase();
    let mut args = dir.args.iter();
    let first = args.next();
    // If the first arg parses as an OID, it's the MIB prefix; the next is NAME.
    let (mib_oid, name): (Option<String>, Option<&String>) = match first {
        Some(f) if f.parse::<netsnmp::oid::Oid>().is_ok() => (Some(f.clone()), args.next()),
        other => (None, other),
    };
    let program = args.next().cloned().unwrap_or_default();
    let rest: Vec<String> = args.cloned().collect();
    ExecEntry {
        kind,
        mib_oid,
        name: name.cloned().unwrap_or_default(),
        program,
        args: rest,
    }
}

/// Parse a `pass`/`pass_persist MIBOID PROG` directive.
fn parse_pass(dir: &netsnmp::config::Directive, persist: bool) -> Option<PassEntry> {
    let mib_oid = dir.arg(0)?;
    let program = dir.arg(1)?;
    Some(PassEntry {
        persist,
        mib_oid: mib_oid.to_string(),
        program: program.to_string(),
    })
}

/// Parse a `disk PATH [MIN]` directive.
fn parse_disk(dir: &netsnmp::config::Directive) -> Option<DiskEntry> {
    let path = dir.arg(0)?;
    Some(DiskEntry {
        path: path.to_string(),
        min: dir.arg(1).map(str::to_string),
    })
}

/// Parse a `proc NAME [MAX] [MIN]` directive.
fn parse_proc(dir: &netsnmp::config::Directive) -> Option<ProcEntry> {
    let name = dir.arg(0)?;
    Some(ProcEntry {
        name: name.to_string(),
        max: dir.arg(1).map(str::to_string),
        min: dir.arg(2).map(str::to_string),
    })
}

/// Parse a `load [1] [5] [15]` directive.
fn parse_load(dir: &netsnmp::config::Directive) -> Option<LoadEntry> {
    if dir.args.is_empty() {
        return Some(LoadEntry::default());
    }
    Some(LoadEntry {
        one: dir.arg(0).map(str::to_string),
        five: dir.arg(1).map(str::to_string),
        fifteen: dir.arg(2).map(str::to_string),
    })
}

/// Parse a `file PATH [MAX]` directive.
fn parse_file(dir: &netsnmp::config::Directive) -> Option<FileEntry> {
    let path = dir.arg(0)?;
    Some(FileEntry {
        path: path.to_string(),
        max: dir.arg(1).map(str::to_string),
    })
}

/// Parse a `logmatch NAME FILE [REGEX [DISKTAG]]` directive.
fn parse_logmatch(dir: &netsnmp::config::Directive) -> Option<LogMatchEntry> {
    let name = dir.arg(0)?;
    let file = dir.arg(1)?;
    Some(LogMatchEntry {
        name: name.to_string(),
        file: file.to_string(),
        args: dir.args.get(2..).map(|s| s.to_vec()).unwrap_or_default(),
    })
}

/// Parse a `master agentx` directive.
fn parse_master(dir: &netsnmp::config::Directive) -> Option<MasterConfig> {
    let typ = dir.arg(0)?;
    Some(MasterConfig {
        typ: typ.to_string(),
        socket: None,
    })
}

/// Parse a `smuxpeer OID PASS` directive.
fn parse_smuxpeer(dir: &netsnmp::config::Directive) -> Option<SmuxPeerEntry> {
    let oid = dir.arg(0)?;
    let password = dir.arg(1).unwrap_or("");
    Some(SmuxPeerEntry {
        oid: oid.to_string(),
        password: password.to_string(),
    })
}

/// Load agent settings from the standard `snmpd.conf` search path.
///
/// The config-file search and parsing are blocking filesystem operations, so
/// they run on tokio's blocking pool via [`tokio::task::spawn_blocking`] rather
/// than stalling the async runtime worker.
pub async fn load_snmpd_settings() -> Result<SnmpdSettings, ArgError> {
    tokio::task::spawn_blocking(|| {
        SnmpdSettings::from_directives(&netsnmp::config::read_app_config("snmpd"))
    })
    .await
    .expect("snmpd config load task panicked")
}

/// The value of a free-form directive (`sysLocation`/`sysContact`): a single
/// quoted token is taken verbatim, otherwise the rest of the line is used.
fn freeform_value(dir: &netsnmp::config::Directive) -> String {
    if dir.args.len() == 1 {
        dir.args[0].clone()
    } else {
        dir.rest.trim().to_string()
    }
}

/// Build a [`UsmUser`] from the arguments of a `createUser` directive.
///
/// Accepts `createUser NAME [auth AUTHPASS [priv PRIVPASS]]`, plus an optional
/// leading `-e ENGINEID` (which is ignored, as our agent is authoritative).
fn build_create_user(args: &[String]) -> Result<UsmUser, ArgError> {
    let mut args = args;
    if args.first().map(String::as_str) == Some("-e") {
        args = args.get(2..).unwrap_or(&[]);
    }
    let name = args
        .first()
        .ok_or_else(|| ArgError("createUser requires a username".into()))?
        .clone();

    match args.len() {
        0 | 1 => Ok(UsmUser::noauth(name)),
        2 => Err(ArgError(format!(
            "createUser '{name}': auth type without a passphrase"
        ))),
        3 => {
            let proto = parse_auth_proto(&args[1])?;
            Ok(UsmUser::auth(name, proto, args[2].clone()))
        }
        4 => Err(ArgError(format!(
            "createUser '{name}': privacy type without a passphrase"
        ))),
        _ => {
            let auth = parse_auth_proto(&args[1])?;
            let priv_proto = parse_priv_proto(&args[3])?;
            Ok(UsmUser::auth_priv(
                name,
                auth,
                args[2].clone(),
                priv_proto,
                args[4].clone(),
            ))
        }
    }
}
