//! `snmpd` — a minimal SNMP agent daemon serving live system data.
//!
//! Rust counterpart of `agent/snmpd.c`. It registers the mibII system group,
//! IF-MIB interfaces and a HOST-RESOURCES subset, all backed by real
//! operating-system data (`/proc`, `/sys`), and serves community-based and
//! SNMPv3/USM requests over UDP. Settings come from `snmpd.conf`
//! (`rocommunity`, `sysLocation`, `createUser`, …) and may be overridden on the
//! command line.

use clap::Parser;
use netsnmp::sd_daemon::{SD_LISTEN_FDS_START, listen_fds_env};
use netsnmp::usm::UsmUser;
use netsnmp_agent::{
    Agent, AgentConfig, Persistence, Registry, ScalarHandler, ScalarPersistable, SystemMibConfig,
    default_persistent_dir,
};
use netsnmp_apps::{AppError, SnmpdSettings, parse_auth_proto, parse_priv_proto};
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

/// A minimal SNMP agent daemon serving live system data.
///
/// Common usage (copy a whole line and run it; stays in the foreground):
///
///   snmpd -c public --sys-location 'Rack 9' 127.0.0.1:1161
///
/// Typical output, then query it from another shell with snmpget/snmpwalk:
///
///   snmpd listening on 127.0.0.1:1161 (community-based v1/v2c)
///   registered mibII system / IF-MIB / HOST-RESOURCES modules
///   $ snmpget -c public 127.0.0.1:1161 sysLocation.0
///   SNMPv2-MIB::sysLocation.0 = STRING: Rack 9
#[derive(Parser, Debug)]
#[command(
    name = "snmpd",
    about = "Minimal SNMP agent serving live mibII/IF-MIB/HOST-RESOURCES data"
)]
struct Cli {
    /// Read/write community (overrides snmpd.conf rocommunity/rwcommunity).
    #[arg(short, long, env = "SNMP_COMMUNITY")]
    community: Option<String>,
    /// Value to report for sysContact.0 (overrides snmpd.conf sysContact).
    #[arg(long = "sys-contact")]
    sys_contact: Option<String>,
    /// Value to report for sysLocation.0 (overrides snmpd.conf sysLocation).
    #[arg(long = "sys-location")]
    sys_location: Option<String>,
    /// SNMPv3/USM user name to accept (enables SNMPv3).
    #[arg(short = 'u', long = "user", env = "SNMP_SECNAME")]
    v3_user: Option<String>,
    /// USM authentication protocol: MD5, SHA or SHA-256.
    #[arg(short = 'a', long = "auth-protocol")]
    auth_protocol: Option<String>,
    /// USM authentication passphrase.
    #[arg(short = 'A', long = "auth-passphrase", env = "SNMP_AUTH_PASSPHRASE")]
    auth_pass: Option<String>,
    /// USM privacy protocol: AES.
    #[arg(short = 'x', long = "priv-protocol")]
    priv_protocol: Option<String>,
    /// USM privacy passphrase.
    #[arg(short = 'X', long = "priv-passphrase", env = "SNMP_PRIV_PASSPHRASE")]
    priv_pass: Option<String>,
    /// Address to bind, e.g. `127.0.0.1:1161` or `0.0.0.0:161` (overrides
    /// snmpd.conf agentAddress).
    #[arg(value_name = "BIND_ADDR")]
    bind_addr: Option<String>,
    /// Inherit pre-bound listening socket(s) from systemd socket activation
    /// (`ListenDatagram=` / `systemd-socket-activate -l`) instead of binding
    /// `BIND_ADDR`. When set, `LISTEN_FDS`/`LISTEN_PID` must be present (pid
    /// matching this process) and at least one datagram fd must be inherited
    /// starting at descriptor 3; each is served concurrently. Errors out if
    /// activation is not in effect.
    #[arg(long, env = "SNMP_SD_ACTIVATED")]
    sd: bool,
}

impl Cli {
    /// Assemble the configured SNMPv3/USM user, if `-u` was given.
    fn v3_user(&self) -> Result<Option<UsmUser>, AppError> {
        let Some(name) = &self.v3_user else {
            return Ok(None);
        };
        // No auth passphrase: a noAuthNoPriv user.
        let Some(auth_pass) = &self.auth_pass else {
            return Ok(Some(UsmUser::noauth(name)));
        };
        let auth_proto = match &self.auth_protocol {
            Some(p) => parse_auth_proto(p).map_err(|e| AppError::msg(e.to_string()))?,
            None => netsnmp::usm::AuthProtocol::HmacSha1,
        };
        // No privacy passphrase: authNoPriv.
        let Some(priv_pass) = &self.priv_pass else {
            return Ok(Some(UsmUser::auth(name, auth_proto, auth_pass)));
        };
        let priv_proto = match &self.priv_protocol {
            Some(p) => parse_priv_proto(p).map_err(|e| AppError::msg(e.to_string()))?,
            None => netsnmp::usm::PrivProtocol::AesCfb128,
        };
        Ok(Some(UsmUser::auth_priv(
            name, auth_proto, auth_pass, priv_proto, priv_pass,
        )))
    }
}

/// Build the registry and return the writable system scalar handlers so they
/// can be attached to a persistence layer. When persistence is disabled the
/// returned vec is simply ignored.
fn build_registry(mib_config: SystemMibConfig) -> (Registry, Vec<Arc<ScalarHandler>>) {
    let mut reg = Registry::new();
    let writable = netsnmp_agent::register_system_mibs_with_persistables(&mut reg, &mib_config);
    (reg, writable)
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    netsnmp_apps::init_tracing();
    let cli = Cli::parse();

    // snmpd.conf provides the baseline; command-line options override it.
    let settings = netsnmp_apps::load_snmpd_settings().await.unwrap_or_else(|e| {
        warn!("ignoring snmpd.conf: {e}");
        SnmpdSettings::default()
    });

    let cli_user = cli.v3_user()?;

    // Defaults: CLI > snmpd.conf > built-in.
    let defaults = AgentConfig::default();
    let community = cli
        .community
        .clone()
        .or_else(|| settings.community.clone())
        .map(String::into_bytes)
        .unwrap_or(defaults.community);
    let contact = cli
        .sys_contact
        .clone()
        .or_else(|| settings.sys_contact.clone())
        .unwrap_or_else(|| "Me <me@example.org>".to_string());
    let location = cli
        .sys_location
        .clone()
        .or_else(|| settings.sys_location.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    // Bind addresses: CLI positional overrides snmpd.conf agentAddress; both
    // may carry a comma/space-separated list. Falls back to the built-in
    // default when neither is present.
    let bind_addrs: Vec<String> = cli
        .bind_addr
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| netsnmp_apps::normalize_bind_addr(s))
                .collect()
        })
        .unwrap_or_else(|| {
            if settings.agent_address.is_empty() {
                vec![defaults.bind_addr.clone()]
            } else {
                settings.agent_address.clone()
            }
        });

    // USM users: those from snmpd.conf `createUser` plus the CLI `-u` user.
    let mut users = settings.users.clone();
    users.extend(cli_user.iter().cloned());

    let mib_config = SystemMibConfig {
        contact,
        location,
        start: Instant::now(),
    };
    let (registry, writable_scalars) = build_registry(mib_config);

    // Persistence: honour `persistentDir` from snmpd.conf, else the
    // SNMP_PERSISTENT_DIR env var, else the compiled default. Register the
    // writable system scalars so their SET values survive restarts, and replay
    // any saved state into the handlers before serving.
    let persistent_dir = settings
        .persistent_dir
        .clone()
        .or_else(|| {
            std::env::var("SNMP_PERSISTENT_DIR")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(default_persistent_dir);
    let persistence = Arc::new(Persistence::new(&persistent_dir));
    for handler in &writable_scalars {
        let key = scalar_persist_key(handler);
        persistence.register(ScalarPersistable::new(key, Arc::clone(handler)));
    }
    // Replay saved state (best-effort: a missing dir/file is a fresh start).
    if let Err(e) = persistence.load() {
        warn!(error = %e, "failed to load persistent state");
    }

    let mut config = AgentConfig {
        community,
        users: users.clone(),
        bind_addr: bind_addrs[0].clone(),
        ..AgentConfig::default()
    };
    // Attach VACM when snmpd.conf carried any VACM directives.
    if let Some(vacm) = settings.vacm.clone() {
        config.vacm = Some(vacm);
    }
    config = config.with_persistence(Arc::clone(&persistence));

    let agent = Arc::new(Agent::new(registry, config.clone()));

    if cli.sd {
        // systemd socket activation: inherit pre-bound datagram fd(s) starting
        // at SD_LISTEN_FDS_START (3) instead of binding BIND_ADDR. The env
        // parsing is safe (netsnmp::sd_daemon); taking ownership of the raw
        // fd is `unsafe` (FromRawFd lets a safe call close a kernel resource),
        // performed here because netsnmp-apps is not #![forbid(unsafe_code)].
        let (count, _pid) = listen_fds_env().ok_or_else(|| {
            AppError::msg("--sd given but systemd socket activation is not in effect \
                           (LISTEN_FDS/LISTEN_PID missing or pid mismatch)")
        })?;
        if count == 0 {
            return Err(AppError::msg(
                "--sd given but LISTEN_FDS=0 (no sockets were passed)",
            ));
        }
        info!(
            "net-snmp-rs snmpd inheriting {count} socket(s) from systemd (fd {}..{})",
            SD_LISTEN_FDS_START,
            SD_LISTEN_FDS_START + count as i32 - 1,
        );
        for user in &users {
            info!(
                "SNMPv3 user '{}' enabled ({:?})",
                user.name,
                user.security_level()
            );
        }
        let mut tasks = Vec::new();
        for i in 0..count as i32 {
            let raw = SD_LISTEN_FDS_START + i;
            // Safety: systemd dup2'd this datagram socket onto descriptor `raw`
            // for this process; we take exclusive ownership and will not double
            // close. The fd is a SOCK_DGRAM listening socket per the activation
            // contract. `from_raw_fd` is the only way to wrap an inherited fd.
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(raw) };
            // Move into tokio's reactor. from_std consumes the std socket.
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| AppError::msg(format!("failed to adopt fd {raw}: {e}")))?;
            let addr = tokio_socket
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| format!("fd {raw}"));
            info!("serving on inherited socket {addr}");
            let agent_arc = Arc::clone(&agent);
            tasks.push(tokio::spawn(async move {
                if let Err(e) = agent_arc.serve_on(tokio_socket).await {
                    warn!(error = %e, "serve_on for inherited socket exited with error");
                }
            }));
        }
        // Drive all inherited sockets concurrently; this never returns under
        // normal operation (each serve_on loops forever).
        for t in tasks {
            let _ = t.await;
        }
        return Ok(());
    }

    info!(
        "net-snmp-rs snmpd listening on {} (community '{}'), serving live mibII/IF-MIB/HOST-RESOURCES data",
        config.bind_addr,
        String::from_utf8_lossy(&config.community)
    );
    if bind_addrs.len() > 1 {
        info!(
            "multi-address bind: {} address(es) configured, serving each concurrently",
            bind_addrs.len()
        );
    }
    for user in &users {
        info!(
            "SNMPv3 user '{}' enabled ({:?})",
            user.name,
            user.security_level()
        );
    }

    // Bind every requested address and serve each on its own task. The first
    // address is already recorded in `config.bind_addr` (used above for the
    // log line and by the sd path); the rest are bound here.
    let mut sockets: Vec<(tokio::net::UdpSocket, String)> = Vec::new();
    for spec in &bind_addrs {
        match agent.bind_to(spec).await {
            Ok(socket) => {
                let addr = socket.local_addr().unwrap().to_string();
                sockets.push((socket, addr));
            }
            Err(e) => {
                warn!(addr = %spec, error = %e, "failed to bind address, skipping");
            }
        }
    }
    if sockets.is_empty() {
        return Err(AppError::msg(format!(
            "no listening sockets could be bound (tried {})",
            bind_addrs.join(", ")
        )));
    }

    // Spawn one serve task per bound socket.
    let mut tasks = Vec::new();
    for (socket, addr) in sockets.drain(..) {
        info!(%addr, "serving on bound socket");
        let agent_arc = Arc::clone(&agent);
        tasks.push(tokio::spawn(async move {
            if let Err(e) = agent_arc.serve_on(socket).await {
                warn!(addr = %addr, error = %e, "serve_on exited with error");
            }
        }));
    }

    // Signal handling: on SIGTERM/SIGINT flush the persistence layer (so
    // writable scalars and engine boots survive the restart) then exit.
    let agent_for_signal = Arc::clone(&agent);
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => info!("received SIGTERM, shutting down"),
            _ = int.recv() => info!("received SIGINT, shutting down"),
        }
        if let Err(e) = agent_for_signal.save_persistent() {
            warn!(error = %e, "failed to save persistent state on shutdown");
        }
        // Exiting the process here is intentional: the serve loops above run
        // forever, so a graceful shutdown requires an explicit exit.
        std::process::exit(0);
    });

    // Drive all serve loops; under normal operation this never returns.
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

/// Map a writable system scalar handler to its persistence key (the
/// `sysContact`/`sysName`/`sysLocation` leaf name). Falls back to the OID
/// string for handlers outside the system group.
fn scalar_persist_key(handler: &ScalarHandler) -> String {
    let root = handler.root();
    // system group = 1.3.6.1.2.1.1.{4,5,6}
    match root.as_slice() {
        [1, 3, 6, 1, 2, 1, 1, 4] => "sysContact".to_string(),
        [1, 3, 6, 1, 2, 1, 1, 5] => "sysName".to_string(),
        [1, 3, 6, 1, 2, 1, 1, 6] => "sysLocation".to_string(),
        _ => root.to_string(),
    }
}
