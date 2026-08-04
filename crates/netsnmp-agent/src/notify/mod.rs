//! Notification originator: the agent-side counterpart of `agent/agent_trap.c`
//! and the `target/` + `notification/` MIB groups.
//!
//! Where [`crate::trap::TrapReceiver`](crate::trap::TrapReceiver) is the
//! *receiving* side (`snmptrapd`), the notification originator is the *sending*
//! side: it builds a notification PDU (auto-prepending `sysUpTime.0` and
//! `snmpTrapOID.0` per RFC 3418) and fans it out to every configured target.
//!
//! The configuration mirrors SNMP-TARGET-MIB (`snmpTargetAddrTable` /
//! `snmpTargetParamsTable`) and SNMP-NOTIFICATION-MIB (`snmpNotifyTable`), kept
//! in-memory as three [`RwLock`]`<Vec<_>>` stores. It is populated either
//! programmatically ([`NotifyConfig::add_target`] etc.) or from the classic
//! net-snmp `snmpd.conf` directives ([`NotifyConfig::from_config_directives`]):
//!
//! | Directive      | Maps to                            |
//! |----------------|------------------------------------|
//! | `trapsink`     | v1 Trap to HOST:PORT with COMM     |
//! | `trap2sink`    | v2c Trap to HOST:PORT with COMM    |
//! | `informsink`   | v2c Inform to HOST:PORT with COMM  |
//! | `trapsess`     | full v2c/v3 session (Trap or Inform) |
//!
//! [`NotificationOriginator`] wraps a [`NotifyConfig`] (shared, so the live
//! target/notify tables can also be walked via
//! [`crate::mibgroup::notify::notify_handlers`]) and exposes
//! [`NotificationOriginator::send`] as the primary entry point used by
//! [`crate::agent::Agent::send_notification`].

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use netsnmp::config::Directive;
use netsnmp::error::{Error, Result};
use netsnmp::message::Version;
use netsnmp::oid::Oid;
use netsnmp::pdu::VarBind;
use netsnmp::session::{Session, SessionConfig};
use netsnmp::usm::{AuthProtocol, PrivProtocol, SecurityLevel, UsmUser};
use netsnmp::v3::EngineParams;
use netsnmp::value::Value;
use tracing::{debug, warn};

/// The conventional notification port (`162`).
const TRAP_PORT: u16 = 162;

/// `sysUpTime.0` — the first varbind of every SNMPv2 notification
/// (`1.3.6.1.2.1.1.3.0`).
const SYSUPTIME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];

/// `snmpTrapOID.0` — the second varbind (`1.3.6.1.6.3.1.1.4.1.0`).
const SNMP_TRAP_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// The standard `coldStart` trap OID (`1.3.6.1.6.3.1.1.5.1`).
pub const COLD_START_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 1];

/// The standard `warmStart` trap OID (`1.3.6.1.6.3.1.1.5.2`).
pub const WARM_START_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 5, 2];

/// Whether a notify entry sends an unconfirmed trap or a confirmed inform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyType {
    /// An unconfirmed SNMPv2-Trap (RFC 3416 §4.2.6).
    Trap,
    /// A confirmed InformRequest (RFC 3416 §4.2.7).
    Inform,
}

impl NotifyType {
    /// The numeric `snmpNotifyType` value: `trap(1)` or `inform(2)`.
    pub fn as_int(self) -> i64 {
        match self {
            NotifyType::Trap => 1,
            NotifyType::Inform => 2,
        }
    }
}

/// One `snmpTargetAddrEntry` (SNMP-TARGET-MIB): a transport endpoint plus the
/// name of the [`TargetParams`] entry describing its security.
#[derive(Clone, Debug)]
pub struct TargetAddr {
    /// Row name (`snmpTargetAddrName`), also the notify tag for simple configs.
    pub name: String,
    /// Transport domain, e.g. `"udp"` (only UDP is wired up here).
    pub transport: String,
    /// `host:port` (or bare `host`, defaulting to port 162).
    pub address: String,
    /// `snmpTargetAddrTimeout` (per-target, applied to informs).
    pub timeout: Duration,
    /// `snmpTargetAddrRetryCount`.
    pub retries: u32,
    /// Name of the [`TargetParams`] row that supplies the security parameters.
    pub params_name: String,
}

/// One `snmpTargetParamsEntry` (SNMP-TARGET-MIB): the security model / name /
/// level / message-processing model used to reach a target.
#[derive(Clone, Debug)]
pub struct TargetParams {
    /// Row name (`snmpTargetParamsName`).
    pub name: String,
    /// `snmpTargetParamsMPModel`: 0 = v1, 1 = v2c, 3 = v3.
    pub mp_model: i32,
    /// `snmpTargetParamsSecurityModel`: 1 = v1, 2 = v2c, 3 = USM.
    pub security_model: i32,
    /// `snmpTargetParamsSecurityName` (community for v1/v2c, user for v3).
    pub security_name: Vec<u8>,
    /// `snmpTargetParamsSecurityLevel`: 0 = noAuth, 1 = authNoPriv, 3 = authPriv.
    pub security_level: i32,
    /// For v3 targets: the fully-specified [`UsmUser`] (auth/priv protocols and
    /// passphrases). `None` for v1/v2c targets.
    pub usm_user: Option<UsmUser>,
}

/// One `snmpNotifyEntry` (SNMP-NOTIFICATION-MIB): binds a tag to a set of
/// target parameters and a [`NotifyType`].
#[derive(Clone, Debug)]
pub struct NotifyEntry {
    /// Row name (`snmpNotifyName`).
    pub name: String,
    /// `snmpNotifyTag` — selects which [`TargetAddr`] rows receive this
    /// notification. The simple config directives set this equal to the
    /// target's `name`, so a 1:1 match is used.
    pub tag: String,
    /// `snmpNotifyType` — Trap or Inform.
    pub typ: NotifyType,
    /// Name of the [`TargetParams`] row to use.
    pub params_name: String,
}

/// In-memory target/notification tables, shared between the
/// [`NotificationOriginator`] (which reads them to dispatch notifications) and
/// the live MIB handlers (which expose them to walkers).
///
/// The three stores are independent [`RwLock`]s so a walk reading one table
/// does not block a `send` reading another.
#[derive(Debug)]
pub struct NotifyConfig {
    targets: RwLock<Vec<TargetAddr>>,
    params: RwLock<Vec<TargetParams>>,
    notifies: RwLock<Vec<NotifyEntry>>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            targets: RwLock::new(Vec::new()),
            params: RwLock::new(Vec::new()),
            notifies: RwLock::new(Vec::new()),
        }
    }
}

impl NotifyConfig {
    /// Create an empty target/notification configuration.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            targets: RwLock::new(Vec::new()),
            params: RwLock::new(Vec::new()),
            notifies: RwLock::new(Vec::new()),
        })
    }

    /// Append a target address row.
    pub fn add_target(&self, target: TargetAddr) {
        self.targets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(target);
    }

    /// Append a target parameters row.
    pub fn add_params(&self, params: TargetParams) {
        self.params
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(params);
    }

    /// Append a notify entry.
    pub fn add_notify(&self, notify: NotifyEntry) {
        self.notifies
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(notify);
    }

    /// Whether at least one target is configured (used to decide whether to
    /// emit a startup `coldStart`).
    pub fn has_targets(&self) -> bool {
        !self
            .targets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// A snapshot of the target address rows.
    pub fn targets(&self) -> Vec<TargetAddr> {
        self.targets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A snapshot of the target parameters rows.
    pub fn params(&self) -> Vec<TargetParams> {
        self.params
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A snapshot of the notify entries.
    pub fn notifies(&self) -> Vec<NotifyEntry> {
        self.notifies
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Parse the classic net-snmp `snmpd.conf` notification directives into a
    /// fresh [`NotifyConfig`]. Recognises `trapsink`, `trap2sink`,
    /// `informsink` and `trapsess`; unknown directives are silently skipped
    /// (this config owns only its own directives, not the rest of the file).
    ///
    /// Each directive maps to one [`TargetAddr`] + one [`TargetParams`] + one
    /// [`NotifyEntry`], all sharing a single derived name so the tag lookup is
    /// a 1:1 match. For v3 `trapsess`, the security parameters are parsed from
    /// the same `-v/-u/-a/-A/-x/-X/-l` flags the `snmptrap` tool accepts.
    pub fn from_config_directives(directives: &[Directive]) -> Arc<Self> {
        let config = Self::new();
        for d in directives {
            if d.is("trapsink") {
                apply_community_sink(&config, d, Version::V1, NotifyType::Trap);
            } else if d.is("trap2sink") {
                apply_community_sink(&config, d, Version::V2c, NotifyType::Trap);
            } else if d.is("informsink") {
                apply_community_sink(&config, d, Version::V2c, NotifyType::Inform);
            } else if d.is("trapsess") {
                apply_trapsess(&config, d);
            }
            // Everything else is ignored: notify owns only its own directives.
        }
        config
    }
}

/// Normalize a `HOST` argument (which may be bare, `host:port`, or
/// `udp:host:port`) into a `host:port` string, defaulting the port to 162.
fn normalize_host_port(host: &str, port: Option<&str>) -> String {
    // Strip a leading `udp:` transport prefix if present.
    let host = host
        .strip_prefix("udp:")
        .or_else(|| host.strip_prefix("UDP:"))
        .unwrap_or(host);
    if host.contains(':') {
        host.to_string()
    } else if let Some(p) = port {
        format!("{host}:{p}")
    } else {
        format!("{host}:{TRAP_PORT}")
    }
}

/// Apply a `trapsink`/`trap2sink`/`informsink HOST [COMM] [PORT]` directive.
///
/// `version` selects v1 (trapsink) vs v2c (trap2sink/informsink); `typ` selects
/// Trap vs Inform. All three produce a community-authenticated target.
fn apply_community_sink(config: &NotifyConfig, d: &Directive, version: Version, typ: NotifyType) {
    let mut args = d.args.iter();
    let Some(host) = args.next() else {
        warn!(line = d.line_no, "{} missing HOST", d.token);
        return;
    };
    let community = args.next().map(String::as_bytes).unwrap_or(b"public");
    let port = args.next().map(String::as_str);
    let address = normalize_host_port(host, port);

    let name = format!("sink{}", config.targets().len() + 1);
    let security_name = community.to_vec();
    let (mp_model, security_model) = match version {
        Version::V1 => (0, 1),
        _ => (1, 2),
    };
    config.add_params(TargetParams {
        name: name.clone(),
        mp_model,
        security_model,
        security_name,
        security_level: 0,
        usm_user: None,
    });
    config.add_target(TargetAddr {
        name: name.clone(),
        transport: "udp".to_string(),
        address,
        timeout: Duration::from_secs(5),
        retries: 2,
        params_name: name.clone(),
    });
    config.add_notify(NotifyEntry {
        name: name.clone(),
        tag: name.clone(),
        typ,
        params_name: name,
    });
}

/// Parse the v3 security flags from a `trapsess` argument list. Mirrors the
/// `snmptrap` / `snmpusm` `-v/-u/-a/-A/-x/-X/-l` convention.
struct V3Args {
    user: String,
    auth_proto: Option<AuthProtocol>,
    auth_pass: Option<String>,
    priv_proto: Option<PrivProtocol>,
    priv_pass: Option<String>,
    level: SecurityLevel,
    host: String,
    port: Option<String>,
}

/// Parse `-v 3 -u USER -a AUTH -A PASS [-x PRIV -X PASS] [-l LEVEL] HOST [PORT]`.
fn parse_trapsess(args: &[String]) -> Option<V3Args> {
    let mut user = None;
    let mut auth_proto: Option<AuthProtocol> = None;
    let mut auth_pass: Option<String> = None;
    let mut priv_proto: Option<PrivProtocol> = None;
    let mut priv_pass: Option<String> = None;
    let mut level: Option<String> = None;
    let mut positional: Vec<&str> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-u" | "--user" => user = iter.next().map(String::as_str).map(String::from),
            "-a" | "--auth-protocol" => {
                if let Some(v) = iter.next() {
                    auth_proto = parse_auth_proto(v).ok();
                }
            }
            "-A" | "--auth-passphrase" => auth_pass = iter.next().cloned(),
            "-x" | "--priv-protocol" => {
                if let Some(v) = iter.next() {
                    priv_proto = parse_priv_proto(v).ok();
                }
            }
            "-X" | "--priv-passphrase" => priv_pass = iter.next().cloned(),
            "-l" | "--security-level" | "-L" => level = iter.next().cloned(),
            // `-v 3` / `--version 3` and the v2c forms: the only accepted v3
            // value is 3; v2c trapsess falls back to community mode below.
            "-v" | "--version" => {
                let _ = iter.next();
            }
            "-c" | "--community" => {
                let _ = iter.next();
            }
            other if other.starts_with('-') => {
                // Unknown flag: skip it and its value if it looks flag-like.
                // (Be conservative: do not consume a following positional.)
            }
            other => positional.push(other),
        }
    }

    let host = positional.first()?.to_string();
    let port = positional.get(1).map(|s| s.to_string());
    let user = user?;

    let auth_pass = auth_pass.filter(|s| !s.is_empty());
    let priv_pass = priv_pass.filter(|s| !s.is_empty());

    let level = match level.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("noauth" | "noauthnopriv" | "noauthnoprivacy") => SecurityLevel::NoAuthNoPriv,
        Some("auth" | "authnopriv" | "authnoprivacy") => SecurityLevel::AuthNoPriv,
        Some("priv" | "authpriv" | "authprivacy") => SecurityLevel::AuthPriv,
        _ => {
            // Infer from the supplied credentials.
            if priv_pass.is_some() {
                SecurityLevel::AuthPriv
            } else if auth_pass.is_some() {
                SecurityLevel::AuthNoPriv
            } else {
                SecurityLevel::NoAuthNoPriv
            }
        }
    };

    Some(V3Args {
        user,
        auth_proto,
        auth_pass,
        priv_proto,
        priv_pass,
        level,
        host,
        port,
    })
}

/// Map an auth-protocol keyword (`MD5`/`SHA`/`SHA-256`) to the enum.
fn parse_auth_proto(s: &str) -> std::result::Result<AuthProtocol, &'static str> {
    match s.to_ascii_uppercase().as_str() {
        "MD5" => Ok(AuthProtocol::HmacMd5),
        "SHA" | "SHA1" => Ok(AuthProtocol::HmacSha1),
        "SHA-256" | "SHA256" => Ok(AuthProtocol::HmacSha256),
        _ => Err("unknown auth protocol"),
    }
}

/// Map a priv-protocol keyword (`AES`) to the enum.
fn parse_priv_proto(s: &str) -> std::result::Result<PrivProtocol, &'static str> {
    match s.to_ascii_uppercase().as_str() {
        "AES" | "AES-128" | "AES128" => Ok(PrivProtocol::AesCfb128),
        _ => Err("unknown priv protocol"),
    }
}

/// Apply a `trapsess [-v 3 ...] HOST [PORT]` (or v2c `trapsess -v 2c -c COMM
/// HOST`) directive. Builds a v3 [`UsmUser`] target when `-v 3` is given,
/// otherwise a community v2c trap target.
fn apply_trapsess(config: &NotifyConfig, d: &Directive) {
    // Peek to decide v3 vs community.
    let is_v3 = d.args.iter().any(|a| {
        (a == "-v" || a == "--version") && {
            // Look at the following token.
            let idx = d.args.iter().position(|x| x == a);
            idx.and_then(|i| d.args.get(i + 1))
                .map(|v| v == "3")
                .unwrap_or(false)
        }
    });

    let name = format!("sess{}", config.targets().len() + 1);

    if is_v3 {
        let Some(parsed) = parse_trapsess(&d.args) else {
            warn!(line = d.line_no, "trapsess: could not parse v3 arguments");
            return;
        };
        let user = match parsed.level {
            SecurityLevel::NoAuthNoPriv => UsmUser::noauth(&parsed.user),
            SecurityLevel::AuthNoPriv => {
                let proto = parsed.auth_proto.unwrap_or(AuthProtocol::HmacSha1);
                let pass = parsed.auth_pass.as_deref().unwrap_or("");
                UsmUser::auth(&parsed.user, proto, pass)
            }
            SecurityLevel::AuthPriv => {
                let proto = parsed.auth_proto.unwrap_or(AuthProtocol::HmacSha1);
                let pass = parsed.auth_pass.as_deref().unwrap_or("");
                let pproto = parsed.priv_proto.unwrap_or(PrivProtocol::AesCfb128);
                let ppass = parsed.priv_pass.as_deref().unwrap_or("");
                UsmUser::auth_priv(&parsed.user, proto, pass, pproto, ppass)
            }
        };
        let sec_level = match parsed.level {
            SecurityLevel::NoAuthNoPriv => 0,
            SecurityLevel::AuthNoPriv => 1,
            SecurityLevel::AuthPriv => 3,
        };
        config.add_params(TargetParams {
            name: name.clone(),
            mp_model: 3,
            security_model: 3,
            security_name: parsed.user.into_bytes(),
            security_level: sec_level,
            usm_user: Some(user),
        });
        let address = normalize_host_port(&parsed.host, parsed.port.as_deref());
        config.add_target(TargetAddr {
            name: name.clone(),
            transport: "udp".to_string(),
            address,
            timeout: Duration::from_secs(5),
            retries: 2,
            params_name: name.clone(),
        });
        config.add_notify(NotifyEntry {
            name: name.clone(),
            tag: name.clone(),
            typ: NotifyType::Trap,
            params_name: name,
        });
    } else {
        // v2c community trapsess: parse -c COMM HOST [PORT].
        let mut community = b"public".to_vec();
        let mut positional: Vec<&str> = Vec::new();
        let mut iter = d.args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-c" | "--community" => {
                    if let Some(c) = iter.next() {
                        community = c.as_bytes().to_vec();
                    }
                }
                "-v" | "--version" => {
                    let _ = iter.next();
                }
                other if other.starts_with('-') => {}
                other => positional.push(other),
            }
        }
        let Some(host) = positional.first().copied() else {
            warn!(line = d.line_no, "trapsess missing HOST");
            return;
        };
        let port = positional.get(1).copied();
        let address = normalize_host_port(host, port);
        config.add_params(TargetParams {
            name: name.clone(),
            mp_model: 1,
            security_model: 2,
            security_name: community,
            security_level: 0,
            usm_user: None,
        });
        config.add_target(TargetAddr {
            name: name.clone(),
            transport: "udp".to_string(),
            address,
            timeout: Duration::from_secs(5),
            retries: 2,
            params_name: name.clone(),
        });
        config.add_notify(NotifyEntry {
            name: name.clone(),
            tag: name.clone(),
            typ: NotifyType::Trap,
            params_name: name,
        });
    }
}

/// Build the engine params an originator stamps into its own v3 traps. A
/// notification originator is itself the authoritative engine (RFC 3414 §4): it
/// does not discover the receiver, but advertises its own engine id. When the
/// agent supplies its real [`EngineParams`], that is used; otherwise a stable
/// default (Net-SNMP enterprise 8072, text "rsnt") is synthesized.
fn notifier_engine(agent_engine: Option<&EngineParams>) -> EngineParams {
    if let Some(e) = agent_engine {
        return e.clone();
    }
    EngineParams {
        engine_id: vec![0x80, 0x00, 0x1f, 0x88, 0x04, b'r', b's', b'n', b't'],
        engine_boots: 1,
        engine_time: 0,
    }
}

/// The notification originator: builds notification PDUs and fans them out to
/// every configured target.
///
/// Holds a shared [`NotifyConfig`] (so the live target/notify MIB tables stay
/// in sync with the dispatch path) and an optional [`EngineParams`] (the
/// agent's authoritative engine, used for v3 traps and as the inform
/// contextEngineID). A [`boot_time`] instant supplies the `sysUpTime.0`
/// TimeTicks value.
///
/// [`boot_time`]: NotificationOriginator::new
#[derive(Debug)]
pub struct NotificationOriginator {
    config: Arc<NotifyConfig>,
    engine: EngineParams,
    boot_time: Instant,
}

impl NotificationOriginator {
    /// Create a new originator. `config` is shared with any live MIB handlers;
    /// `engine` is the agent's authoritative engine params (used to stamp v3
    /// traps); `boot_time` supplies `sysUpTime.0`.
    pub fn new(config: Arc<NotifyConfig>, engine: EngineParams, boot_time: Instant) -> Arc<Self> {
        Arc::new(Self {
            config,
            engine,
            boot_time,
        })
    }

    /// The shared target/notification configuration.
    pub fn config(&self) -> &NotifyConfig {
        &self.config
    }

    /// Whether any targets are configured (i.e. `send` would actually emit).
    pub fn has_targets(&self) -> bool {
        self.config.has_targets()
    }

    /// Send a notification to every configured target.
    ///
    /// Auto-prepends `sysUpTime.0` (the agent's elapsed boot time as
    /// TimeTicks) and `snmpTrapOID.0` (the `trap_oid`) per RFC 3418, then for
    /// each matching notify entry opens a [`Session`] (v1/v2c) or
    /// [`V3Session`](netsnmp::session::V3Session) (v3) to the target address
    /// and sends a Trap or Inform according to [`NotifyType`].
    ///
    /// Errors are logged and swallowed per-target: one dead target must not
    /// stop the others. Returns `Ok(())` as long as the fan-out completed (even
    /// if every individual target failed).
    pub async fn send(&self, trap_oid: &Oid, varbinds: Vec<VarBind>) -> Result<()> {
        if !self.config.has_targets() {
            // No targets configured: nothing to do. This is not an error.
            return Ok(());
        }

        let sys_uptime = (self.boot_time.elapsed().as_millis() / 10) as u32;
        let mut full = Vec::with_capacity(varbinds.len() + 2);
        full.push(VarBind::new(
            Oid::new(SYSUPTIME_OID),
            Value::TimeTicks(sys_uptime),
        ));
        full.push(VarBind::new(
            Oid::new(SNMP_TRAP_OID),
            Value::Oid(trap_oid.clone()),
        ));
        full.extend(varbinds);

        let notifies = self.config.notifies();
        let params = self.config.params();
        let targets = self.config.targets();

        for notify in &notifies {
            // Simple 1:1 tag match: the config directives set the tag equal to
            // the target name, so we look up the target by name.
            let Some(target) = targets.iter().find(|t| t.name == notify.tag) else {
                debug!(
                    notify = %notify.name,
                    tag = %notify.tag,
                    "no target matches notify tag, skipping"
                );
                continue;
            };
            let Some(param) = params.iter().find(|p| p.name == notify.params_name) else {
                debug!(
                    notify = %notify.name,
                    params = %notify.params_name,
                    "no params row for notify, skipping"
                );
                continue;
            };

            if let Err(e) = self
                .send_to_target(target, param, notify.typ, trap_oid, &full)
                .await
            {
                warn!(
                    target = %target.address,
                    notify = %notify.name,
                    error = %e,
                    "failed to send notification to target, continuing"
                );
            }
        }
        Ok(())
    }

    /// Send one notification to one resolved target.
    async fn send_to_target(
        &self,
        target: &TargetAddr,
        param: &TargetParams,
        typ: NotifyType,
        trap_oid: &Oid,
        varbinds: &[VarBind],
    ) -> Result<()> {
        // v3 path: open a notifier V3Session (no discovery) and send.
        if param.mp_model == 3 {
            let Some(user) = &param.usm_user else {
                return Err(Error::Protocol(format!(
                    "v3 target {} has no usm user",
                    target.name
                )));
            };
            let engine = notifier_engine(Some(&self.engine));
            let mut session = netsnmp::session::V3Session::open_udp_notifier(
                &target.address,
                user.clone(),
                engine,
                target.timeout,
                target.retries,
            )
            .await?;
            let varbinds = varbinds.to_vec();
            return match typ {
                NotifyType::Trap => session.send_trap(0, trap_oid, varbinds).await,
                NotifyType::Inform => {
                    let _ = session.send_inform(0, trap_oid, varbinds).await?;
                    Ok(())
                }
            };
        }

        // Community path (v1/v2c).
        let version = if param.mp_model == 0 {
            Version::V1
        } else {
            Version::V2c
        };
        let config = SessionConfig {
            version,
            community: param.security_name.clone(),
            timeout: target.timeout,
            retries: target.retries,
        };
        let session = Session::open_udp(&target.address, config).await?;
        let varbinds = varbinds.to_vec();
        match (typ, version) {
            (NotifyType::Trap, Version::V1) => {
                // v1 Trap-PDU: enterprise = snmpTraps, generic = enterpriseSpecific(6),
                // specific derived from the trap OID's last arc. The v1 trap
                // carries the identity in structured fields rather than a
                // snmpTrapOID varbind, so drop the two leading v2 varbinds.
                let enterprise = Oid::new(netsnmp::trap::SNMP_TRAPS_OID.to_vec());
                let specific = trap_oid.as_slice().last().copied().unwrap_or(0);
                let agent_addr = std::net::Ipv4Addr::new(127, 0, 0, 1);
                let uptime = varbinds
                    .first()
                    .and_then(|vb| match &vb.value {
                        Value::TimeTicks(t) => Some(*t),
                        _ => None,
                    })
                    .unwrap_or(0);
                let extra = varbinds[2..].to_vec();
                session
                    .send_trap_v1(&enterprise, agent_addr, 6, specific, uptime, extra)
                    .await
            }
            (NotifyType::Trap, _) => {
                // v2c Trap: the varbinds already include sysUpTime + snmpTrapOID.
                // Session::send_trap prepends them again, so strip the two we added.
                let sys_uptime = varbinds
                    .first()
                    .and_then(|vb| match &vb.value {
                        Value::TimeTicks(t) => Some(*t),
                        _ => None,
                    })
                    .unwrap_or(0);
                let extra = varbinds[2..].to_vec();
                session.send_trap(sys_uptime, trap_oid, extra).await
            }
            (NotifyType::Inform, _) => {
                let sys_uptime = varbinds
                    .first()
                    .and_then(|vb| match &vb.value {
                        Value::TimeTicks(t) => Some(*t),
                        _ => None,
                    })
                    .unwrap_or(0);
                let extra = varbinds[2..].to_vec();
                let _ = session.send_inform(sys_uptime, trap_oid, extra).await?;
                Ok(())
            }
        }
    }

    /// Send the standard `coldStart` trap (`1.3.6.1.6.3.1.1.5.1`) with no extra
    /// varbinds. Convenience wrapper around [`Self::send`].
    pub async fn send_cold_start(&self) -> Result<()> {
        self.send(&Oid::new(COLD_START_OID.to_vec()), Vec::new())
            .await
    }

    /// Send the standard `warmStart` trap (`1.3.6.1.6.3.1.1.5.2`) with no extra
    /// varbinds. Convenience wrapper around [`Self::send`].
    pub async fn send_warm_start(&self) -> Result<()> {
        self.send(&Oid::new(WARM_START_OID.to_vec()), Vec::new())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::{ReceivedNotification, TrapReceiver, TrapReceiverConfig};
    use netsnmp::config::parse_str;
    use netsnmp::message::Message;
    use netsnmp::pdu::PduType;
    use netsnmp::trap;

    /// A minimal in-process trap receiver used by the originator send test.
    async fn spawn_receiver() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<ReceivedNotification>>>,
    ) {
        let config = TrapReceiverConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            community: Some(b"public".to_vec()),
            ..TrapReceiverConfig::default()
        };
        let receiver = TrapReceiver::new(config);
        let socket = receiver.bind().await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        let collected: std::sync::Arc<std::sync::Mutex<Vec<ReceivedNotification>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = collected.clone();
        tokio::spawn(async move {
            let _ = receiver
                .serve_on(socket, move |note, _peer| {
                    sink.lock().unwrap().push(note.clone());
                })
                .await;
        });
        (addr, collected)
    }

    #[test]
    fn from_config_directives_parses_trap2sink() {
        let dirs = parse_str("trap2sink 127.0.0.1 public\n");
        let config = NotifyConfig::from_config_directives(&dirs);
        assert_eq!(config.targets().len(), 1);
        assert_eq!(config.params().len(), 1);
        assert_eq!(config.notifies().len(), 1);
        let t = &config.targets()[0];
        assert_eq!(t.address, "127.0.0.1:162");
        assert_eq!(t.transport, "udp");
        let p = &config.params()[0];
        assert_eq!(p.mp_model, 1);
        assert_eq!(p.security_model, 2);
        assert_eq!(p.security_name, b"public");
        let n = &config.notifies()[0];
        assert_eq!(n.typ, NotifyType::Trap);
    }

    #[test]
    fn from_config_directives_parses_trapsink_v1() {
        let dirs = parse_str("trapsink 127.0.0.1 public 1162\n");
        let config = NotifyConfig::from_config_directives(&dirs);
        let t = &config.targets()[0];
        assert_eq!(t.address, "127.0.0.1:1162");
        let p = &config.params()[0];
        assert_eq!(p.mp_model, 0);
        assert_eq!(p.security_model, 1);
        let n = &config.notifies()[0];
        assert_eq!(n.typ, NotifyType::Trap);
    }

    #[test]
    fn from_config_directives_parses_informsink() {
        let dirs = parse_str("informsink 127.0.0.1 public\n");
        let config = NotifyConfig::from_config_directives(&dirs);
        let n = &config.notifies()[0];
        assert_eq!(n.typ, NotifyType::Inform);
    }

    #[test]
    fn from_config_directives_parses_trapsess_v3() {
        let dirs = parse_str(
            "trapsess -v 3 -u alice -a SHA -A authpass -x AES -X privpass -l authPriv 127.0.0.1\n",
        );
        let config = NotifyConfig::from_config_directives(&dirs);
        assert_eq!(config.targets().len(), 1);
        let p = &config.params()[0];
        assert_eq!(p.mp_model, 3);
        assert_eq!(p.security_model, 3);
        assert_eq!(p.security_name, b"alice");
        assert_eq!(p.security_level, 3);
        let user = p.usm_user.as_ref().expect("usm user");
        assert_eq!(user.name, "alice");
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
    }

    #[test]
    fn from_config_directives_parses_trapsess_v2c() {
        let dirs = parse_str("trapsess -v 2c -c secret 127.0.0.1 1162\n");
        let config = NotifyConfig::from_config_directives(&dirs);
        let p = &config.params()[0];
        assert_eq!(p.mp_model, 1);
        assert_eq!(p.security_name, b"secret");
        assert!(p.usm_user.is_none());
    }

    #[tokio::test]
    async fn send_delivers_v2c_trap_to_receiver() {
        let (addr, collected) = spawn_receiver().await;
        let config = NotifyConfig::new();
        config.add_params(TargetParams {
            name: "t".to_string(),
            mp_model: 1,
            security_model: 2,
            security_name: b"public".to_vec(),
            security_level: 0,
            usm_user: None,
        });
        config.add_target(TargetAddr {
            name: "t".to_string(),
            transport: "udp".to_string(),
            address: addr,
            timeout: Duration::from_secs(2),
            retries: 1,
            params_name: "t".to_string(),
        });
        config.add_notify(NotifyEntry {
            name: "t".to_string(),
            tag: "t".to_string(),
            typ: NotifyType::Trap,
            params_name: "t".to_string(),
        });
        let originator = NotificationOriginator::new(
            config,
            notifier_engine(None),
            Instant::now(),
        );
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        originator
            .send(&trap_oid, Vec::new())
            .await
            .expect("send succeeds");

        // Wait for delivery (trap is fire-and-forget).
        for _ in 0..200 {
            if !collected.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let got = collected.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].notification.trap_oid, trap_oid);
        // sysUpTime + snmpTrapOID are the two mandatory varbinds; no extras.
        assert!(got[0].notification.sys_uptime <= 600);
    }

    /// Sanity-check that a v2c trap built via the originator's varbind list is
    /// decodable by the receiver's community path (mirrors the wire format the
    /// `send` path produces).
    #[test]
    fn v2c_trap_wire_roundtrips() {
        let pdu = trap::build_notification(
            PduType::TrapV2,
            1,
            4242,
            &"1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            Vec::new(),
        )
        .unwrap();
        let msg = Message::new(Version::V2c, b"public".to_vec(), pdu);
        let bytes = msg.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        let note = trap::parse_notification(&back.pdu).unwrap();
        assert_eq!(note.sys_uptime, 4242);
    }
}
