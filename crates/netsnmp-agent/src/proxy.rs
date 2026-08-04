//! Proxy forwarder (RFC 3413 §1).
//!
//! Counterpart of `agent/mibgroup/agentx/proxy_handler.c` (the Net-SNMP
//! `proxy` directive). A [`ProxyForwarder`] is a [`MibHandler`] that serves a
//! configured subtree by forwarding each GET/GETNEXT/SET to another SNMP agent
//! over a fresh [`Session`](netsnmp::Session) (SNMPv1/v2c) or
//! [`V3Session`](netsnmp::V3Session) (SNMPv3/USM).
//!
//! # Mapping
//!
//! The proxy subtree prefix registered with the [`Registry`](crate::Registry)
//! need not match the OIDs served by the target — usually the same OID is
//! forwarded verbatim. `contextEngineID` rewriting per RFC 3413 §1 is optional
//! and not performed by default; the target's own engine id is used.
//!
//! # Performance
//!
//! A new [`Session`] is opened per request. This is the simplest design and is
//! cheap for UDP (one socket per request), but it does incur a connect syscall
//! and, for v3, a full engine-discovery exchange per request. Caching the
//! session across requests is a future optimization; the per-request open keeps
//! the code simple and avoids lifetime/state-management hazards when the target
//! restarts.
//!
//! # Sync/async bridge
//!
//! [`MibHandler`] methods are synchronous, but forwarding requires async
//! network IO. The handler bridges this with
//! `tokio::task::block_in_place` + `Handle::current().block_on`, which is safe
//! on the multi-threaded tokio runtime the agent runs under. Calling a proxy
//! handler from a single-threaded runtime (or from outside a runtime) will
//! panic — the agent must run under `#[tokio::main]` (the default) or a
//! multi-threaded [`tokio::runtime::Runtime`].

use std::sync::Arc;
use std::time::Duration;

use netsnmp::config::Directive;
use netsnmp::message::Version;
use netsnmp::oid::Oid;
use netsnmp::pdu::{ErrorStatus, VarBind};
use netsnmp::session::{Session, SessionConfig};
use netsnmp::usm::UsmUser;
use netsnmp::value::Value;

use crate::handler::{MibHandler, Reading};
use crate::registry::Registry;

/// SNMPv3/USM forwarding configuration. When set on a [`ProxyForwarder`], the
/// proxy opens a [`V3Session`](netsnmp::V3Session) to the target instead of a
/// community [`Session`].
#[derive(Clone, Debug)]
pub struct V3Config {
    /// The USM user to authenticate as (localized to the target's engine id
    /// during discovery).
    pub user: UsmUser,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Number of retries after the first attempt.
    pub retries: u32,
}

/// A MIB handler that forwards requests to another SNMP agent (RFC 3413).
///
/// See the [module docs](self) for the sync/async bridge and performance notes.
pub struct ProxyForwarder {
    root: Oid,
    target_addr: String,
    community: Vec<u8>,
    version: Version,
    #[allow(dead_code)]
    context: Option<String>,
    snmpv3: Option<V3Config>,
}

impl std::fmt::Debug for ProxyForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyForwarder")
            .field("root", &self.root)
            .field("target_addr", &self.target_addr)
            .field("version", &self.version)
            .field("community", &String::from_utf8_lossy(&self.community))
            .field("has_v3", &self.snmpv3.is_some())
            .finish()
    }
}

impl ProxyForwarder {
    /// Create a v1/v2c proxy forwarder rooted at `root` that forwards to
    /// `target_addr` (host:port) using `community`.
    pub fn new(root: Oid, target_addr: String, community: Vec<u8>) -> Self {
        ProxyForwarder {
            root,
            target_addr,
            community,
            version: Version::V2c,
            context: None,
            snmpv3: None,
        }
    }

    /// Create a v2c proxy with an explicit community version.
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Attach an SNMPv3/USM forwarding configuration. When set, the proxy opens
    /// a [`V3Session`](netsnmp::V3Session) and performs engine discovery
    /// against the target per request (heavier than v2c; see the module docs).
    pub fn with_v3(mut self, v3: V3Config) -> Self {
        self.snmpv3 = Some(v3);
        self
    }

    /// Attach a context name (RFC 3413 `proxy -Cn CONTEXT`). The context is
    /// recorded for diagnostics; contextEngineID rewriting is not performed.
    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    /// The target agent address.
    pub fn target_addr(&self) -> &str {
        &self.target_addr
    }

    /// Parse `proxy` directives into proxy forwarders.
    ///
    /// Syntax (mirrors the Net-SNMP `proxy` directive):
    /// ```text
    /// proxy [-Cn CONTEXT] COMMUNITY HOST [OID]
    /// ```
    /// `OID` defaults to `1.3.6.1` (the `internet` subtree) when omitted. Only
    /// `proxy` directives are consumed; others are ignored.
    pub fn from_directives(directives: &[Directive]) -> Vec<Self> {
        let mut out = Vec::new();
        for d in directives {
            if !d.is("proxy") {
                continue;
            }
            let args = &d.args;
            let mut idx = 0;
            let mut context: Option<String> = None;
            // Optional -Cn CONTEXT
            if args.get(idx).map(|s| s.as_str()) == Some("-Cn") {
                if let Some(ctx) = args.get(idx + 1) {
                    context = Some(ctx.clone());
                    idx += 2;
                }
            }
            let (Some(community), Some(host), oid) =
                (args.get(idx), args.get(idx + 1), args.get(idx + 2))
            else {
                // Malformed; skip.
                continue;
            };
            let root = oid
                .and_then(|o| o.parse::<Oid>().ok())
                .unwrap_or_else(|| Oid::new(vec![1, 3, 6, 1]));
            let mut pf = ProxyForwarder::new(root, host.clone(), community.as_bytes().to_vec());
            if let Some(ctx) = context {
                pf = pf.with_context(ctx);
            }
            out.push(pf);
        }
        out
    }

    /// Warn if a new proxy subtree overlaps an existing registration.
    ///
    /// Returns `Err(message)` describing the overlap when `new_root` is a
    /// prefix of, or is prefixed by, any `existing` OID; otherwise `Ok(())`.
    /// The caller (e.g. `snmpd`) logs the warning and may skip registration.
    pub fn check_conflicts(existing: &[Oid], new_root: &Oid) -> std::result::Result<(), String> {
        for e in existing {
            if e.is_prefix_of(new_root) || new_root.is_prefix_of(e) {
                return Err(format!(
                    "proxy subtree {new_root} overlaps existing registration {e}"
                ));
            }
        }
        Ok(())
    }

    /// Bridge a sync handler call into the async session layer. Panics if not
    /// running on a multi-threaded tokio runtime (the agent's default).
    fn block_on<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(fut)
        })
    }

    /// Open a v2c session to the target with the proxy's short timeout.
    fn open_v2c(&self) -> netsnmp::error::Result<Session> {
        let config = SessionConfig {
            version: self.version,
            community: self.community.clone(),
            timeout: Duration::from_secs(2),
            retries: 1,
        };
        // open_udp is async; bridge it.
        Self::block_on(Session::open_udp(&self.target_addr, config))
    }

    /// Forward a GET for a single OID, returning the value (or `None` on any
    /// error / missing instance).
    fn forward_get(&self, oid: &Oid) -> Option<Value> {
        if let Some(v3) = &self.snmpv3 {
            let mut session = Self::block_on(netsnmp::session::V3Session::open_udp(
                &self.target_addr,
                v3.user.clone(),
                v3.timeout,
                v3.retries,
            ))
            .ok()?;
            let value = Self::block_on(session.get_one(oid)).ok()?;
            // NoSuchObject / NoSuchInstance are distinct exceptions, not real values.
            match value {
                Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => None,
                v => Some(v),
            }
        } else {
            let session = self.open_v2c().ok()?;
            let value = Self::block_on(session.get_one(oid)).ok()?;
            match value {
                Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => None,
                v => Some(v),
            }
        }
    }

    /// Forward a GETNEXT for a single OID, returning the successor reading.
    fn forward_get_next(&self, oid: &Oid) -> Option<Reading> {
        let vars = if let Some(v3) = &self.snmpv3 {
            let mut session = Self::block_on(netsnmp::session::V3Session::open_udp(
                &self.target_addr,
                v3.user.clone(),
                v3.timeout,
                v3.retries,
            ))
            .ok()?;
            Self::block_on(session.get_next(std::slice::from_ref(oid))).ok()?
        } else {
            let session = self.open_v2c().ok()?;
            Self::block_on(session.get_next(std::slice::from_ref(oid))).ok()?
        };
        let vb = vars.into_iter().next()?;
        match vb.value {
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => None,
            _ => Some(Reading {
                oid: vb.oid,
                value: vb.value,
            }),
        }
    }

    /// Forward a SET for a single (oid, value), returning `Ok(())` on success.
    fn forward_set(&self, oid: &Oid, value: &Value) -> std::result::Result<(), ErrorStatus> {
        let result = if let Some(v3) = &self.snmpv3 {
            let mut session = Self::block_on(netsnmp::session::V3Session::open_udp(
                &self.target_addr,
                v3.user.clone(),
                v3.timeout,
                v3.retries,
            ))
            .map_err(|_| ErrorStatus::GenErr)?;
            Self::block_on(session.set(vec![VarBind::new(oid.clone(), value.clone())]))
                .map(|_| ())
        } else {
            let session = self.open_v2c().map_err(|_| ErrorStatus::GenErr)?;
            Self::block_on(session.set(vec![VarBind::new(oid.clone(), value.clone())]))
                .map(|_| ())
        };
        result.map_err(|_| ErrorStatus::GenErr)
    }
}

impl MibHandler for ProxyForwarder {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.forward_get(oid)
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        self.forward_get_next(oid)
    }

    fn set(&self, oid: &Oid, value: &Value) -> std::result::Result<(), ErrorStatus> {
        self.forward_set(oid, value)
    }
}

/// Register a set of [`ProxyForwarder`]s into a [`Registry`]. Each forwarder is
/// wrapped in an [`Arc`] and registered by its root OID. Subtree conflicts are
/// not re-checked here (use [`ProxyForwarder::check_conflicts`] beforehand).
pub fn register_proxy_mibs(registry: &mut Registry, proxies: Vec<ProxyForwarder>) {
    for pf in proxies {
        registry.register(Arc::new(pf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::ScalarHandler;
    use netsnmp::value::Value;

    /// Spawn a minimal in-process agent serving a single scalar under
    /// `1.3.6.1.4.1.9999` and return its bound loopback address.
    async fn spawn_target_agent() -> String {
        let mut reg = Registry::new();
        reg.register(Arc::new(ScalarHandler::new(
            "1.3.6.1.4.1.9999".parse().unwrap(),
            Value::OctetString(b"proxied-value".to_vec()),
        )));
        let config = crate::agent::AgentConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            community: b"public".to_vec(),
            ..crate::agent::AgentConfig::default()
        };
        let agent = crate::agent::Agent::new(reg, config);
        let socket = agent.bind().await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let _ = agent.serve_on(socket).await;
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_get_forwards_to_target() {
        let target_addr = spawn_target_agent().await;
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let pf = ProxyForwarder::new(root.clone(), target_addr, b"public".to_vec());
        // The instance served is root.0.
        let instance = root.child(0);
        let value = pf.get(&instance);
        assert_eq!(value, Some(Value::OctetString(b"proxied-value".to_vec())));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_get_next_forwards_to_target() {
        let target_addr = spawn_target_agent().await;
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let pf = ProxyForwarder::new(root.clone(), target_addr, b"public".to_vec());
        // GETNEXT from below the instance should return root.0.
        let reading = pf.get_next(&root).expect("a successor");
        assert_eq!(reading.oid, root.child(0));
        assert_eq!(reading.value, Value::OctetString(b"proxied-value".to_vec()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_get_returns_none_for_missing_instance() {
        let target_addr = spawn_target_agent().await;
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let pf = ProxyForwarder::new(root.clone(), target_addr, b"public".to_vec());
        // Instance .5 does not exist on the target.
        assert!(pf.get(&root.child(5)).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_get_returns_none_for_unreachable_target() {
        // A port that is almost certainly closed.
        let root: Oid = "1.3.6.1.4.1.9999".parse().unwrap();
        let pf = ProxyForwarder::new(root.clone(), "127.0.0.1:9".to_string(), b"public".to_vec());
        // Port 9 (discard) won't reply to SNMP; the request times out -> None.
        assert!(pf.get(&root.child(0)).is_none());
    }

    #[test]
    fn check_conflicts_detects_overlap() {
        let existing: Vec<Oid> = vec!["1.3.6.1.4.1.9999".parse().unwrap()];
        // New root is a prefix of an existing registration.
        let new_root: Oid = "1.3.6.1.4.1".parse().unwrap();
        assert!(ProxyForwarder::check_conflicts(&existing, &new_root).is_err());
        // New root is nested under an existing registration.
        let new_root: Oid = "1.3.6.1.4.1.9999.1".parse().unwrap();
        assert!(ProxyForwarder::check_conflicts(&existing, &new_root).is_err());
    }

    #[test]
    fn check_conflicts_passes_for_disjoint() {
        let existing: Vec<Oid> = vec!["1.3.6.1.4.1.9999".parse().unwrap()];
        let new_root: Oid = "1.3.6.1.4.1.8888".parse().unwrap();
        assert!(ProxyForwarder::check_conflicts(&existing, &new_root).is_ok());
    }

    #[test]
    fn from_directives_parses_proxy_lines() {
        let directives = vec![
            Directive {
                token: "proxy".to_string(),
                args: vec![
                    "public".to_string(),
                    "127.0.0.1:2161".to_string(),
                    "1.3.6.1.4.1.9999".to_string(),
                ],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 0,
            },
            Directive {
                token: "proxy".to_string(),
                args: vec![
                    "-Cn".to_string(),
                    "ctx".to_string(),
                    "private".to_string(),
                    "127.0.0.1:3161".to_string(),
                ],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 1,
            },
            Directive {
                token: "rocommunity".to_string(),
                args: vec!["public".to_string()],
                rest: String::new(),
                section: None,
                source: None,
                line_no: 2,
            },
        ];
        let proxies = ProxyForwarder::from_directives(&directives);
        assert_eq!(proxies.len(), 2);
        assert_eq!(
            proxies[0].root().to_string(),
            ".1.3.6.1.4.1.9999"
        );
        assert_eq!(proxies[0].target_addr(), "127.0.0.1:2161");
        // The second has a context and defaults the OID to 1.3.6.1.
        assert_eq!(proxies[1].root().to_string(), ".1.3.6.1");
        assert_eq!(proxies[1].context.as_deref(), Some("ctx"));
    }
}
