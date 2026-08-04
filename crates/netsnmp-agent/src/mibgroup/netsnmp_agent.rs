//! NET-SNMP-AGENT-MIB (`1.3.6.1.4.1.8072.1`) self-management objects.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/agent/` modules
//! (`agent/nsCache.c`, `agent/nsDebug.c`, `agent/nsLogging.c`,
//! `agent/nsModuleTable.c`, `agent/nsTransactionTable.c`,
//! `agent/nsVacmAccessTable.c`). These objects let a manager inspect — and, for
//! a few columns, tune — the running agent's internal state: which subsystem
//! caches are enabled and at what TTL, which MIB handlers are registered, what
//! debug/logging is configured, and the (short-lived) SET transactions in
//! flight.
//!
//! The subtree is split across several handlers so each table is served
//! independently and GETNEXT walks them in OID order:
//!
//! | Group / object        | OID                        | Source               |
//! |-----------------------|----------------------------|----------------------|
//! | `nsCacheEnabled.0`    | `8072.1.6.1.0`             | [`NsCacheState`]     |
//! | `nsCacheTable`        | `8072.1.6.2.1`             | [`NsCacheState`]     |
//! | `nsConfigDebug.0`     | `8072.1.3.1.0`             | constant             |
//! | `nsDebugEnabled.0`    | `8072.1.3.2.0`             | constant             |
//! | `nsDebugOutputTable`  | `8072.1.3.4.1`             | empty                |
//! | `nsConfigLogging.0`   | `8072.1.7.1.0`             | constant             |
//! | `nsLoggingTable`      | `8072.1.7.2.1`             | empty                |
//! | `nsModuleTable`       | `8072.1.5.1`               | handler snapshot     |
//! | `nsTransactionTable`  | `8072.1.8.1`               | empty                |
//! | `nsVacmAccessTable`   | `8072.1.9.1`               | empty                |
//!
//! All objects are read-only except `nsCacheTimeout.<module>`, which is writable
//! so a manager can tune a subsystem's cache TTL (see [`NsCacheState`]).
//!
//! # Linkage to the cache helper
//!
//! [`crate::helpers::CacheHandler`] owns its TTL privately and rebuilds its
//! snapshot on expiry. There is no global registry of live `CacheHandler`
//! instances, so this module cannot retroactively push a new TTL into an
//! already-constructed handler. Instead the linkage is **pull-based and
//! opt-in**: a subsystem that wants its cache to honor `nsCacheTimeout` should
//! build its [`crate::helpers::CacheHandler`] with a closure that reads the TTL
//! from the shared [`NsCacheState`] on each snapshot rebuild, e.g. by naming the
//! module in [`NsCacheState::set_ttl`] and consulting [`NsCacheState::ttl`] for
//! that name inside the provider closure. A SET of `nsCacheTimeout.<module>`
//! then takes effect on the handler's next cache refresh, exactly as in the C
//! agent where `nsCache` is a thin control plane over the same
//! `cache_handler.c` TTL.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;

use crate::handler::{MibHandler, Reading};
use crate::scalar::FnHandler;

// --- nsCache (nsAgent 6) -------------------------------------------------

/// `nsCache` group root: `8072.1.6`.
const NS_CACHE: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 6];
/// `nsCacheEnabled` scalar: `8072.1.6.1.0`.
const NS_CACHE_ENABLED: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 6, 1];
/// `nsCacheEntry` (nsCacheTable): `8072.1.6.2.1`.
const NS_CACHE_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1];

// nsCacheTable columns (NET-SNMP-AGENT-MIB::nsCacheEntry).
/// `nsCacheTimeout` (col 2): the cache TTL in seconds. Writable.
const NS_CACHE_TIMEOUT: u32 = 2;
/// `nsCacheStatus` (col 3): RowStatus, reported `active(1)`.
const NS_CACHE_STATUS: u32 = 3;

// --- nsDebug (nsAgent 3) -------------------------------------------------

/// `nsConfigDebug.0`: `8072.1.3.1.0` (a DisplayString summary).
const NS_CONFIG_DEBUG: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 3, 1];
/// `nsDebugEnabled.0`: `8072.1.3.2.0` (TruthValue).
const NS_DEBUG_ENABLED: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 3, 2];
/// `nsDebugOutputEntry`: `8072.1.3.4.1`.
const NS_DEBUG_OUTPUT_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 3, 4, 1];

// --- nsLogging (nsAgent 7) -----------------------------------------------

/// `nsConfigLogging.0`: `8072.1.7.1.0`.
const NS_CONFIG_LOGGING: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 7, 1];
/// `nsLoggingEntry` (nsLoggingTable): `8072.1.7.2.1`.
const NS_LOGGING_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 7, 2, 1];

// --- nsModuleTable (nsAgent 5) -------------------------------------------

/// `nsModuleEntry` (nsModuleTable): `8072.1.5.1`.
const NS_MODULE_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 5, 1];
// nsModuleTable columns.
/// `nsModuleOID` (col 1): the registered handler's root OID.
const NS_MODULE_OID: u32 = 1;
/// `nsModuleName` (col 2): a textual name for the module.
const NS_MODULE_NAME: u32 = 2;

// --- nsTransactionTable (nsAgent 8) --------------------------------------

/// `nsTransactionEntry`: `8072.1.8.1`.
const NS_TRANSACTION_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 8, 1];

// --- nsVacmAccessTable (nsAgent 9) ---------------------------------------

/// `nsVacmAccessEntry`: `8072.1.9.1`.
const NS_VACM_ACCESS_ENTRY: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1, 9, 1];

/// The `RowStatus` value reported for active rows: `active(1)`.
const STATUS_ACTIVE: i64 = 1;
/// The conventional `TruthValue::false(2)` and `TruthValue::true(1)`.
const TV_TRUE: i64 = 1;
const TV_FALSE: i64 = 2;

/// Shared, mutable state backing the `nsCache` group.
///
/// Holds the global `nsCacheEnabled` flag (an [`AtomicBool`] surfaced as a
/// `TruthValue`) and a per-module cache-TTL map (the `nsCacheTable`). A
/// subsystem registers a named module's TTL via [`NsCacheState::set_ttl`]; that
/// row then becomes walkable through `nsCacheTable`, and a manager can adjust
/// the TTL in seconds with a SET of `nsCacheTimeout.<module>`.
///
/// Construct one with [`NsCacheState::new`] and pass it to
/// [`ns_cache_handlers`] to install the `nsCache` MIB objects. The same
/// `Arc<NsCacheState>` should be consulted by any [`crate::helpers::CacheHandler`]
/// that wishes to honor a manager-tuned TTL (see the module-level docs for the
/// pull-based linkage).
pub struct NsCacheState {
    enabled: AtomicBool,
    ttls: RwLock<HashMap<String, Duration>>,
}

impl std::fmt::Debug for NsCacheState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let enabled = self.enabled.load(Ordering::Relaxed);
        let n = self.ttls.read().unwrap_or_else(|e| e.into_inner()).len();
        f.debug_struct("NsCacheState")
            .field("enabled", &enabled)
            .field("modules", &n)
            .finish()
    }
}

impl NsCacheState {
    /// Create an empty cache state. Caching is enabled by default (matching the
    /// C agent, where `nsCacheEnabled` defaults to `true`), and no per-module
    /// TTLs are registered yet.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::with_enabled(true))
    }

    /// Create an empty cache state with the given initial `enabled` flag.
    pub fn with_enabled(enabled: bool) -> Self {
        NsCacheState {
            enabled: AtomicBool::new(enabled),
            ttls: RwLock::new(HashMap::new()),
        }
    }

    /// Whether the global `nsCacheEnabled` flag is set.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Set the global `nsCacheEnabled` flag (the `nsCacheEnabled.0` scalar).
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Register or replace the TTL for module `name`. The module becomes a row
    /// in `nsCacheTable`; its `nsCacheTimeout` column reports `ttl` in seconds.
    /// A [`crate::helpers::CacheHandler`] wishing to honor this value should read
    /// it back via [`NsCacheState::ttl`] inside its provider closure.
    pub fn set_ttl(&self, name: impl Into<String>, ttl: Duration) {
        let mut ttls = self.ttls.write().unwrap_or_else(|e| e.into_inner());
        ttls.insert(name.into(), ttl);
    }

    /// Remove a module's TTL row. The module disappears from `nsCacheTable`.
    /// Returns the removed TTL, if any.
    pub fn remove_ttl(&self, name: &str) -> Option<Duration> {
        let mut ttls = self.ttls.write().unwrap_or_else(|e| e.into_inner());
        ttls.remove(name)
    }

    /// Look up the TTL currently registered for module `name`. Returns the
    /// provided `default` when the module has no row, so cache providers can
    /// fall back to their built-in TTL.
    pub fn ttl(&self, name: &str, default: Duration) -> Duration {
        let ttls = self.ttls.read().unwrap_or_else(|e| e.into_inner());
        ttls.get(name).copied().unwrap_or(default)
    }

    /// A snapshot of every `(module, ttl)` pair currently registered, sorted by
    /// module name for stable `nsCacheTable` walks.
    fn modules(&self) -> Vec<(String, Duration)> {
        let ttls = self.ttls.read().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<(String, Duration)> = ttls
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Build the `nsCacheEnabled.0` + `nsCacheTable` cells for the current
    /// state. The `nsCacheEnabled` scalar is emitted at its instance OID; each
    /// module row contributes a `nsCacheTimeout` (writable) and a `nsCacheStatus`
    /// cell. INDEX is the module name (length-prefixed OCTET STRING).
    fn cells(&self) -> Vec<(Oid, Value)> {
        let mut cells = Vec::new();

        // nsCacheEnabled.0
        let enabled_oid = Oid::new(NS_CACHE_ENABLED.to_vec()).child(0);
        let enabled_val = if self.enabled() {
            Value::Integer(TV_TRUE)
        } else {
            Value::Integer(TV_FALSE)
        };
        cells.push((enabled_oid, enabled_val));

        // nsCacheTable rows.
        let entry = Oid::new(NS_CACHE_ENTRY.to_vec());
        for (name, ttl) in self.modules() {
            let idx = string_index(name.as_bytes());
            let timeout_oid = {
                let mut p = entry.as_slice().to_vec();
                p.push(NS_CACHE_TIMEOUT);
                p.extend_from_slice(&idx);
                Oid::new(p)
            };
            let status_oid = {
                let mut p = entry.as_slice().to_vec();
                p.push(NS_CACHE_STATUS);
                p.extend_from_slice(&idx);
                Oid::new(p)
            };
            // TTL is reported in seconds (NET-SNMP-AGENT-MIB defines
            // nsCacheTimeout as Integer32 seconds).
            cells.push((timeout_oid, Value::Integer(ttl.as_secs() as i64)));
            cells.push((status_oid, Value::Integer(STATUS_ACTIVE)));
        }

        cells
    }
}

impl Default for NsCacheState {
    fn default() -> Self {
        Self::with_enabled(true)
    }
}

/// How long the cache-handler snapshot is reused before rebuilding, mirroring
/// [`crate::scalar::FnHandler`]'s internal TTL so walks of `nsCacheTable` stay
/// cheap without going stale for long.
const SNAPSHOT_TTL: Duration = Duration::from_millis(900);

/// Encode a variable-length OCTET STRING index (length-prefixed), matching the
/// non-IMPLIED INDEX encoding used by these tables.
fn string_index(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u32);
    out.extend(bytes.iter().map(|&b| b as u32));
    out
}

/// A cache-state handler that also accepts SETs on `nsCacheTimeout.<module>`.
///
/// This wraps a shared [`NsCacheState`] and, in addition to serving the
/// `nsCacheEnabled` scalar and the read-only `nsCacheStatus` column, accepts
/// SETs on `nsCacheTimeout.<module>` (column 2) to adjust the named module's
/// TTL in seconds. The TTL is stored as `Duration` (whole seconds; any
/// fractional seconds from the SET are truncated).
struct NsCacheHandler {
    root: Oid,
    state: Arc<NsCacheState>,
    cache: std::sync::Mutex<Option<(std::time::Instant, Arc<Vec<(Oid, Value)>>)>>,
    provider: Box<dyn Fn() -> Vec<(Oid, Value)> + Send + Sync>,
}

impl NsCacheHandler {
    fn new(state: Arc<NsCacheState>) -> Self {
        let root = Oid::new(NS_CACHE.to_vec());
        let for_provider = Arc::clone(&state);
        NsCacheHandler {
            root,
            state,
            cache: std::sync::Mutex::new(None),
            provider: Box::new(move || for_provider.cells()),
        }
    }

    fn snapshot(&self) -> Arc<Vec<(Oid, Value)>> {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = guard
            .as_ref()
            .filter(|(built, _)| built.elapsed() < SNAPSHOT_TTL)
            .map(|(_, cells)| Arc::clone(cells));
        if let Some(cells) = fresh {
            return cells;
        }
        let mut cells = (self.provider)();
        cells.sort_by(|a, b| a.0.cmp(&b.0));
        let cells = Arc::new(cells);
        *guard = Some((std::time::Instant::now(), Arc::clone(&cells)));
        cells
    }

    /// Decode a `nsCacheTimeout.<module>` instance OID into its module name,
    /// provided the OID is the timeout column (col 2) of `nsCacheEntry`.
    fn decode_module_from_timeout(&self, oid: &Oid) -> Option<String> {
        let entry = Oid::new(NS_CACHE_ENTRY.to_vec());
        let prefix = entry.as_slice();
        let tail = oid.as_slice();
        if tail.len() <= prefix.len() + 1 || tail[..prefix.len()] != *prefix {
            return None;
        }
        if tail[prefix.len()] != NS_CACHE_TIMEOUT {
            return None;
        }
        let idx = &tail[prefix.len() + 1..];
        decode_string_index(idx)
    }
}

/// Decode a length-prefixed OCTET STRING index back into a String.
fn decode_string_index(idx: &[u32]) -> Option<String> {
    if idx.is_empty() {
        return None;
    }
    let len = idx[0] as usize;
    if idx.len() != len + 1 {
        return None;
    }
    let bytes: Vec<u8> = idx[1..].iter().map(|&v| v as u8).collect();
    String::from_utf8(bytes).ok()
}

impl MibHandler for NsCacheHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        let cells = self.snapshot();
        cells
            .binary_search_by(|(o, _)| o.cmp(oid))
            .ok()
            .map(|i| cells[i].1.clone())
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let cells = self.snapshot();
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, value)| Reading {
            oid: o.clone(),
            value: value.clone(),
        })
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        // Only nsCacheTimeout.<module> is writable.
        match self.decode_module_from_timeout(oid) {
            Some(_) => {}
            None => return Err(ErrorStatus::NotWritable),
        }
        // nsCacheTimeout is Integer32 seconds.
        match value {
            Value::Integer(secs) if *secs >= 0 => Ok(()),
            _ => Err(ErrorStatus::WrongType),
        }
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        let module = match self.decode_module_from_timeout(oid) {
            Some(m) => m,
            None => return Err(ErrorStatus::NotWritable),
        };
        let secs = match value {
            Value::Integer(s) => *s,
            _ => return Err(ErrorStatus::WrongType),
        };
        self.state
            .set_ttl(module, Duration::from_secs(secs.max(0) as u64));
        // Invalidate the local cell cache so the new TTL is visible at once.
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
        Ok(())
    }
}

/// Build the `nsCache` group handlers (`nsCacheEnabled.0` + `nsCacheTable`)
/// backed by the shared `state`.
///
/// The returned handlers cover the `1.3.6.1.4.1.8072.1.6` subtree. The single
/// [`NsCacheHandler`] serves both the enabled scalar and the table, and accepts
/// SETs on `nsCacheTimeout.<module>` (column 2 of `nsCacheEntry`) to tune a
/// module's TTL in seconds — adjusting the same [`NsCacheState`] that a
/// [`crate::helpers::CacheHandler`] should consult.
pub fn ns_cache_handlers(state: Arc<NsCacheState>) -> Vec<Arc<dyn MibHandler>> {
    vec![Arc::new(NsCacheHandler::new(state))]
}

/// Build the `nsDebug` group handlers (`nsConfigDebug.0`, `nsDebugEnabled.0`
/// and an empty `nsDebugOutputTable`).
///
/// `nsConfigDebug.0` reports a short summary string; `nsDebugEnabled.0` reports
/// `TruthValue::false(2)` (the agent does not honour a global debug flag at
/// present). All objects are read-only.
pub fn ns_debug_handlers() -> Vec<Arc<dyn MibHandler>> {
    vec![
        Arc::new(FnHandler::scalar(
            Oid::new(NS_CONFIG_DEBUG.to_vec()),
            || {
                Value::OctetString(
                    format!("net-snmp-rs debug (level=0)").into_bytes(),
                )
            },
        )),
        Arc::new(FnHandler::scalar(
            Oid::new(NS_DEBUG_ENABLED.to_vec()),
            || Value::Integer(TV_FALSE),
        )),
        // Empty nsDebugOutputTable.
        Arc::new(FnHandler::new(
            Oid::new(NS_DEBUG_OUTPUT_ENTRY.to_vec()),
            || Vec::new(),
        )),
        // Root anchor so GETNEXT from the nsDebug group root lands inside it
        // even before any cell exists. The FnHandler rooted at the entry OID
        // already serves that role; this no-op keeps the group reachable.
        // (Kept explicit for documentation.)
    ]
}

/// Build the `nsLogging` group handlers (`nsConfigLogging.0` and an empty
/// `nsLoggingTable`).
///
/// `nsConfigLogging.0` reports a short summary string; the per-target
/// `nsLoggingTable` is empty (logging targets are configured out of band, e.g.
/// via the `tracing` subscriber, and not reflected here). All objects are
/// read-only.
pub fn ns_logging_handlers() -> Vec<Arc<dyn MibHandler>> {
    vec![
        Arc::new(FnHandler::scalar(
            Oid::new(NS_CONFIG_LOGGING.to_vec()),
            || Value::OctetString(b"net-snmp-rs logging".to_vec()),
        )),
        // Empty nsLoggingTable.
        Arc::new(FnHandler::new(
            Oid::new(NS_LOGGING_ENTRY.to_vec()),
            || Vec::new(),
        )),
    ]
}

/// A captured snapshot of the handlers registered in a [`Registry`](crate::registry::Registry),
/// used to serve `nsModuleTable`.
///
/// The C agent's `nsModuleTable` reflects the live handler list held by the
/// agent registry. In this crate [`Registry`](crate::registry::Registry) owns its
/// handler list privately and exposes no accessor, so reflection is performed
/// against a snapshot captured at registration time: the caller builds the
/// `nsModuleTable` from the same `Vec<Arc<dyn MibHandler>>` it registered. The
/// snapshot is taken once (handlers are not normally added after the agent
/// starts serving), which matches the typical snmpd lifecycle.
///
/// Build one with [`NsModuleSnapshot::new`] (from a handler list) and pass it
/// to [`ns_module_handlers`].
#[derive(Clone)]
pub struct NsModuleSnapshot {
    handlers: Vec<Arc<dyn MibHandler>>,
}

impl NsModuleSnapshot {
    /// Capture a handler list for `nsModuleTable` reflection. Each handler's
    /// root OID becomes one row.
    pub fn new(handlers: Vec<Arc<dyn MibHandler>>) -> Arc<Self> {
        Arc::new(NsModuleSnapshot { handlers })
    }

    /// Build the `nsModuleTable` cells. Each registered handler is one row,
    /// indexed by a synthetic 1-based index assigned in the snapshot's
    /// iteration order (sorted by root OID for stable walks). Columns:
    /// `nsModuleOID`(1) and `nsModuleName`(2).
    fn cells(&self) -> Vec<(Oid, Value)> {
        let entry = Oid::new(NS_MODULE_ENTRY.to_vec());
        // Sort by root OID for a deterministic, walk-friendly row order.
        let mut ordered: Vec<&Arc<dyn MibHandler>> = self.handlers.iter().collect();
        ordered.sort_by(|a, b| a.root().cmp(b.root()));
        let mut cells = Vec::with_capacity(ordered.len() * 2);
        for (i, h) in ordered.iter().enumerate() {
            let index = (i as u32) + 1;
            let root = h.root();
            let oid_cell = {
                let mut p = entry.as_slice().to_vec();
                p.push(NS_MODULE_OID);
                p.push(index);
                Oid::new(p)
            };
            let name_cell = {
                let mut p = entry.as_slice().to_vec();
                p.push(NS_MODULE_NAME);
                p.push(index);
                Oid::new(p)
            };
            cells.push((oid_cell, Value::Oid(root.clone())));
            // The crate does not carry per-handler display names; use the root
            // OID's dotted form as a stand-in name, mirroring how snmpd reports
            // `nsModuleName` from the registered MIB's textual name.
            cells.push((name_cell, Value::OctetString(root.to_string().into_bytes())));
        }
        cells
    }
}

/// Build the `nsModuleTable` handler rooted at `1.3.6.1.4.1.8072.1.5.1`,
/// reflecting the handlers captured in `snapshot`.
///
/// Each row reports the handler's root OID (`nsModuleOID`) and a textual name
/// derived from that OID (`nsModuleName`). To coordinate with
/// `sysORTable`/`SysOrTable`, register the same subsystems into both: a
/// subsystem that appears in `sysORTable` should also be present in the handler
/// list passed to [`NsModuleSnapshot::new`].
pub fn ns_module_handlers(snapshot: Arc<NsModuleSnapshot>) -> Vec<Arc<dyn MibHandler>> {
    vec![Arc::new(FnHandler::new(
        Oid::new(NS_MODULE_ENTRY.to_vec()),
        move || snapshot.cells(),
    ))]
}

/// Build the `nsTransactionTable` handler rooted at
/// `1.3.6.1.4.1.8072.1.8.1`.
///
/// Net-SNMP 5.7's SET transactions are short-lived (they exist only for the
/// duration of a single SET PDU processing), so this table is normally empty
/// and is exposed primarily for structural compatibility — a walk returns no
/// rows rather than an error. The structure is in place so a future
/// transaction-tracking layer can populate it.
pub fn ns_transaction_handlers() -> Vec<Arc<dyn MibHandler>> {
    vec![Arc::new(FnHandler::new(
        Oid::new(NS_TRANSACTION_ENTRY.to_vec()),
        || Vec::new(),
    ))]
}

/// Build the `nsVacmAccessTable` handler rooted at
/// `1.3.6.1.4.1.8072.1.9.1`.
///
/// This is the NET-SNMP-AGENT-MIB extension of VACM (per-row storage type and
/// status metadata). The authoritative VACM state is served by the
/// SNMP-VIEW-BASED-ACM-MIB tables (see [`crate::mibgroup::vacm`]); this table
/// is exposed for structural compatibility and is normally empty.
pub fn ns_vacm_access_handlers() -> Vec<Arc<dyn MibHandler>> {
    vec![Arc::new(FnHandler::new(
        Oid::new(NS_VACM_ACCESS_ENTRY.to_vec()),
        || Vec::new(),
    ))]
}

/// The full set of NET-SNMP-AGENT-MIB handlers under `1.3.6.1.4.1.8072.1`.
///
/// This is a convenience that aggregates the per-group builders. `state` backs
/// the `nsCache` group; `modules` (when supplied) backs `nsModuleTable`. When
/// `modules` is `None`, `nsModuleTable` is served empty.
pub fn netsnmp_agent_handlers(
    state: Arc<NsCacheState>,
    modules: Option<Arc<NsModuleSnapshot>>,
) -> Vec<Arc<dyn MibHandler>> {
    let mut out: Vec<Arc<dyn MibHandler>> = Vec::new();
    out.extend(ns_cache_handlers(state));
    out.extend(ns_debug_handlers());
    out.extend(ns_logging_handlers());
    if let Some(snap) = modules {
        out.extend(ns_module_handlers(snap));
    } else {
        // Still register an empty nsModuleTable so the subtree is walkable.
        out.extend(ns_module_handlers(NsModuleSnapshot::new(Vec::new())));
    }
    out.extend(ns_transaction_handlers());
    out.extend(ns_vacm_access_handlers());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::ScalarHandler;

    /// NET-SNMP-AGENT-MIB root used only by the walk test below.
    const NS_AGENT_ROOT: &[u32] = &[1, 3, 6, 1, 4, 1, 8072, 1];

    // --- NsCacheState ---

    #[test]
    fn cache_state_default_enabled_and_set_get_ttl() {
        let state = NsCacheState::new();
        assert!(state.enabled());
        state.set_enabled(false);
        assert!(!state.enabled());

        // No row yet -> default returned.
        let dflt = Duration::from_secs(60);
        assert_eq!(state.ttl("foo", dflt), dflt);

        state.set_ttl("foo", Duration::from_secs(10));
        assert_eq!(state.ttl("foo", dflt), Duration::from_secs(10));
        // Unknown module still falls back.
        assert_eq!(state.ttl("bar", dflt), dflt);

        // remove works.
        assert_eq!(state.remove_ttl("foo"), Some(Duration::from_secs(10)));
        assert_eq!(state.ttl("foo", dflt), dflt);
    }

    #[test]
    fn cache_state_modules_sorted() {
        let state = NsCacheState::new();
        state.set_ttl("zebra", Duration::from_secs(1));
        state.set_ttl("alpha", Duration::from_secs(2));
        state.set_ttl("mid", Duration::from_secs(3));
        let m = state.modules();
        assert_eq!(
            m.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "mid", "zebra"]
        );
    }

    // --- nsCache cells reflect state ---

    #[test]
    fn ns_cache_enabled_scalar_reflects_state() {
        let state = NsCacheState::new();
        let cells = state.cells();
        let enabled_oid: Oid = "1.3.6.1.4.1.8072.1.6.1.0".parse().unwrap();
        let v = cells
            .iter()
            .find(|(o, _)| o == &enabled_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(v, Some(Value::Integer(TV_TRUE)));

        state.set_enabled(false);
        let cells = state.cells();
        let v = cells
            .iter()
            .find(|(o, _)| o == &enabled_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(v, Some(Value::Integer(TV_FALSE)));
    }

    #[test]
    fn ns_cache_table_cells_match_layout() {
        let state = NsCacheState::new();
        state.set_ttl("ifTable", Duration::from_secs(30));
        let cells = state.cells();

        // nsCacheTimeout.ifTable: col 2, index = length-prefixed "ifTable".
        // 8072.1.6.2.1.2 . <len=7> <i><f><T><a><b><l><e>
        let mut expected_timeout = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 2];
        expected_timeout.extend(string_index(b"ifTable"));
        let timeout_oid = Oid::new(expected_timeout);
        let v = cells
            .iter()
            .find(|(o, _)| o == &timeout_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(v, Some(Value::Integer(30)));

        // nsCacheStatus.ifTable: col 3 -> active(1).
        let mut expected_status = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 3];
        expected_status.extend(string_index(b"ifTable"));
        let status_oid = Oid::new(expected_status);
        let v = cells
            .iter()
            .find(|(o, _)| o == &status_oid)
            .map(|(_, v)| v.clone());
        assert_eq!(v, Some(Value::Integer(STATUS_ACTIVE)));
    }

    #[test]
    fn ns_cache_handler_serves_cells_and_getnext() {
        let state = NsCacheState::new();
        state.set_ttl("alpha", Duration::from_secs(5));
        state.set_ttl("beta", Duration::from_secs(9));
        let handlers = ns_cache_handlers(state);
        assert_eq!(handlers.len(), 1);
        let h = &handlers[0];

        // GET nsCacheEnabled.0
        let enabled_oid: Oid = "1.3.6.1.4.1.8072.1.6.1.0".parse().unwrap();
        assert_eq!(h.get(&enabled_oid), Some(Value::Integer(TV_TRUE)));

        // GETNEXT from the group root lands on the first cell.
        let root: Oid = "1.3.6.1.4.1.8072.1.6".parse().unwrap();
        let first = h.get_next(&root).expect("first successor");
        assert!(first.oid > root);
        // The first cell is the enabled scalar.
        assert_eq!(first.oid, enabled_oid);

        // Walk past enabled -> first nsCacheTimeout row. Cells are sorted by
        // OID, and the INDEX is length-prefixed, so a shorter module name sorts
        // first: "beta" (4 chars) precedes "alpha" (5 chars).
        let next = h.get_next(&enabled_oid).expect("after enabled");
        let beta_timeout_oid: Oid = {
            let mut p = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 2];
            p.extend(string_index(b"beta"));
            Oid::new(p)
        };
        assert_eq!(next.oid, beta_timeout_oid);
        assert_eq!(next.value, Value::Integer(9));

        // Continuing the walk reaches alpha's timeout row next.
        let after_beta = h.get_next(&beta_timeout_oid).expect("after beta");
        let alpha_timeout_oid: Oid = {
            let mut p = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 2];
            p.extend(string_index(b"alpha"));
            Oid::new(p)
        };
        assert_eq!(after_beta.oid, alpha_timeout_oid);
        assert_eq!(after_beta.value, Value::Integer(5));
    }

    // --- nsCacheTimeout SET ---

    #[test]
    fn set_ns_cache_timeout_updates_ttl() {
        let state = NsCacheState::new();
        state.set_ttl("mib", Duration::from_secs(10));
        let handlers = ns_cache_handlers(Arc::clone(&state));
        let h = &handlers[0];

        let timeout_oid: Oid = {
            let mut p = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 2];
            p.extend(string_index(b"mib"));
            Oid::new(p)
        };

        // prepare + commit a SET to 30s.
        h.prepare_set(&timeout_oid, &Value::Integer(30)).unwrap();
        h.commit_set(&timeout_oid, &Value::Integer(30)).unwrap();

        // The shared state now carries 30s for "mib".
        assert_eq!(state.ttl("mib", Duration::from_secs(99)), Duration::from_secs(30));

        // The handler now reports 30 for that cell.
        assert_eq!(h.get(&timeout_oid), Some(Value::Integer(30)));
    }

    #[test]
    fn set_ns_cache_timeout_rejects_wrong_column_and_type() {
        let state = NsCacheState::new();
        state.set_ttl("mib", Duration::from_secs(10));
        let handlers = ns_cache_handlers(state);
        let h = &handlers[0];

        // nsCacheStatus column (3) is read-only.
        let status_oid: Oid = {
            let mut p = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 3];
            p.extend(string_index(b"mib"));
            Oid::new(p)
        };
        let err = h.prepare_set(&status_oid, &Value::Integer(1)).unwrap_err();
        assert_eq!(err, ErrorStatus::NotWritable);

        // nsCacheEnabled scalar is read-only.
        let enabled_oid: Oid = "1.3.6.1.4.1.8072.1.6.1.0".parse().unwrap();
        let err = h.prepare_set(&enabled_oid, &Value::Integer(TV_TRUE)).unwrap_err();
        assert_eq!(err, ErrorStatus::NotWritable);

        // Wrong type (OctetString onto Integer column).
        let timeout_oid: Oid = {
            let mut p = vec![1, 3, 6, 1, 4, 1, 8072, 1, 6, 2, 1, 2];
            p.extend(string_index(b"mib"));
            Oid::new(p)
        };
        let err = h
            .prepare_set(&timeout_oid, &Value::OctetString(b"x".to_vec()))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
    }

    // --- nsModuleTable ---

    #[test]
    fn ns_module_table_lists_registered_handlers() {
        let h1 = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1".parse().unwrap(),
            Value::OctetString(b"sys".to_vec()),
        ));
        let h2 = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.2".parse().unwrap(),
            Value::OctetString(b"if".to_vec()),
        ));
        let snapshot = NsModuleSnapshot::new(vec![h1, h2]);
        let handlers = ns_module_handlers(snapshot);
        assert_eq!(handlers.len(), 1);
        let h = &handlers[0];

        // nsModuleOID.1 = col 1, index 1 -> the first root OID (sorted).
        let oid1: Oid = "1.3.6.1.4.1.8072.1.5.1.1.1".parse().unwrap();
        assert_eq!(
            h.get(&oid1),
            Some(Value::Oid("1.3.6.1.2.1.1".parse().unwrap()))
        );
        // nsModuleName.2 = col 2, index 2 -> the second root OID name.
        let name2: Oid = "1.3.6.1.4.1.8072.1.5.1.2.2".parse().unwrap();
        assert_eq!(
            h.get(&name2),
            Some(Value::OctetString(b".1.3.6.1.2.1.2".to_vec()))
        );

        // GETNEXT from the entry root lands on the first row.
        let root: Oid = "1.3.6.1.4.1.8072.1.5.1".parse().unwrap();
        let first = h.get_next(&root).expect("first row");
        assert_eq!(first.oid, oid1);
    }

    #[test]
    fn ns_module_table_empty_when_no_handlers() {
        let snapshot = NsModuleSnapshot::new(Vec::new());
        let handlers = ns_module_handlers(snapshot);
        let h = &handlers[0];
        let root: Oid = "1.3.6.1.4.1.8072.1.5.1".parse().unwrap();
        // No rows: GETNEXT returns None (end of this handler's subtree).
        assert!(h.get_next(&root).is_none());
    }

    // --- nsDebug / nsLogging scalars ---

    #[test]
    fn ns_debug_scalars_return_defaults() {
        let handlers = ns_debug_handlers();
        let h = &handlers[0];
        // nsConfigDebug.0
        let cfg: Oid = "1.3.6.1.4.1.8072.1.3.1.0".parse().unwrap();
        let v = h.get(&cfg).expect("config debug value");
        assert!(matches!(v, Value::OctetString(_)));

        let h2 = &handlers[1];
        let en: Oid = "1.3.6.1.4.1.8072.1.3.2.0".parse().unwrap();
        assert_eq!(h2.get(&en), Some(Value::Integer(TV_FALSE)));
    }

    #[test]
    fn ns_logging_scalars_return_defaults() {
        let handlers = ns_logging_handlers();
        let h = &handlers[0];
        let cfg: Oid = "1.3.6.1.4.1.8072.1.7.1.0".parse().unwrap();
        let v = h.get(&cfg).expect("config logging value");
        assert!(matches!(v, Value::OctetString(_)));
    }

    // --- nsTransactionTable / nsVacmAccessTable empty but walkable ---

    #[test]
    fn ns_transaction_and_vacm_tables_empty_but_walkable() {
        let tx = ns_transaction_handlers();
        let vacm = ns_vacm_access_handlers();
        let tx_root: Oid = "1.3.6.1.4.1.8072.1.8.1".parse().unwrap();
        let vacm_root: Oid = "1.3.6.1.4.1.8072.1.9.1".parse().unwrap();
        assert!(tx[0].get_next(&tx_root).is_none());
        assert!(vacm[0].get_next(&vacm_root).is_none());
    }

    // --- Full subtree walk via Registry ---

    #[test]
    fn walk_over_ns_agent_root_returns_expected_suboids() {
        use crate::registry::Registry;
        use netsnmp::pdu::{Pdu, PduType};

        let state = NsCacheState::new();
        state.set_ttl("alpha", Duration::from_secs(5));
        let h1 = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1".parse().unwrap(),
            Value::OctetString(b"sys".to_vec()),
        ));
        let modules = NsModuleSnapshot::new(vec![h1]);

        let mut reg = Registry::new();
        for handler in netsnmp_agent_handlers(state, Some(modules)) {
            reg.register(handler);
        }

        // Walk from below the root and collect every OID we see, until
        // EndOfMibView. Every visited OID must live under 8072.1.
        let mut current: Oid = "1.3.6.1.4.1.8072.1".parse().unwrap();
        let mut seen: Vec<Oid> = Vec::new();
        loop {
            let pdu = Pdu::new(PduType::GetNext, 1).with_null_var(current.clone());
            let resp = reg.process(&pdu);
            let vb = &resp.variables[0];
            if vb.value == Value::EndOfMibView {
                break;
            }
            assert!(
                vb.oid.as_slice().starts_with(NS_AGENT_ROOT),
                "walk left the NET-SNMP-AGENT-MIB subtree: {}",
                vb.oid
            );
            seen.push(vb.oid.clone());
            current = vb.oid.clone();
        }
        // Sanity: we visited nsCacheEnabled.0 and at least one nsModule row.
        let has_enabled = seen
            .iter()
            .any(|o| o.as_slice() == &[1, 3, 6, 1, 4, 1, 8072, 1, 6, 1, 0]);
        let has_module = seen
            .iter()
            .any(|o| o.as_slice().starts_with(&[1, 3, 6, 1, 4, 1, 8072, 1, 5, 1]));
        assert!(has_enabled, "nsCacheEnabled.0 not visited: {seen:?}");
        assert!(has_module, "nsModuleTable not visited: {seen:?}");
    }
}
