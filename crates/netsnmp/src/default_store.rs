//! # The Net-SNMP Default Store
//!
//! Counterpart of `snmplib/default_store.c` / `include/net-snmp/library/default_store.h`.
//!
//! The *Default Store* (DS) is a small runtime key/value registry used across
//! Net-SNMP to hold process-wide boolean/integer/string switches — things like
//! "print OIDs numerically", "agent role: master/subagent", "MIB parsing
//! warnings level". It is keyed by a `(category, id)` pair, where the category
//! mirrors the upstream `DS_LIBRARY` / `DS_APPLICATION` / `DS_AGENT` / `DS_MIB`
//! / `DS_TOKEN` split and the `id` is one of the well-known numeric slots from
//! `default_store.h`.
//!
//! This module reproduces that abstraction in safe Rust:
//!
//! * [`DsCategory`] — the five categories.
//! * [`DsValue`] — a tagged `bool` / `i64` / `String` slot.
//! * [`DefaultStore`] — a thread-safe (`RwLock<HashMap>`) implementation.
//! * [`default_store`] — the process-wide singleton (the equivalent of
//!   `netsnmp_ds_*` operating on the global store).
//! * [`ids`] — best-effort mirrors of the stable `DS_*_ID` numeric slots, e.g.
//!   [`ids::LIB_PRINT_NUMERIC_OIDS`].
//! * [`resolve_ds_name`] / [`apply_override_directives`] / [`load_default_store`]
//!   — glue to the `override` config directive (see `override: bool
//!   printNumericOids true` in `snmp.conf`).

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use crate::config::Directive;

/// A Default Store category, mirroring the upstream `DS_LIBRARY` /
/// `DS_APPLICATION` / `DS_AGENT` / `DS_MIB` / `DS_TOKEN` split.
///
/// `Other` stands in for `DS_TOKEN` (and any future custom categories): the
/// public Net-SNMP API exposes only the four typed categories plus a generic
/// "user-defined token" namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DsCategory {
    /// `DS_LIBRARY` — snmplib behavior (printing, OID formatting, MIB parsing).
    Library,
    /// `DS_APPLICATION` — client application behavior (`snmpget`, `snmpwalk`…).
    Application,
    /// `DS_AGENT` — agent (snmpd) behavior.
    Agent,
    /// `DS_MIB` — MIB parser behavior.
    Mib,
    /// `DS_TOKEN` / user-defined categories.
    Other,
}

/// A single Default Store value: a tagged `bool`, `i64`, or `String`.
///
/// Net-SNMP keeps the three kinds in separate per-type tables; we model the
/// same idea as a single enum so a slot's type is whatever was last written
/// (which matches the upstream "last writer wins" semantics when callers mix
/// `set_boolean`/`set_int` on the same `(cat, id)`).
#[derive(Debug, Clone)]
pub enum DsValue {
    /// A boolean switch (`netsnmp_ds_set_boolean`).
    Bool(bool),
    /// An integer setting (`netsnmp_ds_set_int`).
    Int(i64),
    /// A string setting (`netsnmp_ds_set_string`).
    String(String),
}

/// The runtime Default Store: a thread-safe map of `(category, id) -> value`.
///
/// All accessors take a shared `&self` reference and perform internal locking
/// via a [`RwLock`], mirroring the upstream "many readers / exclusive writer"
/// pattern. Reads of a missing slot return the type's zero value (`false` / `0`
/// / `""`), exactly like `netsnmp_ds_get_boolean` / `_int` / `_string`.
pub struct DefaultStore {
    inner: RwLock<HashMap<(DsCategory, i32), DsValue>>,
}

impl Default for DefaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultStore {
    /// Create an empty Default Store.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Set the boolean switch `(cat, id)` to `v`.
    ///
    /// Counterpart of `netsnmp_ds_set_boolean`.
    pub fn set_bool(&self, cat: DsCategory, id: i32, v: bool) {
        let mut guard = self.inner.write().unwrap();
        guard.insert((cat, id), DsValue::Bool(v));
    }

    /// Read the boolean switch `(cat, id)`, defaulting to `false` when unset.
    ///
    /// Counterpart of `netsnmp_ds_get_boolean`. If the slot currently holds a
    /// non-boolean value, the behavior mirrors the upstream "best effort": the
    /// numeric value is interpreted as truthy (non-zero `Int` → `true`,
    /// `String` → `false`).
    pub fn get_bool(&self, cat: DsCategory, id: i32) -> bool {
        let guard = self.inner.read().unwrap();
        match guard.get(&(cat, id)) {
            Some(DsValue::Bool(b)) => *b,
            Some(DsValue::Int(n)) => *n != 0,
            Some(DsValue::String(_)) => false,
            None => false,
        }
    }

    /// Toggle the boolean switch `(cat, id)` and return the new value.
    ///
    /// A missing slot is treated as `false` (so the first toggle yields `true`),
    /// matching the upstream `SNMP_TOGGLE` semantics.
    pub fn toggle_bool(&self, cat: DsCategory, id: i32) -> bool {
        let new = !self.get_bool(cat, id);
        self.set_bool(cat, id, new);
        new
    }

    /// Set the integer setting `(cat, id)` to `v`.
    ///
    /// Counterpart of `netsnmp_ds_set_int`.
    pub fn set_int(&self, cat: DsCategory, id: i32, v: i64) {
        let mut guard = self.inner.write().unwrap();
        guard.insert((cat, id), DsValue::Int(v));
    }

    /// Read the integer setting `(cat, id)`, defaulting to `0` when unset.
    ///
    /// Counterpart of `netsnmp_ds_get_int`. A `Bool` slot is read as `0`/`1`.
    pub fn get_int(&self, cat: DsCategory, id: i32) -> i64 {
        let guard = self.inner.read().unwrap();
        match guard.get(&(cat, id)) {
            Some(DsValue::Int(n)) => *n,
            Some(DsValue::Bool(b)) => i64::from(*b),
            Some(DsValue::String(_)) => 0,
            None => 0,
        }
    }

    /// Set the string setting `(cat, id)` to `v`.
    ///
    /// Counterpart of `netsnmp_ds_set_string`.
    pub fn set_string(&self, cat: DsCategory, id: i32, v: impl Into<String>) {
        let mut guard = self.inner.write().unwrap();
        guard.insert((cat, id), DsValue::String(v.into()));
    }

    /// Read the string setting `(cat, id)`, defaulting to an empty `String`.
    ///
    /// Counterpart of `netsnmp_ds_get_string`. A non-string slot is read as the
    /// empty string (the upstream helper returns `char*`, so `NULL`/non-string
    /// cases collapse to the same "no text" outcome).
    pub fn get_string(&self, cat: DsCategory, id: i32) -> String {
        let guard = self.inner.read().unwrap();
        match guard.get(&(cat, id)) {
            Some(DsValue::String(s)) => s.clone(),
            _ => String::new(),
        }
    }

    /// Like [`get_string`](Self::get_string) but returns `None` for unset or
    /// non-string slots, so callers can distinguish "explicitly empty string"
    /// from "never set".
    pub fn get_string_opt(&self, cat: DsCategory, id: i32) -> Option<String> {
        let guard = self.inner.read().unwrap();
        match guard.get(&(cat, id)) {
            Some(DsValue::String(s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Remove the slot `(cat, id)`, returning `true` if a value was present.
    ///
    /// Counterpart of `netsnmp_ds_remove`.
    pub fn remove(&self, cat: DsCategory, id: i32) -> bool {
        let mut guard = self.inner.write().unwrap();
        guard.remove(&(cat, id)).is_some()
    }

    /// Remove every slot from the store, regardless of category.
    ///
    /// Counterpart of `netsnmp_ds_shutdown` (the "clear everything" sense).
    pub fn clear(&self) {
        let mut guard = self.inner.write().unwrap();
        guard.clear();
    }

    /// The total number of slots currently held in the store.
    pub fn len(&self) -> usize {
        let guard = self.inner.read().unwrap();
        guard.len()
    }

    /// `true` iff the store holds no slots.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Stable numeric IDs for the well-known Default Store slots.
///
/// These are a best-effort mirror of the constants in
/// `include/net-snmp/library/default_store.h`. The numbers are *not* part of
/// any ABI — they exist purely so that callers can name slots symbolically and
/// interoperate with the human-readable `override` directive (see
/// [`resolve_ds_name`]). Names follow the upstream `DS_<CAT>_<NAME>` spelling
/// but drop the `DS_` prefix (`LIB_*`, `APP_*`, `AGENT_*`, `MIB_*`).
pub mod ids {
    use super::DsCategory;

    /// `DS_LIBRARY_ID` category tag (re-exported here for convenience).
    pub const LIB: DsCategory = DsCategory::Library;
    /// `DS_APPLICATION_ID` category tag (re-exported here for convenience).
    pub const APP: DsCategory = DsCategory::Application;
    /// `DS_AGENT_ID` category tag (re-exported here for convenience).
    pub const AGENT: DsCategory = DsCategory::Agent;
    /// `DS_MIB_ID` category tag (re-exported here for convenience).
    pub const MIB: DsCategory = DsCategory::Mib;

    // ----- DS_LIBRARY_* (snmplib behavior) -----

    /// Print OIDs numerically (`NETSNMP_DS_LIB_PRINT_NUMERIC_OIDS`).
    pub const LIB_PRINT_NUMERIC_OIDS: i32 = 0;
    /// netsnmp quick-print mode (`NETSNMP_DS_LIB_QUICK_PRINT`).
    pub const LIB_QUICK_PRINT: i32 = 1;
    /// Don't print UNITS suffix (`NETSNMP_DS_LIB_DONT_PRINT_UNITS`).
    pub const LIB_DONT_PRINT_UNITS: i32 = 2;
    /// Print only the value, no OID (`NETSNMP_DS_LIB_PRINT_BARE_VALUE`).
    pub const LIB_PRINT_BARE_VALUE: i32 = 3;
    /// Print the full OID, not just the leaf (`NETSNMP_DS_LIB_PRINT_FULL_OID`).
    pub const LIB_PRINT_FULL_OID: i32 = 4;
    /// Suppress leading `0` index printing (`NETSNMP_DS_LIB_NO_ZERO_INDEX`).
    pub const LIB_NO_ZERO_INDEX: i32 = 5;
    /// Selects OID output formatting (`NETSNMP_DS_LIB_OID_OUTPUT_FORMAT`).
    pub const LIB_OID_OUTPUT_FORMAT: i32 = 6;
    /// Save passphrases as plaintext (`NETSNMP_DS_LIB_SAVE_PLAINTEXT`).
    pub const LIB_SAVE_PLAINTEXT: i32 = 7;
    /// Disable MIB parsing entirely (`NETSNMP_DS_LIB_DISABLE_PARSING_MIBS`).
    pub const LIB_DISABLE_PARSING_MIBS: i32 = 8;
    /// MIB warnings verbosity level (`NETSNMP_DS_LIB_MIB_WARNINGS`).
    pub const LIB_MIB_WARNINGS: i32 = 9;
    /// Print suffixes for repeated OIDs (`NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY` / a
    /// sibling of the OID-format family).
    pub const LIB_PRINT_SUFFIX_ONLY: i32 = 10;
    /// OID prefix to print (`NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY`'s sibling — the
    /// "print only the suffix, but remember the prefix" mode).
    pub const LIB_PRINT_UCD_STYLE_OID: i32 = 11;
    /// Don't check range/value enums (`NETSNMP_DS_LIB_DONT_CHECK_RANGE`).
    pub const LIB_DONT_CHECK_RANGE: i32 = 12;
    /// Don't break-down the OID in search (`NETSNMP_DS_LIB_NO_DISPLAY_HINT`).
    pub const LIB_NO_DISPLAY_HINT: i32 = 13;
    /// Expand the index of a table (`NETSNMP_DS_LIB_EXTENDED_INDEX`).
    pub const LIB_EXTENDED_INDEX: i32 = 14;
    /// Print hex-string value as raw text (`NETSNMP_DS_LIB_PRINT_HEX_TEXT`).
    pub const LIB_PRINT_HEX_TEXT: i32 = 15;
    /// Print 1-minute counters (`NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM`).
    pub const LIB_PRINT_NUMERIC_ENUM: i32 = 16;
    /// Reverse the OID rendering (`NETSNMP_DS_LIB_PRINT_REVERSE_NUMERIC`).
    pub const LIB_PRINT_REVERSE_NUMERIC: i32 = 17;

    // ----- DS_APPLICATION_* (client application behavior) -----

    /// Print OIDs numerically (`NETSNMP_DS_APP_NUMERIC_OIDS`, app side).
    pub const APP_NUMERIC_OIDS: i32 = 0;
    /// Don't print the trailing index (`NETSNMP_DS_APP_DONT_PRINT_SUFFIX_ONLY`).
    pub const APP_DONT_PRINT_SUFFIX_ONLY: i32 = 1;
    /// Print full OID for the application output.
    pub const APP_PRINT_FULL_OID: i32 = 2;
    /// Use the community string verbatim (`NETSNMP_DS_APP_NO_TOKEN`).
    pub const APP_NO_TOKEN: i32 = 3;
    /// Split the output per field (`NETSNMP_DS_APP_SPLIT_QUOTED_STRINGS`).
    pub const APP_SPLIT_QUOTED_STRINGS: i32 = 4;
    /// Use a literal colon as field separator (`NETSNMP_DS_APP_LITERAL_TIME`).
    pub const APP_LITERAL_TIME: i32 = 5;
    /// Don't print units in app output (`NETSNMP_DS_APP_DONT_PRINT_UNITS`).
    pub const APP_DONT_PRINT_UNITS: i32 = 6;

    // ----- DS_AGENT_* (snmpd / AgentX behavior) -----

    /// Don't drop privileges / require root (`NETSNMP_DS_AGENT_NO_ROOT_ACCESS`).
    pub const AGENT_NO_ROOT_ACCESS: i32 = 0;
    /// Act as an AgentX master (`NETSNMP_DS_AGENT_AGENTX_MASTER`).
    pub const AGENT_AGENTX_MASTER: i32 = 1;
    /// Agent role: 0 = master/snmpd, 1 = subagent (`NETSNMP_DS_AGENT_ROLE`).
    pub const AGENT_ROLE: i32 = 2;
    /// Override the request timeout in seconds (`NETSNMP_DS_AGENT_TIMEOUT`).
    pub const AGENT_TIMEOUT: i32 = 3;
    /// Persist directory override (`NETSNMP_DS_AGENT_PERSIST_DIR`).
    pub const AGENT_PERSIST_DIR: i32 = 4;
    /// Don't load any per-module MIBs (`NETSNMP_DS_AGENT_NO_ROOT_ACCESS`-like
    /// global toggle for `snmpd`'s startup).
    pub const AGENT_FLAGS: i32 = 5;
    /// Disable disk-based state persistence (`NETSNMP_DS_AGENT_DONT_PERSIST_STATE`).
    pub const AGENT_DONT_PERSIST_STATE: i32 = 6;
    /// Save state on shutdown (`NETSNMP_DS_AGENT_SAVE_STATE_ON_SHUTDOWN`).
    pub const AGENT_SAVE_STATE_ON_SHUTDOWN: i32 = 7;
    /// Start the agent without logging (`NETSNMP_DS_AGENT_NO_CONNECTION_HOOKS`).
    pub const AGENT_NO_CONNECTION_HOOKS: i32 = 8;
    /// Leave AgentX socket group-writable (`NETSNMP_DS_AGENT_LEAVE_PIDFILE`).
    pub const AGENT_LEAVE_PIDFILE: i32 = 9;
    /// Rewrite the AgentX perms (`NETSNMP_DS_AGENT_PERM_PERM`).
    pub const AGENT_X_SOCK_PERM: i32 = 10;
    /// AgentX socket directory perms (`NETSNMP_DS_AGENT_X_DIR_PERM`).
    pub const AGENT_X_DIR_PERM: i32 = 11;
    /// AgentX socket user/group (`NETSNMP_DS_AGENT_X_SOCK_USER`).
    pub const AGENT_X_SOCK_USER: i32 = 12;
    /// AgentX socket gid (`NETSNMP_DS_AGENT_X_SOCK_GROUP`).
    pub const AGENT_X_SOCK_GROUP: i32 = 13;

    // ----- DS_MIB_* (MIB parser behavior) -----

    /// Re-label parsed MIB nodes (`NETSNMP_DS_MIB_PARSE_LABELS`).
    pub const MIB_PARSE_LABELS: i32 = 0;
    /// Save MIB description (`NETSNMP_DS_MIB_SAVE_DESCR`).
    pub const MIB_SAVE_DESCR: i32 = 1;
    /// Don't error-out on redefinitions (`NETSNMP_DS_MIB_REPLACEMIB_ERRORS`).
    pub const MIB_REPLACEMIB_ERRORS: i32 = 2;
    /// Allow underscores in MIB identifiers (`NETSNMP_DS_MIB_PARSE_ERRORS`).
    pub const MIB_ALLOW_UNDERSCORES: i32 = 3;
    /// Report the OID on a forward reference (`NETSNMP_DS_MIB_FORWARD_REF`).
    pub const MIB_FORWARD_REF: i32 = 4;
    /// Drop redundant trailing comments (`NETSNMP_DS_MIB_PARSE_COMMENT`).
    pub const MIB_PARSE_COMMENT: i32 = 5;
    /// Strict numeric checks during parse (`NETSNMP_DS_MIB_CHECK_NUMERS`).
    pub const MIB_CHECK_NUMERS: i32 = 6;

    /// `(category, id)` tuples for every well-known name, used by
    /// [`crate::default_store::resolve_ds_name`].
    ///
    /// Kept here (next to the `const`s) so a new slot only has to be added in
    /// one place. The string keys are the canonical (lowercase, no-underscore)
    /// form; see [`resolve_ds_name`](crate::default_store::resolve_ds_name) for
    /// the normalization rules.
    pub(crate) const WELL_KNOWN: &[(&str, DsCategory, i32)] = &[
        // Library
        ("printnumericoids", DsCategory::Library, LIB_PRINT_NUMERIC_OIDS),
        ("quickprint", DsCategory::Library, LIB_QUICK_PRINT),
        ("dontprintunits", DsCategory::Library, LIB_DONT_PRINT_UNITS),
        ("printbarevalue", DsCategory::Library, LIB_PRINT_BARE_VALUE),
        ("printfulloid", DsCategory::Library, LIB_PRINT_FULL_OID),
        ("nozeroindex", DsCategory::Library, LIB_NO_ZERO_INDEX),
        ("oidoutputformat", DsCategory::Library, LIB_OID_OUTPUT_FORMAT),
        ("saveplaintext", DsCategory::Library, LIB_SAVE_PLAINTEXT),
        ("disableparsingmibs", DsCategory::Library, LIB_DISABLE_PARSING_MIBS),
        ("mibwarnings", DsCategory::Library, LIB_MIB_WARNINGS),
        // Application
        ("numericoids", DsCategory::Application, APP_NUMERIC_OIDS),
        // Agent
        ("norootaccess", DsCategory::Agent, AGENT_NO_ROOT_ACCESS),
        ("agentxmaster", DsCategory::Agent, AGENT_AGENTX_MASTER),
        ("agentrole", DsCategory::Agent, AGENT_ROLE),
        ("agenttimeout", DsCategory::Agent, AGENT_TIMEOUT),
        ("persistdir", DsCategory::Agent, AGENT_PERSIST_DIR),
        ("agentpersistdir", DsCategory::Agent, AGENT_PERSIST_DIR),
        // Mib
        ("parselabels", DsCategory::Mib, MIB_PARSE_LABELS),
        ("mibparselabels", DsCategory::Mib, MIB_PARSE_LABELS),
    ];
}

static GLOBAL: OnceLock<DefaultStore> = OnceLock::new();

/// Borrow the process-wide Default Store singleton.
///
/// Counterpart of the implicit "global DS" accessed by the upstream
/// `netsnmp_ds_*` functions. The store is lazily initialized on first access.
pub fn default_store() -> &'static DefaultStore {
    GLOBAL.get_or_init(DefaultStore::new)
}

/// Map a human / `DS_*`-style name to its `(category, id)` slot.
///
/// The lookup is forgiving: the input is lower-cased and stripped of any
/// leading `ds` / `lib` / `agent` / `mib` / `app` prefix plus all underscores,
/// then matched against the canonical names in [`ids::WELL_KNOWN`]. This means
/// any of `"printNumericOids"`, `"DS_LIB_PRINT_NUMERIC_OIDS"`,
/// `"ds_lib_printnumericoids"` and `"printnumericoids"` resolve to the same
/// `(DsCategory::Library, ids::LIB_PRINT_NUMERIC_OIDS)` slot. Returns `None`
/// for unrecognized names.
pub fn resolve_ds_name(name: &str) -> Option<(DsCategory, i32)> {
    // Lowercase, drop underscores.
    let mut normalized = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch == '_' {
            continue;
        }
        normalized.extend(ch.to_lowercase());
    }

    // Candidate normalizations to try, in order of decreasing specificity:
    //   1. The full lowercased, underscore-stripped form as-is (handles
    //      `printNumericOids`, `agentRole`, `agentrole`, ...).
    //   2. The same form with one known category prefix peeled off (handles
    //      `DS_LIB_PRINT_NUMERIC_OIDS` → `printnumericoids`, `lib_printnumericoids`,
    //      `agent_agentrole`, ...). We only peel at most one prefix so that a
    //      canonical name like `agentrole` — which happens to *start with* `agent`
    //      — is not damaged by first being matched verbatim in step 1.
    let try_match = |s: &str| -> Option<(DsCategory, i32)> {
        for (canonical, cat, id) in ids::WELL_KNOWN {
            if *canonical == s {
                return Some((*cat, *id));
            }
        }
        None
    };

    if let Some(hit) = try_match(&normalized) {
        return Some(hit);
    }

    // Peel one or two of the common prefixes (`DS_`, `LIB_`, `AGENT_`, `MIB_`,
    // `APP_`), matching the upstream `DS_<CAT>_<NAME>` naming convention where
    // both `DS_LIB_*` and bare `LIB_*` / `AGENT_*` are common. We try the
    // one-prefix forms first, then the two-prefix forms, so that canonical names
    // like `agentrole` (already matched verbatim above) are never damaged.
    let prefixes = ["ds", "lib", "agent", "mib", "app"];
    for p in &prefixes {
        if normalized.starts_with(p) && normalized.len() > p.len() {
            let peeled = &normalized[p.len()..];
            if let Some(hit) = try_match(peeled) {
                return Some(hit);
            }
        }
    }
    // Two-prefix peel, e.g. `dslibprintnumericoids` → `printnumericoids`.
    for p1 in &prefixes {
        if !normalized.starts_with(p1) {
            continue;
        }
        let rest1 = &normalized[p1.len()..];
        for p2 in &prefixes {
            if rest1.starts_with(p2) && rest1.len() > p2.len() {
                let peeled = &rest1[p2.len()..];
                if let Some(hit) = try_match(peeled) {
                    return Some(hit);
                }
            }
        }
    }

    None
}

/// Apply the `override` config directives in `directives` to the global
/// [`DefaultStore`].
///
/// Counterpart of the `override` token supported by `snmp.conf` / `snmpd.conf`:
///
/// ```text
/// override TYPE NAME [with] VALUE
/// ```
///
/// where `TYPE` is `bool`, `integer`, or `string`, `NAME` is resolved via
/// [`resolve_ds_name`] (e.g. `printNumericOids`, `agentRole`), and `VALUE` is
/// parsed according to `TYPE`. Unknown names and malformed directives are
/// logged via `tracing::warn!` and skipped (matching the upstream "warn and
/// carry on" behavior).
pub fn apply_override_directives(directives: &[Directive]) {
    apply_override_directives_to(default_store(), directives);
}

/// Like [`apply_override_directives`] but against a caller-supplied store.
///
/// Tests should prefer this variant to avoid racing on the process-wide
/// singleton ([`default_store`]).
pub fn apply_override_directives_to(store: &DefaultStore, directives: &[Directive]) {
    for dir in directives {
        if !dir.is("override") {
            continue;
        }
        // Expected shapes:
        //   override TYPE NAME VALUE
        //   override TYPE NAME with VALUE
        let args = &dir.args;
        if args.len() < 3 {
            tracing::warn!(
                token = %dir.token,
                "override directive needs at least 3 args (TYPE NAME VALUE); skipping"
            );
            continue;
        }
        let ty = args[0].as_str();
        let name = args[1].as_str();
        let (value_str, value_idx): (&str, usize) = if args.len() >= 4
            && args[2].eq_ignore_ascii_case("with")
        {
            (args[3].as_str(), 3)
        } else {
            (args[2].as_str(), 2)
        };

        // The "rest of the line" is preferred for free-form (string) values,
        // because the upstream `override string NAME with <text>` form takes the
        // remainder verbatim. For quoted single-word args the tokenizer has
        // already produced a single token, so this matches either way.
        let value_text = if value_idx >= 3 {
            // Skip "TYPE NAME [with] " in `rest` and take the verbatim tail.
            // `rest` is the raw remainder of the line after the token, with only
            // leading whitespace trimmed, so recompute the prefix length.
            // TYPE + NAME = args[0] + args[1] plus the optional "with" plus
            // their separating whitespace. Rather than reconstruct from `rest`,
            // we simply fall back to the already-tokenized `value_str`: when the
            // value spans multiple words the tokenizer split it into multiple
            // args, so re-join args[value_idx..] with single spaces (matches
            // what a writer would have re-quoted anyway).
            if args.len() > value_idx + 1 {
                args[value_idx..].join(" ")
            } else {
                value_str.to_string()
            }
        } else {
            value_str.to_string()
        };

        let Some((cat, id)) = resolve_ds_name(name) else {
            tracing::warn!(name = %name, "override: unknown DS name; skipping");
            continue;
        };

        match ty.to_ascii_lowercase().as_str() {
            "bool" | "boolean" => {
                let v = match value_str.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    other => {
                        tracing::warn!(
                            name = %name,
                            value = %other,
                            "override bool: unrecognized value (expected true/false); skipping"
                        );
                        continue;
                    }
                };
                store.set_bool(cat, id, v);
            }
            "integer" | "int" => match value_str.parse::<i64>() {
                Ok(v) => store.set_int(cat, id, v),
                Err(_) => {
                    tracing::warn!(
                        name = %name,
                        value = %value_str,
                        "override integer: not a valid integer; skipping"
                    );
                    continue;
                }
            },
            "string" | "str" => {
                store.set_string(cat, id, value_text);
            }
            other => {
                tracing::warn!(
                    kind = %other,
                    "override: unknown type (expected bool/integer/string); skipping"
                );
                continue;
            }
        }
    }
}

/// Read the standard `snmp.conf` files and apply any `override` directives.
///
/// This is the convenience entry point called early by client applications
/// (mirroring the implicit `init_snmp` → `read_premib_configs` step). It does
/// nothing if no configuration files are present.
pub fn load_default_store() {
    let dirs = crate::config::read_app_config("snmp");
    apply_override_directives(&dirs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;
    use ids::*;

    #[test]
    fn set_get_bool_roundtrip() {
        let store = DefaultStore::new();
        assert!(!store.get_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS));
        store.set_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS, true);
        assert!(store.get_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS));
        store.set_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS, false);
        assert!(!store.get_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS));
    }

    #[test]
    fn toggle_changes_and_returns_new_value() {
        let store = DefaultStore::new();
        // Missing slot is treated as false, so first toggle -> true.
        assert!(store.toggle_bool(DsCategory::Agent, AGENT_AGENTX_MASTER));
        assert!(store.get_bool(DsCategory::Agent, AGENT_AGENTX_MASTER));
        assert!(!store.toggle_bool(DsCategory::Agent, AGENT_AGENTX_MASTER));
        assert!(!store.get_bool(DsCategory::Agent, AGENT_AGENTX_MASTER));
    }

    #[test]
    fn set_get_int_roundtrip() {
        let store = DefaultStore::new();
        assert_eq!(store.get_int(DsCategory::Agent, AGENT_ROLE), 0);
        store.set_int(DsCategory::Agent, AGENT_ROLE, 42);
        assert_eq!(store.get_int(DsCategory::Agent, AGENT_ROLE), 42);
    }

    #[test]
    fn string_default_empty_and_opt() {
        let store = DefaultStore::new();
        assert_eq!(store.get_string(DsCategory::Agent, AGENT_PERSIST_DIR), "");
        assert_eq!(store.get_string_opt(DsCategory::Agent, AGENT_PERSIST_DIR), None);
        store.set_string(DsCategory::Agent, AGENT_PERSIST_DIR, "/var/lib/snmp");
        assert_eq!(store.get_string(DsCategory::Agent, AGENT_PERSIST_DIR), "/var/lib/snmp");
        assert_eq!(
            store.get_string_opt(DsCategory::Agent, AGENT_PERSIST_DIR),
            Some("/var/lib/snmp".to_string())
        );
    }

    #[test]
    fn category_isolation_same_id() {
        // The same `id` in two categories must be independent — this is the
        // whole point of the (cat, id) key.
        let store = DefaultStore::new();
        store.set_bool(DsCategory::Library, 7, true);
        store.set_bool(DsCategory::Agent, 7, false);
        assert!(store.get_bool(DsCategory::Library, 7));
        assert!(!store.get_bool(DsCategory::Agent, 7));
    }

    #[test]
    fn remove_and_clear() {
        let store = DefaultStore::new();
        store.set_int(DsCategory::Library, LIB_MIB_WARNINGS, 2);
        assert_eq!(store.len(), 1);
        assert!(store.remove(DsCategory::Library, LIB_MIB_WARNINGS));
        assert!(!store.remove(DsCategory::Library, LIB_MIB_WARNINGS));
        assert!(store.is_empty());

        store.set_int(DsCategory::Library, LIB_MIB_WARNINGS, 2);
        store.set_bool(DsCategory::Agent, AGENT_ROLE, true);
        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.get_int(DsCategory::Library, LIB_MIB_WARNINGS), 0);
    }

    #[test]
    fn resolve_ds_name_normalization() {
        assert_eq!(
            resolve_ds_name("printNumericOids"),
            Some((DsCategory::Library, LIB_PRINT_NUMERIC_OIDS))
        );
        assert_eq!(
            resolve_ds_name("DS_LIB_PRINT_NUMERIC_OIDS"),
            Some((DsCategory::Library, LIB_PRINT_NUMERIC_OIDS))
        );
        assert_eq!(
            resolve_ds_name("agentRole"),
            Some((DsCategory::Agent, AGENT_ROLE))
        );
        assert_eq!(
            resolve_ds_name("DS_AGENT_ROLE"),
            Some((DsCategory::Agent, AGENT_ROLE))
        );
        assert_eq!(
            resolve_ds_name("numericoids"),
            Some((DsCategory::Application, APP_NUMERIC_OIDS))
        );
        assert_eq!(resolve_ds_name("totally bogus name"), None);
    }

    #[test]
    fn override_directive_bool() {
        let dirs = parse_str("override bool printNumericOids true");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert!(store.get_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS));
    }

    #[test]
    fn override_directive_bool_with_keyword() {
        let dirs = parse_str("override bool printNumericOids with 1");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert!(store.get_bool(DsCategory::Library, LIB_PRINT_NUMERIC_OIDS));
    }

    #[test]
    fn override_directive_integer() {
        let dirs = parse_str("override integer agentRole 1");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert_eq!(store.get_int(DsCategory::Agent, AGENT_ROLE), 1);
    }

    #[test]
    fn override_directive_string() {
        let dirs = parse_str("override string persistdir /var/lib/snmp");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert_eq!(store.get_string(DsCategory::Agent, AGENT_PERSIST_DIR), "/var/lib/snmp");
    }

    #[test]
    fn override_directive_unknown_name_skipped() {
        let dirs = parse_str("override bool notARealName true");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert!(store.is_empty(), "no slot should have been written");
    }

    #[test]
    fn override_directive_malformed_skipped() {
        let dirs = parse_str("override bool"); // too few args
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert!(store.is_empty());
    }

    #[test]
    fn override_directive_ignores_other_tokens() {
        // Non-override lines must be left alone.
        let dirs = parse_str("rocommunity public\noverride integer agentTimeout 5");
        let store = DefaultStore::new();
        apply_override_directives_to(&store, &dirs);
        assert_eq!(store.get_int(DsCategory::Agent, AGENT_TIMEOUT), 5);
        assert_eq!(store.len(), 1);
    }
}
