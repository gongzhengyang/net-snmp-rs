//! SNMP-VIEW-BASED-ACM-MIB access control (RFC 3415).
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/vacm_conf.c` plus the
//! `vacm` checks in `agent/snmp_agent.c`. This module owns the in-memory VACM
//! tables — security-to-group mappings, access entries, view-tree-family rows
//! and contexts — and implements the access-check algorithm from RFC 3415 §3.
//!
//! # Default behaviour (backwards compatibility)
//!
//! An *empty* [`Vacm`] (no groups, access entries or views) is **permissive**:
//! [`Vacm::is_view_accessible`] returns `true` for every request. This keeps
//! existing agents (which never configure VACM) behaving exactly as before —
//! authentication alone gates access. As soon as the first group/access/view
//! is added, the full RFC 3415 algorithm is enforced and unconfigured
//! (securityModel, securityName) pairs are denied.
//!
//! # The algorithm
//!
//! [`Vacm::is_view_accessible`] implements the four RFC 3415 §3.2 stages:
//!
//! 1. **Select group** — find the [`VacmGroup`] whose `security_model` and
//!    `security_name` match the caller. `security_model == 0` is a wildcard.
//! 2. **Select access entry** — among the group's [`VacmAccess`] rows pick the
//!    one whose context prefix matches (longest prefix wins), whose security
//!    model matches (or is `0`) and whose minimum security level is met.
//! 3. **Select view name** — read/write/notify per `view_type`.
//! 4. **Family match** — walk the [`VacmView`] rows for that view name,
//!    applying the bit mask. An `Included` row that matches grants access; an
//!    `Excluded` row that matches denies it (exclusions override inclusions).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use netsnmp::config::Directive;
use netsnmp::oid::Oid;
use tracing::warn;

/// A view name: an opaque byte string of 1..32 bytes (RFC 3415 §2.1).
pub type ViewName = Vec<u8>;
/// A group name: an opaque byte string (RFC 3415 §2.2).
pub type GroupName = Vec<u8>;
/// A context name: an opaque byte string (RFC 3415 §2.3).
pub type ContextName = Vec<u8>;
/// A security name: the community string (v1/v2c) or USM user name (v3).
pub type SecurityName = Vec<u8>;

/// Which view of a [`VacmAccess`] entry a request consults.
///
/// This mirrors the `read`/`write`/`notify` view-name slots of
/// `vacmAccessEntry` (RFC 3415 §2.4). It is defined here, separately from
/// `netsnmp_apps::mgmt::ViewType` (which is *view-tree-family* included/excluded
/// type), because `netsnmp-apps` is not a dependency of `netsnmp-agent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessView {
    /// The read view (`vacmAccessReadViewName`): consulted for GET/GETNEXT.
    Read,
    /// The write view (`vacmAccessWriteViewName`): consulted for SET.
    Write,
    /// The notify view (`vacmAccessNotifyViewName`): consulted for notifications.
    Notify,
}

/// View-tree-family row type: whether a subtree is included or excluded from
/// the view (RFC 3415 §2.5, `vacmViewTreeFamilyType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTreeFamilyType {
    /// The subtree is included in the view.
    Included,
    /// The subtree is excluded from the view (overrides inclusions).
    Excluded,
}

impl ViewTreeFamilyType {
    /// The integer value carried by `vacmViewTreeFamilyType`.
    pub fn code(self) -> i64 {
        match self {
            ViewTreeFamilyType::Included => 1,
            ViewTreeFamilyType::Excluded => 2,
        }
    }

    /// Build from the on-wire integer (`1` = included, `2` = excluded).
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(ViewTreeFamilyType::Included),
            2 => Some(ViewTreeFamilyType::Excluded),
            _ => None,
        }
    }
}

/// One `vacmViewTreeFamilyEntry` row: a subtree plus a bit mask that defines
/// which sub-identifiers must match (RFC 3415 §2.5).
///
/// The `mask` is a bit string, MSB-first within each byte: bit `i` (byte
/// `i / 8`, bit `7 - (i % 8)`) corresponds to sub-identifier `i` of `subtree`.
/// A set bit means "this sub-identifier must match"; a clear bit makes the
/// remainder a wildcard.
#[derive(Clone, Debug)]
pub struct VacmView {
    /// The subtree OID this family entry applies to.
    pub subtree: Oid,
    /// The bit mask (MSB-first per byte). An empty mask matches the whole
    /// subtree exactly up to its length (see [`VacmView::matches`]).
    pub mask: Vec<u8>,
    /// Whether the subtree is included in or excluded from the view.
    pub typ: ViewTreeFamilyType,
}

impl VacmView {
    /// Whether `oid` falls within this family entry, applying the bit mask.
    ///
    /// Per RFC 3415 §3.1 the OID is compared arc-by-arc against `subtree`:
    ///
    /// * For each sub-identifier index `i` of `subtree`, if mask bit `i` is
    ///   **set**, `oid[i]` must equal `subtree[i]` (a required match).
    /// * The first sub-identifier whose mask bit is **clear** stops the
    ///   comparison — everything from that arc on is a wildcard, so the OID
    ///   matches as long as it shares the matched prefix.
    /// * If every mask bit (over the subtree length) is set, the OID must
    ///   equal the subtree over its whole length *and* be at least as long.
    /// * An **empty** mask is treated as "match the subtree exactly as a
    ///   prefix" — i.e. `oid` must start with `subtree`. This is the pragmatic
    ///   net-snmp behaviour for a family row created without an explicit mask.
    pub fn matches(&self, oid: &Oid) -> bool {
        let sub = self.subtree.as_slice();
        let oid = oid.as_slice();
        if self.mask.is_empty() {
            // Empty mask: require oid to start with subtree.
            return oid.len() >= sub.len() && oid[..sub.len()] == sub[..];
        }
        // Walk sub-identifiers of the subtree. Bit i is in byte i/8 at
        // position 7-(i%8) (MSB-first).
        for (i, &want) in sub.iter().enumerate() {
            let bit_set = {
                let byte = self.mask.get(i / 8).copied().unwrap_or(0);
                (byte >> (7 - (i % 8))) & 1 == 1
            };
            if bit_set {
                // Required match: oid must have this arc and it must equal.
                match oid.get(i) {
                    Some(&got) if got == want => continue,
                    _ => return false,
                }
            } else {
                // Wildcard from here: the prefix up to (but not including)
                // this arc must match, then anything goes.
                return oid.len() >= i && oid[..i] == sub[..i];
            }
        }
        // Every mask bit over the subtree was set and matched: require oid to
        // be at least as long as the subtree (the subtree is a strict prefix).
        oid.len() >= sub.len()
    }
}

/// A `vacmSecurityToGroupEntry` row: maps a (securityModel, securityName) pair
/// to a group name (RFC 3415 §2.3).
#[derive(Clone, Debug)]
pub struct VacmGroup {
    /// The security model this mapping applies to (`1`=v1, `2`=v2c, `3`=USM,
    /// `0` = wildcard — matches any model).
    pub security_model: i32,
    /// The security name (community string or USM user name).
    pub security_name: SecurityName,
    /// The group name this pair belongs to.
    pub group: GroupName,
}

/// Whether the context prefix must match exactly or as a prefix
/// (`vacmAccessContextMatch`, RFC 3415 §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextMatch {
    /// `contextName` must equal the access entry's `context_prefix` exactly.
    Exact,
    /// `contextName` must start with the access entry's `context_prefix`.
    Prefix,
}

impl Default for ContextMatch {
    fn default() -> Self {
        // RFC 3415 §2.4: the DEFVAL is exact(1).
        ContextMatch::Exact
    }
}

/// A `vacmAccessEntry` row: the views granted to a group for a given context
/// prefix, security model and minimum security level (RFC 3415 §2.4).
#[derive(Clone, Debug, Default)]
pub struct VacmAccess {
    /// The group name this access entry belongs to.
    pub group: GroupName,
    /// The context prefix matched against the request's context name.
    pub context_prefix: ContextName,
    /// The security model (`1`=v1, `2`=v2c, `3`=USM, `0`=any).
    pub security_model: i32,
    /// The minimum security level required (0=noAuthNoPriv, 1=authNoPriv,
    /// 3=authPriv). A request at a *higher* level than this still matches.
    pub security_level: i32,
    /// How `context_prefix` is matched against the request context name.
    pub context_match: ContextMatch,
    /// The read view name (None / empty = no read access).
    pub read_view: Option<ViewName>,
    /// The write view name (None / empty = no write access).
    pub write_view: Option<ViewName>,
    /// The notify view name (None / empty = no notify access).
    pub notify_view: Option<ViewName>,
}

/// The SNMP-VIEW-BASED-ACM-MIB access control state.
///
/// Holds the four VACM tables behind [`RwLock`]s so configuration mutations
/// (e.g. a `snmpvacm` SET adding a row) and concurrent request checks do not
/// block each other for long. Created once per agent and shared (via [`Arc`])
/// between the request dispatch path and the live MIB handlers in
/// [`crate::mibgroup::vacm`].
#[derive(Default)]
pub struct Vacm {
    groups: RwLock<Vec<VacmGroup>>,
    access: RwLock<Vec<VacmAccess>>,
    views: RwLock<HashMap<ViewName, Vec<VacmView>>>,
    contexts: RwLock<Vec<ContextName>>,
}

impl std::fmt::Debug for Vacm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vacm")
            .field("groups", &self.groups.read().map(|d| d.len()).unwrap_or(0))
            .field("access", &self.access.read().map(|d| d.len()).unwrap_or(0))
            .field("views", &self.views.read().map(|d| d.len()).unwrap_or(0))
            .field("contexts", &self.contexts.read().map(|d| d.len()).unwrap_or(0))
            .finish()
    }
}

impl Vacm {
    /// Create an empty `Vacm` (permissive: see the module-level docs).
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the VACM has no configured state at all. When `true`, the agent
    /// treats every request as accessible (backwards compatibility).
    pub fn is_empty(&self) -> bool {
        let g = self.groups.read().unwrap_or_else(|e| e.into_inner());
        if !g.is_empty() {
            return false;
        }
        let a = self.access.read().unwrap_or_else(|e| e.into_inner());
        if !a.is_empty() {
            return false;
        }
        let v = self.views.read().unwrap_or_else(|e| e.into_inner());
        v.is_empty()
    }

    /// Add a security-to-group mapping.
    pub fn add_group(&self, group: VacmGroup) {
        let mut g = self.groups.write().unwrap_or_else(|e| e.into_inner());
        // Replace any existing mapping for the same (model, name).
        if let Some(slot) = g
            .iter_mut()
            .find(|e| e.security_model == group.security_model && e.security_name == group.security_name)
        {
            *slot = group;
        } else {
            g.push(group);
        }
    }

    /// Remove the security-to-group mapping for `(security_model, security_name)`.
    /// Returns `true` if a row was removed.
    pub fn remove_group(&self, security_model: i32, security_name: &SecurityName) -> bool {
        let mut g = self.groups.write().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|e| !(e.security_model == security_model && e.security_name == *security_name));
        g.len() != before
    }

    /// Add an access entry. A duplicate `(group, context_prefix, security_model,
    /// security_level)` replaces the existing row.
    pub fn add_access(&self, access: VacmAccess) {
        let mut a = self.access.write().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = a.iter_mut().find(|e| {
            e.group == access.group
                && e.context_prefix == access.context_prefix
                && e.security_model == access.security_model
                && e.security_level == access.security_level
        }) {
            *slot = access;
        } else {
            a.push(access);
        }
    }

    /// Remove the access entry identified by `(group, context_prefix,
    /// security_model, security_level)`. Returns `true` if a row was removed.
    pub fn remove_access(
        &self,
        group: &GroupName,
        context_prefix: &ContextName,
        security_model: i32,
        security_level: i32,
    ) -> bool {
        let mut a = self.access.write().unwrap_or_else(|e| e.into_inner());
        let before = a.len();
        a.retain(|e| {
            !(e.group == *group
                && e.context_prefix == *context_prefix
                && e.security_model == security_model
                && e.security_level == security_level)
        });
        a.len() != before
    }

    /// Add a view-tree-family row under `view_name`.
    pub fn add_view(&self, view_name: ViewName, view: VacmView) {
        let mut v = self.views.write().unwrap_or_else(|e| e.into_inner());
        let rows = v.entry(view_name).or_default();
        // Replace an existing row with the same subtree.
        if let Some(slot) = rows.iter_mut().find(|r| r.subtree == view.subtree) {
            *slot = view;
        } else {
            rows.push(view);
        }
    }

    /// Remove the view-tree-family row `(view_name, subtree)`. Returns `true`
    /// if a row was removed.
    pub fn remove_view(&self, view_name: &ViewName, subtree: &Oid) -> bool {
        let mut v = self.views.write().unwrap_or_else(|e| e.into_inner());
        let Some(rows) = v.get_mut(view_name) else {
            return false;
        };
        let before = rows.len();
        rows.retain(|r| r.subtree != *subtree);
        let removed = rows.len() != before;
        if removed && rows.is_empty() {
            // Drop the now-empty view entry. `rows` is a borrow into `v`, so
            // re-check membership before removing to satisfy the borrow checker.
            if v.get(view_name).map(|r| r.is_empty()).unwrap_or(true) {
                v.remove(view_name);
            }
        }
        removed
    }

    /// Register a context name (`vacmContextTable`).
    pub fn add_context(&self, context: ContextName) {
        let mut c = self.contexts.write().unwrap_or_else(|e| e.into_inner());
        if !c.iter().any(|x| x == &context) {
            c.push(context);
        }
    }

    /// Remove a registered context name. Returns `true` if removed.
    pub fn remove_context(&self, context: &ContextName) -> bool {
        let mut c = self.contexts.write().unwrap_or_else(|e| e.into_inner());
        let before = c.len();
        c.retain(|x| x != context);
        c.len() != before
    }

    /// Drop every configured group, access entry, view and context. After this
    /// the [`Vacm`] is permissive again (see [`Vacm::is_empty`]).
    pub fn clear(&self) {
        self.groups.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.access.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.views.write().unwrap_or_else(|e| e.into_inner()).clear();
        self.contexts.write().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// A snapshot of the registered context names, sorted lexicographically.
    pub fn contexts(&self) -> Vec<ContextName> {
        let mut c = self
            .contexts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        c.sort();
        c
    }

    /// A snapshot of the security-to-group mappings.
    pub fn groups(&self) -> Vec<VacmGroup> {
        self.groups.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// A snapshot of the access entries.
    pub fn access(&self) -> Vec<VacmAccess> {
        self.access.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// A snapshot of the view-tree-family rows under `view_name`.
    pub fn views_for(&self, view_name: &ViewName) -> Vec<VacmView> {
        self.views
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(view_name)
            .cloned()
            .unwrap_or_default()
    }

    /// All view names currently configured (sorted), with their rows.
    pub fn views(&self) -> Vec<(ViewName, Vec<VacmView>)> {
        let v = self.views.read().unwrap_or_else(|e| e.into_inner());
        let mut entries: Vec<(ViewName, Vec<VacmView>)> = v
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Look up the group name for `(security_model, security_name)`, applying
    /// the RFC 3415 §3.2 step (1) selection: an exact-model match wins; a
    /// wildcard model (`0`) is the fallback.
    pub fn group_for(&self, security_model: i32, security_name: &SecurityName) -> Option<GroupName> {
        let g = self.groups.read().unwrap_or_else(|e| e.into_inner());
        // Prefer an exact security_model match.
        if let Some(e) = g
            .iter()
            .find(|e| e.security_model == security_model && e.security_name == *security_name)
        {
            return Some(e.group.clone());
        }
        // Fall back to a wildcard (model 0) entry.
        g.iter()
            .find(|e| e.security_model == 0 && e.security_name == *security_name)
            .map(|e| e.group.clone())
    }

    /// Whether `oid` is accessible to the caller under the given view type,
    /// implementing the RFC 3415 §3.2 algorithm.
    ///
    /// Returns `true` for an empty [`Vacm`] (permissive default) and `false`
    /// once configured if the caller fails any of the four stages.
    pub fn is_view_accessible(
        &self,
        view_type: AccessView,
        security_model: i32,
        security_name: &SecurityName,
        security_level: i32,
        context_name: &ContextName,
        oid: &Oid,
    ) -> bool {
        // Backwards compatibility: an unconfigured VACM allows everything.
        if self.is_empty() {
            return true;
        }

        // Step 1: select the group.
        let Some(group) = self.group_for(security_model, security_name) else {
            return false;
        };

        // Step 2: select the access entry for that group. Among the matching
        // rows pick the one with the longest context prefix (RFC 3415 §3.2
        // step 2: "the exact match ... otherwise ... the longest prefix").
        let access = self.access.read().unwrap_or_else(|e| e.into_inner());
        let matching: Vec<&VacmAccess> = access
            .iter()
            .filter(|a| a.group == group)
            .filter(|a| a.security_model == security_model || a.security_model == 0)
            .filter(|a| security_level >= a.security_level)
            .filter(|a| context_matches(a.context_match, &a.context_prefix, context_name))
            .collect();
        // Pick the longest context_prefix, then prefer an exact security_model
        // match over a wildcard.
        let Some(access) = matching
            .into_iter()
            .max_by(|a, b| {
                a.context_prefix
                    .len()
                    .cmp(&b.context_prefix.len())
                    .then_with(|| {
                        // Prefer exact model (non-zero) over wildcard (0).
                        let a_exact = i32::from(a.security_model != 0);
                        let b_exact = i32::from(b.security_model != 0);
                        a_exact.cmp(&b_exact)
                    })
            })
        else {
            return false;
        };

        // Step 3: select the view name for the requested view type.
        let view_name = match view_type {
            AccessView::Read => &access.read_view,
            AccessView::Write => &access.write_view,
            AccessView::Notify => &access.notify_view,
        };
        let Some(view_name) = view_name else {
            return false;
        };
        if view_name.is_empty() {
            return false;
        }

        // Step 4: family match. Walk every family row under that view name.
        let views = self.views.read().unwrap_or_else(|e| e.into_inner());
        let Some(rows) = views.get(view_name) else {
            // A named view with no rows matches nothing.
            return false;
        };

        // An inclusion grants; an exclusion (that matches) denies, overriding
        // any earlier inclusion. Walk all rows: track the strongest signal.
        let mut included = false;
        for row in rows {
            if row.matches(oid) {
                if row.typ == ViewTreeFamilyType::Excluded {
                    return false;
                }
                included = true;
            }
        }
        included
    }

    /// Parse Net-SNMP `snmpd.conf` VACM directives into a fresh [`Vacm`].
    ///
    /// Recognises `com2sec`/`com2sec6`, `group`, `view`, `access`/`access2`
    /// and the `rocommunity`/`rwcommunity` shortcuts. Unknown directives are
    /// skipped; malformed lines emit a `tracing::warn!` and are skipped.
    pub fn from_config_directives(directives: &[Directive]) -> Arc<Self> {
        let vacm = Arc::new(Self::new());
        for d in directives {
            if d.is("com2sec") || d.is("com2sec6") {
                apply_com2sec(&vacm, d);
            } else if d.is("group") {
                apply_group(&vacm, d);
            } else if d.is("view") {
                apply_view(&vacm, d);
            } else if d.is("access") || d.is("access2") {
                apply_access(&vacm, d);
            } else if d.is("rocommunity") || d.is("rocommunity6") {
                apply_rocommunity(&vacm, d, false);
            } else if d.is("rwcommunity") || d.is("rwcommunity6") {
                apply_rwcommunity(&vacm, d);
            }
            // Everything else is silently ignored: VACM only owns its own
            // directives, not the rest of snmpd.conf.
        }
        vacm
    }
}

/// Whether `context_name` matches `prefix` under the given match rule.
fn context_matches(match_type: ContextMatch, prefix: &ContextName, context_name: &ContextName) -> bool {
    match match_type {
        ContextMatch::Exact => prefix == context_name,
        ContextMatch::Prefix => context_name.starts_with(prefix),
    }
}

/// Map a security-model keyword from `snmpd.conf` to its integer value.
fn parse_model(word: &str) -> Option<i32> {
    match word.to_ascii_lowercase().as_str() {
        "v1" | "snmpv1" => Some(1),
        "v2c" | "snmpv2c" => Some(2),
        "usm" => Some(3),
        "any" | "" => Some(0),
        other => other.parse().ok(),
    }
}

/// Map a security-level keyword from `snmpd.conf` to its integer value.
fn parse_level(word: &str) -> Option<i32> {
    match word.to_ascii_lowercase().as_str() {
        "noauth" | "noauthnopriv" | "noauthnoprivacy" => Some(0),
        "auth" | "authnopriv" | "authnoprivacy" => Some(1),
        "priv" | "authpriv" | "authprivacy" => Some(3),
        other => other.parse().ok(),
    }
}

/// Parse a hex-or-decimal mask argument like `0xff` or `fe` into bytes.
fn parse_mask(word: &str) -> Vec<u8> {
    let stripped = word
        .strip_prefix("0x")
        .or_else(|| word.strip_prefix("0X"))
        .unwrap_or(word);
    // Accept bare hex digits (e.g. `fe` or `fe80`), even length.
    if !stripped.is_empty()
        && stripped.len() % 2 == 0
        && stripped.chars().all(|c| c.is_ascii_hexdigit())
    {
        return (0..stripped.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&stripped[i..i + 2], 16).ok())
            .collect();
    }
    // Otherwise treat as a literal byte string.
    word.as_bytes().to_vec()
}

/// Apply a `com2sec [-C] NAME SOURCE COMMUNITY` directive.
///
/// Maps to a security-to-group row: the group is named `NAME`, the security
/// name is `COMMUNITY`, and the model is `2` (v2c) — net-snmp's `com2sec`
/// applies to both v1 and v2c, so we also add a v1 mapping.
fn apply_com2sec(vacm: &Vacm, d: &Directive) {
    // Skip the optional `-C` context flag if present.
    let mut args = d.args.iter().skip_while(|a| a.starts_with('-'));
    let Some(name) = args.next() else {
        warn!(line = d.line_no, "com2sec missing NAME");
        return;
    };
    let Some(_source) = args.next() else {
        warn!(line = d.line_no, "com2sec missing SOURCE");
        return;
    };
    let Some(community) = args.next() else {
        warn!(line = d.line_no, "com2sec missing COMMUNITY");
        return;
    };
    let group = name.as_bytes().to_vec();
    let sec_name = community.as_bytes().to_vec();
    vacm.add_group(VacmGroup {
        security_model: 1,
        security_name: sec_name.clone(),
        group: group.clone(),
    });
    vacm.add_group(VacmGroup {
        security_model: 2,
        security_name: sec_name,
        group,
    });
}

/// Apply a `group NAME MODEL SECURITYNAME` directive.
fn apply_group(vacm: &Vacm, d: &Directive) {
    let mut args = d.args.iter();
    let Some(name) = args.next() else {
        warn!(line = d.line_no, "group missing NAME");
        return;
    };
    let Some(model_word) = args.next() else {
        warn!(line = d.line_no, "group missing MODEL");
        return;
    };
    let Some(sec_name) = args.next() else {
        warn!(line = d.line_no, "group missing SECURITYNAME");
        return;
    };
    let Some(model) = parse_model(model_word) else {
        warn!(line = d.line_no, model = model_word, "group: unknown MODEL");
        return;
    };
    vacm.add_group(VacmGroup {
        security_model: model,
        security_name: sec_name.as_bytes().to_vec(),
        group: name.as_bytes().to_vec(),
    });
}

/// Apply a `view NAME TYPE SUBTREE [MASK]` directive.
fn apply_view(vacm: &Vacm, d: &Directive) {
    let mut args = d.args.iter();
    let Some(name) = args.next() else {
        warn!(line = d.line_no, "view missing NAME");
        return;
    };
    let Some(typ_word) = args.next() else {
        warn!(line = d.line_no, "view missing TYPE");
        return;
    };
    let Some(subtree_word) = args.next() else {
        warn!(line = d.line_no, "view missing SUBTREE");
        return;
    };
    let typ = match typ_word.to_ascii_lowercase().as_str() {
        "included" | "include" => ViewTreeFamilyType::Included,
        "excluded" | "exclude" => ViewTreeFamilyType::Excluded,
        other => {
            warn!(line = d.line_no, typ = other, "view: unknown TYPE");
            return;
        }
    };
    let Ok(subtree) = subtree_word.parse::<Oid>() else {
        warn!(line = d.line_no, subtree = subtree_word, "view: bad SUBTREE OID");
        return;
    };
    let mask = args.next().map(|m| parse_mask(m)).unwrap_or_default();
    vacm.add_view(
        name.as_bytes().to_vec(),
        VacmView {
            subtree,
            mask,
            typ,
        },
    );
}

/// Apply an `access NAME CTX MODEL LEVEL [PREFIX] READ WRITE NOTIFY` directive.
fn apply_access(vacm: &Vacm, d: &Directive) {
    let args: Vec<&str> = d.args.iter().map(String::as_str).collect();
    if args.len() < 7 {
        warn!(line = d.line_no, "access: need at least 7 args");
        return;
    }
    let group = args[0].as_bytes().to_vec();
    let context_prefix = args[1].as_bytes().to_vec();
    let Some(model) = parse_model(args[2]) else {
        warn!(line = d.line_no, model = args[2], "access: unknown MODEL");
        return;
    };
    let Some(level) = parse_level(args[3]) else {
        warn!(line = d.line_no, level = args[3], "access: unknown LEVEL");
        return;
    };
    // `access` (7-arg form) has no explicit context-match word; `access2`
    // inserts one (exact/prefix) between LEVEL and READ. Detect it.
    let (context_match, read_idx) = if args.len() >= 8
        && matches!(
            args[4].to_ascii_lowercase().as_str(),
            "exact" | "prefix"
        ) {
        let cm = if args[4].eq_ignore_ascii_case("prefix") {
            ContextMatch::Prefix
        } else {
            ContextMatch::Exact
        };
        (cm, 5)
    } else {
        (ContextMatch::Exact, 4)
    };
    let view_or_none = |s: &str| -> Option<ViewName> {
        if s.is_empty() || s == "NULL" || s == "null" {
            None
        } else {
            Some(s.as_bytes().to_vec())
        }
    };
    let read_view = view_or_none(args[read_idx]);
    let write_view = view_or_none(args[read_idx + 1]);
    let notify_view = view_or_none(args[read_idx + 2]);
    vacm.add_access(VacmAccess {
        group,
        context_prefix,
        security_model: model,
        security_level: level,
        context_match,
        read_view,
        write_view,
        notify_view,
    });
}

/// Apply an `rocommunity COMMUNITY [SOURCE] [OID]` shortcut.
///
/// Expands to a `com2sec` + `group` + `view` + `access` quartet granting the
/// community read access to `OID` (default `1`, i.e. the whole tree).
fn apply_rocommunity(vacm: &Vacm, d: &Directive, _writable: bool) {
    let args: Vec<&str> = d.args.iter().map(String::as_str).collect();
    if args.is_empty() {
        warn!(line = d.line_no, "rocommunity missing COMMUNITY");
        return;
    }
    let community = args[0];
    // args[1] is SOURCE (default "default"); args[2] is the OID.
    let oid_word = args.get(2).copied().unwrap_or(".1");
    let subtree = oid_word.parse::<Oid>().unwrap_or_else(|_| {
        warn!(line = d.line_no, oid = oid_word, "rocommunity: bad OID, defaulting to .1");
        "1.3.6.1.2.1".parse().unwrap()
    });
    let group = format!("community_{community}").into_bytes();
    let view = format!("ro_{community}").into_bytes();
    vacm.add_group(VacmGroup {
        security_model: 1,
        security_name: community.as_bytes().to_vec(),
        group: group.clone(),
    });
    vacm.add_group(VacmGroup {
        security_model: 2,
        security_name: community.as_bytes().to_vec(),
        group: group.clone(),
    });
    vacm.add_view(
        view.clone(),
        VacmView {
            subtree,
            mask: Vec::new(),
            typ: ViewTreeFamilyType::Included,
        },
    );
    vacm.add_access(VacmAccess {
        group,
        context_prefix: Vec::new(),
        security_model: 0,
        security_level: 0,
        context_match: ContextMatch::Prefix,
        read_view: Some(view),
        write_view: None,
        notify_view: None,
    });
}

/// Apply an `rwcommunity COMMUNITY [SOURCE] [OID]` shortcut (read+write).
fn apply_rwcommunity(vacm: &Vacm, d: &Directive) {
    let args: Vec<&str> = d.args.iter().map(String::as_str).collect();
    if args.is_empty() {
        warn!(line = d.line_no, "rwcommunity missing COMMUNITY");
        return;
    }
    let community = args[0];
    let oid_word = args.get(2).copied().unwrap_or(".1");
    let subtree = oid_word.parse::<Oid>().unwrap_or_else(|_| {
        warn!(line = d.line_no, oid = oid_word, "rwcommunity: bad OID, defaulting to .1");
        "1.3.6.1.2.1".parse().unwrap()
    });
    let group = format!("community_{community}").into_bytes();
    let view = format!("rw_{community}").into_bytes();
    vacm.add_group(VacmGroup {
        security_model: 1,
        security_name: community.as_bytes().to_vec(),
        group: group.clone(),
    });
    vacm.add_group(VacmGroup {
        security_model: 2,
        security_name: community.as_bytes().to_vec(),
        group: group.clone(),
    });
    vacm.add_view(
        view.clone(),
        VacmView {
            subtree,
            mask: Vec::new(),
            typ: ViewTreeFamilyType::Included,
        },
    );
    vacm.add_access(VacmAccess {
        group,
        context_prefix: Vec::new(),
        security_model: 0,
        security_level: 0,
        context_match: ContextMatch::Prefix,
        read_view: Some(view.clone()),
        write_view: Some(view),
        notify_view: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Vacm` granting community `public` read access to `1.3.6.1.2.1.1`
    /// (the `system` group) and nothing else.
    fn sample_vacm() -> Vacm {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g1".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g1".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"system".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"system".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        vacm
    }

    #[test]
    fn empty_vacm_is_permissive() {
        let vacm = Vacm::new();
        assert!(vacm.is_empty());
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn configured_view_allows_in_subtree() {
        let vacm = sample_vacm();
        assert!(!vacm.is_empty());
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.5.0".parse().unwrap(),
        ));
    }

    #[test]
    fn configured_view_denies_outside_subtree() {
        let vacm = sample_vacm();
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.2.2.1.2.1".parse().unwrap(), // interfaces
        ));
    }

    #[test]
    fn unknown_security_name_denied() {
        let vacm = sample_vacm();
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"secret".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn write_view_absent_denies_set() {
        let vacm = sample_vacm();
        // No write view configured: SET must be denied.
        assert!(!vacm.is_view_accessible(
            AccessView::Write,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn wildcard_security_model_matches() {
        let vacm = Vacm::new();
        // Group registered only for model 0 (any).
        vacm.add_group(VacmGroup {
            security_model: 0,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        // A v2c request (model 2) matches the wildcard group.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // A USM request (model 3) also matches.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            3,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn security_level_minimum_enforced() {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 3,
            security_name: b"alice".to_vec(),
            group: b"g".to_vec(),
        });
        // Access requires authPriv (level 3).
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 3,
            security_level: 3,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        // noAuthNoPriv request (level 0) is denied.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            3,
            &b"alice".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // authPriv request (level 3) is allowed.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            3,
            &b"alice".to_vec(),
            3,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn exact_context_match() {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: b"ctxA".to_vec(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Exact,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        // Exact context matches.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &b"ctxA".to_vec(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // A prefix of ctxA does NOT match under Exact.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &b"ctx".to_vec(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // Empty context does not match ctxA either.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn longest_context_prefix_wins() {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        // A short prefix granting access to a "narrow" view that denies the OID.
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"none".to_vec()),
            write_view: None,
            notify_view: None,
        });
        // A longer prefix granting access to the real view.
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: b"ctx".to_vec(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"all".to_vec()),
            write_view: None,
            notify_view: None,
        });
        vacm.add_view(
            b"all".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        // `none` view is empty (no rows) -> nothing matches.
        // Request with context "ctxFoo" should select the longer-prefix row.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &b"ctxFoo".to_vec(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn excluded_view_overrides_inclusion() {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        // Include the whole tree...
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Included,
            },
        );
        // ...but exclude the interfaces subtree.
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1.2".parse().unwrap(),
                mask: Vec::new(),
                typ: ViewTreeFamilyType::Excluded,
            },
        );
        // system is included.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // interfaces is excluded.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.2.2.1.2.1".parse().unwrap(),
        ));
    }

    #[test]
    fn mask_wildcards_early_arc() {
        // A view with subtree 1.3.6.1.2.1 and a mask that only requires the
        // first arc to match (bit 0 set) should match any OID starting with 1.
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        // Mask 0x80 = bit 0 set -> only subid 0 must match.
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1".parse().unwrap(),
                mask: vec![0x80],
                typ: ViewTreeFamilyType::Included,
            },
        );
        // Any OID starting with 1 matches.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.99.99.99".parse().unwrap(),
        ));
        // An OID starting with 2 does not match.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"2.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn mask_full_match_requires_prefix() {
        // Subtree 1.3.6.1.2.1.1 with a full mask (all bits set) requires the
        // OID to start with exactly that subtree.
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"g".to_vec(),
        });
        vacm.add_access(VacmAccess {
            group: b"g".to_vec(),
            context_prefix: Vec::new(),
            security_model: 0,
            security_level: 0,
            context_match: ContextMatch::Prefix,
            read_view: Some(b"v".to_vec()),
            write_view: None,
            notify_view: None,
        });
        // 7 subids -> bits 0..6 all set = bytes 0xFE 0x80 (7 bits).
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: "1.3.6.1.2.1.1".parse().unwrap(),
                mask: vec![0xfe, 0x80],
                typ: ViewTreeFamilyType::Included,
            },
        );
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.5.0".parse().unwrap(),
        ));
        // An OID that diverges at arc 5 (1.3.6.1.2.2...) must NOT match.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.2.1.1".parse().unwrap(),
        ));
    }

    #[test]
    fn group_for_prefers_exact_model() {
        let vacm = Vacm::new();
        vacm.add_group(VacmGroup {
            security_model: 0,
            security_name: b"public".to_vec(),
            group: b"anygroup".to_vec(),
        });
        vacm.add_group(VacmGroup {
            security_model: 2,
            security_name: b"public".to_vec(),
            group: b"v2cgroup".to_vec(),
        });
        // A v2c request should pick the exact-model row.
        assert_eq!(
            vacm.group_for(2, &b"public".to_vec()),
            Some(b"v2cgroup".to_vec())
        );
        // A USM request falls back to the wildcard.
        assert_eq!(
            vacm.group_for(3, &b"public".to_vec()),
            Some(b"anygroup".to_vec())
        );
        // Unknown name -> None.
        assert_eq!(vacm.group_for(2, &b"other".to_vec()), None);
    }

    #[test]
    fn add_view_replaces_same_subtree() {
        let vacm = Vacm::new();
        let s: Oid = "1.3.6.1.2.1".parse().unwrap();
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: s.clone(),
                mask: vec![],
                typ: ViewTreeFamilyType::Included,
            },
        );
        vacm.add_view(
            b"v".to_vec(),
            VacmView {
                subtree: s.clone(),
                mask: vec![0x80],
                typ: ViewTreeFamilyType::Excluded,
            },
        );
        let rows = vacm.views_for(&b"v".to_vec());
        assert_eq!(rows.len(), 1, "expected replacement, got {rows:?}");
        assert_eq!(rows[0].typ, ViewTreeFamilyType::Excluded);
    }

    #[test]
    fn remove_view_and_clear_work() {
        let vacm = sample_vacm();
        assert!(!vacm.is_empty());
        let s: Oid = "1.3.6.1.2.1.1".parse().unwrap();
        assert!(vacm.remove_view(&b"system".to_vec(), &s));
        vacm.clear();
        assert!(vacm.is_empty());
    }

    #[test]
    fn from_config_rocommunity_grants_read() {
        let dirs = netsnmp::config::parse_str("rocommunity public default .1.3.6.1.2.1.1");
        let vacm = Vacm::from_config_directives(&dirs);
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // Outside the granted subtree.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.2.2.1.2.1".parse().unwrap(),
        ));
        // rocommunity grants no write access.
        assert!(!vacm.is_view_accessible(
            AccessView::Write,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn from_config_rwcommunity_grants_read_and_write() {
        let dirs = netsnmp::config::parse_str("rwcommunity private");
        let vacm = Vacm::from_config_directives(&dirs);
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"private".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        assert!(vacm.is_view_accessible(
            AccessView::Write,
            2,
            &b"private".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // A different community is denied.
        assert!(!vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"other".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }

    #[test]
    fn from_config_group_view_access() {
        let conf = "\
group g1 v2c public
view all included .1.3.6.1.2.1
view sys included .1.3.6.1.2.1.1
view sysif excluded .1.3.6.1.2.1.2
access g1 \"\" any noauth prefix all NULL all
";
        let dirs = netsnmp::config::parse_str(conf);
        let vacm = Vacm::from_config_directives(&dirs);
        // public can read system.
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
        // public can read interfaces (all includes .1.3.6.1.2.1).
        assert!(vacm.is_view_accessible(
            AccessView::Read,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.2.2.1.2.1".parse().unwrap(),
        ));
        // No write view (NULL) -> SET denied.
        assert!(!vacm.is_view_accessible(
            AccessView::Write,
            2,
            &b"public".to_vec(),
            0,
            &Vec::new(),
            &"1.3.6.1.2.1.1.1.0".parse().unwrap(),
        ));
    }
}
