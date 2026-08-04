//! MIB object-name registry and OID translation.
//!
//! This is the high-level counterpart of `snmplib/mib.c`: a bidirectional
//! name↔OID registry plus symbolic value formatting. It is seeded with a
//! compact set of built-in MIB-II names so the tools work offline, and can be
//! populated from real MIB files by [`MibRegistry::load_dir`] /
//! [`MibRegistry::load_file`], which drive the SMI parser in [`crate::smi`]
//! (the `parse.c` reimplementation).

use crate::oid::Oid;
use crate::smi::{self, Access, BaseType, Constraint, ObjectDef, Syntax, TextualConvention};
use crate::value::Value;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Maximum number of MIB files read concurrently in [`MibRegistry::load_dir`].
/// Bounds the in-flight `tokio::fs` reads so a large `mibs/` tree loads fast
/// without spawning an unbounded number of blocking filesystem operations.
const MAX_CONCURRENT_FILE_READS: usize = 64;

/// Error returned by [`MibRegistry::validate_value`] when a value violates the
/// type or constraint metadata of a registered object definition.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ConstraintError {
    /// No object definition is known for the OID (nothing to validate against).
    #[error("no object definition registered for OID {oid}")]
    Unknown {
        /// The OID that had no registered definition.
        oid: Oid,
    },
    /// The value's SMI type does not match the object's SYNTAX.
    #[error("wrong type: expected {expected}, got {actual}")]
    WrongType {
        /// Expected base type label.
        expected: &'static str,
        /// Actual value type label.
        actual: &'static str,
    },
    /// An INTEGER value fell outside the declared range subranges.
    #[error("integer {value} out of declared range")]
    OutOfRange {
        /// The offending value.
        value: i64,
    },
    /// An OCTET STRING length violated the declared SIZE constraint.
    #[error("octet string length {len} violates SIZE constraint")]
    WrongSize {
        /// The offending length.
        len: usize,
    },
}

/// A bidirectional registry mapping symbolic names to numeric OIDs, plus
/// optional INTEGER enumerations for symbolic value display. It additionally
/// holds the structured (semantic) object definitions and textual conventions
/// parsed by the SMI module (Task 5.17), enabling SYNTAX/STATUS/DESCRIPTION
/// display, writability checks and value-constraint validation.
#[derive(Debug, Clone)]
pub struct MibRegistry {
    by_name: BTreeMap<String, Oid>,
    by_oid: BTreeMap<Oid, String>,
    enums: BTreeMap<Oid, Vec<(i64, String)>>,
    /// Structured OBJECT-TYPE definitions keyed by their numeric OID.
    object_defs: BTreeMap<Oid, ObjectDef>,
    /// Textual conventions keyed by their (case-sensitive) name.
    tcs: BTreeMap<String, TextualConvention>,
    /// Per-OID defining module name (best-effort), for `-Of` qualified names.
    module_of: BTreeMap<Oid, String>,
}

impl Default for MibRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

impl MibRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        MibRegistry {
            by_name: BTreeMap::new(),
            by_oid: BTreeMap::new(),
            enums: BTreeMap::new(),
            object_defs: BTreeMap::new(),
            tcs: BTreeMap::new(),
            module_of: BTreeMap::new(),
        }
    }

    /// Create a registry pre-populated with common MIB-II object names.
    pub fn with_builtins() -> Self {
        let mut r = MibRegistry::new();
        for (name, oid) in BUILTINS {
            r.insert(name, oid.parse().expect("valid builtin OID"));
        }
        r
    }

    /// Register a name/OID pair (both lookup directions).
    pub fn insert(&mut self, name: &str, oid: Oid) {
        self.by_name.insert(name.to_string(), oid.clone());
        self.by_oid.insert(oid, name.to_string());
    }

    /// Register an INTEGER enumeration (value → label) for an OID.
    pub fn insert_enum(&mut self, oid: Oid, pairs: Vec<(i64, String)>) {
        if !pairs.is_empty() {
            self.enums.insert(oid, pairs);
        }
    }

    /// Ingest the objects produced by the SMI parser, registering names,
    /// OIDs, and any enumerations. Returns the number of objects added.
    pub fn add_objects(&mut self, objects: Vec<crate::smi::MibObject>) -> usize {
        let mut added = 0;
        for obj in objects {
            // Earlier definitions win on name collisions, but always learn the
            // OID→name mapping and enums.
            self.by_name
                .entry(obj.name.clone())
                .or_insert_with(|| obj.oid.clone());
            self.by_oid
                .entry(obj.oid.clone())
                .or_insert_with(|| obj.name.clone());
            if let Some(pairs) = obj.enums {
                self.insert_enum(obj.oid.clone(), pairs);
            }
            added += 1;
        }
        added
    }

    /// Parse MIB module text and add its objects. Returns the count added.
    ///
    /// The registry's current name→OID bindings are passed to the SMI resolver
    /// as seeds, so modules that anchor at names defined elsewhere (e.g.
    /// `enterprises`, `mib-2`) resolve correctly.
    ///
    /// In the same pass this also ingests the structured (semantic) object
    /// definitions and textual conventions produced by the richer SMI parser
    /// (Task 5.17). That enrichment is best-effort: any failure in the rich
    /// path leaves the authoritative OID path untouched.
    pub fn load_str(&mut self, text: &str) -> usize {
        let seeds: std::collections::HashMap<String, Oid> = self
            .by_name
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let added = self.add_objects(crate::smi::parse_text_with_seeds(text, &seeds));
        // Best-effort semantic enrichment: never let a failure here drop OIDs.
        self.ingest_semantic(text);
        added
    }

    /// Parse and store the structured OBJECT-TYPE definitions, textual
    /// conventions, and module-name annotations from `text`. Failures are
    /// swallowed so the OID-only path always wins. The registry's current
    /// name→OID bindings are passed as seeds so object OIDs that anchor at
    /// cross-module roots (e.g. `enterprises`) resolve correctly.
    fn ingest_semantic(&mut self, text: &str) {
        let module = module_name_of(text);
        let seeds: std::collections::HashMap<String, Oid> = self
            .by_name
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let defs = smi::parse_object_defs_with_seeds(text, &seeds);
        for mut def in defs {
            if def.oid.is_empty() {
                // OID unresolvable from this single text; skip — the OID path
                // (which runs across all modules) is authoritative.
                continue;
            }
            if module.is_some() {
                def.module = module.clone();
            }
            // Record the defining module for this OID even if an object def
            // was already stored, so qualified_name() can answer later.
            if let Some(m) = &module {
                self.module_of
                    .entry(def.oid.clone())
                    .or_insert_with(|| m.clone());
            }
            self.object_defs.entry(def.oid.clone()).or_insert(def);
        }
        for tc in smi::parse_textual_conventions(text) {
            self.tcs.entry(tc.name.clone()).or_insert(tc);
        }
    }

    /// Load and parse a single MIB file.
    ///
    /// The file is read with [`tokio::fs`], so the read runs on tokio's blocking
    /// pool and never stalls the async runtime worker.
    pub async fn load_file(&mut self, path: impl AsRef<Path>) -> io::Result<usize> {
        let text = tokio::fs::read_to_string(path).await?;
        Ok(self.load_str(&text))
    }

    /// Load every `*.txt` / `*.mib` file in a directory.
    ///
    /// All files are parsed and pooled before resolution per file; because the
    /// SMI resolver seeds well-known roots and earlier names persist in the
    /// registry, cross-file references resolve once their defining file is
    /// loaded. To maximize resolution regardless of directory order, the files
    /// are parsed together via [`crate::smi`].
    ///
    /// Directory listing and file reads use [`tokio::fs`] so they run on tokio's
    /// blocking pool rather than blocking the async runtime worker. The files
    /// are read **concurrently** (bounded by [`MAX_CONCURRENT_FILE_READS`]) via a
    /// `futures` stream pipeline, which markedly speeds up loading a large
    /// `mibs/` tree over a sequential read loop.
    pub async fn load_dir(&mut self, dir: impl AsRef<Path>) -> io::Result<usize> {
        let mut entries: Vec<std::path::PathBuf> = Vec::new();
        let mut read_dir = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            if matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("txt") | Some("mib") | Some("MIB")
            ) {
                entries.push(path);
            }
        }
        entries.sort();

        // Read files concurrently, but keep results in the sorted directory
        // order: `buffered` (not `buffer_unordered`) preserves output order while
        // running up to N reads in flight, so the "earlier definition wins"
        // collision rule in `add_objects` stays deterministic. Unreadable files
        // are skipped, matching the previous best-effort behaviour.
        let texts: Vec<String> = futures::stream::iter(entries)
            .map(|path| async move { tokio::fs::read_to_string(path).await.ok() })
            .buffered(MAX_CONCURRENT_FILE_READS)
            .filter_map(|text| async move { text })
            .collect()
            .await;

        let mut combined = String::with_capacity(texts.iter().map(|t| t.len() + 1).sum());
        for text in texts {
            combined.push_str(&text);
            combined.push('\n');
        }
        // Parsing all modules together lets the fixed-point resolver satisfy
        // cross-module references in a single pass.
        Ok(self.load_str(&combined))
    }

    /// Construct a registry with built-ins plus all MIBs from `dir`.
    pub async fn from_dir(dir: impl AsRef<Path>) -> io::Result<Self> {
        let mut reg = MibRegistry::with_builtins();
        reg.load_dir(dir).await?;
        Ok(reg)
    }

    /// Look up the enumeration labels registered for an OID, if any.
    pub fn enums_for(&self, oid: &Oid) -> Option<&[(i64, String)]> {
        self.enums.get(oid).map(|v| v.as_slice())
    }

    /// Format a value for display, using enumeration labels when the OID is a
    /// known enumerated object (e.g. `up(1)` instead of `INTEGER: 1`). The OID
    /// passed should be the object's instance OID; its parent column OID is
    /// also consulted so table cells resolve against the columnar definition.
    pub fn format_value(&self, oid: &Oid, value: &Value) -> String {
        if let Value::Integer(n) = value {
            // Try the exact OID, then its parent (column) OID for table cells.
            let candidates = [Some(oid.clone()), parent_oid(oid)];
            for cand in candidates.into_iter().flatten() {
                if let Some(pairs) = self.enums.get(&cand)
                    && let Some((_, label)) = pairs.iter().find(|(v, _)| v == n)
                {
                    return format!("INTEGER: {label}({n})");
                }
            }
        }
        value.to_string()
    }

    /// Resolve a symbolic name (e.g. `sysDescr`) to its OID.
    pub fn name_to_oid(&self, name: &str) -> Option<Oid> {
        self.by_name.get(name).cloned()
    }

    /// Return the structured OBJECT-TYPE definition registered for `oid`, if
    /// any. The instance OID is matched directly, then its parent column OID
    /// (so table cells resolve against the columnar definition).
    pub fn object_def(&self, oid: &Oid) -> Option<&ObjectDef> {
        let candidates = [Some(oid.clone()), parent_oid(oid)];
        for cand in candidates.into_iter().flatten() {
            if let Some(def) = self.object_defs.get(&cand) {
                return Some(def);
            }
        }
        None
    }

    /// Look up a textual convention by name (e.g. `DisplayString`).
    pub fn textual_convention(&self, name: &str) -> Option<&TextualConvention> {
        self.tcs.get(name)
    }

    /// True if `oid` has a registered object definition whose MAX-ACCESS is
    /// `read-write` or `read-create` (i.e. it is SET-able). Useful for the
    /// agent's Reserve1 phase and for `snmpset` precondition checks.
    pub fn is_writable(&self, oid: &Oid) -> bool {
        self.object_def(oid)
            .map(|d| matches!(d.max_access, Access::ReadWrite | Access::ReadCreate))
            .unwrap_or(false)
    }

    /// Validate `value` against the type and SIZE/range constraints of the
    /// object definition for `oid` (instance OID or its parent column OID).
    /// Returns `Ok(())` if the value is acceptable or no constraint metadata
    /// is known; returns an error only for concrete violations.
    pub fn validate_value(&self, oid: &Oid, value: &Value) -> Result<(), ConstraintError> {
        let def = match self.object_def(oid) {
            Some(d) => d,
            None => return Err(ConstraintError::Unknown { oid: oid.clone() }),
        };
        // Resolve a TC reference to its underlying base type + merged constraint.
        let (base, constraint) = self.effective_syntax(&def.syntax);
        let expected = base_type_label(base);
        let actual = value.type_name();
        if !types_compatible(base, value) {
            return Err(ConstraintError::WrongType { expected, actual });
        }
        // Range check for integers.
        if let (Some(c), Value::Integer(n)) = (constraint.as_ref(), value) {
            if !c.check_int(*n) {
                return Err(ConstraintError::OutOfRange { value: *n });
            }
        }
        // Size check for octet strings.
        if let (Some(c), Value::OctetString(b)) = (constraint.as_ref(), value) {
            if !c.check_size(b.len()) {
                return Err(ConstraintError::WrongSize { len: b.len() });
            }
        }
        Ok(())
    }

    /// Resolve a [`Syntax`] to its effective `(BaseType, Option<Constraint>)`,
    /// following a single textual-convention indirection and merging any
    /// inline constraint with the TC's base constraint.
    fn effective_syntax(&self, syntax: &Syntax) -> (BaseType, Option<Constraint>) {
        match syntax {
            Syntax::Base(bt, c) => (*bt, c.clone()),
            Syntax::Tc(name, inline) => {
                if let Some(tc) = self.tcs.get(name) {
                    let (bt, base_c) = self.effective_syntax(&tc.base);
                    (bt, merge_constraints(base_c, inline.clone()))
                } else {
                    (BaseType::Integer, inline.clone())
                }
            }
            Syntax::Sequence => (BaseType::Null, None),
        }
    }

    /// Find the symbolic name for an exact OID, if registered.
    pub fn oid_to_name(&self, oid: &Oid) -> Option<&str> {
        self.by_oid.get(oid).map(|s| s.as_str())
    }

    /// Iterate over every registered `(OID, name)` pair, ordered by numeric OID.
    ///
    /// Useful for dumping a whole MIB tree (e.g. `snmptranslate -Tl`) after
    /// loading one or more MIB directories.
    pub fn iter_oids(&self) -> impl Iterator<Item = (&Oid, &str)> {
        self.by_oid.iter().map(|(oid, name)| (oid, name.as_str()))
    }

    /// Translate an input that may be either numeric (`1.3.6...`) or a known
    /// name, optionally with a trailing instance suffix such as `sysDescr.0`.
    pub fn translate(&self, input: &str) -> Option<Oid> {
        let input = input.trim().trim_start_matches('.');
        // Pure numeric OID.
        if input.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return input.parse().ok();
        }
        // name or name.suffix
        let (name, suffix) = match input.split_once('.') {
            Some((n, s)) => (n, Some(s)),
            None => (input, None),
        };
        let base = self.name_to_oid(name)?;
        match suffix {
            None => Some(base),
            Some(s) => {
                let mut parts = base.as_slice().to_vec();
                for tok in s.split('.') {
                    parts.push(tok.parse().ok()?);
                }
                Some(Oid::new(parts))
            }
        }
    }

    /// Render an OID symbolically when the longest known prefix matches,
    /// e.g. `1.3.6.1.2.1.1.1.0` -> `sysDescr.0`. Falls back to numeric form.
    pub fn format_oid(&self, oid: &Oid) -> String {
        match self.longest_prefix(oid) {
            Some((prefix, name)) if prefix.len() <= oid.len() => {
                render_with_suffix(name, oid, prefix.len())
            }
            _ => oid.to_string(),
        }
    }

    /// Render the fully-qualified `MODULE::name` for an OID when the defining
    /// module is known (mirrors `snmptranslate -Of`), else the bare name.
    pub fn qualified_name(&self, oid: &Oid) -> String {
        match (self.module_of.get(oid), self.by_oid.get(oid)) {
            (Some(m), Some(n)) => format!("{m}::{n}"),
            _ => self.format_oid(oid),
        }
    }

    /// Render the short (leaf) name for the longest known prefix of `oid`,
    /// followed by any trailing instance sub-identifiers (mirrors
    /// `snmptranslate -Os`).
    pub fn short_name(&self, oid: &Oid) -> String {
        match self.longest_prefix(oid) {
            Some((prefix, name)) if prefix.len() <= oid.len() => {
                render_with_suffix(name, oid, prefix.len())
            }
            None => oid.to_string(),
            _ => oid.to_string(),
        }
    }

    /// Render the OID using only the last path segment of the symbolic name
    /// (the entry/table name is dropped), mirroring `snmptranslate -OS`.
    pub fn suffix_name(&self, oid: &Oid) -> String {
        match self.longest_prefix(oid) {
            Some((prefix, name)) if prefix.len() <= oid.len() => {
                let leaf = name.rsplit('.').next().unwrap_or(name);
                render_with_suffix(leaf, oid, prefix.len())
            }
            _ => oid.to_string(),
        }
    }

    /// Find the longest registered `(oid, name)` prefix of `oid`.
    fn longest_prefix(&self, oid: &Oid) -> Option<(&Oid, &String)> {
        let mut best: Option<(&Oid, &String)> = None;
        for (cand, name) in &self.by_oid {
            if cand.is_prefix_of(oid) {
                match best {
                    Some((b, _)) if b.len() >= cand.len() => {}
                    _ => best = Some((cand, name)),
                }
            }
        }
        best
    }

    /// Number of registered names.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// Common MIB-II / SNMPv2-MIB object names and their numeric OIDs.
const BUILTINS: &[(&str, &str)] = &[
    ("iso", "1"),
    ("org", "1.3"),
    ("dod", "1.3.6"),
    ("internet", "1.3.6.1"),
    ("directory", "1.3.6.1.1"),
    ("mgmt", "1.3.6.1.2"),
    ("mib-2", "1.3.6.1.2.1"),
    ("system", "1.3.6.1.2.1.1"),
    ("sysDescr", "1.3.6.1.2.1.1.1"),
    ("sysObjectID", "1.3.6.1.2.1.1.2"),
    ("sysUpTime", "1.3.6.1.2.1.1.3"),
    ("sysContact", "1.3.6.1.2.1.1.4"),
    ("sysName", "1.3.6.1.2.1.1.5"),
    ("sysLocation", "1.3.6.1.2.1.1.6"),
    ("sysServices", "1.3.6.1.2.1.1.7"),
    ("interfaces", "1.3.6.1.2.1.2"),
    ("ifNumber", "1.3.6.1.2.1.2.1"),
    ("ifTable", "1.3.6.1.2.1.2.2"),
    ("ifEntry", "1.3.6.1.2.1.2.2.1"),
    ("ifIndex", "1.3.6.1.2.1.2.2.1.1"),
    ("ifDescr", "1.3.6.1.2.1.2.2.1.2"),
    ("ifType", "1.3.6.1.2.1.2.2.1.3"),
    ("ifMtu", "1.3.6.1.2.1.2.2.1.4"),
    ("ifSpeed", "1.3.6.1.2.1.2.2.1.5"),
    ("ifPhysAddress", "1.3.6.1.2.1.2.2.1.6"),
    ("ifOperStatus", "1.3.6.1.2.1.2.2.1.8"),
    ("ifInOctets", "1.3.6.1.2.1.2.2.1.10"),
    ("ifOutOctets", "1.3.6.1.2.1.2.2.1.16"),
    ("ip", "1.3.6.1.2.1.4"),
    ("icmp", "1.3.6.1.2.1.5"),
    ("tcp", "1.3.6.1.2.1.6"),
    ("udp", "1.3.6.1.2.1.7"),
    ("snmp", "1.3.6.1.2.1.11"),
    ("host", "1.3.6.1.2.1.25"),
    ("hrSystemUptime", "1.3.6.1.2.1.25.1.1"),
    ("hrStorageTable", "1.3.6.1.2.1.25.2.3"),
    ("private", "1.3.6.1.4"),
    ("enterprises", "1.3.6.1.4.1"),
    ("netSnmp", "1.3.6.1.4.1.8072"),
];

/// Return the parent OID (all but the last sub-identifier), if any.
fn parent_oid(oid: &Oid) -> Option<Oid> {
    let s = oid.as_slice();
    if s.len() <= 1 {
        None
    } else {
        Some(Oid::new(s[..s.len() - 1].to_vec()))
    }
}

/// Extract the module name from a MIB module header of the form
/// `NAME DEFINITIONS ::= BEGIN`. Returns `None` when no such header is found.
fn module_name_of(text: &str) -> Option<String> {
    let toks = smi::lex(text);
    for i in 0..toks.len() {
        if let (Some(smi::Tok::Ident(name)), Some(smi::Tok::Ident(kw))) =
            (toks.get(i), toks.get(i + 1))
        {
            if kw.eq_ignore_ascii_case("DEFINITIONS") && !name.is_empty() {
                return Some(name.clone());
            }
        }
    }
    None
}

/// Human-readable label for a base SMI type, used in ConstraintError messages.
fn base_type_label(b: BaseType) -> &'static str {
    match b {
        BaseType::Integer => "INTEGER",
        BaseType::OctetString => "OCTET STRING",
        BaseType::Oid => "OBJECT IDENTIFIER",
        BaseType::IpAddress => "IpAddress",
        BaseType::Counter32 => "Counter32",
        BaseType::Gauge32 => "Gauge32",
        BaseType::TimeTicks => "TimeTicks",
        BaseType::Opaque => "Opaque",
        BaseType::Counter64 => "Counter64",
        BaseType::Null => "NULL",
        BaseType::Unsigned32 => "Unsigned32",
    }
}

/// Whether a runtime [`Value`] is type-compatible with a declared [`BaseType`].
/// Counters/gauges accept their unsigned integer counterparts; IpAddress also
/// accepts a 4-octet OCTET STRING.
fn types_compatible(declared: BaseType, value: &Value) -> bool {
    match (declared, value) {
        (BaseType::Integer, Value::Integer(_)) => true,
        (BaseType::OctetString, Value::OctetString(_)) => true,
        (BaseType::Oid, Value::Oid(_)) => true,
        (BaseType::IpAddress, Value::IpAddress(_)) => true,
        (BaseType::IpAddress, Value::OctetString(b)) if b.len() == 4 => true,
        (BaseType::Counter32, Value::Counter32(_)) => true,
        (BaseType::Gauge32 | BaseType::Unsigned32, Value::Gauge32(_)) => true,
        (BaseType::TimeTicks, Value::TimeTicks(_)) => true,
        (BaseType::Opaque, Value::Opaque(_)) => true,
        (BaseType::Counter64, Value::Counter64(_)) => true,
        (BaseType::Null, Value::Null) => true,
        _ => false,
    }
}

/// Merge two optional constraints into one (union of all subranges/sizes).
fn merge_constraints(a: Option<Constraint>, b: Option<Constraint>) -> Option<Constraint> {
    match (a, b) {
        (None, None) => None,
        (Some(c), None) | (None, Some(c)) => Some(c),
        (Some(mut a), Some(b)) => {
            a.ranges.extend(b.ranges);
            a.sizes.extend(b.sizes);
            Some(a)
        }
    }
}

/// Render `name` followed by the trailing sub-identifiers of `oid` past the
/// first `prefix_len` arcs, e.g. ("sysDescr", oid=sysDescr.0, 7) -> "sysDescr.0".
fn render_with_suffix(name: &str, oid: &Oid, prefix_len: usize) -> String {
    if prefix_len >= oid.as_slice().len() {
        name.to_string()
    } else {
        let tail: Vec<String> = oid.as_slice()[prefix_len..]
            .iter()
            .map(|n| n.to_string())
            .collect();
        format!("{name}.{}", tail.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_to_oid_and_back() {
        let mib = MibRegistry::with_builtins();
        let oid = mib.name_to_oid("sysDescr").unwrap();
        assert_eq!(oid.to_string(), ".1.3.6.1.2.1.1.1");
        assert_eq!(mib.oid_to_name(&oid), Some("sysDescr"));
    }

    #[test]
    fn translate_name_with_instance() {
        let mib = MibRegistry::with_builtins();
        let oid = mib.translate("sysDescr.0").unwrap();
        assert_eq!(oid.to_string(), ".1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn translate_numeric_passthrough() {
        let mib = MibRegistry::with_builtins();
        let oid = mib.translate("1.3.6.1.2.1.1.5.0").unwrap();
        assert_eq!(oid.to_string(), ".1.3.6.1.2.1.1.5.0");
    }

    #[test]
    fn format_oid_uses_longest_prefix() {
        let mib = MibRegistry::with_builtins();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        assert_eq!(mib.format_oid(&oid), "sysDescr.0");
    }

    #[test]
    fn load_str_resolves_names() {
        let mut mib = MibRegistry::with_builtins();
        let text = r#"
            DEMO DEFINITIONS ::= BEGIN
            demoRoot OBJECT IDENTIFIER ::= { enterprises 99999 }
            demoLeaf OBJECT-TYPE
                SYNTAX INTEGER
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "x"
                ::= { demoRoot 1 }
            END
        "#;
        assert!(mib.load_str(text) >= 2);
        assert_eq!(
            mib.name_to_oid("demoLeaf").unwrap().to_string(),
            ".1.3.6.1.4.1.99999.1"
        );
    }

    #[test]
    fn enum_aware_value_formatting() {
        let mut mib = MibRegistry::with_builtins();
        let text = r#"
            DEMO DEFINITIONS ::= BEGIN
            demoStatus OBJECT-TYPE
                SYNTAX INTEGER { up(1), down(2) }
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "x"
                ::= { enterprises 4242 }
            END
        "#;
        mib.load_str(text);
        let col: Oid = "1.3.6.1.4.1.4242".parse().unwrap();
        // Exact-OID match.
        assert_eq!(mib.format_value(&col, &Value::Integer(1)), "INTEGER: up(1)");
        // Table-cell style: instance OID under the column resolves via parent.
        assert_eq!(
            mib.format_value(&col.child(0), &Value::Integer(2)),
            "INTEGER: down(2)"
        );
        // Unknown enum value falls back to plain rendering.
        assert_eq!(mib.format_value(&col, &Value::Integer(9)), "INTEGER: 9");
    }

    /// Sample MIB text exercising the semantic path: a TC, a read-write
    /// enumerated object, a read-only SIZE-constrained object, and a row with
    /// an INDEX clause. Reused by the semantic-method unit tests below.
    fn semantic_sample() -> &'static str {
        r#"
            DEMO-MIB DEFINITIONS ::= BEGIN
            demoRoot OBJECT IDENTIFIER ::= { enterprises 4242 }

            DemoString ::= TEXTUAL-CONVENTION
                DISPLAY-HINT "255a"
                STATUS       current
                DESCRIPTION  "a string"
                SYNTAX       OCTET STRING (SIZE (0..4))

            demoRW OBJECT-TYPE
                SYNTAX      INTEGER { enabled(1), disabled(2) }
                MAX-ACCESS  read-write
                STATUS      current
                DESCRIPTION "read-write enum"
                ::= { demoRoot 1 }

            demoRO OBJECT-TYPE
                SYNTAX      DemoString
                MAX-ACCESS  read-only
                STATUS      current
                DESCRIPTION "sized string"
                ::= { demoRoot 2 }

            demoTable OBJECT-TYPE
                SYNTAX      SEQUENCE OF DemoEntry
                MAX-ACCESS  not-accessible
                STATUS      current
                DESCRIPTION "table"
                ::= { demoRoot 3 }

            demoEntry OBJECT-TYPE
                SYNTAX      DemoEntry
                MAX-ACCESS  not-accessible
                STATUS      current
                DESCRIPTION "row"
                INDEX { demoIndex }
                ::= { demoTable 1 }
            END
        "#
    }

    #[test]
    fn object_def_and_writability() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let rw: Oid = "1.3.6.1.4.1.4242.1".parse().unwrap();
        let ro: Oid = "1.3.6.1.4.1.4242.2".parse().unwrap();

        let rw_def = mib.object_def(&rw).expect("demoRW object def");
        assert_eq!(rw_def.name, "demoRW");
        assert_eq!(rw_def.max_access, Access::ReadWrite);
        assert_eq!(rw_def.status, crate::smi::Status::Current);
        assert_eq!(
            rw_def.enums,
            vec![(1, "enabled".into()), (2, "disabled".into())]
        );
        assert_eq!(rw_def.description.as_deref(), Some("read-write enum"));

        assert!(mib.is_writable(&rw));
        assert!(!mib.is_writable(&ro));

        // Defining module is captured for qualified_name().
        assert_eq!(mib.qualified_name(&rw), "DEMO-MIB::demoRW");
    }

    #[test]
    fn textual_convention_loaded() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let ds = mib.textual_convention("DemoString").expect("DemoString TC");
        assert_eq!(ds.display_hint.as_deref(), Some("255a"));
    }

    #[test]
    fn validate_value_accepts_in_range() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let rw: Oid = "1.3.6.1.4.1.4242.1".parse().unwrap();
        // Valid enumerated INTEGER.
        assert!(mib.validate_value(&rw, &Value::Integer(1)).is_ok());
        assert!(mib.validate_value(&rw, &Value::Integer(2)).is_ok());
    }

    #[test]
    fn validate_value_rejects_wrong_type() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let rw: Oid = "1.3.6.1.4.1.4242.1".parse().unwrap();
        let err = mib
            .validate_value(&rw, &Value::OctetString(b"hi".to_vec()))
            .unwrap_err();
        assert!(matches!(err, ConstraintError::WrongType { .. }));
    }

    #[test]
    fn validate_value_rejects_over_size_via_tc() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let ro: Oid = "1.3.6.1.4.1.4242.2".parse().unwrap();
        // demoRO has SYNTAX DemoString, whose base is OCTET STRING (SIZE 0..4).
        assert!(mib
            .validate_value(&ro, &Value::OctetString(b"abcd".to_vec()))
            .is_ok());
        let err = mib
            .validate_value(&ro, &Value::OctetString(b"abcde".to_vec()))
            .unwrap_err();
        assert!(matches!(err, ConstraintError::WrongSize { len: 5 }));
    }

    #[test]
    fn validate_value_unknown_oid_errors() {
        let mib = MibRegistry::with_builtins();
        let oid: Oid = "1.2.3.4.5.6.7.8.9".parse().unwrap();
        assert!(matches!(
            mib.validate_value(&oid, &Value::Integer(0)),
            Err(ConstraintError::Unknown { .. })
        ));
    }

    #[test]
    fn name_variants_render() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let oid: Oid = "1.3.6.1.4.1.4242.1.0".parse().unwrap();
        // short_name uses the registered leaf name demoRW + instance suffix.
        assert_eq!(mib.short_name(&oid), "demoRW.0");
    }

    #[test]
    fn index_clause_captured_for_row() {
        let mut mib = MibRegistry::with_builtins();
        mib.load_str(semantic_sample());
        let entry: Oid = "1.3.6.1.4.1.4242.3.1".parse().unwrap();
        let def = mib.object_def(&entry).expect("demoEntry def");
        assert_eq!(
            def.index.as_ref().unwrap(),
            &crate::smi::Index::Plain(vec!["demoIndex".into()])
        );
    }
}
