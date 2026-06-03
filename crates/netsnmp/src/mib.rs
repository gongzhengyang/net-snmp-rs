//! MIB object-name registry and OID translation.
//!
//! This is the high-level counterpart of `snmplib/mib.c`: a bidirectional
//! name↔OID registry plus symbolic value formatting. It is seeded with a
//! compact set of built-in MIB-II names so the tools work offline, and can be
//! populated from real MIB files by [`MibRegistry::load_dir`] /
//! [`MibRegistry::load_file`], which drive the SMI parser in [`crate::smi`]
//! (the `parse.c` reimplementation).

use crate::oid::Oid;
use crate::value::Value;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Maximum number of MIB files read concurrently in [`MibRegistry::load_dir`].
/// Bounds the in-flight `tokio::fs` reads so a large `mibs/` tree loads fast
/// without spawning an unbounded number of blocking filesystem operations.
const MAX_CONCURRENT_FILE_READS: usize = 64;

/// A bidirectional registry mapping symbolic names to numeric OIDs, plus
/// optional INTEGER enumerations for symbolic value display.
#[derive(Debug, Clone)]
pub struct MibRegistry {
    by_name: BTreeMap<String, Oid>,
    by_oid: BTreeMap<Oid, String>,
    enums: BTreeMap<Oid, Vec<(i64, String)>>,
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
    pub fn load_str(&mut self, text: &str) -> usize {
        let seeds: std::collections::HashMap<String, Oid> = self
            .by_name
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.add_objects(crate::smi::parse_text_with_seeds(text, &seeds))
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
        // Find the longest registered prefix.
        let mut best: Option<(&Oid, &String)> = None;
        for (cand, name) in &self.by_oid {
            if cand.is_prefix_of(oid) {
                match best {
                    Some((b, _)) if b.len() >= cand.len() => {}
                    _ => best = Some((cand, name)),
                }
            }
        }
        match best {
            Some((prefix, name)) if prefix.len() <= oid.len() => {
                let suffix = &oid.as_slice()[prefix.len()..];
                if suffix.is_empty() {
                    name.clone()
                } else {
                    let tail: Vec<String> = suffix.iter().map(|n| n.to_string()).collect();
                    format!("{name}.{}", tail.join("."))
                }
            }
            _ => oid.to_string(),
        }
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
}
