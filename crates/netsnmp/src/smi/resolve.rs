//! Stage 3 of the MIB parser: cross-module name resolution.
//!
//! Turns raw definitions (whose OID values may reference symbolic parents like
//! `{ mib-2 1 }`) into numeric OIDs via a fixed-point pass over every collected
//! definition.

use std::collections::HashMap;

use crate::oid::Oid;

use super::parse::{Comp, RawDef};

/// A fully resolved MIB object: a name bound to a numeric OID, with optional
/// enumeration metadata.
#[derive(Clone, Debug)]
pub struct MibObject {
    /// Object name.
    pub name: String,
    /// Numeric OID.
    pub oid: Oid,
    /// Optional INTEGER enumeration (value → label).
    pub enums: Option<Vec<(i64, String)>>,
}

/// Seed the resolver with the well-known root arcs.
fn seed_roots() -> HashMap<String, Oid> {
    let mut m = HashMap::new();
    m.insert("iso".to_string(), Oid::new([1]));
    m.insert("ccitt".to_string(), Oid::new([0]));
    m.insert("itu".to_string(), Oid::new([0]));
    m.insert("itu-t".to_string(), Oid::new([0]));
    m.insert("joint-iso-ccitt".to_string(), Oid::new([2]));
    m.insert("joint-iso-itu-t".to_string(), Oid::new([2]));
    m
}

/// Resolve raw definitions into numeric OIDs via a fixed-point pass, seeding
/// only the well-known roots.
///
/// Names defined in any input module become resolvable for all others, which
/// is how `{ mib-2 1 }` resolves even when `mib-2` lives in a different file.
pub fn resolve(defs: Vec<RawDef>) -> Vec<MibObject> {
    resolve_with_seeds(defs, &HashMap::new())
}

/// Resolve raw definitions, seeding the resolver with additional already-known
/// name→OID bindings (e.g. names a [`crate::mib::MibRegistry`] already holds).
/// This lets a module that anchors at `enterprises` resolve even when that
/// root is defined elsewhere and not in the same text.
pub fn resolve_with_seeds(defs: Vec<RawDef>, seeds: &HashMap<String, Oid>) -> Vec<MibObject> {
    let mut resolved: HashMap<String, Oid> = seed_roots();
    for (name, oid) in seeds {
        resolved.entry(name.clone()).or_insert_with(|| oid.clone());
    }
    let mut pending = defs;
    let mut objects: Vec<MibObject> = Vec::new();

    loop {
        let mut progressed = false;
        let mut still_pending = Vec::new();

        for def in pending.into_iter() {
            match resolve_one(&def.spec, &resolved) {
                Some(oid) => {
                    // First definition of a name wins; ignore later duplicates.
                    resolved
                        .entry(def.name.clone())
                        .or_insert_with(|| oid.clone());
                    objects.push(MibObject {
                        name: def.name,
                        oid,
                        enums: def.enums,
                    });
                    progressed = true;
                }
                None => still_pending.push(def),
            }
        }

        pending = still_pending;
        if !progressed || pending.is_empty() {
            break;
        }
    }

    objects
}

/// Resolve a single spec against the currently-known names.
fn resolve_one(spec: &[Comp], resolved: &HashMap<String, Oid>) -> Option<Oid> {
    let mut parts: Vec<u32> = Vec::new();
    for (idx, comp) in spec.iter().enumerate() {
        match comp {
            Comp::Number(v) => parts.push(*v),
            Comp::Named(name, v) => {
                if idx == 0 {
                    // First component symbolic: prefer a known base, else use number.
                    if let Some(base) = resolved.get(name) {
                        parts.extend_from_slice(base.as_slice());
                    } else {
                        parts.push(*v);
                    }
                } else {
                    parts.push(*v);
                }
            }
            Comp::Name(name) => {
                if idx == 0 {
                    let base = resolved.get(name)?;
                    parts.extend_from_slice(base.as_slice());
                } else {
                    // A bare name in a non-leading position is not resolvable here.
                    return None;
                }
            }
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(Oid::new(parts))
    }
}
