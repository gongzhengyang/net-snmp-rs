//! Scalar and in-memory table handlers.
//!
//! Counterpart of `agent/helpers/scalar.c`, `instance.c`, `watcher.c` and the
//! `table_data` helpers. These cover the common case of serving values held
//! in memory, with optional write support. [`FnHandler`] additionally serves
//! values produced on demand, which is how the `mibgroup/` modules expose live
//! system data.

use crate::handler::{MibHandler, Reading};
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long a [`FnHandler`] reuses one built snapshot before rebuilding. A walk
/// issues many GETNEXTs in quick succession; caching the sorted snapshot for a
/// short window keeps a full table walk close to `O(rows·log rows)` instead of
/// rebuilding (and re-sorting) every column on every step. Shorter than the
/// underlying collector's refresh interval so freshness is unaffected.
const SNAPSHOT_TTL: Duration = Duration::from_millis(900);

/// Whether two values share a compatible SMI base type, for the purposes of
/// SET validation. Mirrors the loose type-check the C agent performs in
/// reserve1: an INTEGER-compatible value can replace another INTEGER-compatible
/// value (Integer, Counter32, Gauge32, TimeTicks, Counter64), and an
/// OCTET-STRING-compatible value can replace another
/// (OctetString, Oid, IpAddress, Opaque). NULL/exception values are not
/// acceptable SET targets.
pub(crate) fn types_compatible(current: &Value, new: &Value) -> bool {
    match (current, new) {
        // Exception/NULL sentinels are never valid SET values.
        (_, Value::Null)
        | (_, Value::NoSuchObject)
        | (_, Value::NoSuchInstance)
        | (_, Value::EndOfMibView)
        | (Value::Null, _)
        | (Value::NoSuchObject, _)
        | (Value::NoSuchInstance, _)
        | (Value::EndOfMibView, _) => false,
        // INTEGER family: Integer, Counter32, Gauge32, TimeTicks, Counter64.
        (Value::Integer(_), Value::Integer(_)) => true,
        (Value::Counter32(_), Value::Counter32(_)) => true,
        (Value::Gauge32(_), Value::Gauge32(_)) => true,
        (Value::TimeTicks(_), Value::TimeTicks(_)) => true,
        (Value::Counter64(_), Value::Counter64(_)) => true,
        // OctetString-family.
        (Value::OctetString(_), Value::OctetString(_)) => true,
        (Value::Oid(_), Value::Oid(_)) => true,
        (Value::IpAddress(_), Value::IpAddress(_)) => true,
        (Value::Opaque(_), Value::Opaque(_)) => true,
        // Different variants are incompatible.
        _ => false,
    }
}

/// A sorted set of instance cells, shared cheaply across requests.
pub(crate) type CellSnapshot = Arc<Vec<(Oid, Value)>>;

/// A read-only handler whose cells are produced by a closure. This is how live
/// system data is served (the role of the C `mibgroup/` data collectors): the
/// closure reads the current state and returns every instance cell under
/// `root`. Cells are sorted here, so GET/GETNEXT behave correctly regardless of
/// closure order, and a freshly built snapshot is cached for [`SNAPSHOT_TTL`]
/// so large-table walks stay fast.
pub struct FnHandler {
    root: Oid,
    provider: Box<dyn Fn() -> Vec<(Oid, Value)> + Send + Sync>,
    cache: Mutex<Option<(Instant, CellSnapshot)>>,
}

impl FnHandler {
    /// Create a handler rooted at `root` whose `provider` returns all instance
    /// cells (OID, value) currently present under that root.
    pub fn new<F>(root: Oid, provider: F) -> Self
    where
        F: Fn() -> Vec<(Oid, Value)> + Send + Sync + 'static,
    {
        FnHandler {
            root,
            provider: Box::new(provider),
            cache: Mutex::new(None),
        }
    }

    /// Convenience constructor for a single live scalar served at `root.0`.
    pub fn scalar<F>(root: Oid, getter: F) -> Self
    where
        F: Fn() -> Value + Send + Sync + 'static,
    {
        let instance = root.child(0);
        FnHandler::new(root, move || vec![(instance.clone(), getter())])
    }

    /// Return the provider's cells, sorted by OID, reusing a recent build when
    /// one is still within [`SNAPSHOT_TTL`].
    fn snapshot(&self) -> CellSnapshot {
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
        *guard = Some((Instant::now(), Arc::clone(&cells)));
        cells
    }
}

impl MibHandler for FnHandler {
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
        // First cell strictly greater than `oid` (cells are sorted).
        let idx = cells.partition_point(|(o, _)| o <= oid);
        cells.get(idx).map(|(o, value)| Reading {
            oid: o.clone(),
            value: value.clone(),
        })
    }
}

/// A single scalar object served at `root.0` (the conventional instance form).
///
/// Equivalent to registering a scalar with `netsnmp_register_scalar`.
pub struct ScalarHandler {
    root: Oid,
    instance: Oid,
    value: RwLock<Value>,
    writable: bool,
}

impl ScalarHandler {
    /// Create a read-only scalar served at `root.0`.
    pub fn new(root: Oid, value: Value) -> Self {
        let instance = root.child(0);
        ScalarHandler {
            root,
            instance,
            value: RwLock::new(value),
            writable: false,
        }
    }

    /// Mark this scalar writable so SET requests are accepted.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// The root OID this scalar is registered under (without the trailing `.0`
    /// instance sub-identifier).
    pub fn root(&self) -> &Oid {
        &self.root
    }

    /// A snapshot of the scalar's current value. Used by the persistence layer
    /// ([`crate::persist::ScalarPersistable`]) to serialize writable scalars
    /// across agent restarts.
    pub fn get_value(&self) -> Value {
        self.value.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replace the scalar's current value. Used by the persistence layer to
    /// restore a saved value at agent startup; also handy for out-of-band
    /// updates that bypass the SET/commit machinery. The new value's SMI base
    /// type need not match the previous one.
    pub fn set_value(&self, value: Value) {
        *self.value.write().unwrap_or_else(|e| e.into_inner()) = value;
    }
}

impl MibHandler for ScalarHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        if oid == &self.instance {
            Some(self.value.read().unwrap().clone())
        } else {
            None
        }
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        if oid < &self.instance {
            Some(Reading {
                oid: self.instance.clone(),
                value: self.value.read().unwrap().clone(),
            })
        } else {
            None
        }
    }

    fn set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if !self.writable {
            return Err(ErrorStatus::NotWritable);
        }
        if oid != &self.instance {
            return Err(ErrorStatus::NoCreation);
        }
        *self.value.write().unwrap() = value.clone();
        Ok(())
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if !self.writable {
            return Err(ErrorStatus::NotWritable);
        }
        if oid != &self.instance {
            // The scalar is a single object at root.0; any other instance is a
            // creation attempt, which a plain scalar does not support.
            return Err(ErrorStatus::NoCreation);
        }
        // Reject obvious type mismatches up front (reserve phase). This is the
        // minimal cross-type check: same SMI base type. Anything that survives
        // here is accepted for commit.
        let current = self.value.read().unwrap();
        if !types_compatible(&current, value) {
            return Err(ErrorStatus::WrongType);
        }
        Ok(())
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        // Delegate to the legacy single-step setter: same writable/existence
        // checks, then apply.
        self.set(oid, value)
    }
}

/// A handler backing an arbitrary set of instance OIDs with in-memory values,
/// kept sorted for correct GETNEXT semantics. Equivalent to a `table_data`
/// store or a collection of registered instances.
pub struct MapHandler {
    root: Oid,
    entries: RwLock<BTreeMap<Oid, Value>>,
    writable: bool,
}

impl MapHandler {
    /// Create an empty map handler rooted at `root`.
    pub fn new(root: Oid) -> Self {
        MapHandler {
            root,
            entries: RwLock::new(BTreeMap::new()),
            writable: false,
        }
    }

    /// Insert or replace an instance value (builder style).
    pub fn with(self, oid: Oid, value: Value) -> Self {
        self.entries.write().unwrap().insert(oid, value);
        self
    }

    /// Allow SET to modify existing instances.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Insert or replace an instance at runtime.
    pub fn insert(&self, oid: Oid, value: Value) {
        self.entries.write().unwrap().insert(oid, value);
    }
}

impl MibHandler for MapHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        self.entries.read().unwrap().get(oid).cloned()
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        let entries = self.entries.read().unwrap();
        // First entry strictly greater than `oid`.
        entries
            .range((
                std::ops::Bound::Excluded(oid.clone()),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .map(|(k, v)| Reading {
                oid: k.clone(),
                value: v.clone(),
            })
    }

    fn set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if !self.writable {
            return Err(ErrorStatus::NotWritable);
        }
        let mut entries = self.entries.write().unwrap();
        match entries.get_mut(oid) {
            Some(slot) => {
                *slot = value.clone();
                Ok(())
            }
            None => Err(ErrorStatus::NoCreation),
        }
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if !self.writable {
            return Err(ErrorStatus::NotWritable);
        }
        let entries = self.entries.read().unwrap();
        match entries.get(oid) {
            // Existing instance: validate the new value's type matches.
            Some(current) if !types_compatible(current, value) => {
                Err(ErrorStatus::WrongType)
            }
            Some(_) => Ok(()),
            // Unknown instance: a plain map does not create rows via SET.
            None => Err(ErrorStatus::NoCreation),
        }
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        self.set(oid, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_get_and_getnext() {
        let root: Oid = "1.3.6.1.2.1.1.1".parse().unwrap();
        let h = ScalarHandler::new(root.clone(), Value::OctetString(b"hi".to_vec()));
        assert_eq!(
            h.get(&root.child(0)),
            Some(Value::OctetString(b"hi".to_vec()))
        );
        let nx = h.get_next(&root).unwrap();
        assert_eq!(nx.oid, root.child(0));
    }

    #[test]
    fn map_getnext_is_ordered() {
        let root: Oid = "1.3.6.1.2.1.2.2.1.2".parse().unwrap();
        let h = MapHandler::new(root.clone())
            .with(root.child(1), Value::OctetString(b"lo".to_vec()))
            .with(root.child(2), Value::OctetString(b"eth0".to_vec()));
        let first = h.get_next(&root).unwrap();
        assert_eq!(first.oid, root.child(1));
        let second = h.get_next(&first.oid).unwrap();
        assert_eq!(second.oid, root.child(2));
        assert!(h.get_next(&second.oid).is_none());
    }

    #[test]
    fn fn_handler_serves_live_cells() {
        let root: Oid = "1.3.6.1.2.1.2.2".parse().unwrap();
        let entry = root.child(1);
        let h = FnHandler::new(root.clone(), move || {
            vec![
                (entry.child(2).child(1), Value::OctetString(b"lo".to_vec())),
                (
                    entry.child(2).child(2),
                    Value::OctetString(b"eth0".to_vec()),
                ),
            ]
        });
        let first = h.get_next(&root).unwrap();
        assert_eq!(first.oid.to_string(), ".1.3.6.1.2.1.2.2.1.2.1");
        let second = h.get_next(&first.oid).unwrap();
        assert_eq!(second.oid.to_string(), ".1.3.6.1.2.1.2.2.1.2.2");
        assert!(h.get_next(&second.oid).is_none());
        assert_eq!(h.get(&first.oid), Some(Value::OctetString(b"lo".to_vec())));
    }

    #[test]
    fn fn_scalar_serves_instance_zero() {
        let root: Oid = "1.3.6.1.2.1.1.3".parse().unwrap();
        let h = FnHandler::scalar(root.clone(), || Value::TimeTicks(4242));
        assert_eq!(h.get(&root.child(0)), Some(Value::TimeTicks(4242)));
        assert_eq!(h.get_next(&root).unwrap().oid, root.child(0));
    }

    #[test]
    fn writable_scalar_accepts_set() {
        let root: Oid = "1.3.6.1.2.1.1.6".parse().unwrap();
        let h = ScalarHandler::new(root.clone(), Value::OctetString(b"old".to_vec())).writable();
        h.set(&root.child(0), &Value::OctetString(b"new".to_vec()))
            .unwrap();
        assert_eq!(
            h.get(&root.child(0)),
            Some(Value::OctetString(b"new".to_vec()))
        );
    }

    #[test]
    fn scalar_prepare_set_rejects_wrong_type() {
        let root: Oid = "1.3.6.1.2.1.1.7".parse().unwrap();
        let h = ScalarHandler::new(root.clone(), Value::OctetString(b"old".to_vec())).writable();
        // Integer onto an OctetString scalar: reserve must reject.
        let err = h
            .prepare_set(&root.child(0), &Value::Integer(7))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
        // And the value is unchanged.
        assert_eq!(
            h.get(&root.child(0)),
            Some(Value::OctetString(b"old".to_vec()))
        );
    }

    #[test]
    fn scalar_prepare_set_accepts_same_type() {
        let root: Oid = "1.3.6.1.2.1.1.8".parse().unwrap();
        let h = ScalarHandler::new(root.clone(), Value::Integer(1)).writable();
        h.prepare_set(&root.child(0), &Value::Integer(2)).unwrap();
        // Commit applies.
        h.commit_set(&root.child(0), &Value::Integer(2)).unwrap();
        assert_eq!(h.get(&root.child(0)), Some(Value::Integer(2)));
    }

    #[test]
    fn map_prepare_set_rejects_unknown_instance() {
        let root: Oid = "1.3.6.1.2.1.99.1".parse().unwrap();
        let h = MapHandler::new(root.clone())
            .with(root.child(1), Value::OctetString(b"lo".to_vec()))
            .writable();
        // Unknown index: plain maps do not support row creation.
        let err = h
            .prepare_set(&root.child(2), &Value::OctetString(b"x".to_vec()))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::NoCreation);
    }

    #[test]
    fn map_prepare_set_rejects_wrong_type() {
        let root: Oid = "1.3.6.1.2.1.99.2".parse().unwrap();
        let h = MapHandler::new(root.clone())
            .with(root.child(1), Value::OctetString(b"lo".to_vec()))
            .writable();
        let err = h.prepare_set(&root.child(1), &Value::Integer(1)).unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
    }
}
