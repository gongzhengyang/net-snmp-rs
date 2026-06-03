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

/// A sorted set of instance cells, shared cheaply across requests.
type CellSnapshot = Arc<Vec<(Oid, Value)>>;

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
}
