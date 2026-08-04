//! Generic TTL cache wrapper around a cell provider.
//!
//! Counterpart of `agent/helpers/cache_handler.c`. [`CacheHandler`] wraps a
//! closure that returns every `(Oid, Value)` cell under a root and reuses the
//! sorted snapshot for a configurable [`Duration`], so a walk of a large table
//! does not re-invoke the (potentially expensive) provider on every GETNEXT.
//!
//! This is essentially [`crate::scalar::FnHandler`] with a configurable TTL,
//! extracted so any future handler can opt into the same caching strategy.

use crate::handler::{MibHandler, Reading};
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type Snapshot = Arc<Vec<(Oid, Value)>>;

/// A TTL-cached read-only handler backed by a cell-provider closure.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use std::sync::atomic::{AtomicU32, Ordering};
/// use netsnmp_agent::helpers::CacheHandler;
/// use netsnmp_agent::MibHandler;
/// use netsnmp::value::Value;
///
/// let root: netsnmp::oid::Oid = "1.3.6.1.2.1.777".parse().unwrap();
/// let instance = root.child(0);
/// let calls = AtomicU32::new(0);
/// let h = CacheHandler::new(root, Duration::from_millis(50), move || {
///     let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
///     vec![(instance.clone(), Value::Integer(n as i64))]
/// });
/// assert_eq!(h.get(&"1.3.6.1.2.1.777.0".parse().unwrap()),
///            Some(Value::Integer(1)));
/// // Within TTL: provider is not called again.
/// assert_eq!(h.get(&"1.3.6.1.2.1.777.0".parse().unwrap()),
///            Some(Value::Integer(1)));
/// ```
pub struct CacheHandler {
    root: Oid,
    ttl: Duration,
    provider: Box<dyn Fn() -> Vec<(Oid, Value)> + Send + Sync>,
    cache: Mutex<Option<(Instant, Snapshot)>>,
}

impl CacheHandler {
    /// Create a new cached handler rooted at `root` with the given TTL.
    pub fn new<F>(root: Oid, ttl: Duration, provider: F) -> Self
    where
        F: Fn() -> Vec<(Oid, Value)> + Send + Sync + 'static,
    {
        CacheHandler {
            root,
            ttl,
            provider: Box::new(provider),
            cache: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> Snapshot {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((built, cells)) = guard.as_ref() {
            if built.elapsed() < self.ttl {
                return Arc::clone(cells);
            }
        }
        let mut cells = (self.provider)();
        cells.sort_by(|a, b| a.0.cmp(&b.0));
        let cells = Arc::new(cells);
        *guard = Some((Instant::now(), Arc::clone(&cells)));
        cells
    }
}

impl MibHandler for CacheHandler {
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
        cells.get(idx).map(|(o, v)| Reading {
            oid: o.clone(),
            value: v.clone(),
        })
    }

    fn set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn within_ttl_provider_is_called_once() {
        let root: Oid = "1.3.6.1.2.1.777".parse().unwrap();
        let instance = root.child(0);
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let h = CacheHandler::new(root, Duration::from_secs(60), move || {
            let n = c.fetch_add(1, Ordering::SeqCst) + 1;
            vec![(instance.clone(), Value::Integer(n as i64))]
        });
        // Two GETs in quick succession: only one provider call.
        let probe: Oid = "1.3.6.1.2.1.777.0".parse().unwrap();
        let _ = h.get(&probe);
        let _ = h.get(&probe);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn after_ttl_provider_is_called_again() {
        let root: Oid = "1.3.6.1.2.1.778".parse().unwrap();
        let instance = root.child(0);
        let probe: Oid = "1.3.6.1.2.1.778.0".parse().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&counter);
        let h = CacheHandler::new(root, Duration::from_millis(10), move || {
            let n = c.fetch_add(1, Ordering::SeqCst) + 1;
            vec![(instance.clone(), Value::Integer(n as i64))]
        });
        let first = h.get(&probe).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let second = h.get(&probe).unwrap();
        assert_ne!(first, second);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn getnext_walks_sorted_snapshot() {
        let root: Oid = "1.3.6.1.2.1.779".parse().unwrap();
        let probe: Oid = "1.3.6.1.2.1.779".parse().unwrap();
        // Provider returns out of order; the snapshot sorts.
        let h = CacheHandler::new(root, Duration::from_secs(60), || {
            vec![
                ("1.3.6.1.2.1.779.2".parse::<Oid>().unwrap(), Value::Integer(2)),
                ("1.3.6.1.2.1.779.1".parse::<Oid>().unwrap(), Value::Integer(1)),
            ]
        });
        let r1 = h.get_next(&probe).unwrap();
        assert_eq!(r1.oid, "1.3.6.1.2.1.779.1".parse::<Oid>().unwrap());
        let r2 = h.get_next(&r1.oid).unwrap();
        assert_eq!(r2.oid, "1.3.6.1.2.1.779.2".parse::<Oid>().unwrap());
        assert!(h.get_next(&r2.oid).is_none());
    }
}
