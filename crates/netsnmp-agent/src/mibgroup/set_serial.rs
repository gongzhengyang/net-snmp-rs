//! SNMPv2-MIB `setSerialNo` (`1.3.6.1.6.3.1.1.6.1.0`) — the monotonic SET
//! serial number of RFC 1907 §2.3.
//!
//! Counterpart of Net-SNMP's `agent/mibgroup/mibII/setSerialNo.c`.
//! `setSerialNo` is a single read-write `TestAndIncr` scalar: each successful
//! SET transaction on the agent increments it, and a manager may use it to
//! detect concurrent modifications. Per RFC 1907 the value wraps at 2^31-1.
//!
//! The value is held in an [`AtomicI32`] so it can be incremented lock-free
//! from the agent's SET commit path. The scalar is writable: a SET to the
//! instance updates the stored value (validated as an INTEGER in range, per the
//! `TestAndIncr` textual convention).
//!
//! # Wiring note
//!
//! Calling [`increment_set_serial`] from the registry's commit phase is
//! **optional** and intentionally left out of this module to avoid modifying
//! `registry.rs`. The handler is immediately walkable and SET-able; the value
//! starts at 0. A future change can hold the returned `Arc<AtomicI32>` inside
//! the registry and call `increment_set_serial` after each successful commit.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;

use crate::handler::MibHandler;

/// `setSerialNo` root: `1.3.6.1.6.3.1.1.6.1` (instance at `.0`).
const SET_SERIAL_NO: [u32; 10] = [1, 3, 6, 1, 6, 3, 1, 1, 6, 1];

/// Extract an `i64` from any INTEGER-family [`Value`] (Integer, Counter32,
/// Gauge32, TimeTicks, Counter64). Returns `None` for non-integer types, so
/// callers can map that to `WrongType`. `Counter64` values beyond `i64::MAX`
/// saturate to `i64::MAX` (they would already fail the `TestAndIncr` range
/// check).
fn integer_value(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(n) => Some(*n),
        Value::Counter32(n) => Some(*n as i64),
        Value::Gauge32(n) => Some(*n as i64),
        Value::TimeTicks(n) => Some(*n as i64),
        Value::Counter64(n) => Some(*n as i64),
        _ => None,
    }
}

/// A read-write `TestAndIncr` scalar backed by an [`AtomicI32`].
///
/// Implements [`MibHandler`] directly so the value is served and updated
/// without a `Mutex`. The GET path loads the atomic; the SET path validates
/// the incoming value is an INTEGER-compatible number in `0..=2^31-1` and
/// stores it.
pub struct SetSerialNoHandler {
    root: Oid,
    instance: Oid,
    value: Arc<AtomicI32>,
}

impl SetSerialNoHandler {
    /// Create a handler rooted at `1.3.6.1.6.3.1.1.6.1` backed by `value`.
    ///
    /// Pass the same `Arc<AtomicI32>` to [`increment_set_serial`] to bump the
    /// counter from the agent's commit path.
    pub fn new(value: Arc<AtomicI32>) -> Self {
        let root = Oid::new(SET_SERIAL_NO.to_vec());
        let instance = root.child(0);
        SetSerialNoHandler {
            root,
            instance,
            value,
        }
    }

    /// Create a handler with its own fresh `AtomicI32` starting at 0, returning
    /// both the handler and the shared counter so callers can increment it.
    pub fn with_fresh_counter() -> (Self, Arc<AtomicI32>) {
        let value = Arc::new(AtomicI32::new(0));
        let handler = Self::new(Arc::clone(&value));
        (handler, value)
    }
}

impl MibHandler for SetSerialNoHandler {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        if oid == &self.instance {
            Some(Value::Integer(self.value.load(Ordering::Relaxed) as i64))
        } else {
            None
        }
    }

    fn get_next(&self, oid: &Oid) -> Option<crate::handler::Reading> {
        if oid < &self.instance {
            Some(crate::handler::Reading {
                oid: self.instance.clone(),
                value: Value::Integer(self.value.load(Ordering::Relaxed) as i64),
            })
        } else {
            None
        }
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if oid != &self.instance {
            return Err(ErrorStatus::NoCreation);
        }
        // TestAndIncr: INTEGER 0..2147483647.
        match integer_value(value) {
            Some(n) => {
                if !(0..=i32::MAX as i64).contains(&n) {
                    return Err(ErrorStatus::WrongValue);
                }
                Ok(())
            }
            None => Err(ErrorStatus::WrongType),
        }
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if oid != &self.instance {
            return Err(ErrorStatus::NoCreation);
        }
        match integer_value(value) {
            Some(n) => {
                // Clamp defensively (prepare_set already validated).
                let stored = n.clamp(0, i32::MAX as i64) as i32;
                self.value.store(stored, Ordering::Relaxed);
                Ok(())
            }
            None => Err(ErrorStatus::WrongType),
        }
    }
}

/// Increment the `setSerialNo` counter by one, wrapping at 2^31-1 (RFC 1907
/// `TestAndIncr` semantics).
///
/// Intended to be called by the registry's SET commit phase after every
/// successful transaction. Calling it from elsewhere is harmless.
pub fn increment_set_serial(counter: &AtomicI32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(if v >= i32::MAX { 0 } else { v + 1 })
    });
}

/// Build the `setSerialNo` handler rooted at `1.3.6.1.6.3.1.1.6.1`.
///
/// The returned handler owns a private `AtomicI32` starting at 0. Use
/// [`set_serial_no_handler_with`] to share a counter with the registry's commit
/// path.
pub fn set_serial_no_handler() -> Arc<dyn MibHandler> {
    let (handler, _counter) = SetSerialNoHandler::with_fresh_counter();
    Arc::new(handler)
}

/// Build the `setSerialNo` handler sharing `counter` so the registry can bump
/// it via [`increment_set_serial`].
pub fn set_serial_no_handler_with(counter: Arc<AtomicI32>) -> Arc<dyn MibHandler> {
    Arc::new(SetSerialNoHandler::new(counter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_current_value() {
        let counter = Arc::new(AtomicI32::new(42));
        let h = SetSerialNoHandler::new(counter);
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        assert_eq!(h.get(&oid), Some(Value::Integer(42)));
    }

    #[test]
    fn get_next_from_root_lands_on_instance() {
        let counter = Arc::new(AtomicI32::new(7));
        let h = SetSerialNoHandler::new(counter);
        let root: Oid = "1.3.6.1.6.3.1.1.6.1".parse().unwrap();
        let next = h.get_next(&root).expect("successor");
        assert_eq!(next.oid.to_string(), ".1.3.6.1.6.3.1.1.6.1.0");
        assert_eq!(next.value, Value::Integer(7));
    }

    #[test]
    fn set_updates_value() {
        let counter = Arc::new(AtomicI32::new(0));
        let h = SetSerialNoHandler::new(Arc::clone(&counter));
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        h.prepare_set(&oid, &Value::Integer(99)).unwrap();
        h.commit_set(&oid, &Value::Integer(99)).unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 99);
        assert_eq!(h.get(&oid), Some(Value::Integer(99)));
    }

    #[test]
    fn set_rejects_wrong_type() {
        let h = SetSerialNoHandler::new(Arc::new(AtomicI32::new(0)));
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        let err = h
            .prepare_set(&oid, &Value::OctetString(b"no".to_vec()))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
    }

    #[test]
    fn set_rejects_out_of_range() {
        let h = SetSerialNoHandler::new(Arc::new(AtomicI32::new(0)));
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        // Negative is out of range for TestAndIncr.
        let err = h.prepare_set(&oid, &Value::Integer(-1)).unwrap_err();
        assert_eq!(err, ErrorStatus::WrongValue);
        // 2^31 is out of range.
        let err = h
            .prepare_set(&oid, &Value::Integer(i32::MAX as i64 + 1))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::WrongValue);
    }

    #[test]
    fn set_rejects_wrong_instance() {
        let h = SetSerialNoHandler::new(Arc::new(AtomicI32::new(0)));
        let other: Oid = "1.3.6.1.6.3.1.1.6.1.1".parse().unwrap();
        let err = h
            .prepare_set(&other, &Value::Integer(1))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::NoCreation);
    }

    #[test]
    fn increment_wraps_at_max() {
        let counter = AtomicI32::new(i32::MAX);
        increment_set_serial(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        increment_set_serial(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handler_factory_is_walkable() {
        let h = set_serial_no_handler();
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        assert_eq!(h.get(&oid), Some(Value::Integer(0)));
        let root: Oid = "1.3.6.1.6.3.1.1.6.1".parse().unwrap();
        let next = h.get_next(&root).expect("successor");
        assert!(next.oid > root);
    }

    #[test]
    fn shared_counter_visible_through_handler() {
        let counter = Arc::new(AtomicI32::new(5));
        let h = set_serial_no_handler_with(Arc::clone(&counter));
        increment_set_serial(&counter);
        let oid: Oid = "1.3.6.1.6.3.1.1.6.1.0".parse().unwrap();
        assert_eq!(h.get(&oid), Some(Value::Integer(6)));
    }
}
