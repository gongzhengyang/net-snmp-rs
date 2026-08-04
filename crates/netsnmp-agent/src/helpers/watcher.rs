//! Watcher handler: map an in-memory value to an SNMP scalar.
//!
//! Counterpart of `agent/helpers/watcher.c`. [`Watcher`] wraps a piece of
//! shared mutable state (`Arc<RwLock<T>>`) plus getter/setter closures, and
//! serves it as a single scalar instance at `root.0`. Compared to
//! [`crate::scalar::ScalarHandler`] it lets the underlying value live in a
//! caller-owned structure rather than inside the handler, which is useful for
//! instrumenting live runtime state.

use crate::handler::{MibHandler, Reading};
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::sync::{Arc, RwLock};

/// A scalar handler backed by an externally-owned `Arc<RwLock<T>>`.
///
/// # Example
///
/// ```
/// use std::sync::{Arc, RwLock};
/// use netsnmp_agent::helpers::Watcher;
/// use netsnmp_agent::MibHandler;
/// use netsnmp::value::Value;
///
/// let state = Arc::new(RwLock::new(42i64));
/// let root = "1.3.6.1.2.1.666".parse().unwrap();
/// let h = Watcher::new(
///     root,
///     Arc::clone(&state),
///     |v| Value::Integer(*v),
///     |incoming| match incoming {
///         Value::Integer(n) => Ok(*n),
///         _ => Err(netsnmp::pdu::ErrorStatus::WrongType),
///     },
/// );
/// assert_eq!(h.get(&"1.3.6.1.2.1.666.0".parse().unwrap()),
///            Some(Value::Integer(42)));
/// ```
pub struct Watcher<T: Send + Sync + 'static> {
    root: Oid,
    instance: Oid,
    state: Arc<RwLock<T>>,
    getter: Box<dyn Fn(&T) -> Value + Send + Sync>,
    setter: Box<dyn Fn(&Value) -> Result<T, ErrorStatus> + Send + Sync>,
}

impl<T: Send + Sync + 'static> Watcher<T> {
    /// Create a new watcher at `root` (served at `root.0`) backed by `state`.
    /// The `getter` reads the current value into a [`Value`]; the `setter`
    /// parses an incoming SET value, returning the new state on success or an
    /// SNMP error-status on failure.
    pub fn new<G, S>(root: Oid, state: Arc<RwLock<T>>, getter: G, setter: S) -> Self
    where
        G: Fn(&T) -> Value + Send + Sync + 'static,
        S: Fn(&Value) -> Result<T, ErrorStatus> + Send + Sync + 'static,
    {
        let instance = root.child(0);
        Watcher {
            root,
            instance,
            state,
            getter: Box::new(getter),
            setter: Box::new(setter),
        }
    }
}

impl<T: Send + Sync + 'static> MibHandler for Watcher<T> {
    fn root(&self) -> &Oid {
        &self.root
    }

    fn get(&self, oid: &Oid) -> Option<Value> {
        if oid == &self.instance {
            let guard = self.state.read().unwrap();
            Some((self.getter)(&guard))
        } else {
            None
        }
    }

    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        if oid < &self.instance {
            let guard = self.state.read().unwrap();
            Some(Reading {
                oid: self.instance.clone(),
                value: (self.getter)(&guard),
            })
        } else {
            None
        }
    }

    fn prepare_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if oid != &self.instance {
            return Err(ErrorStatus::NoCreation);
        }
        // Run the setter against a value-only copy: type/range validation only.
        (self.setter)(value).map(|_| ())
    }

    fn commit_set(&self, oid: &Oid, value: &Value) -> Result<(), ErrorStatus> {
        if oid != &self.instance {
            return Err(ErrorStatus::NoCreation);
        }
        let new = (self.setter)(value)?;
        *self.state.write().unwrap() = new;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_reads_state() {
        let state = Arc::new(RwLock::new(7i64));
        let root: Oid = "1.3.6.1.2.1.700".parse().unwrap();
        let h = Watcher::new(
            root.clone(),
            state,
            |v| Value::Integer(*v),
            |incoming| match incoming {
                Value::Integer(n) => Ok(*n),
                _ => Err(ErrorStatus::WrongType),
            },
        );
        assert_eq!(h.get(&root.child(0)), Some(Value::Integer(7)));
    }

    #[test]
    fn watcher_writes_state_via_commit() {
        let state = Arc::new(RwLock::new(0i64));
        let root: Oid = "1.3.6.1.2.1.701".parse().unwrap();
        let h = Watcher::new(
            root.clone(),
            Arc::clone(&state),
            |v| Value::Integer(*v),
            |incoming| match incoming {
                Value::Integer(n) => Ok(*n),
                _ => Err(ErrorStatus::WrongType),
            },
        );
        h.commit_set(&root.child(0), &Value::Integer(99)).unwrap();
        assert_eq!(*state.read().unwrap(), 99);
    }

    #[test]
    fn watcher_rejects_wrong_type_in_prepare() {
        let state = Arc::new(RwLock::new(0i64));
        let root: Oid = "1.3.6.1.2.1.702".parse().unwrap();
        let h = Watcher::new(
            root,
            state,
            |v| Value::Integer(*v),
            |incoming| match incoming {
                Value::Integer(n) => Ok(*n),
                _ => Err(ErrorStatus::WrongType),
            },
        );
        let err = h
            .prepare_set(&"1.3.6.1.2.1.702.0".parse().unwrap(), &Value::OctetString(vec![1]))
            .unwrap_err();
        assert_eq!(err, ErrorStatus::WrongType);
    }
}
