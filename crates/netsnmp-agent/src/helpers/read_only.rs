//! Read-only wrapper.
//!
//! Counterpart of `agent/helpers/read_only.c`. Wrapping any
//! [`MibHandler`] in [`ReadOnly`] forces every SET to return `notWritable`,
//! regardless of whether the underlying handler is writable. GET/GETNEXT are
//! delegated unchanged.

use crate::handler::{MibHandler, Reading};
use netsnmp::oid::Oid;
use netsnmp::pdu::ErrorStatus;
use netsnmp::value::Value;
use std::sync::Arc;

/// A wrapper that makes any handler read-only.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use netsnmp_agent::{MibHandler, ScalarHandler};
/// use netsnmp_agent::helpers::read_only;
/// use netsnmp::value::Value;
///
/// let inner: Arc<dyn MibHandler> = Arc::new(
///     ScalarHandler::new("1.3.6.1.2.1.1.5".parse().unwrap(),
///                        Value::OctetString(b"host".to_vec())).writable());
/// let wrapped = read_only(inner);
/// let oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
/// // GET still works.
/// assert_eq!(wrapped.get(&oid), Some(Value::OctetString(b"host".to_vec())));
/// // SET is rejected.
/// let err = wrapped.set(&oid, &Value::OctetString(b"x".to_vec())).unwrap_err();
/// assert_eq!(err, netsnmp::pdu::ErrorStatus::NotWritable);
/// ```
pub struct ReadOnly {
    inner: Arc<dyn MibHandler>,
}

impl ReadOnly {
    /// Create a new read-only wrapper around `inner`.
    pub fn new(inner: Arc<dyn MibHandler>) -> Self {
        ReadOnly { inner }
    }
}

impl MibHandler for ReadOnly {
    fn root(&self) -> &Oid {
        self.inner.root()
    }
    fn get(&self, oid: &Oid) -> Option<Value> {
        self.inner.get(oid)
    }
    fn get_next(&self, oid: &Oid) -> Option<Reading> {
        self.inner.get_next(oid)
    }
    fn prepare_set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
    fn commit_set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
    fn set(&self, _oid: &Oid, _value: &Value) -> Result<(), ErrorStatus> {
        Err(ErrorStatus::NotWritable)
    }
}

/// Wrap `inner` in a [`ReadOnly`] handler and return it as a trait object,
/// ready to be registered with a [`crate::registry::Registry`].
pub fn read_only(inner: Arc<dyn MibHandler>) -> Arc<dyn MibHandler> {
    Arc::new(ReadOnly::new(inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalar::ScalarHandler;

    #[test]
    fn delegates_get_and_getnext() {
        let inner: Arc<dyn MibHandler> = Arc::new(ScalarHandler::new(
            "1.3.6.1.2.1.1.9".parse().unwrap(),
            Value::OctetString(b"v".to_vec()),
        ));
        let ro = read_only(inner);
        assert_eq!(
            ro.get(&"1.3.6.1.2.1.1.9.0".parse().unwrap()),
            Some(Value::OctetString(b"v".to_vec()))
        );
        assert!(ro
            .get_next(&"1.3.6.1.2.1.1.1".parse().unwrap())
            .is_some());
    }

    #[test]
    fn blocks_set_even_when_inner_is_writable() {
        let inner: Arc<dyn MibHandler> = Arc::new(
            ScalarHandler::new(
                "1.3.6.1.2.1.1.10".parse().unwrap(),
                Value::OctetString(b"v".to_vec()),
            )
            .writable(),
        );
        let ro = read_only(inner);
        let oid: Oid = "1.3.6.1.2.1.1.10.0".parse().unwrap();
        // Blocked at prepare (reserve) phase.
        assert_eq!(
            ro.prepare_set(&oid, &Value::OctetString(b"x".to_vec())),
            Err(ErrorStatus::NotWritable)
        );
        // And at single-step set.
        assert_eq!(
            ro.set(&oid, &Value::OctetString(b"x".to_vec())),
            Err(ErrorStatus::NotWritable)
        );
    }
}
