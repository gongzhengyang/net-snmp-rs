//! Object Identifier (OID) representation and parsing.
//!
//! Corresponds to the OID handling spread across `snmplib/mib.c` and the
//! `tools.c` comparison helpers in the C implementation.

use crate::error::{Error, Result};
use std::fmt;
use std::str::FromStr;

/// Maximum number of sub-identifiers in an OID, matching `MAX_OID_LEN` in C.
pub const MAX_OID_LEN: usize = 128;

/// An object identifier: an ordered sequence of unsigned 32-bit sub-identifiers.
///
/// Stored as a `Vec<u32>`; comparison is lexicographic, which matches SNMP
/// lexicographic ordering used by GETNEXT/GETBULK.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Oid(Vec<u32>);

impl Oid {
    /// Create an OID from a slice of sub-identifiers.
    pub fn new(parts: impl Into<Vec<u32>>) -> Self {
        Oid(parts.into())
    }

    /// The empty/null OID (`0.0`), often used as a placeholder.
    pub fn null() -> Self {
        Oid(Vec::new())
    }

    /// Borrow the sub-identifiers.
    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }

    /// Number of sub-identifiers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the OID has no sub-identifiers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return a new OID with `child` appended as a final sub-identifier.
    pub fn child(&self, child: u32) -> Oid {
        let mut v = self.0.clone();
        v.push(child);
        Oid(v)
    }

    /// Whether `self` is a strict or equal prefix of `other`.
    ///
    /// Used by the agent to decide whether a request OID falls within a
    /// registered subtree.
    pub fn is_prefix_of(&self, other: &Oid) -> bool {
        other.0.len() >= self.0.len() && other.0[..self.0.len()] == self.0[..]
    }

    /// Validate that the OID is well-formed for use on the wire.
    pub fn validate(&self) -> Result<()> {
        if self.0.len() > MAX_OID_LEN {
            return Err(Error::InvalidOid(format!(
                "too many sub-identifiers ({} > {MAX_OID_LEN})",
                self.0.len()
            )));
        }
        Ok(())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, ".");
        }
        for part in &self.0 {
            write!(f, ".{part}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({self})")
    }
}

impl FromStr for Oid {
    type Err = Error;

    /// Parse a numeric OID such as `1.3.6.1.2.1.1.1.0` or `.1.3.6.1`.
    fn from_str(s: &str) -> Result<Self> {
        let trimmed = s.trim().trim_start_matches('.');
        if trimmed.is_empty() {
            return Ok(Oid::null());
        }
        let mut parts = Vec::new();
        for token in trimmed.split('.') {
            let n: u32 = token
                .parse()
                .map_err(|_| Error::InvalidOid(format!("invalid sub-identifier '{token}'")))?;
            parts.push(n);
        }
        Ok(Oid(parts))
    }
}

impl From<Vec<u32>> for Oid {
    fn from(v: Vec<u32>) -> Self {
        Oid(v)
    }
}

impl<const N: usize> From<[u32; N]> for Oid {
    fn from(v: [u32; N]) -> Self {
        Oid(v.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        assert_eq!(oid.len(), 9);
        assert_eq!(oid.to_string(), ".1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn leading_dot_is_accepted() {
        let a: Oid = ".1.3.6".parse().unwrap();
        let b: Oid = "1.3.6".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn prefix_and_ordering() {
        let base: Oid = "1.3.6.1".parse().unwrap();
        let child: Oid = "1.3.6.1.5".parse().unwrap();
        assert!(base.is_prefix_of(&child));
        assert!(!child.is_prefix_of(&base));
        assert!(base < child);
    }

    #[test]
    fn lexicographic_order_matches_getnext() {
        let a: Oid = "1.3.6.1.2.1.1".parse().unwrap();
        let b: Oid = "1.3.6.1.2.1.2".parse().unwrap();
        let c: Oid = "1.3.6.1.2.1.1.1".parse().unwrap();
        assert!(a < c);
        assert!(c < b);
    }
}
