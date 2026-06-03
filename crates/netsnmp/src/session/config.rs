//! Configuration for a community [`Session`](super::Session).

use std::time::Duration;

use crate::message::Version;

/// Configuration for building a [`Session`](super::Session).
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// SNMP protocol version.
    pub version: Version,
    /// Community string.
    pub community: Vec<u8>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Number of retries after the first attempt (so total tries = retries+1).
    pub retries: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            version: Version::V2c,
            community: b"public".to_vec(),
            timeout: Duration::from_secs(5),
            retries: 2,
        }
    }
}
