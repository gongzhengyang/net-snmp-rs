//! Error and result types for the SNMP library.
//!
//! Mirrors the `SNMPERR_*` conventions in the C `snmplib` (`snmp_api.c`,
//! `snmp_client.c`) using `thiserror` for ergonomic, structured errors and
//! clean propagation across the async IO layer.

use thiserror::Error;

/// The crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while encoding, decoding, or exchanging SNMP messages.
#[derive(Debug, Error)]
pub enum Error {
    /// The input ended before a complete value could be parsed.
    #[error("unexpected end of input")]
    UnexpectedEof,

    /// A BER/DER tag did not match the expected type.
    #[error("unexpected ASN.1 tag: expected 0x{expected:02x}, found 0x{found:02x}")]
    UnexpectedTag {
        /// The tag that was expected.
        expected: u8,
        /// The tag that was actually found.
        found: u8,
    },

    /// A length field was malformed or exceeded sane limits.
    #[error("invalid ASN.1 length encoding")]
    InvalidLength,

    /// An OID was malformed (too short, bad sub-identifier, etc.).
    #[error("invalid OID: {0}")]
    InvalidOid(String),

    /// An integer value could not be represented in the target width.
    #[error("integer value out of range")]
    IntegerOverflow,

    /// The SNMP version in a message is unsupported by this implementation.
    #[error("unsupported SNMP version: {0}")]
    UnsupportedVersion(i64),

    /// A value type was not valid in the context it appeared.
    #[error("invalid value: {0}")]
    InvalidValue(String),

    /// The agent/peer returned a non-zero `error-status` in its response.
    #[error("SNMP error-status {status} at varbind index {index}")]
    SnmpError {
        /// The SNMP error-status code.
        status: crate::pdu::ErrorStatus,
        /// The 1-based index of the offending varbind, or 0.
        index: usize,
    },

    /// A request timed out waiting for a response.
    #[error("request timed out")]
    Timeout,

    /// A response PDU did not match the outstanding request-id.
    #[error("request-id mismatch: sent {sent}, received {received}")]
    RequestIdMismatch {
        /// The request-id that was sent.
        sent: i32,
        /// The request-id that was received.
        received: i32,
    },

    /// SNMPv3/USM authentication failed (digest mismatch or missing key).
    #[error("USM authentication failure: {0}")]
    AuthFailure(String),

    /// SNMPv3/USM privacy (decryption) failure or missing key.
    #[error("USM privacy failure: {0}")]
    PrivFailure(String),

    /// A security-level / configuration error in the SNMPv3 stack.
    #[error("SNMPv3 security error: {0}")]
    Security(String),

    /// The remote returned an SNMPv3 Report PDU (e.g. during engine discovery
    /// or on a USM error such as unknown engine-id / not-in-time-window).
    #[error("received SNMPv3 report: {0}")]
    Report(String),

    /// An underlying I/O error from the transport layer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A catch-all for protocol violations with a human-readable message.
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl From<rasn::error::DecodeError> for Error {
    fn from(err: rasn::error::DecodeError) -> Self {
        Error::Protocol(format!("BER decode error: {err}"))
    }
}

impl From<rasn::error::EncodeError> for Error {
    fn from(err: rasn::error::EncodeError) -> Self {
        Error::Protocol(format!("BER encode error: {err}"))
    }
}
