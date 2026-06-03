//! Error types shared by the SNMP command-line tools.

/// Error returned when arguments are malformed; carries a usage hint.
#[derive(Debug)]
pub struct ArgError(pub String);

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ArgError {}

/// Top-level error type returned by the CLI tools' `main` functions.
///
/// Each tool returns `Result<(), AppError>`; on `Err` the Rust runtime exits
/// with a non-zero status. [`AppError`]'s `Debug` impl forwards to `Display`
/// so the printed message is the human-readable text rather than the derived
/// struct dump.
#[derive(thiserror::Error)]
pub enum AppError {
    /// Invalid or missing command-line arguments.
    #[error(transparent)]
    Args(#[from] ArgError),
    /// A token could not be resolved to an OID.
    #[error("cannot parse OID '{0}'")]
    ParseOid(String),
    /// Any other tool-specific failure with a ready-made message.
    #[error("{0}")]
    Message(String),
    /// An error from the underlying SNMP stack (transport, protocol, USM, …).
    #[error(transparent)]
    Snmp(#[from] netsnmp::Error),
}

impl AppError {
    /// Build an [`AppError::Message`] from anything string-like.
    pub fn msg(text: impl Into<String>) -> Self {
        AppError::Message(text.into())
    }
}

// Forward Debug to Display so `fn main() -> Result<(), AppError>` prints the
// friendly message (the runtime uses the Debug representation on error exit).
impl std::fmt::Debug for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
