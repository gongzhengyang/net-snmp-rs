//! SNMPv3 message security levels.

/// The SNMPv3 message security level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// No authentication, no privacy.
    NoAuthNoPriv,
    /// Authentication only.
    AuthNoPriv,
    /// Authentication and privacy.
    AuthPriv,
}

impl SecurityLevel {
    /// The `msgFlags` security bits (bit0 = auth, bit1 = priv).
    pub fn flag_bits(self) -> u8 {
        match self {
            SecurityLevel::NoAuthNoPriv => 0b000,
            SecurityLevel::AuthNoPriv => 0b001,
            SecurityLevel::AuthPriv => 0b011,
        }
    }

    /// Whether authentication is required at this level.
    pub fn has_auth(self) -> bool {
        matches!(self, SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv)
    }

    /// Whether privacy (encryption) is required at this level.
    pub fn has_priv(self) -> bool {
        matches!(self, SecurityLevel::AuthPriv)
    }
}
