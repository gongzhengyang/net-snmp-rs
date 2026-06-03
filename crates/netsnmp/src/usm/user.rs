//! A USM user: security name plus optional auth/priv credentials, and the
//! localized-key derivation built on them.

use super::{AuthProtocol, PrivProtocol, SecurityLevel};

/// A USM user with its credentials and protocols.
#[derive(Clone, Debug)]
pub struct UsmUser {
    /// The security name (`msgUserName`).
    pub name: String,
    /// Authentication protocol and password, if any.
    pub auth: Option<(AuthProtocol, String)>,
    /// Privacy protocol and password, if any.
    pub priv_: Option<(PrivProtocol, String)>,
}

impl UsmUser {
    /// A `noAuthNoPriv` user with just a security name.
    pub fn noauth(name: impl Into<String>) -> Self {
        UsmUser {
            name: name.into(),
            auth: None,
            priv_: None,
        }
    }

    /// An `authNoPriv` user.
    pub fn auth(name: impl Into<String>, proto: AuthProtocol, password: impl Into<String>) -> Self {
        UsmUser {
            name: name.into(),
            auth: Some((proto, password.into())),
            priv_: None,
        }
    }

    /// An `authPriv` user.
    pub fn auth_priv(
        name: impl Into<String>,
        auth_proto: AuthProtocol,
        auth_password: impl Into<String>,
        priv_proto: PrivProtocol,
        priv_password: impl Into<String>,
    ) -> Self {
        UsmUser {
            name: name.into(),
            auth: Some((auth_proto, auth_password.into())),
            priv_: Some((priv_proto, priv_password.into())),
        }
    }

    /// The security level implied by the configured credentials.
    pub fn security_level(&self) -> SecurityLevel {
        match (self.auth.is_some(), self.priv_.is_some()) {
            (true, true) => SecurityLevel::AuthPriv,
            (true, false) => SecurityLevel::AuthNoPriv,
            _ => SecurityLevel::NoAuthNoPriv,
        }
    }

    /// The localized authentication key for an engine id.
    pub fn auth_key(&self, engine_id: &[u8]) -> Option<Vec<u8>> {
        self.auth
            .as_ref()
            .map(|(proto, pw)| proto.localized_key(pw.as_bytes(), engine_id))
    }

    /// The localized privacy key for an engine id (derived with the auth hash,
    /// truncated to the cipher key length), per RFC 3414 §2.6.
    pub fn priv_key(&self, engine_id: &[u8]) -> Option<Vec<u8>> {
        let (auth_proto, _) = self.auth.as_ref()?;
        let (priv_proto, priv_pw) = self.priv_.as_ref()?;
        let mut key = auth_proto.localized_key(priv_pw.as_bytes(), engine_id);
        // The localized key must supply at least the cipher key length; MD5
        // yields 16 bytes, SHA-1/256 more. Truncate to the cipher key size.
        if key.len() < priv_proto.key_len() {
            return None;
        }
        key.truncate(priv_proto.key_len());
        Some(key)
    }
}
