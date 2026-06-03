//! USM protocol-token parsing and `UsmUser` assembly for the v3 tools.

use netsnmp::usm::{AuthProtocol, PrivProtocol, UsmUser};

use crate::error::ArgError;

/// Parse a USM authentication protocol token (`-a`).
pub fn parse_auth_proto(s: &str) -> Result<AuthProtocol, ArgError> {
    match s.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
        "MD5" | "USMHMACMD5AUTHPROTOCOL" => Ok(AuthProtocol::HmacMd5),
        "SHA" | "SHA1" | "USMHMACSHAAUTHPROTOCOL" => Ok(AuthProtocol::HmacSha1),
        "SHA256" | "SHA2256" | "USMHMAC192SHA256AUTHPROTOCOL" => Ok(AuthProtocol::HmacSha256),
        other => Err(ArgError(format!(
            "unsupported auth protocol '{other}' (use MD5, SHA, or SHA-256)"
        ))),
    }
}

/// Parse a USM privacy protocol token (`-x`).
pub fn parse_priv_proto(s: &str) -> Result<PrivProtocol, ArgError> {
    match s.to_ascii_uppercase().replace(['-', '_'], "").as_str() {
        "AES" | "AES128" | "USMAESCFB128PROTOCOL" => Ok(PrivProtocol::AesCfb128),
        other => Err(ArgError(format!(
            "unsupported privacy protocol '{other}' (use AES)"
        ))),
    }
}

/// Assemble a [`UsmUser`] from the parsed v3 options, honoring an explicit
/// `-l` security level when given and otherwise inferring it from the
/// passphrases supplied.
pub(crate) fn build_usm_user(
    sec_name: Option<String>,
    auth_proto: Option<AuthProtocol>,
    auth_pass: Option<String>,
    priv_proto: Option<PrivProtocol>,
    priv_pass: Option<String>,
    level: Option<String>,
) -> Result<UsmUser, ArgError> {
    let name = sec_name.ok_or_else(|| ArgError("SNMPv3 requires -u SECURITY-NAME".into()))?;

    // Determine the desired level (explicit -l overrides inference).
    let want_auth;
    let want_priv;
    match level.as_deref().map(|s| s.to_ascii_lowercase()) {
        Some(ref l) if l == "noauthnopriv" => {
            want_auth = false;
            want_priv = false;
        }
        Some(ref l) if l == "authnopriv" => {
            want_auth = true;
            want_priv = false;
        }
        Some(ref l) if l == "authpriv" => {
            want_auth = true;
            want_priv = true;
        }
        Some(other) => return Err(ArgError(format!("invalid security level '{other}'"))),
        None => {
            want_auth = auth_pass.is_some();
            want_priv = priv_pass.is_some();
        }
    }

    if want_priv && !want_auth {
        return Err(ArgError("authPriv requires authentication (-a/-A)".into()));
    }

    if !want_auth {
        return Ok(UsmUser::noauth(name));
    }

    let proto = auth_proto.unwrap_or(AuthProtocol::HmacSha1);
    let apass =
        auth_pass.ok_or_else(|| ArgError("auth level requires -A AUTH-PASSPHRASE".into()))?;
    if !want_priv {
        return Ok(UsmUser::auth(name, proto, apass));
    }

    let pproto = priv_proto.unwrap_or(PrivProtocol::AesCfb128);
    let ppass = priv_pass.ok_or_else(|| ArgError("authPriv requires -X PRIV-PASSPHRASE".into()))?;
    Ok(UsmUser::auth_priv(name, proto, apass, pproto, ppass))
}
