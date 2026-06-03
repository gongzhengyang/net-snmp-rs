//! USM authentication: key derivation (`keytools.c`) and the keyed-MAC
//! protocols (HMAC-MD5-96, HMAC-SHA-96, HMAC-192-SHA-256).

use digest::{Digest, KeyInit};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;

/// The amount of password material hashed during `Ku` generation (RFC 3414).
const KU_EXPANSION_BYTES: usize = 1_048_576;

/// The USM authentication protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProtocol {
    /// HMAC-MD5-96 (RFC 3414).
    HmacMd5,
    /// HMAC-SHA-96 (RFC 3414).
    HmacSha1,
    /// HMAC-192-SHA-256 (RFC 7860).
    HmacSha256,
}

impl AuthProtocol {
    /// The truncated MAC length placed on the wire.
    pub fn mac_len(self) -> usize {
        match self {
            AuthProtocol::HmacMd5 | AuthProtocol::HmacSha1 => 12,
            AuthProtocol::HmacSha256 => 24,
        }
    }

    /// Derive the non-localized intermediate key `Ku` from a password.
    fn ku(self, password: &[u8]) -> Vec<u8> {
        match self {
            AuthProtocol::HmacMd5 => generate_ku::<md5::Md5>(password),
            AuthProtocol::HmacSha1 => generate_ku::<sha1::Sha1>(password),
            AuthProtocol::HmacSha256 => generate_ku::<sha2::Sha256>(password),
        }
    }

    /// Derive the engine-localized key `Kul` from a password and engine id.
    pub fn localized_key(self, password: &[u8], engine_id: &[u8]) -> Vec<u8> {
        let ku = self.ku(password);
        match self {
            AuthProtocol::HmacMd5 => localize::<md5::Md5>(&ku, engine_id),
            AuthProtocol::HmacSha1 => localize::<sha1::Sha1>(&ku, engine_id),
            AuthProtocol::HmacSha256 => localize::<sha2::Sha256>(&ku, engine_id),
        }
    }

    /// Compute the truncated HMAC over `message` with the localized key.
    pub fn mac(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let full: Vec<u8> = match self {
            AuthProtocol::HmacMd5 => {
                let mut m = Hmac::<md5::Md5>::new_from_slice(key).expect("any key length");
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
            AuthProtocol::HmacSha1 => {
                let mut m = Hmac::<sha1::Sha1>::new_from_slice(key).expect("any key length");
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
            AuthProtocol::HmacSha256 => {
                let mut m = Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
                m.update(message);
                m.finalize().into_bytes().to_vec()
            }
        };
        full[..self.mac_len()].to_vec()
    }

    /// Constant-time verification that `tag` matches the expected MAC.
    pub fn verify(self, key: &[u8], message: &[u8], tag: &[u8]) -> bool {
        let expected = self.mac(key, message);
        expected.ct_eq(tag).into()
    }

    /// Plain (un-keyed) digest of `data` with this protocol's hash. Used by the
    /// KeyChange construction.
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            AuthProtocol::HmacMd5 => md5::Md5::digest(data).to_vec(),
            AuthProtocol::HmacSha1 => sha1::Sha1::digest(data).to_vec(),
            AuthProtocol::HmacSha256 => sha2::Sha256::digest(data).to_vec(),
        }
    }

    /// Build the RFC 3414 §A.2 `KeyChange` value used to remotely change a
    /// USM user's localized key.
    ///
    /// The result is `random || (newKey XOR digest(oldKey || random))`, where
    /// both keys are localized to `engine_id` and `random` supplies the fresh
    /// `keyLength` octets (injected so callers control the RNG and tests are
    /// deterministic). Supports the single-block keys used by all supported
    /// protocols (MD5/SHA-1/SHA-256), where the localized key length equals the
    /// digest length.
    ///
    /// # Panics
    /// Panics if `random` is shorter than the localized key length.
    pub fn key_change(
        self,
        old_password: &[u8],
        new_password: &[u8],
        engine_id: &[u8],
        random: &[u8],
    ) -> Vec<u8> {
        let old_key = self.localized_key(old_password, engine_id);
        let new_key = self.localized_key(new_password, engine_id);
        let key_len = old_key.len();
        assert!(
            random.len() >= key_len,
            "KeyChange needs at least {key_len} random octets"
        );
        let rnd = &random[..key_len];
        let digest = self.digest(&[old_key.as_slice(), rnd].concat());
        let mut delta = new_key;
        for (d, h) in delta.iter_mut().zip(digest.iter()) {
            *d ^= *h;
        }
        let mut out = rnd.to_vec();
        out.extend_from_slice(&delta);
        out
    }
}

/// Generate the non-localized key `Ku` by hashing 1 MiB of repeated password.
pub(super) fn generate_ku<D: Digest>(password: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    if password.is_empty() {
        return hasher.finalize().to_vec();
    }
    let mut buf = [0u8; 64];
    let mut idx = 0usize;
    let mut count = 0usize;
    while count < KU_EXPANSION_BYTES {
        for b in buf.iter_mut() {
            *b = password[idx % password.len()];
            idx += 1;
        }
        hasher.update(buf);
        count += 64;
    }
    hasher.finalize().to_vec()
}

/// Localize `Ku` to an engine id: `Kul = H(Ku || engineID || Ku)`.
pub(super) fn localize<D: Digest>(ku: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(ku);
    hasher.update(engine_id);
    hasher.update(ku);
    hasher.finalize().to_vec()
}
