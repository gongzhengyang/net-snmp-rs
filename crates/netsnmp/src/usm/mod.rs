//! User-based Security Model (USM) cryptography.
//!
//! Rust counterpart of `snmplib/snmpusm.c` and `snmplib/keytools.c`. It
//! implements the RFC 3414 / RFC 7860 / RFC 3826 primitives that SNMPv3 needs,
//! split into focused submodules:
//!
//! * [`level`](mod@self::level) — the [`SecurityLevel`] enum.
//! * [`auth`](mod@self::auth) — key derivation (`Ku`/`Kul`) and the keyed-MAC
//!   protocols (HMAC-MD5-96, HMAC-SHA-96, HMAC-192-SHA-256), plus the
//!   `KeyChange` construction.
//! * [`privacy`](mod@self::privacy) — AES-128-CFB encryption (RFC 3826).
//! * [`user`](mod@self::user) — the [`UsmUser`] credential bundle and its
//!   localized-key derivation.
//!
//! All cryptography is delegated to audited RustCrypto crates (`md-5`, `sha1`,
//! `sha2`, `hmac`, `aes`, `cfb-mode`); this module only wires them to the USM
//! rules. DES privacy is intentionally omitted (legacy and insecure).

mod auth;
mod level;
mod privacy;
mod user;

pub use auth::AuthProtocol;
pub use level::SecurityLevel;
pub use privacy::PrivProtocol;
pub use user::UsmUser;

#[cfg(test)]
mod tests {
    use super::auth::{generate_ku, localize};
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 3414 Appendix A.3.1 — MD5 password-to-key test vectors.
    #[test]
    fn rfc3414_md5_key_vectors() {
        let ku = generate_ku::<md5::Md5>(b"maplesyrup");
        assert_eq!(hex(&ku), "9faf3283884e92834ebc9847d8edd963");

        let engine_id = unhex("000000000000000000000002");
        let kul = localize::<md5::Md5>(&ku, &engine_id);
        assert_eq!(hex(&kul), "526f5eed9fcce26f8964c2930787d82b");
    }

    // RFC 3414 Appendix A.3.2 — SHA-1 password-to-key test vectors.
    #[test]
    fn rfc3414_sha1_key_vectors() {
        let ku = generate_ku::<sha1::Sha1>(b"maplesyrup");
        assert_eq!(hex(&ku), "9fb5cc0381497b3793528939ff788d5d79145211");

        let engine_id = unhex("000000000000000000000002");
        let kul = localize::<sha1::Sha1>(&ku, &engine_id);
        assert_eq!(hex(&kul), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn auth_protocol_localized_key_matches_vectors() {
        let engine_id = unhex("000000000000000000000002");
        let kul = AuthProtocol::HmacMd5.localized_key(b"maplesyrup", &engine_id);
        assert_eq!(hex(&kul), "526f5eed9fcce26f8964c2930787d82b");
    }

    #[test]
    fn mac_truncation_lengths() {
        let key = [0x11u8; 16];
        assert_eq!(AuthProtocol::HmacMd5.mac(&key, b"hello").len(), 12);
        assert_eq!(AuthProtocol::HmacSha1.mac(&key, b"hello").len(), 12);
        assert_eq!(AuthProtocol::HmacSha256.mac(&key, b"hello").len(), 24);
    }

    #[test]
    fn mac_verify_roundtrip() {
        let key = [0x42u8; 20];
        let msg = b"the quick brown fox";
        let tag = AuthProtocol::HmacSha1.mac(&key, msg);
        assert!(AuthProtocol::HmacSha1.verify(&key, msg, &tag));
        assert!(!AuthProtocol::HmacSha1.verify(&key, b"tampered", &tag));
    }

    #[test]
    fn aes_cfb_roundtrip() {
        let priv_key = [0x99u8; 16];
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let plaintext = b"a scoped PDU of arbitrary, non-block-aligned length!!";
        let ct = PrivProtocol::AesCfb128
            .encrypt(&priv_key, 7, 123456, &salt, plaintext)
            .unwrap();
        assert_ne!(&ct[..], &plaintext[..]);
        assert_eq!(ct.len(), plaintext.len());
        let pt = PrivProtocol::AesCfb128
            .decrypt(&priv_key, 7, 123456, &salt, &ct)
            .unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn usm_user_derives_keys() {
        let engine_id = unhex("80001f8880e9630000d61367");
        let user = UsmUser::auth_priv(
            "bob",
            AuthProtocol::HmacSha1,
            "authpass12345",
            PrivProtocol::AesCfb128,
            "privpass12345",
        );
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
        let ak = user.auth_key(&engine_id).unwrap();
        assert_eq!(ak.len(), 20);
        let pk = user.priv_key(&engine_id).unwrap();
        assert!(pk.len() >= 16);
    }
}
