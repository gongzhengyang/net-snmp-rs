//! USM privacy: AES-128-CFB (RFC 3826).

use cipher::KeyIvInit;

use crate::error::{Error, Result};

/// The USM privacy protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivProtocol {
    /// AES-128 in CFB mode (RFC 3826).
    AesCfb128,
}

impl PrivProtocol {
    /// The cipher key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            PrivProtocol::AesCfb128 => 16,
        }
    }

    /// Build the 16-byte AES IV from engine boots/time and the 8-byte salt
    /// (the `msgPrivacyParameters`), per RFC 3826 §3.1.
    fn aes_iv(engine_boots: u32, engine_time: u32, salt: &[u8]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        let n = salt.len().min(8);
        iv[8..8 + n].copy_from_slice(&salt[..n]);
        iv
    }

    /// Encrypt `plaintext` (a serialized ScopedPDU). Returns the ciphertext.
    pub fn encrypt(
        self,
        priv_key: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if priv_key.len() < self.key_len() {
            return Err(Error::PrivFailure("privacy key too short".into()));
        }
        match self {
            PrivProtocol::AesCfb128 => {
                let iv = Self::aes_iv(engine_boots, engine_time, salt);
                let mut buf = plaintext.to_vec();
                cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(&priv_key[..16], &iv)
                    .map_err(|_| Error::PrivFailure("invalid AES key/iv".into()))?
                    .encrypt(&mut buf);
                Ok(buf)
            }
        }
    }

    /// Decrypt `ciphertext` back into ScopedPDU bytes.
    pub fn decrypt(
        self,
        priv_key: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if priv_key.len() < self.key_len() {
            return Err(Error::PrivFailure("privacy key too short".into()));
        }
        match self {
            PrivProtocol::AesCfb128 => {
                if salt.len() != 8 {
                    return Err(Error::PrivFailure(
                        "AES privacy salt must be 8 bytes".into(),
                    ));
                }
                let iv = Self::aes_iv(engine_boots, engine_time, salt);
                let mut buf = ciphertext.to_vec();
                cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&priv_key[..16], &iv)
                    .map_err(|_| Error::PrivFailure("invalid AES key/iv".into()))?
                    .decrypt(&mut buf);
                Ok(buf)
            }
        }
    }
}
