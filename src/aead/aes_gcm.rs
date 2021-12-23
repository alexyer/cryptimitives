//! AES-GCM cipher.

use aes_gcm::{aead::Aead as _, Key, NewAead, Nonce};
use cryptraits::aead::Aead;

use crate::errors::AeadError;

/// AES-GCM with a 256-bit key and 96-bit nonce.
pub struct Aes256Gcm(::aes_gcm::Aes256Gcm);

impl Aead for Aes256Gcm {
    type E = AeadError;
    const NONCE_LEN: usize = 12;

    fn new(key: &[u8]) -> Self {
        let key = Key::from_slice(key);
        Self(::aes_gcm::Aes256Gcm::new(key))
    }

    fn encrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::E> {
        let nonce = Nonce::from_slice(nonce);
        self.0.encrypt(nonce, data).or(Err(AeadError))
    }

    fn decrypt(&self, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::E> {
        let nonce = Nonce::from_slice(nonce);
        self.0.decrypt(nonce, data).or(Err(AeadError))
    }
}

#[cfg(test)]
mod tests {
    use cryptraits::aead::Aead;

    use super::Aes256Gcm;

    #[test]
    fn it_should_cipher() {
        const MSG: &'static str = "very very secret message";

        let cipher = Aes256Gcm::new(b"swrdf1shswrdf1shswrdf1shswrdf1sh");

        let ciphertext = cipher.encrypt(b"blahblahblah", MSG.as_bytes()).unwrap();

        assert_ne!(MSG.as_bytes(), &ciphertext);

        let decrypted_msg = cipher.decrypt(b"blahblahblah", &ciphertext).unwrap();

        assert_eq!(MSG.as_bytes(), &decrypted_msg);
    }
}
