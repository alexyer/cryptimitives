//! SHA-256 based HMAC.

use hmac::Mac;
use sha2::Sha256;

use crate::errors::HmacError;

/// SHA-256 based HMAC.
pub struct Hmac(hmac::Hmac<Sha256>);

impl cryptraits::hmac::Hmac for Hmac {
    type E = HmacError;

    fn new_from_slice(key: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let hmac = hmac::Hmac::new_from_slice(key).or(Err(HmacError::InvalidLength))?;
        Ok(Self(hmac))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn verify_slice(self, tag: &[u8]) -> Result<(), Self::E> {
        self.0.verify_slice(tag).or(Err(HmacError::MacError))
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use cryptraits::hmac::Hmac as _;
    use hex_literal::hex;

    use super::Hmac;

    #[test]
    fn test_hmac_sha256() {
        let mut mac = Hmac::new_from_slice(b"my secret and secure key")
            .expect("HMAC can take key of any size");

        mac.update(b"input message");

        let code_bytes = hex!(
            "
                97d2a569059bbcd8ead4444ff99071f4
                c01d005bcefe0d3567e1be628e5fdcd9
            "
        );

        assert!(mac.verify_slice(&code_bytes[..]).is_ok());
    }
}
