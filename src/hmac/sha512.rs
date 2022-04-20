//! SHA-512 based HMAC.

use core::mem::ManuallyDrop;

use hmac::Mac;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::errors::HmacError;

/// SHA-512 based HMAC.
#[derive(Clone, Zeroize)]
pub struct Hmac(#[zeroize(skip)] ManuallyDrop<hmac::Hmac<Sha512>>);

impl Drop for Hmac {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.0) }
    }
}

impl cryptraits::hmac::Hmac for Hmac {
    type E = HmacError;

    fn new_from_slice(key: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let hmac = hmac::Hmac::new_from_slice(key).or(Err(HmacError::InvalidLength))?;
        Ok(Self(ManuallyDrop::new(hmac)))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn verify_slice(mut self, tag: &[u8]) -> Result<(), Self::E> {
        unsafe {
            ManuallyDrop::take(&mut self.0)
                .verify_slice(tag)
                .or(Err(HmacError::MacError))
        }
    }

    fn finalize(mut self) -> Vec<u8> {
        unsafe {
            ManuallyDrop::take(&mut self.0)
                .finalize()
                .into_bytes()
                .to_vec()
        }
    }
}

impl cryptraits::convert::Len for Hmac {
    const LEN: usize = 64;
}

#[cfg(test)]
mod tests {
    use cryptraits::hmac::Hmac as _;

    use super::Hmac;

    #[test]
    fn test_hmac_sha512() {
        let mut mac = Hmac::new_from_slice(b"my secret and secure key")
            .expect("HMAC can take key of any size");

        mac.update(b"input message");

        let code_bytes = hex::decode(
            "e51c913d44379e50c69201a5d95fb43ec0dc5b1736cd6f2214b506e64bd35c9dc0214c900f62be4b61d507a60299b6bb1625e5e365a9aa4ed1089b0262fb99a5",
        )
        .unwrap();

        assert!(mac.verify_slice(&code_bytes[..]).is_ok());
    }
}
