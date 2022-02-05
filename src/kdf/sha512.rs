//! HKDF sha512.

use cryptraits::kdf::Kdf as KdfTrait;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::KdfError;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Kdf(#[zeroize(skip)] Hkdf<Sha512>);

impl KdfTrait for Kdf {
    type E = KdfError;

    fn new(salt: Option<&[u8]>, data: &[u8]) -> Self {
        Self(Hkdf::<Sha512>::new(salt, data))
    }

    fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), Self::E> {
        self.0.expand(info, okm).or(Err(KdfError::InvalidLength))
    }
}
