//! SHA-512 hash.

use cryptraits::hash::Hash as HashTrait;
use sha2::Digest;
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub struct Hash(#[zeroize(skip)] sha2::Sha512);

impl HashTrait for Hash {
    fn new() -> Self {
        Self(sha2::Sha512::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}
