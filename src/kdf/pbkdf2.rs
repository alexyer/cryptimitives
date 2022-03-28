//! PBKDF2 implementation.

use std::marker::PhantomData;

use cryptraits::{convert::Len, hmac::Hmac, kdf::Kdf as KdfTrait};
use zeroize::Zeroize;

use crate::errors::KdfError;

pub struct Kdf<PRF>
where
    PRF: Hmac + Len,
{
    data: Vec<u8>,
    salt: Vec<u8>,

    _prf: PhantomData<PRF>,
}

impl<PRF> Zeroize for Kdf<PRF>
where
    PRF: Hmac + Len,
{
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.salt.zeroize();
    }
}

impl<PRF> KdfTrait for Kdf<PRF>
where
    PRF: Hmac + Len,
{
    type E = KdfError;

    fn new(salt: Option<&[u8]>, data: &[u8]) -> Self {
        Self {
            data: Vec::from(data),
            salt: Vec::from(salt.or(Some("".as_bytes())).unwrap()),
            _prf: PhantomData::default(),
        }
    }

    fn expand(&self, _info: &[u8], okm: &mut [u8]) -> Result<(), Self::E> {
        self.pbkdf2(okm, 4096)
    }
}

impl<PRF> Kdf<PRF>
where
    PRF: Hmac + Len,
{
    /// Expand with `rounds` number of iterations.
    pub fn pbkdf2(&self, okm: &mut [u8], rounds: usize) -> Result<(), KdfError> {
        let chunk_size = PRF::LEN;

        for (i, chunk) in okm.chunks_mut(chunk_size).enumerate() {
            self.pbkdf2_body(i, chunk, rounds);
        }

        Ok(())
    }

    fn pbkdf2_body(&self, i: usize, chunk: &mut [u8], rounds: usize) {
        for v in chunk.iter_mut() {
            *v = 0;
        }

        let mut salt = {
            let mut prf = PRF::new_from_slice(&self.data).unwrap();

            prf.update(&self.salt);
            prf.update(&(i + 1).to_be_bytes());

            let salt = prf.finalize();
            self.xor(chunk, &salt);
            salt
        };

        for _ in 1..rounds {
            let mut prf = PRF::new_from_slice(&self.data).unwrap();
            prf.update(&salt);
            salt = prf.finalize();

            self.xor(chunk, &salt);
        }
    }

    fn xor(&self, res: &mut [u8], salt: &[u8]) {
        debug_assert!(salt.len() >= res.len(), "length mismatch in xor");
        res.iter_mut().zip(salt.iter()).for_each(|(a, b)| *a ^= b);
    }
}
