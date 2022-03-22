//! Utility functions and test stubs.

use cryptraits::{
    convert::{FromBytes, Len, ToVec},
    kdf::Kdf,
    key::{Generate, PublicKey, SecretKey},
    signature::Signature,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::KeyPairError;

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Zeroize)]
pub struct TestPublicKey([u8; 5]);

impl PublicKey for TestPublicKey {}

impl FromBytes for TestPublicKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyPairError>
    where
        Self: Sized,
    {
        let mut key: [u8; <Self as Len>::LEN] = [0; <Self as Len>::LEN];

        for i in 0..<Self as Len>::LEN {
            key[i] = bytes[i];
        }

        Ok(Self(key))
    }
}

impl Len for TestPublicKey {
    const LEN: usize = 5;
}

impl ToVec for TestPublicKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0)
    }
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TestSecretKey([u8; 5]);

impl SecretKey for TestSecretKey {
    type PK = TestPublicKey;

    fn to_public(&self) -> Self::PK {
        todo!()
    }
}

impl Generate for TestSecretKey {
    fn generate_with<R: CryptoRng + RngCore>(_csprng: R) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn generate() -> Self {
        todo!()
    }
}

impl FromBytes for TestSecretKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyPairError>
    where
        Self: Sized,
    {
        let mut key: [u8; Self::LEN] = [0; Self::LEN];

        for i in 0..Self::LEN {
            key[i] = bytes[i];
        }

        Ok(Self(key))
    }
}

impl Len for TestSecretKey {
    const LEN: usize = 5;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TestSignature([u8; 2]);

impl Signature for TestSignature {}

impl ToVec for TestSignature {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0)
    }
}

impl Len for TestSignature {
    const LEN: usize = 2;
}

impl FromBytes for TestSignature {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyPairError>
    where
        Self: Sized,
    {
        let mut signature: [u8; 2] = [0; 2];

        for i in 0..2 {
            signature[i] = bytes[i];
        }

        Ok(Self(signature))
    }
}

pub fn seed_from_entropy(entropy: &[u8], password: &str) -> Result<[u8; 64], KeyPairError> {
    if entropy.len() < 16 || entropy.len() > 32 || entropy.len() % 4 != 0 {
        return Err(KeyPairError::InvalidEntropy);
    }

    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; 64];

    let pbkdf2 =
        crate::kdf::pbkdf2::Kdf::<crate::hmac::sha512::Hmac>::new(Some(salt.as_bytes()), entropy);

    pbkdf2
        .pbkdf2(&mut seed, 2048)
        .or(Err(KeyPairError::InvalidEntropy))?;

    salt.zeroize();

    Ok(seed)
}
