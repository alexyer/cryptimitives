//! Utility functions and test stubs.

use cryptraits::{
    convert::{FromBytes, ToVec},
    key::{PublicKey, SecretKey},
    signature::Signature,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::KeyPairError;

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct TestPublicKey([u8; 5]);

impl PublicKey for TestPublicKey {}

impl FromBytes for TestPublicKey {
    type E = KeyPairError;
    const LEN: usize = 5;

    fn from_bytes(bytes: &[u8]) -> Result<Self, KeyPairError>
    where
        Self: Sized,
    {
        let mut key: [u8; <Self as FromBytes>::LEN] = [0; <Self as FromBytes>::LEN];

        for i in 0..<Self as FromBytes>::LEN {
            key[i] = bytes[i];
        }

        Ok(Self(key))
    }
}

impl ToVec for TestPublicKey {
    const LEN: usize = 5;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0)
    }
}

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct TestSecretKey([u8; 5]);

impl SecretKey for TestSecretKey {
    type PK = TestPublicKey;

    fn generate_with<R: CryptoRng + RngCore>(_csprng: R) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn to_public(&self) -> Self::PK {
        todo!()
    }
}

impl FromBytes for TestSecretKey {
    type E = KeyPairError;
    const LEN: usize = 5;

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TestSignature([u8; 2]);

impl Signature for TestSignature {}

impl ToVec for TestSignature {
    const LEN: usize = 2;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0)
    }
}

impl FromBytes for TestSignature {
    type E = KeyPairError;
    const LEN: usize = 2;

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
