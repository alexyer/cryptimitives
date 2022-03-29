//! Curve25519 Edwards point.
use cryptraits::convert::{FromBytes, Len, ToVec};
use cryptraits::signature::{Sign, Verify};
use cryptraits::{
    key::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait},
    signature::Signature as SignatureTrait,
};
use ed25519_dalek::Verifier;

#[cfg(feature = "serde_derive")]
use serde::de::{Error, SeqAccess, Unexpected, Visitor};

#[cfg(feature = "serde_derive")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::fmt::Debug;

use core::hash::Hash;

#[cfg(not(feature = "std"))]
use alloc::fmt::Display;

#[cfg(feature = "std")]
use std::fmt::Display;

use zeroize::Zeroize;

#[cfg(not(feature = "std"))]
use alloc::fmt::Debug;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::errors::{KeyPairError, SignatureError};

pub type KeyPair = super::KeyPair<SecretKey>;

#[cfg(feature = "serde_derive")]
impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_vec().serialize(serializer)
    }
}

#[cfg(feature = "serde_derive")]
impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyPairVisitor;

        impl<'de> Visitor<'de> for KeyPairVisitor {
            type Value = KeyPair;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();

                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }

                let keypair = KeyPair::from_bytes(&bytes)
                    .or(Err(Error::invalid_type(Unexpected::Seq, &self)))?;

                Ok(keypair)
            }
        }

        deserializer.deserialize_byte_buf(KeyPairVisitor)
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(ed25519_dalek::ExpandedSecretKey);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&self.to_vec()).finish()
    }
}

impl SecretKeyTrait for SecretKey {
    type PK = PublicKey;

    fn to_public(&self) -> Self::PK {
        PublicKey((&self.0).into())
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(ed25519_dalek::ExpandedSecretKey::from_bytes(&self.0.to_bytes()).unwrap())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Len for SecretKey {
    const LEN: usize = 64;
}

impl FromBytes for SecretKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let secret = ed25519_dalek::ExpandedSecretKey::from_bytes(bytes)?;
        Ok(Self(secret))
    }
}

impl ToVec for SecretKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl<'a> Sign for SecretKey {
    type SIG = Signature;

    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized,
    {
        Signature(self.0.sign(&data, &(&self.0).into()))
    }
}

#[cfg(feature = "serde_derive")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_vec().serialize(serializer)
    }
}

#[cfg(feature = "serde_derive")]
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecretKeyVisitor;

        impl<'de> Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();

                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }

                let secret = SecretKey::from_bytes(&bytes)
                    .or(Err(Error::invalid_type(Unexpected::Seq, &self)))?;

                Ok(secret)
            }
        }

        deserializer.deserialize_byte_buf(SecretKeyVisitor)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct PublicKey(#[zeroize(skip)] ed25519_dalek::PublicKey);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(self.to_vec()))
            .finish()
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl PublicKeyTrait for PublicKey {}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_vec()))
    }
}

impl Len for PublicKey {
    const LEN: usize = 32;
}

impl FromBytes for PublicKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let public = ed25519_dalek::PublicKey::from_bytes(bytes)?;
        Ok(Self(public))
    }
}

impl ToVec for PublicKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl Verify for PublicKey {
    type E = SignatureError;
    type SIG = Signature;

    fn verify(&self, data: &[u8], signature: &Self::SIG) -> Result<(), Self::E> {
        self.0
            .verify(data, &signature.0)
            .or(Err(SignatureError::EquationFalse))
    }
}

#[cfg(feature = "serde_derive")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_vec().serialize(serializer)
    }
}

#[cfg(feature = "serde_derive")]
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();

                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }

                let public = PublicKey::from_bytes(&bytes)
                    .or(Err(Error::invalid_type(Unexpected::Seq, &self)))?;

                Ok(public)
            }
        }

        deserializer.deserialize_byte_buf(PublicKeyVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);
impl SignatureTrait for Signature {}

impl Len for Signature {
    const LEN: usize = 64;
}

impl FromBytes for Signature {
    type E = SignatureError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let signature = ed25519_dalek::Signature::from_bytes(bytes)?;
        Ok(Self(signature))
    }
}

impl ToVec for Signature {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        errors::SignatureError,
        key::{ed25519::KeyPair, x25519_ristretto},
    };
    use cryptraits::{
        convert::{FromBytes, ToVec},
        key::{Generate, KeyPair as _},
        signature::{Sign, Verify},
    };

    use super::SecretKey;

    const ALICE: [u8; 96] = [
        24, 96, 63, 231, 236, 136, 164, 225, 105, 202, 11, 198, 122, 20, 82, 211, 7, 123, 242, 95,
        196, 12, 125, 239, 30, 213, 142, 152, 44, 190, 208, 114, 219, 196, 254, 31, 193, 139, 137,
        179, 134, 57, 239, 57, 136, 47, 200, 220, 133, 163, 62, 113, 192, 43, 117, 234, 84, 54, 80,
        32, 109, 230, 181, 34, 228, 20, 176, 204, 111, 171, 211, 222, 35, 93, 59, 130, 87, 43, 211,
        240, 152, 245, 205, 241, 214, 228, 202, 182, 62, 70, 230, 244, 33, 77, 237, 60,
    ];

    const BOB: [u8; 96] = [
        56, 36, 219, 22, 94, 68, 246, 204, 121, 18, 213, 150, 205, 112, 138, 10, 55, 15, 30, 205,
        107, 246, 104, 215, 142, 131, 242, 58, 67, 51, 47, 52, 32, 25, 135, 101, 169, 189, 245, 47,
        104, 215, 211, 85, 82, 92, 50, 116, 113, 159, 117, 134, 151, 85, 221, 211, 53, 81, 31, 51,
        123, 46, 0, 26, 186, 109, 157, 40, 129, 127, 220, 84, 204, 251, 238, 87, 99, 176, 115, 51,
        16, 169, 199, 33, 242, 3, 230, 66, 106, 41, 84, 238, 51, 47, 208, 48,
    ];

    #[test]
    fn key_construct_from_bytes() {
        assert!(KeyPair::from_bytes(&ALICE).is_ok());
    }

    #[test]
    fn key_to_vec() {
        assert_eq!(&KeyPair::from_bytes(&ALICE).unwrap().to_vec(), &ALICE);
    }

    #[test]
    fn test_secret_key_partial_eq() {
        let ristretto_keypair = x25519_ristretto::KeyPair::generate();
        let secret_bytes = ristretto_keypair.secret.to_ed25519_bytes();

        let alice = SecretKey::from_bytes(&secret_bytes).unwrap();
        let bob = SecretKey::from_bytes(&secret_bytes).unwrap();

        assert_eq!(alice, bob);
    }

    #[test]
    fn key_should_verify_signature() {
        const MSG: &[u8] = b"sw0rdfish";

        let alice_keypair = KeyPair::from_bytes(&ALICE).unwrap();
        let bob_keypair = KeyPair::from_bytes(&BOB).unwrap();
        let alice_public = alice_keypair.to_public();

        let signature = alice_keypair.sign(MSG);

        assert_eq!(
            bob_keypair.verify(MSG, &signature),
            Err(SignatureError::EquationFalse)
        );

        assert!(alice_public.verify(MSG, &signature).is_ok());
    }

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_secret_key_serde() {
        use serde_test::{assert_tokens, Token};

        let secret = KeyPair::from_bytes(&ALICE).unwrap().secret().clone();

        let mut tokens = Vec::new();

        tokens.push(Token::Seq { len: Some(64) });

        for byte in secret.to_vec().into_iter() {
            tokens.push(Token::U8(byte));
        }

        tokens.push(Token::SeqEnd);

        assert_tokens(&secret, &tokens);
    }

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_public_key_serde() {
        use serde_test::{assert_tokens, Token};

        let public = KeyPair::from_bytes(&ALICE).unwrap().to_public();

        let mut tokens = Vec::new();

        tokens.push(Token::Seq { len: Some(32) });

        for byte in public.to_vec().into_iter() {
            tokens.push(Token::U8(byte));
        }

        tokens.push(Token::SeqEnd);

        assert_tokens(&public, &tokens);
    }

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_keypair_serde() {
        use serde_test::{assert_tokens, Token};

        let keypair = KeyPair::from_bytes(&ALICE).unwrap();

        let mut tokens = Vec::new();

        tokens.push(Token::Seq { len: Some(96) });

        for byte in keypair.to_vec().into_iter() {
            tokens.push(Token::U8(byte));
        }

        tokens.push(Token::SeqEnd);

        assert_tokens(&keypair, &tokens);
    }
}
