//! Curve25519 Edwards point.
use cryptraits::convert::{FromBytes, Len, ToVec};
use cryptraits::signature::{Sign, Verify};
use cryptraits::{
    key::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait},
    signature::Signature as SignatureTrait,
};
use ed25519_dalek::{Signer, Verifier};

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

#[derive(Clone, Zeroize, PartialEq)]
#[zeroize(drop)]
pub struct SecretKey(ed25519_dalek::SecretKey);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&self.to_vec()).finish()
    }
}

impl SecretKeyTrait for SecretKey {
    type PK = PublicKey;

    fn to_public(&self) -> Self::PK {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.0);
        PublicKey(signing_key.verifying_key())
    }
}

impl Len for SecretKey {
    const LEN: usize = 32;
}

impl FromBytes for SecretKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let mut secret = [0; 32];
        secret.copy_from_slice(&bytes[..32]);

        Ok(Self(secret))
    }
}

impl ToVec for SecretKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        self.0.to_vec()
    }
}

impl Sign for SecretKey {
    type SIG = Signature;

    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized,
    {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.0);
        Signature(signing_key.sign(data))
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

#[derive(Clone, Copy, Eq, Zeroize)]
pub struct PublicKey(#[zeroize(skip)] ed25519_dalek::VerifyingKey);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&hex::encode(self.to_vec()))
            .finish()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl PublicKeyTrait for PublicKey {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

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
        if bytes.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut public_bytes = [0; 32];
        public_bytes.copy_from_slice(bytes);

        let public = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes)?;
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
        let signature = ed25519_dalek::Signature::from_slice(bytes)?;
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

    const ALICE: [u8; 64] = [
        24, 96, 63, 231, 236, 136, 164, 225, 105, 202, 11, 198, 122, 20, 82, 211, 7, 123, 242, 95,
        196, 12, 125, 239, 30, 213, 142, 152, 44, 190, 208, 114, 23, 48, 153, 209, 41, 119, 171,
        75, 133, 143, 182, 126, 166, 183, 13, 200, 228, 46, 12, 196, 74, 33, 172, 184, 76, 85, 46,
        248, 175, 115, 126, 18,
    ];

    const BOB: [u8; 64] = [
        56, 36, 219, 22, 94, 68, 246, 204, 121, 18, 213, 150, 205, 112, 138, 10, 55, 15, 30, 205,
        107, 246, 104, 215, 142, 131, 242, 58, 67, 51, 47, 52, 158, 148, 186, 206, 11, 99, 185,
        148, 160, 154, 166, 185, 189, 173, 44, 238, 186, 13, 222, 208, 67, 192, 239, 191, 83, 52,
        155, 51, 241, 231, 218, 51,
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

        tokens.push(Token::Seq { len: Some(32) });

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

        tokens.push(Token::Seq { len: Some(64) });

        for byte in keypair.to_vec().into_iter() {
            tokens.push(Token::U8(byte));
        }

        tokens.push(Token::SeqEnd);

        assert_tokens(&keypair, &tokens);
    }
}
