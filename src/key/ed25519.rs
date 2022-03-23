//! Curve25519 Edwards point.
use cryptraits::convert::{FromBytes, Len, ToVec};
use cryptraits::key::{Blind, SharedSecretKey};
use cryptraits::key_exchange::DiffieHellman;
use cryptraits::signature::{Sign, Verify};
use cryptraits::{
    key::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait},
    signature::Signature as SignatureTrait,
};
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use curve25519_dalek_ng::montgomery::MontgomeryPoint;
use curve25519_dalek_ng::scalar::Scalar;
use ed25519_dalek::Verifier;

#[cfg(feature = "serde_derive")]
use serde::de::{Error, SeqAccess, Unexpected, Visitor};

#[cfg(feature = "serde_derive")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::fmt::Debug;

use core::hash::Hash;
use std::ops::MulAssign;

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

impl Blind for KeyPair {
    type E = KeyPairError;

    fn blind(&mut self, blinding_factor: &[u8]) -> Result<(), Self::E> {
        self.secret.blind(blinding_factor)?;
        self.public = self.secret.to_public();

        Ok(())
    }

    fn to_blind(&self, blinding_factor: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let secret = self.secret.to_blind(blinding_factor)?;
        let public = secret.to_public();

        Ok(Self { secret, public })
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct SecretKey(ed25519_dalek::SecretKey);

impl SecretKeyTrait for SecretKey {
    type PK = PublicKey;

    fn to_public(&self) -> Self::PK {
        PublicKey((&self.0).into())
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(ed25519_dalek::SecretKey::from_bytes(self.0.as_bytes()).unwrap())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
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
        let secret = ed25519_dalek::SecretKey::from_bytes(bytes)?;
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
        let expanded: ed25519_dalek::ExpandedSecretKey = (&self.0).into();
        Signature(expanded.sign(&data, &(&self.0).into()))
    }
}

impl DiffieHellman for SecretKey {
    type SSK = SharedSecret;
    type PK = PublicKey;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> Self::SSK {
        let mut secret_bytes: [u8; 32] = [0; 32];

        secret_bytes.copy_from_slice(&self.0.to_bytes()[..32]);

        let scalar = Scalar::from_canonical_bytes(secret_bytes).unwrap();
        let point = CompressedEdwardsY(peer_public.0.to_bytes())
            .decompress()
            .unwrap()
            .to_montgomery();

        SharedSecret(scalar * point)
    }
}

impl Blind for SecretKey {
    type E = KeyPairError;

    fn blind(&mut self, blinding_factor: &[u8]) -> Result<(), Self::E> {
        // Blinding factor length should be equal to the secret key Scalar length.
        if blinding_factor.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut bytes = self.0.to_bytes();

        let mut scalar = [0; 32];
        scalar.copy_from_slice(&bytes[..32]);

        let mut factor = [0; 32];
        factor.copy_from_slice(blinding_factor);

        let new_scalar = Scalar::from_bits(scalar) * Scalar::from_bits(factor);

        bytes[..32].copy_from_slice(&new_scalar.to_bytes());

        self.0 = ed25519_dalek::SecretKey::from_bytes(&bytes[..32])?;

        Ok(())
    }

    fn to_blind(&self, blinding_factor: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        // Blinding factor length should be equal to the secret key Scalar length.
        if blinding_factor.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut bytes = self.0.to_bytes();

        let mut scalar = [0; 32];
        scalar.copy_from_slice(&bytes[..32]);

        let mut factor = [0; 32];
        factor.copy_from_slice(blinding_factor);

        let new_scalar = Scalar::from_bits(scalar) * Scalar::from_bits(factor);

        bytes[..32].copy_from_slice(&new_scalar.to_bytes());

        Ok(Self(ed25519_dalek::SecretKey::from_bytes(&bytes[..32])?))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct PublicKey(#[zeroize(skip)] ed25519_dalek::PublicKey);

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl PublicKeyTrait for PublicKey {}

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

impl Blind for PublicKey {
    type E = KeyPairError;

    fn blind(&mut self, blinding_factor: &[u8]) -> Result<(), Self::E> {
        // Blinding factor length should be equal to the secret key Scalar length.
        if blinding_factor.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut factor = [0; 32];
        factor.copy_from_slice(blinding_factor);

        let mut point = CompressedEdwardsY(self.0.to_bytes()).decompress().unwrap();
        point.mul_assign(Scalar::from_bits(factor));

        self.0 = ed25519_dalek::PublicKey::from_bytes(&point.compress().to_bytes()).unwrap();

        Ok(())
    }

    fn to_blind(&self, blinding_factor: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        // Blinding factor length should be equal to the secret key Scalar length.
        if blinding_factor.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut factor = [0; 32];
        factor.copy_from_slice(blinding_factor);

        let mut point = CompressedEdwardsY(self.0.to_bytes()).decompress().unwrap();
        point.mul_assign(Scalar::from_bits(factor));

        Ok(Self(
            ed25519_dalek::PublicKey::from_bytes(&point.compress().to_bytes()).unwrap(),
        ))
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

/// A Diffie-Hellman shared secret derived from an `EphemeralSecretKey`
/// and the other party's `PublicKey`.
pub struct SharedSecret(MontgomeryPoint);
impl SharedSecretKey for SharedSecret {}

impl From<SharedSecret> for [u8; 32] {
    fn from(shared_secret: SharedSecret) -> Self {
        shared_secret.0.to_bytes()
    }
}

impl ToVec for SharedSecret {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl Len for SharedSecret {
    const LEN: usize = 32;
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::SignatureError,
        key::{ed25519::KeyPair, x25519_ristretto},
    };
    use cryptraits::{
        convert::{FromBytes, ToVec},
        key::{Blind, Generate, KeyPair as _},
        signature::{Sign, Verify},
    };

    use super::SecretKey;

    const ALICE: [u8; 64] = [
        160, 238, 129, 16, 105, 33, 213, 166, 178, 49, 108, 143, 6, 85, 228, 70, 44, 96, 252, 37,
        227, 67, 54, 189, 0, 234, 29, 15, 93, 4, 210, 107, 157, 216, 224, 144, 215, 13, 69, 102,
        243, 45, 194, 240, 80, 66, 122, 78, 126, 227, 9, 187, 166, 159, 170, 15, 47, 52, 172, 59,
        87, 20, 194, 6,
    ];

    const BOB: [u8; 64] = [
        200, 179, 165, 85, 124, 194, 171, 142, 172, 121, 1, 12, 69, 172, 146, 243, 191, 201, 117,
        174, 71, 101, 63, 21, 113, 79, 168, 62, 167, 110, 140, 110, 86, 97, 134, 139, 3, 83, 167,
        161, 110, 209, 147, 218, 205, 234, 105, 215, 150, 132, 4, 73, 11, 109, 131, 132, 5, 249,
        111, 188, 152, 67, 44, 82,
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

        let alice = SecretKey::from_bytes(&secret_bytes[..32]).unwrap();
        let bob = SecretKey::from_bytes(&secret_bytes[..32]).unwrap();

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

    #[test]
    fn test_secret_key_blinding() {
        let mut secret = SecretKey::from_bytes(&ALICE[..32]).unwrap();

        let blinding_factor = vec![
            143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72, 245,
            101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4,
        ];

        assert!(secret.blind(&blinding_factor).is_ok());

        let another_secret = SecretKey::from_bytes(&ALICE[..32]).unwrap();

        let blinded_secret = another_secret.to_blind(&blinding_factor).unwrap();

        assert_ne!(another_secret.to_vec(), blinded_secret.to_vec());
        assert_eq!(secret.to_vec(), blinded_secret.to_vec());
    }

    #[test]
    fn test_public_key_blinding() {
        let keypair = KeyPair::from_bytes(&ALICE).unwrap();
        let another_keypair = KeyPair::from_bytes(&ALICE).unwrap();

        let mut public = keypair.to_public();

        let another_public = another_keypair.to_public();

        assert_eq!(public.to_vec(), another_public.to_vec());

        let blinding_factor = vec![
            143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72, 245,
            101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4,
        ];

        assert!(public.blind(&blinding_factor).is_ok());

        let blinded_public = another_public.to_blind(&blinding_factor).unwrap();

        assert_ne!(another_public.to_vec(), blinded_public.to_vec());
        assert_eq!(public.to_vec(), blinded_public.to_vec());
    }

    #[test]
    fn test_keypair_blinding() {
        let mut keypair = KeyPair::from_bytes(&ALICE).unwrap();
        let another_keypair = KeyPair::from_bytes(&ALICE).unwrap();

        assert_eq!(keypair.to_vec(), another_keypair.to_vec());

        let blinding_factor = vec![
            143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72, 245,
            101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4,
        ];

        assert!(keypair.blind(&blinding_factor).is_ok());

        let blinded_keypair = another_keypair.to_blind(&blinding_factor).unwrap();

        assert_ne!(another_keypair.to_vec(), blinded_keypair.to_vec());
        assert_eq!(keypair.to_vec(), blinded_keypair.to_vec());
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
