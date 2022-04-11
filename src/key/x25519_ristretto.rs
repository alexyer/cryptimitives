//! Curve25519 with Ristretto point compression.

use bip39::{Language, Mnemonic};
use cryptraits::{
    convert::{FromBytes, Len, ToVec},
    key::PublicKey as PublicKeyTrait,
    key::{Blind, Generate, SecretKey as SecretKeyTrait, SharedSecretKey, WithPhrase},
    key_exchange::DiffieHellman,
    signature::{Sign, Signature as SignatureTrait, Verify},
};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, OsRng, RngCore};
use schnorrkel::{ExpansionMode, MiniSecretKey};

#[cfg(feature = "serde_derive")]
use serde::{
    de::{Error, SeqAccess, Unexpected, Visitor},
    Deserialize, Serialize,
};
use zeroize::Zeroize;

use crate::errors::{KeyPairError, SignatureError};

#[cfg(feature = "std")]
use std::fmt::Debug;
use std::ops::MulAssign;

#[cfg(not(feature = "std"))]
use alloc::fmt::Display;

#[cfg(feature = "std")]
use std::fmt::Display;

#[cfg(not(feature = "std"))]
use alloc::fmt::Debug;

#[cfg(not(feature = "std"))]
use alloc::string::String;

use super::util::seed_from_entropy;

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

impl WithPhrase for KeyPair {
    type E = KeyPairError;

    fn generate_with_phrase(
        word_count: usize,
        password: Option<&str>,
    ) -> Result<(Self, String), Self::E>
    where
        Self: Sized,
    {
        let s = Mnemonic::generate(word_count)?.to_string();
        let keypair = Self::from_phrase(&s, password)?;

        Ok((keypair, s))
    }

    fn from_phrase<'a, S: Into<std::borrow::Cow<'a, str>>>(
        s: S,
        password: Option<&str>,
    ) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let secret = SecretKey::from_phrase(s, password)?;
        let public = secret.to_public();

        Ok(Self { secret, public })
    }

    fn generate_in_with<R>(
        csprng: &mut R,
        word_count: usize,
        password: Option<&str>,
    ) -> Result<(Self, String), Self::E>
    where
        Self: Sized,
        R: RngCore + CryptoRng,
    {
        if word_count < 12 || word_count % 6 != 0 || word_count > 24 {
            return Err(KeyPairError::MnemonicPhraseError(String::from(
                "Bad word count",
            )));
        }

        let entropy_bytes = (word_count / 3) * 4;
        let mut entropy = [0u8; (24 / 3) * 4];
        rand_core::RngCore::fill_bytes(csprng, &mut entropy[0..entropy_bytes]);
        let phrase =
            Mnemonic::from_entropy_in(Language::English, &entropy[0..entropy_bytes])?.to_string();

        let keypair = Self::from_phrase(&phrase, password)?;

        Ok((keypair, phrase))
    }
}

#[derive(Zeroize, Debug, Clone, PartialEq)]
#[zeroize(drop)]
pub struct SecretKey(schnorrkel::SecretKey);

impl SecretKey {
    /// Convert this SecretKey into an array of 64 bytes, corresponding to an Ed25519 expanded secret key.
    pub fn to_ed25519_bytes(&self) -> Vec<u8> {
        Vec::from(self.0.to_ed25519_bytes())
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

impl SecretKeyTrait for SecretKey {
    type PK = PublicKey;

    fn to_public(&self) -> Self::PK {
        PublicKey(self.0.to_public())
    }
}

impl Generate for SecretKey {
    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(schnorrkel::SecretKey::generate_with(csprng))
    }

    fn generate() -> Self {
        Self::generate_with(&mut OsRng)
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

        self.0 = schnorrkel::SecretKey::from_bytes(&bytes)?;

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

        Ok(Self(schnorrkel::SecretKey::from_bytes(&bytes)?))
    }
}

impl Len for SecretKey {
    const LEN: usize = 64;
}

impl From<EphemeralSecretKey> for SecretKey {
    fn from(esk: EphemeralSecretKey) -> Self {
        Self::from_bytes(&esk.to_vec()).unwrap()
    }
}

impl DiffieHellman for SecretKey {
    type SSK = SharedSecret;
    type PK = PublicKey;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> Self::SSK {
        let mut secret_bytes: [u8; 32] = [0; 32];

        secret_bytes.copy_from_slice(&self.0.to_bytes()[..32]);

        let scalar = Scalar::from_canonical_bytes(secret_bytes).unwrap();

        SharedSecret(scalar * peer_public.0.as_point())
    }
}

impl FromBytes for SecretKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let secret = schnorrkel::SecretKey::from_bytes(bytes)
            .map_err(|e| KeyPairError::UnknownError(e.to_string()))?;

        Ok(SecretKey(secret))
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

impl WithPhrase for SecretKey {
    type E = KeyPairError;

    fn from_phrase<'a, S: Into<std::borrow::Cow<'a, str>>>(
        s: S,
        password: Option<&str>,
    ) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let entropy = Mnemonic::parse(s)?.to_entropy();
        let seed = seed_from_entropy(&entropy, password.unwrap_or(""))?;
        let mini_secret_key = MiniSecretKey::from_bytes(&seed[..32]).unwrap();
        Ok(SecretKey(mini_secret_key.expand(ExpansionMode::Uniform)))
    }

    fn generate_with_phrase(
        word_count: usize,
        password: Option<&str>,
    ) -> Result<(Self, String), Self::E>
    where
        Self: Sized,
    {
        let phrase = Mnemonic::generate(word_count)?.to_string();
        let secret_key = Self::from_phrase(&phrase, password)?;

        Ok((secret_key, phrase))
    }

    fn generate_in_with<R>(
        csprng: &mut R,
        word_count: usize,
        password: Option<&str>,
    ) -> Result<(Self, String), Self::E>
    where
        Self: Sized,
        R: RngCore + CryptoRng,
    {
        if word_count < 12 || word_count % 6 != 0 || word_count > 24 {
            return Err(KeyPairError::MnemonicPhraseError(String::from(
                "Bad word count",
            )));
        }

        let entropy_bytes = (word_count / 3) * 4;
        let mut entropy = [0u8; (24 / 3) * 4];
        rand_core::RngCore::fill_bytes(csprng, &mut entropy[0..entropy_bytes]);
        let phrase =
            Mnemonic::from_entropy_in(Language::English, &entropy[0..entropy_bytes])?.to_string();

        let secret_key = Self::from_phrase(&phrase, password)?;

        Ok((secret_key, phrase))
    }
}

impl<'a> Sign for SecretKey {
    type SIG = Signature;

    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized,
    {
        Signature(self.0.sign_simple(b"X3DH", data, &self.0.to_public()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Zeroize)]
pub struct PublicKey(#[zeroize(skip)] schnorrkel::PublicKey);

impl PublicKeyTrait for PublicKey {}

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

impl FromBytes for PublicKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let public = schnorrkel::PublicKey::from_bytes(bytes)
            .map_err(|e| KeyPairError::UnknownError(e.to_string()))?;

        Ok(PublicKey(public))
    }
}

impl Len for PublicKey {
    const LEN: usize = 32;
}

impl From<EphemeralPublicKey> for PublicKey {
    fn from(epk: EphemeralPublicKey) -> Self {
        Self(epk.0)
    }
}

#[allow(clippy::from_over_into)]
impl Into<EphemeralPublicKey> for &PublicKey {
    fn into(self) -> EphemeralPublicKey {
        EphemeralPublicKey(self.0)
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
        match self.0.verify_simple(b"X3DH", data, &signature.0) {
            Ok(_) => Ok(()),
            Err(schnorrkel::SignatureError::EquationFalse) => Err(SignatureError::EquationFalse),
            Err(e) => panic!("Unknown error: {:?}", e),
        }
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

        let mut point = self.0.into_point();
        point.mul_assign(Scalar::from_bits(factor));

        self.0 = schnorrkel::PublicKey::from_point(point);

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

        let mut point = self.0.into_point();
        point.mul_assign(Scalar::from_bits(factor));

        Ok(Self(schnorrkel::PublicKey::from_point(point)))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PublicKey")
            .field(
                &self
                    .0
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{:02X}", *b))
                    .collect::<Vec<_>>()
                    .join(""),
            )
            .finish()
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_vec()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(schnorrkel::Signature);
impl SignatureTrait for Signature {}

impl FromBytes for Signature {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let signature = schnorrkel::Signature::from_bytes(bytes)
            .map_err(|e| KeyPairError::UnknownError(e.to_string()))?;

        Ok(Signature(signature))
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

impl Len for Signature {
    const LEN: usize = 64;
}

/// A Diffie-Hellman shared secret derived from an `EphemeralSecretKey`
/// and the other party's `PublicKey`.
#[derive(Clone, Debug, Zeroize)]
pub struct SharedSecret(#[zeroize(skip)] RistrettoPoint);
impl SharedSecretKey for SharedSecret {}

impl From<SharedSecret> for [u8; 32] {
    fn from(shared_secret: SharedSecret) -> Self {
        shared_secret.0.compress().to_bytes()
    }
}

impl ToVec for SharedSecret {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.compress().to_bytes())
    }
}

impl Len for SharedSecret {
    const LEN: usize = 32;
}

#[derive(Zeroize, Debug, Clone)]
#[zeroize(drop)]
/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that only exists for a short time.
pub struct EphemeralSecretKey(schnorrkel::SecretKey);

impl SecretKeyTrait for EphemeralSecretKey {
    type PK = EphemeralPublicKey;

    fn to_public(&self) -> Self::PK {
        EphemeralPublicKey(self.0.to_public())
    }
}

impl Generate for EphemeralSecretKey {
    fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(schnorrkel::SecretKey::generate_with(csprng))
    }
}

impl DiffieHellman for EphemeralSecretKey {
    type SSK = SharedSecret;
    type PK = EphemeralPublicKey;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> Self::SSK {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0.to_bytes()[..32]);

        SharedSecret(Scalar::from_bits(bytes) * peer_public.0.as_point())
    }
}

impl Blind for EphemeralSecretKey {
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

        self.0 = schnorrkel::SecretKey::from_bytes(&bytes)?;

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

        Ok(Self(schnorrkel::SecretKey::from_bytes(&bytes)?))
    }
}

/// The public key derived from an ephemeral secret key.
#[derive(Debug, Clone, Copy, PartialEq, Zeroize)]
pub struct EphemeralPublicKey(#[zeroize(skip)] schnorrkel::PublicKey);

impl PublicKeyTrait for EphemeralPublicKey {}

impl Display for EphemeralPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_vec()))
    }
}

impl From<PublicKey> for EphemeralPublicKey {
    fn from(ik: PublicKey) -> Self {
        Self(ik.0)
    }
}

impl Len for EphemeralPublicKey {
    const LEN: usize = 32;
}

impl ToVec for EphemeralPublicKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl FromBytes for EphemeralPublicKey {
    type E = KeyPairError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let public = schnorrkel::PublicKey::from_bytes(bytes)
            .map_err(|e| KeyPairError::UnknownError(e.to_string()))?;

        Ok(EphemeralPublicKey(public))
    }
}

impl Blind for EphemeralPublicKey {
    type E = KeyPairError;

    fn blind(&mut self, blinding_factor: &[u8]) -> Result<(), Self::E> {
        // Blinding factor length should be equal to the secret key Scalar length.
        if blinding_factor.len() != 32 {
            return Err(KeyPairError::BytesLengthError);
        }

        let mut factor = [0; 32];
        factor.copy_from_slice(blinding_factor);

        let mut point = self.0.into_point();
        point.mul_assign(Scalar::from_bits(factor));

        self.0 = schnorrkel::PublicKey::from_point(point);

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

        let mut point = self.0.into_point();
        point.mul_assign(Scalar::from_bits(factor));

        Ok(Self(schnorrkel::PublicKey::from_point(point)))
    }
}

impl Len for EphemeralSecretKey {
    const LEN: usize = 32;
}

impl ToVec for EphemeralSecretKey {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

#[allow(unused_imports)]
mod tests {
    use super::{EphemeralSecretKey, PublicKey, SecretKey};
    use crate::errors::{KeyPairError, SignatureError};
    use crate::key::ed25519;
    use crate::key::x25519_ristretto::{EphemeralPublicKey, KeyPair};
    use bip39::Mnemonic;
    use cryptraits::convert::{FromBytes, ToVec};
    use cryptraits::key::{Blind, Generate, KeyPair as _, SecretKey as _, WithPhrase};
    use cryptraits::key_exchange::DiffieHellman;
    use cryptraits::signature::{Sign, Verify};
    use rand_core::OsRng;

    #[test]
    fn key_construct_from_bytes() {
        let bytes = vec![
            163, 32, 145, 4, 0, 205, 62, 240, 59, 87, 154, 77, 76, 172, 14, 144, 106, 224, 121,
            160, 178, 53, 227, 200, 15, 100, 125, 223, 69, 79, 178, 6, 249, 60, 236, 118, 88, 251,
            237, 212, 121, 28, 158, 94, 173, 159, 109, 18, 119, 32, 95, 39, 151, 112, 222, 230,
            246, 253, 15, 253, 139, 251, 161, 240, 172, 234, 111, 40, 46, 158, 32, 9, 119, 8, 125,
            180, 202, 113, 253, 218, 95, 6, 129, 230, 117, 54, 144, 169, 174, 74, 105, 33, 243,
            176, 206, 32,
        ];

        assert!(KeyPair::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn key_to_vec() {
        let bytes = [
            163, 32, 145, 4, 0, 205, 62, 240, 59, 87, 154, 77, 76, 172, 14, 144, 106, 224, 121,
            160, 178, 53, 227, 200, 15, 100, 125, 223, 69, 79, 178, 6, 249, 60, 236, 118, 88, 251,
            237, 212, 121, 28, 158, 94, 173, 159, 109, 18, 119, 32, 95, 39, 151, 112, 222, 230,
            246, 253, 15, 253, 139, 251, 161, 240, 172, 234, 111, 40, 46, 158, 32, 9, 119, 8, 125,
            180, 202, 113, 253, 218, 95, 6, 129, 230, 117, 54, 144, 169, 174, 74, 105, 33, 243,
            176, 206, 32,
        ];

        assert_eq!(&KeyPair::from_bytes(&bytes).unwrap().to_vec(), &bytes);
    }

    #[test]
    fn key_should_verify_signature() {
        const MSG: &[u8] = b"sw0rdfish";

        let alice_keypair = KeyPair::default();
        let bob_keypair = KeyPair::default();
        let alice_public = alice_keypair.to_public();

        let signature = alice_keypair.sign(MSG);

        assert_eq!(
            bob_keypair.verify(MSG, &signature),
            Err(SignatureError::EquationFalse)
        );

        assert!(alice_public.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn random_dh() {
        let alice_secret = EphemeralSecretKey::generate_with(&mut OsRng);
        let alice_public = alice_secret.to_public();

        let bob_secret = EphemeralSecretKey::generate_with(&mut OsRng);
        let bob_public = bob_secret.to_public();

        let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
        let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            <[u8; 32]>::from(alice_shared_secret),
            <[u8; 32]>::from(bob_shared_secret)
        );
    }

    #[test]
    fn test_secret_key_from_phrase() {
        assert!(SecretKey::from_phrase("zzzzz", Some("sw0rdf1sh")).is_err());

        let sk = SecretKey::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart",
            Some("sw0rdf1sh")
        )
        .unwrap();

        assert_eq!(
            sk.to_vec(),
            vec![
                143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72,
                245, 101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4, 48, 235, 96, 211, 80,
                219, 108, 91, 188, 178, 72, 160, 214, 67, 143, 125, 177, 251, 164, 18, 189, 58,
                182, 233, 204, 231, 25, 232, 4, 233, 63, 212
            ]
        );
    }

    #[test]
    fn test_secret_key_generate_with_phrase() {
        assert!(SecretKey::generate_with_phrase(12, Some("sw0rdf1sh")).is_ok());

        let (secret_key, phrase) = SecretKey::generate_with_phrase(12, Some("sw0rdf1sh")).unwrap();
        let secret_key_bytes = secret_key.to_vec();
        let secret_key = SecretKey::from_phrase(&phrase, Some("sw0rdf1sh")).unwrap();

        assert_eq!(secret_key.to_vec(), secret_key_bytes);
    }

    #[test]
    fn test_secret_key_generate_in_with_phrase() {
        assert!(SecretKey::generate_in_with(&mut OsRng, 12, Some("sw0rdf1sh")).is_ok());

        let (secret_key, phrase) = SecretKey::generate_with_phrase(12, Some("sw0rdf1sh")).unwrap();
        let secret_key_bytes = secret_key.to_vec();
        let secret_key = SecretKey::from_phrase(&phrase, Some("sw0rdf1sh")).unwrap();

        assert_eq!(secret_key.to_vec(), secret_key_bytes);
    }

    #[test]
    fn test_keypair_from_phrase() {
        assert!(KeyPair::from_phrase("zzzzz", Some("sw0rdf1sh")).is_err());

        let keypair = KeyPair::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart",
            Some("sw0rdf1sh")
        )
        .unwrap();

        assert_eq!(
            keypair.secret().to_vec(),
            vec![
                143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72,
                245, 101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4, 48, 235, 96, 211, 80,
                219, 108, 91, 188, 178, 72, 160, 214, 67, 143, 125, 177, 251, 164, 18, 189, 58,
                182, 233, 204, 231, 25, 232, 4, 233, 63, 212
            ]
        );
    }

    #[test]
    fn test_keypair_generate_with_phrase() {
        assert!(KeyPair::generate_with_phrase(12, Some("sw0rdf1sh")).is_ok());

        let (keypair, phrase) = KeyPair::generate_with_phrase(12, Some("sw0rdf1sh")).unwrap();
        let keypair_bytes = keypair.to_vec();
        let keypair = KeyPair::from_phrase(&phrase, Some("sw0rdf1sh")).unwrap();

        assert_eq!(keypair.to_vec(), keypair_bytes);
    }

    #[test]
    fn test_keypair_generate_in_with_phrase() {
        assert!(KeyPair::generate_in_with(&mut OsRng, 12, Some("sw0rdf1sh")).is_ok());

        let (keypair, phrase) = KeyPair::generate_with_phrase(12, Some("sw0rdf1sh")).unwrap();
        let keypair_bytes = keypair.to_vec();
        let keypair = KeyPair::from_phrase(&phrase, Some("sw0rdf1sh")).unwrap();

        assert_eq!(keypair.to_vec(), keypair_bytes);
    }

    #[test]
    fn test_secret_key_blinding() {
        let mut secret = SecretKey::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

        let blinding_factor = vec![
            143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72, 245,
            101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4,
        ];

        assert!(secret.blind(&blinding_factor).is_ok());

        let another_secret = SecretKey::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

        let blinded_secret = another_secret.to_blind(&blinding_factor).unwrap();

        assert_ne!(another_secret.to_vec(), blinded_secret.to_vec());
        assert_eq!(secret.to_vec(), blinded_secret.to_vec());
    }

    #[test]
    fn test_public_key_blinding() {
        let keypair = KeyPair::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

        let another_keypair = KeyPair::from_phrase(
                "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

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
    fn test_public_keypair_blinding() {
        let mut keypair = KeyPair::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

        let another_keypair = KeyPair::from_phrase(
                "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart", None).unwrap();

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

    #[test]
    fn test_keypair_clone() {
        let keypair = KeyPair::generate();
        let clonned = keypair.clone();

        assert_eq!(keypair.to_vec(), clonned.to_vec());
    }

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_secret_key_serde() {
        use serde::{Deserialize, Serialize, Serializer};
        use serde_test::{assert_tokens, Token};

        let secret = SecretKey::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart",
            Some("sw0rdf1sh")).unwrap();

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
        use serde::{Deserialize, Serialize, Serializer};
        use serde_test::{assert_tokens, Token};

        let public = SecretKey::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart",
            Some("sw0rdf1sh")).unwrap().to_public();

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
        use serde::{Deserialize, Serialize, Serializer};
        use serde_test::{assert_tokens, Token};

        let keypair = KeyPair::from_phrase(
            "trade open write rug piece company bonus tone crop pulse story craft rigid solar drama run coconut input crawl blush liar start oxygen smart",
            Some("sw0rdf1sh")).unwrap();

        let mut tokens = Vec::new();

        tokens.push(Token::Seq { len: Some(96) });

        for byte in keypair.to_vec().into_iter() {
            tokens.push(Token::U8(byte));
        }

        tokens.push(Token::SeqEnd);

        assert_tokens(&keypair, &tokens);
    }

    #[test]
    fn test_keypair_from_secret() {
        let secret = SecretKey::generate();
        let keypair = KeyPair::from(secret.clone());

        assert_eq!(keypair.secret(), &secret);
    }

    #[test]
    fn test_ephemeral_secret_key_blinding() {
        let mut secret = EphemeralSecretKey::generate();
        let another_secret = secret.clone();

        let blinding_factor = vec![
            143, 50, 102, 65, 121, 149, 204, 85, 156, 141, 109, 158, 18, 78, 54, 192, 46, 72, 245,
            101, 84, 67, 231, 80, 12, 178, 157, 87, 165, 252, 59, 4,
        ];

        assert!(secret.blind(&blinding_factor).is_ok());

        let blinded_secret = another_secret.to_blind(&blinding_factor).unwrap();

        assert_ne!(another_secret.to_vec(), blinded_secret.to_vec());
        assert_eq!(secret.to_vec(), blinded_secret.to_vec());
    }

    #[test]
    fn test_ephemeral_public_key_blinding() {
        let mut public = EphemeralSecretKey::generate().to_public();
        let another_public = public.clone();

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
}
