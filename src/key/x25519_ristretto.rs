//! Curve25519 with Ristretto point compression.

use cryptraits::{
    convert::{FromBytes, ToVec},
    key::PublicKey as PublicKeyTrait,
    key::{SecretKey as SecretKeyTrait, SharedSecretKey},
    key_exchange::DiffieHellman,
    signature::{Sign, Signature as SignatureTrait, Verify},
};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::{KeyPairError, SignatureError};

#[cfg(feature = "std")]
use std::fmt::Debug;

#[cfg(not(feature = "std"))]
use alloc::fmt::Debug;

pub type KeyPair = super::KeyPair<SecretKey>;

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct SecretKey(schnorrkel::SecretKey);

impl SecretKeyTrait for SecretKey {
    type PK = PublicKey;

    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(schnorrkel::SecretKey::generate_with(csprng))
    }

    fn to_public(&self) -> Self::PK {
        PublicKey(self.0.to_public())
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
    const LEN: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let secret = schnorrkel::SecretKey::from_bytes(bytes)
            .or_else(|e| Err(KeyPairError::UnknownError(e.to_string())))?;

        Ok(SecretKey(secret))
    }
}

impl ToVec for SecretKey {
    const LEN: usize = 64;

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
        Signature(self.0.sign_simple(b"X3DH", &data, &self.0.to_public()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(schnorrkel::PublicKey);

impl PublicKeyTrait for PublicKey {}

impl FromBytes for PublicKey {
    type E = KeyPairError;
    const LEN: usize = 32;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let public = schnorrkel::PublicKey::from_bytes(bytes)
            .or_else(|e| Err(KeyPairError::UnknownError(e.to_string())))?;

        Ok(PublicKey(public))
    }
}

impl From<EphemeralPublicKey> for PublicKey {
    fn from(epk: EphemeralPublicKey) -> Self {
        Self(epk.0)
    }
}

impl Into<EphemeralPublicKey> for &PublicKey {
    fn into(self) -> EphemeralPublicKey {
        EphemeralPublicKey(self.0)
    }
}

impl ToVec for PublicKey {
    const LEN: usize = 32;

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

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(schnorrkel::Signature);
impl SignatureTrait for Signature {}

impl FromBytes for Signature {
    type E = KeyPairError;
    const LEN: usize = 64;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let signature = schnorrkel::Signature::from_bytes(bytes)
            .or_else(|e| Err(KeyPairError::UnknownError(e.to_string())))?;

        Ok(Signature(signature))
    }
}

impl ToVec for Signature {
    const LEN: usize = 64;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

/// A Diffie-Hellman shared secret derived from an `EphemeralSecretKey`
/// and the other party's `PublicKey`.
pub struct SharedSecret(RistrettoPoint);
impl SharedSecretKey for SharedSecret {}

impl From<SharedSecret> for [u8; 32] {
    fn from(shared_secret: SharedSecret) -> Self {
        shared_secret.0.compress().to_bytes()
    }
}

impl ToVec for SharedSecret {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.compress().to_bytes())
    }
}

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
/// A Diffie-Hellman secret key used to derive a shared secret when
/// combined with a public key, that only exists for a short time.
pub struct EphemeralSecretKey(schnorrkel::SecretKey);

impl SecretKeyTrait for EphemeralSecretKey {
    type PK = EphemeralPublicKey;

    fn generate_with<R: CryptoRng + RngCore>(csprng: R) -> Self
    where
        Self: Sized,
    {
        Self(schnorrkel::SecretKey::generate_with(csprng))
    }

    fn to_public(&self) -> Self::PK {
        EphemeralPublicKey(self.0.to_public())
    }
}

impl DiffieHellman for EphemeralSecretKey {
    type SSK = SharedSecret;
    type PK = EphemeralPublicKey;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> Self::SSK {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0.to_ed25519_bytes()[..32]);

        SharedSecret(Scalar::from_bits(bytes) * peer_public.0.as_point())
    }
}

/// The public key derived from an ephemeral secret key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EphemeralPublicKey(schnorrkel::PublicKey);

impl PublicKeyTrait for EphemeralPublicKey {}

impl From<PublicKey> for EphemeralPublicKey {
    fn from(ik: PublicKey) -> Self {
        Self(ik.0)
    }
}

impl ToVec for EphemeralPublicKey {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

impl ToVec for EphemeralSecretKey {
    const LEN: usize = 32;

    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        Vec::from(self.0.to_bytes())
    }
}

#[allow(unused_imports)]
mod tests {
    use super::EphemeralSecretKey;
    use crate::errors::SignatureError;
    use crate::key::x25519_ristretto::KeyPair;
    use cryptraits::convert::{FromBytes, ToVec};
    use cryptraits::key::{KeyPair as _, SecretKey};
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
}
