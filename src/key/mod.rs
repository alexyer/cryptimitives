#[cfg(feature = "std")]
use std::fmt::Debug;

#[cfg(not(feature = "std"))]
use alloc::fmt::Debug;

use cryptraits::{
    convert::{FromBytes, ToVec},
    key::{KeyPair as KeypairTrait, SecretKey},
    key_exchange::DiffieHellman,
    signature::{Sign, Verify},
};
use rand_core::{CryptoRng, OsRng, RngCore};

use zeroize::Zeroize;

use crate::errors::{KeyPairError, SignatureError};

pub mod util;
pub mod x25519_ristretto;

pub struct KeyPair<SK>
where
    SK: SecretKey,
{
    secret: SK,
    public: SK::PK,
}

impl<SK> KeypairTrait for KeyPair<SK>
where
    SK: SecretKey,
{
    type SK = SK;

    fn generate_with<R>(csprng: R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let secret: SK = SK::generate_with(csprng);
        let public = secret.to_public();

        KeyPair { secret, public }
    }

    fn to_public(&self) -> SK::PK {
        self.public
    }

    fn public(&self) -> &<Self::SK as SecretKey>::PK {
        &self.public
    }

    fn secret(&self) -> &Self::SK {
        &self.secret
    }
}

impl<SK> Zeroize for KeyPair<SK>
where
    SK: SecretKey,
{
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<SK> Drop for KeyPair<SK>
where
    SK: SecretKey,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<SK> FromBytes for KeyPair<SK>
where
    SK: SecretKey + FromBytes,
    SK::PK: FromBytes,
    KeyPairError: From<<SK as FromBytes>::E> + From<<<SK as SecretKey>::PK as FromBytes>::E>,
{
    type E = KeyPairError;
    const LEN: usize = SK::LEN + <<SK as SecretKey>::PK as FromBytes>::LEN;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::E> {
        if bytes.len() != Self::LEN {
            return Err(KeyPairError::BytesLengthError);
        }

        let secret = SK::from_bytes(&bytes[..SK::LEN])?;
        let public = SK::PK::from_bytes(&bytes[SK::LEN..])?;

        Ok(KeyPair { secret, public })
    }
}

impl<SK> ToVec for KeyPair<SK>
where
    SK: SecretKey + ToVec,
    SK::PK: ToVec,
{
    const LEN: usize = SK::LEN + <SK::PK as ToVec>::LEN;

    fn to_vec(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(self.secret.to_vec());
        bytes.extend(self.public.to_vec());

        bytes
    }
}

impl<SK> Sign for KeyPair<SK>
where
    SK: SecretKey + Sign,
{
    type SIG = <SK as Sign>::SIG;

    fn sign(&self, data: &[u8]) -> Self::SIG
    where
        Self: Sized,
    {
        self.secret.sign(data)
    }
}

impl<SK> DiffieHellman for KeyPair<SK>
where
    SK: SecretKey + Sign + DiffieHellman,
{
    type SSK = <SK as DiffieHellman>::SSK;
    type PK = <SK as DiffieHellman>::PK;

    fn diffie_hellman(&self, peer_public: &Self::PK) -> <SK as DiffieHellman>::SSK {
        self.secret.diffie_hellman(peer_public)
    }
}

impl<SK> Verify for KeyPair<SK>
where
    SK: SecretKey,
    SK::PK: Verify<E = SignatureError>,
{
    type E = SignatureError;
    type SIG = <SK::PK as Verify>::SIG;

    fn verify(&self, data: &[u8], signature: &Self::SIG) -> Result<(), Self::E> {
        self.public.verify(data, signature)
    }
}

impl<SK> Debug for KeyPair<SK>
where
    SK: SecretKey,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("secret", &String::from("<erased>"))
            .field("public", &self.public)
            .finish()
    }
}

impl<SK> Default for KeyPair<SK>
where
    SK: SecretKey,
{
    fn default() -> Self {
        let secret: SK = SecretKey::generate_with(OsRng);
        let public = secret.to_public();

        Self { secret, public }
    }
}
