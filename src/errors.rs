//! Crate custom errors.

use cryptraits_macros::Error;

/// AEAD algorithm error.
#[derive(Debug, Error)]
pub struct AeadError;

/// KDF algorithm error.
#[derive(Debug, Error)]
pub enum KdfError {
    InvalidLength,
}

/// KeyPair errors.
#[derive(Debug, Error)]
pub enum KeyPairError {
    BytesLengthError,
    UnknownError(String),
    MnemonicPhraseError(String),
    InvalidEntropy,
}

/// HMAC algorithm errors.
#[derive(Debug, Error)]
pub enum HmacError {
    InvalidLength,
    MacError,
}

/// Stream cipher algorithm errors.
#[derive(Debug, Error)]
pub enum StreamCipherError {
    /// The error returned when key or nonce used in stream cipher
    /// has an invalid length.
    InvalidLength,

    /// The error returned when cipher reached the end of stream.
    LoopError,
}

/// Errors which may occur while processing signatures.
#[derive(Debug, Error, PartialEq)]
pub enum SignatureError {
    /// A signature verification equation failed.
    EquationFalse,
}

impl From<bip39::Error> for KeyPairError {
    fn from(e: bip39::Error) -> Self {
        Self::MnemonicPhraseError(e.to_string())
    }
}
