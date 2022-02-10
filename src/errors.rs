//! Crate custom errors.

use std::fmt::Display;

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
    ScalarFormatError,
    EquationFalse,
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

impl From<schnorrkel::SignatureError> for KeyPairError {
    fn from(e: schnorrkel::SignatureError) -> Self {
        match e {
            schnorrkel::SignatureError::EquationFalse => KeyPairError::EquationFalse,
            schnorrkel::SignatureError::ScalarFormatError => KeyPairError::ScalarFormatError,
            schnorrkel::SignatureError::BytesLengthError {
                name: _,
                description: _,
                length: _,
            } => KeyPairError::BytesLengthError,
            schnorrkel::SignatureError::NotMarkedSchnorrkel => todo!(),
            _ => KeyPairError::UnknownError(e.to_string()),
        }
    }
}

impl Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AeadError")
    }
}

impl Display for KdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("KdfError::{:?}", self))
    }
}

impl Display for KeyPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("KeyPairError::{:?}", self))
    }
}

impl Display for HmacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("HmacError::{:?}", self))
    }
}

impl Display for StreamCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("StreamCipherError::{:?}", self))
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("SignatureErrors::{:?}", self))
    }
}
