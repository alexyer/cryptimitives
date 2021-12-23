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
}

/// Errors which may occur while processing signatures.
#[derive(Debug, Error, PartialEq)]
pub enum SignatureError {
    /// A signature verification equation failed.
    EquationFalse,
}
