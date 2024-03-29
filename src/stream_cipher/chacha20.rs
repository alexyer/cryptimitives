//! ChaCha20 stream cipher.
use chacha20::{
    cipher::{KeyIvInit, StreamCipher as _},
    ChaCha20,
};
use cryptraits::stream_cipher::StreamCipher as StreamCipherTrait;
use zeroize::Zeroize;

use crate::errors::StreamCipherError;

/// ChaCha20 stream cipher.
#[derive(Zeroize)]
pub struct StreamCipher(#[zeroize(skip)] ChaCha20);

impl StreamCipherTrait for StreamCipher {
    type E = StreamCipherError;

    fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self, Self::E>
    where
        Self: Sized,
    {
        let cipher =
            ChaCha20::new_from_slices(key, nonce).or(Err(StreamCipherError::InvalidLength))?;

        Ok(Self(cipher))
    }

    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<(), Self::E> {
        self.0
            .try_apply_keystream(data)
            .or(Err(StreamCipherError::LoopError))
    }
}

#[cfg(test)]
mod tests {
    use cryptraits::stream_cipher::StreamCipher as _;
    use hex_literal::hex;

    use crate::stream_cipher::chacha20::StreamCipher;

    const KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    const IV: [u8; 12] = hex!("000000000000004a00000000");

    const PLAINTEXT: [u8; 114] = hex!(
        "
        4c616469657320616e642047656e746c
        656d656e206f662074686520636c6173
        73206f66202739393a20496620492063
        6f756c64206f6666657220796f75206f
        6e6c79206f6e652074697020666f7220
        746865206675747572652c2073756e73
        637265656e20776f756c642062652069
        742e
        "
    );

    const KEYSTREAM: [u8; 114] = hex!(
        "
        224f51f3401bd9e12fde276fb8631ded8c131f823d2c06
        e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b
        9334794cba40c63e34cdea212c4cf07d41b769a6749f3f
        630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a
        c40c5945398b6eda1a832c89c167eacd901d7e2bf363
        "
    );

    const CIPHERTEXT: [u8; 114] = hex!(
        "
        6e2e359a2568f98041ba0728dd0d6981
        e97e7aec1d4360c20a27afccfd9fae0b
        f91b65c5524733ab8f593dabcd62b357
        1639d624e65152ab8f530c359f0861d8
        07ca0dbf500d6a6156a38e088a22b65e
        52bc514d16ccf806818ce91ab7793736
        5af90bbf74a35be6b40b8eedf2785e42
        874d
        "
    );

    #[test]
    fn test_keystream() {
        let mut cipher = StreamCipher::new_from_slices(&KEY, &IV).unwrap();

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix).unwrap();

        let mut buf = [0u8; 114];
        cipher.apply_keystream(&mut buf).unwrap();
        assert_eq!(&buf[..], &KEYSTREAM[..]);
    }

    #[test]
    fn test_encryption() {
        let mut cipher = StreamCipher::new_from_slices(&KEY, &IV).unwrap();
        let mut buf = PLAINTEXT.clone();

        // The test vectors omit the first 64-bytes of the keystream
        let mut prefix = [0u8; 64];
        cipher.apply_keystream(&mut prefix).unwrap();

        cipher.apply_keystream(&mut buf).unwrap();
        assert_eq!(&buf[..], &CIPHERTEXT[..]);
    }
}
