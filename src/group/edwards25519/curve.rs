use crate::cipher::StreamError;
use crate::dh::Dh;
use crate::group::edwards25519::Point;
use crate::group::edwards25519::Scalar;
use crate::group::Group;
use crate::util::key::Generator;
use crate::util::key::KeyError;
use crate::util::random;

use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use sha2::{Digest, Sha512};
use thiserror::Error;

/// [`Curve`] represents the `Ed25519` [`group`](Group).
/// There are no parameters and no initialization is required
/// because it supports only this one specific curve.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Curve {}

impl Dh for Curve {
    type H = Sha256;
}

impl Group for Curve {
    type POINT = Point;

    /// [`string()`] return the name of the curve, `Ed25519`.
    fn string(&self) -> String {
        "Ed25519".to_string()
    }

    /// [`scalar()`] creates a new scalar for the prime-order subgroup of the Ed25519 curve.
    /// The scalars in this package implement scalar's [`set_bytes()`]
    /// method, interpreting the bytes as a little-endian integer, in order to remain
    /// compatible with other Ed25519 implementations, and with the standard implementation
    /// of the EdDSA signature.
    fn scalar(&self) -> Scalar {
        Scalar::default()
    }

    /// [`scalar_len()`] returns 32, the size in bytes of an encoded [`Scalar`]
    /// for the Ed25519 curve.
    fn scalar_len(&self) -> usize {
        32
    }

    fn point(&self) -> Point {
        Point::default()
    }

    /// [`point_len()`] returns 32, the size in bytes of an encoded [`Point`] on the Ed25519 curve.
    fn point_len(&self) -> usize {
        32
    }

    fn is_prime_order(&self) -> Option<bool> {
        None
    }
}

impl Curve {
    pub const fn new() -> Self {
        Curve {}
    }

    /// [`new_key_and_seed_with_input()`] returns a formatted Ed25519 key (avoid subgroup attack by
    /// requiring it to be a multiple of 8). It also returns the input and the digest used
    /// to generate the key.
    pub fn new_key_and_seed_with_input(self, buffer: &[u8]) -> (Scalar, &[u8], Vec<u8>) {
        let mut hasher = Sha512::new();
        hasher.update(buffer);

        let mut digest = hasher.finalize();
        digest[0] &= 0xf8;
        digest[31] &= 0x7f;
        digest[31] |= 0x40;

        let mut secret = self.scalar();
        secret.v.copy_from_slice(&digest[0..32]);

        (secret, buffer, digest[32..].to_vec())
    }

    /// [`new_key_and_seed()`] returns a formatted Ed25519 key (avoid subgroup attack by requiring
    /// it to be a multiple of 8). It also returns the seed and the input used to generate
    /// the key.
    pub fn new_key_and_seed<S: crate::cipher::Stream>(
        self,
        stream: &mut S,
    ) -> Result<(Scalar, Vec<u8>, Vec<u8>), CurveError> {
        let mut buffer = vec![0u8; 32];
        random::bytes(&mut buffer, stream)?;
        let (sc, buff, digest) = self.new_key_and_seed_with_input(&buffer);

        Ok((sc, buff.to_vec(), digest))
    }
}

impl Generator<Scalar> for Curve {
    /// [`new_key()`] returns a formatted Ed25519 key (avoiding subgroup attack by requiring
    /// it to be a multiple of 8). [`new_key()`] implements the [`Generator`] trait.
    fn new_key<S: crate::cipher::Stream>(
        &self,
        stream: &mut S,
    ) -> Result<Option<Scalar>, KeyError> {
        let (secret, _, _) = self.new_key_and_seed(stream)?;
        Ok(Some(secret))
    }
}

impl Default for Curve {
    fn default() -> Self {
        Curve::new()
    }
}

#[derive(Error, Debug)]
pub enum CurveError {
    #[error("stream error")]
    StreamError(#[from] StreamError),
}
