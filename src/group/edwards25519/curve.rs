use crate::dh::Dh;
use crate::group::edwards25519::Point;
use crate::group::edwards25519::Scalar;
use crate::group::Group;
use crate::util::key::Generator;
use crate::util::random;
use anyhow::Result;

use sha2::Sha256;
use sha2::{Digest, Sha512};

/// Curve represents the Ed25519 group.
/// There are no parameters and no initialization is required
/// because it supports only this one specific curve.
#[derive(Clone, Copy, Debug)]
pub struct Curve {}

impl Dh for Curve {
    type H = Sha256;
}

impl Group for Curve {
    type POINT = Point;

    /// Return the name of the curve, "Ed25519".
    fn string(&self) -> String {
        "Ed25519".to_string()
    }

    /// scalar creates a new scalar for the prime-order subgroup of the Ed25519 curve.
    /// The scalars in this package implement kyber.scalar's SetBytes
    /// method, interpreting the bytes as a little-endian integer, in order to remain
    /// compatible with other Ed25519 implementations, and with the standard implementation
    /// of the EdDSA signature.
    fn scalar(&self) -> Scalar {
        Scalar::default()
    }

    /// ScalarLen returns 32, the size in bytes of an encoded scalar
    /// for the Ed25519 curve.
    fn scalar_len(&self) -> usize {
        return 32;
    }

    fn point(&self) -> Point {
        Point::default()
    }

    /// PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
    fn point_len(&self) -> usize {
        return 32;
    }

    fn is_prime_order(&self) -> Option<bool> {
        None
    }
}

impl Curve {
    pub const fn new() -> Self {
        Curve {}
    }

    /// NewKeyAndSeedWithInput returns a formatted Ed25519 key (avoid subgroup attack by
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

        return (secret, buffer, digest.to_vec()[32..].to_vec());
    }

    /// NewKeyAndSeed returns a formatted Ed25519 key (avoid subgroup attack by requiring
    /// it to be a multiple of 8). It also returns the seed and the input used to generate
    /// the key.
    pub fn new_key_and_seed<S: crate::cipher::Stream>(
        self,
        stream: &mut S,
    ) -> Result<(Scalar, Vec<u8>, Vec<u8>)> {
        let mut buffer = vec![0u8; 32];
        random::bytes(&mut buffer, stream)?;
        let (sc, buff, digest) = self.new_key_and_seed_with_input(&buffer);

        Ok((sc, buff.to_vec(), digest))
    }
}

impl Generator for Curve {
    type SCALAR = Scalar;

    /// NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
    /// it to be a multiple of 8). NewKey implements the kyber/util/key.Generator interface.
    fn new_key<S: crate::cipher::Stream>(&self, stream: &mut S) -> Result<Scalar> {
        let (secret, _, _) = self.new_key_and_seed(stream)?;
        Ok(secret)
    }
}

impl Default for Curve {
    fn default() -> Self {
        Curve::new()
    }
}
