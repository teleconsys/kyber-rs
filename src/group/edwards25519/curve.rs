use std::marker::PhantomData;

use crate::group::edwards25519::Point as EdPoint;
use crate::group::edwards25519::Scalar as EdScalar;
use crate::util::key::Generator;
use crate::util::random;
use crate::{group::Group, Scalar};
use anyhow::Result;

use sha2::{Digest, Sha512};

/// Curve represents the Ed25519 group.
/// There are no parameters and no initialization is required
/// because it supports only this one specific curve.
#[derive(Clone, Copy)]
pub struct Curve<SCALAR: Scalar> {
    _phantom: PhantomData<SCALAR>,
}

impl<SCALAR: Scalar> Curve<SCALAR> {
    pub const fn new() -> Self {
        Curve {
            _phantom: PhantomData,
        }
    }
}

impl Group<EdScalar, EdPoint> for Curve<EdScalar> {
    /// Return the name of the curve, "Ed25519".
    fn string(&self) -> String {
        "Ed25519".to_string()
    }

    /// scalar creates a new scalar for the prime-order subgroup of the Ed25519 curve.
    /// The scalars in this package implement kyber.scalar's SetBytes
    /// method, interpreting the bytes as a little-endian integer, in order to remain
    /// compatible with other Ed25519 implementations, and with the standard implementation
    /// of the EdDSA signature.
    fn scalar(&self) -> EdScalar {
        EdScalar::default()
    }

    fn point(&self) -> EdPoint {
        EdPoint::default()
    }
}

impl Curve<EdScalar> {
    /// ScalarLen returns 32, the size in bytes of an encoded scalar
    /// for the Ed25519 curve.
    fn scalar_len() -> usize {
        return 32;
    }

    // PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
    fn point_len() -> usize {
        return 32;
    }

    /// NewKeyAndSeedWithInput returns a formatted Ed25519 key (avoid subgroup attack by
    /// requiring it to be a multiple of 8). It also returns the input and the digest used
    /// to generate the key.
    pub fn new_key_and_seed_with_input(self, buffer: &[u8]) -> (EdScalar, &[u8], Vec<u8>) {
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
    ) -> Result<(EdScalar, Vec<u8>, Vec<u8>)> {
        let mut buffer = vec![0u8; 32];
        random::bytes(&mut buffer, stream)?;
        let (sc, buff, digest) = self.new_key_and_seed_with_input(&buffer);

        Ok((sc, buff.to_vec(), digest))
    }
}

impl Generator<EdScalar> for Curve<EdScalar> {
    /// NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
    /// it to be a multiple of 8). NewKey implements the kyber/util/key.Generator interface.
    fn new_key<S: crate::cipher::Stream>(self, stream: &mut S) -> Result<EdScalar> {
        let (secret, _, _) = self.new_key_and_seed(stream)?;
        Ok(secret)
    }
}

impl<SCALAR> Default for Curve<SCALAR>
where
    SCALAR: Scalar,
{
    fn default() -> Self {
        Curve {
            _phantom: PhantomData,
        }
    }
}
