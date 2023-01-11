// // Package key creates asymmetric key pairs.
// package key

// import (
// 	"crypto/cipher"

// 	"go.dedis.ch/kyber/v3"
// )
use crate::{Group, Point, Random, Scalar};
use anyhow::Result;

/// Generator is a type that needs to implement a special case in order
/// to correctly choose a key. It should always be implemented for a suite
/// if you want to use the 'key' utils, but if no generator should be provided
/// the 'new_key' function shall return 'None'
pub trait Generator<SCALAR: Scalar> {
    fn new_key<S: crate::cipher::Stream>(&self, stream: &mut S) -> Result<Option<SCALAR>>;
}

/// Suite defines the capabilities required by this package.
pub trait Suite: Group + Random {}

/// Pair represents a public/private keypair together with the
/// ciphersuite the key was generated from.
#[derive(Debug, Clone)]
pub struct Pair<POINT: Point> {
    pub public: POINT,          // Public key
    pub private: POINT::SCALAR, // Private key
}

/// NewKeyPair directly creates a secret/public key pair
pub fn new_key_pair<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>>(
    suite: &SUITE,
) -> Result<Pair<SUITE::POINT>> {
    let mut kp = Pair::default();
    kp.gen(suite)?;
    Ok(kp)
}

impl<POINT: Point> Pair<POINT> {
    /// Gen creates a fresh public/private keypair with the given
    /// ciphersuite, using a given source of cryptographic randomness. If
    /// suite implements key.Generator, then suite.NewKey is called
    /// to generate the private key, otherwise the normal technique
    /// of choosing a random scalar from the group is used.
    pub(crate) fn gen<SUITE: Suite<POINT = POINT> + Generator<POINT::SCALAR>>(
        &mut self,
        suite: &SUITE,
    ) -> Result<()> {
        let mut random = suite.random_stream();
        self.private = match suite.new_key(&mut random)? {
            Some(key) => key,
            None => suite.scalar().pick(&mut random),
        };
        self.public = suite.point().mul(&self.private, None);
        Ok(())
    }
}

impl<POINT: Point> Default for Pair<POINT> {
    fn default() -> Self {
        Pair {
            private: POINT::SCALAR::default(),
            public: POINT::default(),
        }
    }
}
