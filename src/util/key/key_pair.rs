/// module key creates asymmetric key pairs.
use crate::{group::edwards25519::CurveError, Group, Point, Random, Scalar};
use thiserror::Error;

/// [`Generator`] is a type that needs to implement a special case in order
/// to correctly choose a key. It should always be implemented for a [`Suite`]
/// if you want to use the `key` utils, but if no generator should be provided
/// the [`new_key()`] function shall return `None`
pub trait Generator<SCALAR: Scalar> {
    fn new_key<S: crate::cipher::Stream>(&self, stream: &mut S)
        -> Result<Option<SCALAR>, KeyError>;
}

/// [`Suite`] defines the capabilities required by this package.
pub trait Suite: Group + Random {}

/// [`Pair`] represents a public/private keypair together with the
/// [`ciphersuite`](Suite) the key was generated from.
#[derive(Debug, Clone, Default)]
pub struct Pair<POINT: Point> {
    pub public: POINT,          // Public key
    pub private: POINT::SCALAR, // Private key
}

/// [`new_key_pair()`] directly creates a secret/public key pair
pub fn new_key_pair<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>>(
    suite: &SUITE,
) -> Result<Pair<SUITE::POINT>, KeyError> {
    let mut kp = Pair::default();
    kp.gen(suite)?;
    Ok(kp)
}

impl<POINT: Point> Pair<POINT> {
    /// [`gen()`] creates a fresh public/private keypair with the given
    /// [`ciphersuite`](Suite), using a given source of cryptographic randomness. If
    /// [`Suite`] implements [`Generator`], then [`new_key()`] is called
    /// to generate the private key, otherwise the normal technique
    /// of choosing a random scalar from the group is used.
    pub(crate) fn gen<SUITE: Suite<POINT = POINT> + Generator<POINT::SCALAR>>(
        &mut self,
        suite: &SUITE,
    ) -> Result<(), KeyError> {
        let mut random = suite.random_stream();
        self.private = match suite.new_key(&mut random)? {
            Some(key) => key,
            None => suite.scalar().pick(&mut random),
        };
        self.public = suite.point().mul(&self.private, None);
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("curve error")]
    CurveError(#[from] CurveError),
}
