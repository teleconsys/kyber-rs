use sha2::Sha256;

use crate::{
    cipher::Stream,
    group::{
        edwards25519::{Curve, Point as EdPoint, Scalar as EdScalar, SuiteEd25519},
        HashFactory,
    },
    share::vss::suite::Suite,
    sign::dss,
    util, xof, Group, Point, Random, Scalar, XOFFactory,
};

use super::{new_key_pair, Generator, KeyError, Suite as KeySuite};

#[test]
fn test_new_key_pair() {
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let keypair = new_key_pair(&suite).unwrap();
    let public = suite.point().mul(&keypair.private, None);

    assert_eq!(public, keypair.public);
}

#[derive(Clone, Debug, Copy, Default)]
/// A type to test interface Generator by intentionally creating a fixed private key.
struct FixedPrivSuiteEd25519 {
    pub(crate) curve: Curve,
}

impl Group for FixedPrivSuiteEd25519 {
    type POINT = EdPoint;

    fn string(&self) -> String {
        self.curve.string()
    }

    fn scalar(&self) -> EdScalar {
        self.curve.scalar()
    }

    fn scalar_len(&self) -> usize {
        self.curve.scalar_len()
    }

    fn point(&self) -> EdPoint {
        self.curve.point()
    }

    fn point_len(&self) -> usize {
        self.curve.point_len()
    }

    fn is_prime_order(&self) -> Option<bool> {
        None
    }
}

impl Random for FixedPrivSuiteEd25519 {
    fn random_stream(&self) -> Box<dyn Stream> {
        Box::<util::random::random::RandStream>::default()
    }
}

impl XOFFactory for FixedPrivSuiteEd25519 {
    fn xof(&self, key: Option<&[u8]>) -> Box<dyn crate::XOF> {
        Box::new(xof::blake3::Xof::new(key))
    }
}

impl HashFactory for FixedPrivSuiteEd25519 {
    type T = Sha256;
}

impl Suite for FixedPrivSuiteEd25519 {}
impl dss::Suite for FixedPrivSuiteEd25519 {}
impl KeySuite for FixedPrivSuiteEd25519 {}

impl Generator<EdScalar> for FixedPrivSuiteEd25519 {
    fn new_key<S: crate::cipher::Stream>(
        &self,
        _: &mut S,
    ) -> anyhow::Result<Option<EdScalar>, KeyError> {
        Ok(Some(self.scalar().set_int64(33)))
    }
}

#[test]
fn test_new_key_pair_gen() {
    let suite = &FixedPrivSuiteEd25519::default();
    let key = new_key_pair(suite).unwrap();

    let scalar33 = suite.scalar().set_int64(33);
    assert_eq!(key.private, scalar33);
}
