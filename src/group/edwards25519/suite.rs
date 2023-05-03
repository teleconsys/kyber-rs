use core::fmt::{Display, Formatter};
use core::ops::{Deref, DerefMut};

use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;

use crate::cipher::Stream;
use crate::group::edwards25519::curve::Curve;
use crate::group::edwards25519::scalar::Scalar;
use crate::group::Group;
use crate::group::HashFactory;
use crate::share::vss::suite::Suite;
use crate::sign::dss;
use crate::util;
use crate::util::key::Generator;
use crate::util::key::KeyError;
use crate::util::key::Suite as KeySuite;
use crate::{xof, Random, XOFFactory};

use super::Point;

/// [`SuiteEd25519`] implements some basic functionalities such as [`Group`], [`HashFactory`],
/// and [`XOFFactory`].
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct SuiteEd25519 {
    // TODO: find a way to implement an embedded Stream without breaking everything
    // r: Box<dyn Stream>,
    curve: Curve,
}

impl SuiteEd25519 {
    /// [`new_blake3_sha256_ed25519()`] returns a cipher suite based on `blake3`,
    /// `SHA-256`, and the `Ed25519 curve`.It produces cryptographically random
    /// numbers via crate [`rand`].
    pub fn new_blake3_sha256_ed25519() -> SuiteEd25519 {
        SuiteEd25519::default()
    }

    // TODO: find a way to provide this extended flexibility
    // func (s *SuiteEd25519) Read(r io.Reader, objs ...interface{}) error {
    // return fixbuf.Read(r, s, objs...)
    // }
    //
    // func (s *SuiteEd25519) Write(w io.Writer, objs ...interface{}) error {
    // return fixbuf.Write(w, objs)
    // }
    //
    // /// New implements the kyber.Encoding interface
    // func (s *SuiteEd25519) New(t reflect.Type) interface{} {
    // return marshalling.GroupNew(s, t)
    // }

    // /// NewBlakeSHA256Ed25519WithRand returns a cipher suite based on package
    // /// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
    // /// It produces cryptographically random numbers via the provided stream r.
    // func NewBlakeSHA256Ed25519WithRand(r cipher.Stream) *SuiteEd25519 {
    // suite := new(SuiteEd25519)
    // suite.r = r
    // return suite
    // }
}

impl Deref for SuiteEd25519 {
    type Target = Curve;

    fn deref(&self) -> &Self::Target {
        &self.curve
    }
}

impl DerefMut for SuiteEd25519 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.curve
    }
}

impl Generator<Scalar> for SuiteEd25519 {
    fn new_key<S: crate::cipher::Stream>(
        &self,
        stream: &mut S,
    ) -> Result<Option<Scalar>, KeyError> {
        self.curve.new_key(stream)
    }
}

impl Display for SuiteEd25519 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.curve)
    }
}

impl Group for SuiteEd25519 {
    type POINT = Point;

    fn scalar(&self) -> Scalar {
        self.curve.scalar()
    }

    fn scalar_len(&self) -> usize {
        self.curve.scalar_len()
    }

    fn point(&self) -> Point {
        self.curve.point()
    }

    fn point_len(&self) -> usize {
        self.curve.point_len()
    }

    fn is_prime_order(&self) -> Option<bool> {
        self.curve.is_prime_order()
    }
}

impl Random for SuiteEd25519 {
    /// [`random_stream()`] returns a [`Box<Stream>`] that contains a [`Stream`]
    fn random_stream(&self) -> Box<dyn Stream> {
        // TODO: add this when the embedded r is added
        // if self.r != nil {
        //     return s.r;
        // }
        Box::<util::random::random_stream::RandStream>::default()
    }
}

impl XOFFactory for SuiteEd25519 {
    /// [`xof()`] returns an [`XOF`] which is implemented via the `blake3` hash.
    fn xof(&self, key: Option<&[u8]>) -> Box<dyn crate::XOF> {
        Box::new(xof::blake3::Xof::new(key))
    }
}

impl HashFactory for SuiteEd25519 {
    type T = Sha256;
}

impl Suite for SuiteEd25519 {}
impl dss::Suite for SuiteEd25519 {}
impl KeySuite for SuiteEd25519 {}
