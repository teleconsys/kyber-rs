use crate::cipher::Stream;
use crate::group::edwards25519::curve::Curve;
use crate::group::edwards25519::scalar::Scalar;
use crate::group::group::Group;
use crate::util::random;
use crate::{xof, Random, Suite, XOFFactory};

use super::Point;

/// SuiteEd25519 implements some basic functionalities such as Group, HashFactory,
/// and XOFFactory.
#[derive(Clone, Copy)]
pub struct SuiteEd25519 {
    // Curve
    // r: Box<dyn Stream>,
    curve: Curve,
}

impl SuiteEd25519 {
    // /// Hash returns a newly instanciated sha256 hash function.
    // fn  Hash(&self) -> hash.Hash {
    //     return sha256.New()
    // }

    //     func (s *SuiteEd25519) Read(r io.Reader, objs ...interface{}) error {
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

    /// new_blake_sha256ed25519 returns a cipher suite based on package
    /// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
    /// It produces cryptographically random numbers via package crypto/rand.
    pub fn new_blake_sha256ed25519() -> SuiteEd25519 {
        SuiteEd25519::default()
        // suite := new(SuiteEd25519)
        // return suite
    }

    // /// NewBlakeSHA256Ed25519WithRand returns a cipher suite based on package
    // /// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
    // /// It produces cryptographically random numbers via the provided stream r.
    // func NewBlakeSHA256Ed25519WithRand(r cipher.Stream) *SuiteEd25519 {
    // suite := new(SuiteEd25519)
    // suite.r = r
    // return suite
    // }
}

impl Group<Scalar, Point> for SuiteEd25519 {
    fn string(&self) -> String {
        self.curve.string()
    }

    fn scalar(&self) -> Scalar {
        self.curve.scalar()
    }

    fn point(&self) -> Point {
        self.curve.point()
    }
}

impl Default for SuiteEd25519 {
    fn default() -> Self {
        SuiteEd25519 {
            curve: Curve::default(),
            // r: todo!(),
        }
    }
}

impl Random for SuiteEd25519 {
    /// RandomStream returns a cipher.Stream that returns a key stream
    /// from crypto/rand.
    fn RandomStream(&self) -> Box<dyn Stream> {
        // if self.r != nil {
        //     return s.r;
        // }
        Box::new(random::Randstream::default())
    }
}

impl XOFFactory for SuiteEd25519 {
    /// xof returns an XOF which is implemented via the Blake2b hash.
    fn xof(&self, key: Option<&[u8]>) -> Box<dyn crate::XOF> {
        Box::new(xof::blake::XOF::new(key))
    }
}

impl Suite<Scalar, Point> for SuiteEd25519 {}
