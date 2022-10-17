use crate::group::edwards25519::curve::Curve;
use crate::group::edwards25519::scalar::Scalar;
use crate::group::group::Group;
use crate::xof;

/// SuiteEd25519 implements some basic functionalities such as Group, HashFactory,
/// and XOFFactory.
pub struct SuiteEd25519 {
    // Curve
    // r cipher.Stream

    curve: Curve,
}

impl SuiteEd25519 {

    // /// Hash returns a newly instanciated sha256 hash function.
    // fn  Hash(&self) -> hash.Hash {
    //     return sha256.New()
    // }

    /// xof returns an XOF which is implemented via the Blake2b hash.
    pub fn xof(&self, key: &[u8]) -> xof::blake2xb::XOF {
        xof::blake2xb::XOF::new(key)
    }

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
//
// /// RandomStream returns a cipher.Stream that returns a key stream
// /// from crypto/rand.
// func (s *SuiteEd25519) RandomStream() cipher.Stream {
// if s.r != nil {
// return s.r
// }
// return random.New()
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

impl Group<Scalar> for SuiteEd25519 {
    fn string(&self) -> String {
        self.curve.string()
    }

    fn scalar(&self) -> Scalar {
        self.curve.scalar()
    }
}

impl Default for SuiteEd25519 {
    fn default() -> Self {
        SuiteEd25519 { curve: Curve::default() }
    }
}