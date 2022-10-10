use crate::xof;
use crate::xof::blake2xb;

/// SuiteEd25519 implements some basic functionalities such as Group, HashFactory,
/// and XOFFactory.
struct SuiteEd25519 {
    // Curve
    // r cipher.Stream
}

impl SuiteEd25519 {

    // /// Hash returns a newly instanciated sha256 hash function.
    // fn  Hash(&self) -> hash.Hash {
    //     return sha256.New()
    // }

    /// xof returns an XOF which is implemented via the Blake2b hash.
    fn xof(&self, key: &[u8]) -> xof::blake2xb::blake::xof {
        todo!()
        // return blake2xb.New(key);
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
//
// /// NewBlakeSHA256Ed25519 returns a cipher suite based on package
// /// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
// /// It produces cryptographically random numbers via package crypto/rand.
// func NewBlakeSHA256Ed25519() *SuiteEd25519 {
// suite := new(SuiteEd25519)
// return suite
// }
//
// /// NewBlakeSHA256Ed25519WithRand returns a cipher suite based on package
// /// go.dedis.ch/kyber/v3/xof/blake2xb, SHA-256, and the Ed25519 curve.
// /// It produces cryptographically random numbers via the provided stream r.
// func NewBlakeSHA256Ed25519WithRand(r cipher.Stream) *SuiteEd25519 {
// suite := new(SuiteEd25519)
// suite.r = r
// return suite
// }
}
