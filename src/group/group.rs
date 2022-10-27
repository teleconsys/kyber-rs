use anyhow::Result;

use crate::cipher::cipher::Stream;
use crate::encoding::Marshaling;
use std::fmt::Debug;

/// scalar represents a scalar value by which
/// a Point (group element) may be encrypted to produce another Point.
/// This is an exponent in DSA-style groups,
/// in which security is based on the Discrete Logarithm assumption,
/// and a scalar multiplier in elliptic curve groups.
pub trait Scalar: Marshaling + Clone + PartialEq + Debug + ToString {
    //// Set sets the receiver equal to another scalar a.
    fn set(&mut self, a: &Self) -> &mut Self;

    /// set_int64 sets the receiver to a small integer value.
    fn set_int64(&mut self, v: i64) -> &mut Self;

    /// Set to the additive identity (0).
    fn zero(&mut self) -> &mut Self;

    /// Set to the modular sum of scalars a and b.
    fn add(&mut self, a: &Self, b: &Self) -> &mut Self;

    // Set to the modular difference a - b.
    fn sub(&mut self, a: &Self, b: &Self) -> &mut Self;

    // // Set to the modular negation of scalar a.
    // Neg(a scalar) scalar
    //
    // // Set to the multiplicative identity (1).
    // One() scalar

    /// Set to the modular product of scalars a and b.
    fn mul(&mut self, a: &Self, b: &Self) -> &mut Self;

    // // Set to the modular division of scalar a by scalar b.
    // Div(a, b scalar) scalar
    //
    // // Set to the modular inverse of scalar a.
    // Inv(a scalar) scalar

    // Set to a fresh random or pseudo-random scalar.
    fn pick(&mut self, rand: &mut impl Stream) -> &mut Self;

    /// set_bytes sets the scalar from a byte-slice,
    /// reducing if necessary to the appropriate modulus.
    /// The endianess of the byte-slice is determined by the
    /// implementation.
    fn set_bytes(&mut self, bytes: &[u8]) -> Self;
}

/// Point represents an element of a public-key cryptographic Group.
/// For example,
/// this is a number modulo the prime P in a DSA-style Schnorr group,
/// or an (x, y) point on an elliptic curve.
/// A Point can contain a Diffie-Hellman public key, an ElGamal ciphertext, etc.
pub trait Point<SCALAR: Scalar>: Marshaling + Clone {
    /// Equality test for two Points derived from the same Group.
    fn equal(&self, s2: &Self) -> bool;

    /// Null sets the receiver to the neutral identity element.
    fn null(&mut self) -> &mut Self;

    /// Base sets the receiver to this group's standard base point.
    fn base(&mut self) -> &mut Self;

    /// Pick sets the receiver to a fresh random or pseudo-random Point.
    fn pick<S: Stream>(&mut self, rand: S) -> &mut Self;

    /// Set sets the receiver equal to another Point p.
    fn set(&mut self, p: Self) -> &mut Self;

    /// Maximum number of bytes that can be embedded in a single
    /// group element via Pick().
    fn embed_len(&self) -> usize;

    /// Embed encodes a limited amount of specified data in the
    /// Point, using r as a source of cryptographically secure
    /// random data.  Implementations only embed the first EmbedLen
    /// bytes of the given data.
    fn embed<S: Stream>(&mut self, data: &[u8], r: S) -> &mut Self;

    /// Extract data embedded in a point chosen via Embed().
    /// Returns an error if doesn't represent valid embedded data.
    fn data(&self) -> Result<Vec<u8>>;

    /// Add points so that their scalars add homomorphically.
    fn add(&mut self, a: &Self, b: &Self) -> &mut Self;

    /// Subtract points so that their scalars subtract homomorphically.
    fn sub(&mut self, a: &Self, b: &Self) -> &mut Self;

    /// Set to the negation of point a.
    fn neg(&self, a: &Self) -> &mut Self;

    /// Multiply point p by the scalar s.
    /// If p == nil, multiply with the standard base point Base().
    fn mul(&mut self, s: &SCALAR, p: Option<&Self>) -> &mut Self;
}

/// AllowsVarTime allows callers to determine if a given kyber.scalar
/// or kyber.Point supports opting-in to variable time operations. If
/// an object implements AllowsVarTime, then the caller can use
/// AllowVarTime(true) in order to allow variable time operations on
/// that object until AllowVarTime(false) is called. Variable time
/// operations may be faster, but also risk leaking information via a
/// timing side channel. Thus they are only safe to use on public
/// Scalars and Points, never on secret ones.
pub trait AllowsVarTime {
    // fn AllowVarTime(bool);
}

/// Group interface represents a mathematical group
/// usable for Diffie-Hellman key exchange, ElGamal encryption,
/// and the related body of public-key cryptographic algorithms
/// and zero-knowledge proof methods.
/// The Group interface is designed in particular to be a generic front-end
/// to both traditional DSA-style modular arithmetic groups
/// and ECDSA-style elliptic curves:
/// the caller of this interface's methods
/// need not know or care which specific mathematical construction
/// underlies the interface.
///
/// The Group interface is essentially just a "constructor" interface
/// enabling the caller to generate the two particular types of objects
/// relevant to DSA-style public-key cryptography;
/// we call these objects Points and Scalars.
/// The caller must explicitly initialize or set a new Point or scalar object
/// to some value before using it as an input to some other operation
/// involving Point and/or scalar objects.
/// For example, to compare a point P against the neutral (identity) element,
/// you might use P.Equal(suite.Point().Null()),
/// but not just P.Equal(suite.Point()).
///
/// It is expected that any implementation of this interface
/// should satisfy suitable hardness assumptions for the applicable group:
/// e.g., that it is cryptographically hard for an adversary to
/// take an encrypted Point and the known generator it was based on,
/// and derive the scalar with which the Point was encrypted.
/// Any implementation is also expected to satisfy
/// the standard homomorphism properties that Diffie-Hellman
/// and the associated body of public-key cryptography are based on.
pub trait Group<SCALAR, POINT>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
{
    fn string(&self) -> String;

    // /// Max length of scalars in bytes
    // fn scalar_len(&self) -> i32;

    /// Create new scalar
    fn scalar(&self) -> SCALAR;

    // Max length of point in bytes
    // PointLen() int

    /// Create new point
    fn point(&self) -> POINT;
}

/// A HashFactory is an interface that can be mixed in to local suite definitions.
trait HashFactory {
    // fn hash() -> hash.Hash
}
