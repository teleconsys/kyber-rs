pub mod edwards25519;
pub mod integer_field;
mod internal;

use anyhow::Result;
use digest::DynDigest;

use crate::cipher::cipher::Stream;
use crate::encoding::Marshaling;
use std::fmt::Debug;
use std::io::Write;
use std::ops::{Add, Mul};

/// scalar represents a scalar value by which
/// a Point (group element) may be encrypted to produce another Point.
/// This is an exponent in DSA-style groups,
/// in which security is based on the Discrete Logarithm assumption,
/// and a scalar multiplier in elliptic curve groups.
pub trait Scalar:
    Marshaling
    + Clone
    + PartialEq
    + Debug
    + ToString
    + Add<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Default
{
    //// Set sets the receiver equal to another scalar a.
    fn set(self, a: &Self) -> Self;

    /// set_int64 sets the receiver to a small integer value.
    fn set_int64(self, v: i64) -> Self;

    /// Set to the additive identity (0).
    fn zero(self) -> Self;

    // Set to the modular difference a - b.
    fn sub(self, a: &Self, b: &Self) -> Self;

    // // Set to the modular negation of scalar a.
    // Neg(a scalar) scalar
    //
    // // Set to the multiplicative identity (1).
    // One() scalar

    // // Set to the modular division of scalar a by scalar b.
    // Div(a, b scalar) scalar
    //
    // // Set to the modular inverse of scalar a.
    // Inv(a scalar) scalar

    // Set to a fresh random or pseudo-random scalar.
    fn pick(self, rand: &mut impl Stream) -> Self;

    /// set_bytes sets the scalar from a byte-slice,
    /// reducing if necessary to the appropriate modulus.
    /// The endianess of the byte-slice is determined by the
    /// implementation.
    fn set_bytes(self, bytes: &[u8]) -> Self;
}

pub trait ScalarCanCheckCanonical {
    fn is_canonical(&self, b: &[u8]) -> bool;
}

pub trait PointCanCheckCanonicalAndSmallOrder {
    fn has_small_order(&self) -> bool;
    fn is_canonical(&self, b: &[u8]) -> bool;
}

/// Point represents an element of a public-key cryptographic Group.
/// For example,
/// this is a number modulo the prime P in a DSA-style Schnorr group,
/// or an (x, y) point on an elliptic curve.
/// A Point can contain a Diffie-Hellman public key, an ElGamal ciphertext, etc.
pub trait Point: Marshaling + Clone + PartialEq + Default {
    type SCALAR: Scalar;

    /// Equality test for two Points derived from the same Group.
    fn equal(&self, s2: &Self) -> bool;

    /// Null sets the receiver to the neutral identity element.
    fn null(&mut self) -> &mut Self;

    /// Base sets the receiver to this group's standard base point.
    fn base(self) -> Self;

    /// Pick sets the receiver to a fresh random or pseudo-random Point.
    fn pick<S: Stream>(self, rand: &mut S) -> Self;

    /// Set sets the receiver equal to another Point p.
    fn set(&mut self, p: Self) -> &mut Self;

    /// Maximum number of bytes that can be embedded in a single
    /// group element via Pick().
    fn embed_len(&self) -> usize;

    /// Embed encodes a limited amount of specified data in the
    /// Point, using r as a source of cryptographically secure
    /// random data.  Implementations only embed the first EmbedLen
    /// bytes of the given data.
    fn embed<S: Stream>(self, data: Option<&[u8]>, rand: &mut S) -> Self;

    /// Extract data embedded in a point chosen via Embed().
    /// Returns an error if doesn't represent valid embedded data.
    fn data(&self) -> Result<Vec<u8>>;

    /// Add points so that their scalars add homomorphically.
    fn add(self, a: &Self, b: &Self) -> Self;

    /// Subtract points so that their scalars subtract homomorphically.
    fn sub(&mut self, a: &Self, b: &Self) -> &mut Self;

    /// Set to the negation of point a.
    fn neg(&self, a: &Self) -> &mut Self;

    /// Multiply point p by the scalar s.
    /// If p == nil, multiply with the standard base point Base().
    fn mul(self, s: &Self::SCALAR, p: Option<&Self>) -> Self;
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
pub trait Group: Clone {
    type POINT: Point;

    fn string(&self) -> String;

    // /// Max length of scalars in bytes
    // fn scalar_len(&self) -> i32;

    /// Create new scalar
    fn scalar(&self) -> <Self::POINT as Point>::SCALAR;

    // Max length of point in bytes
    // PointLen() int

    /// Create new point
    fn point(&self) -> Self::POINT;
}

/// A HashFactory is an interface that can be mixed in to local suite definitions.
pub trait HashFactory {
    fn hash(&self) -> Box<dyn Hasher>;
}

pub trait Hasher: DynDigest + Write {}

impl<T> Hasher for T
where
    T: DynDigest,
    T: Write,
{
}
