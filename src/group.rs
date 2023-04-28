pub mod edwards25519;
pub mod integer_field;
mod internal;

use digest::{Digest, FixedOutputReset, Reset, Update};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::cipher::stream::Stream;
use crate::dh::{Dh, HmacCompatible};
use crate::encoding::Marshaling;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::ops::{Add, Mul};

/// [`Scalar`] represents a scalar value by which
/// a [`Point`] ([`Group`] element) may be encrypted to produce another [`Point`].
/// This is an exponent in DSA-style groups,
/// in which security is based on the Discrete Logarithm assumption,
/// and a scalar multiplier in elliptic curve groups.
pub trait Scalar:
    Marshaling
    + Clone
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Debug
    + Add<Self, Output = Self>
    + Mul<Self, Output = Self>
    + Default
    + Serialize
    + DeserializeOwned
    + Display
{
    /// [`set()`] sets the receiver equal to another scalar `a`.
    fn set(self, a: &Self) -> Self;

    /// [`set_int64()`] sets the receiver to a small integer value.
    fn set_int64(self, v: i64) -> Self;

    /// [`zero()`] sets to the additive identity (`0`).
    fn zero(self) -> Self;

    /// [`sub()`] sets to the modular difference `a - b`.
    fn sub(self, a: &Self, b: &Self) -> Self;

    /// [`neg()`] sets to the modular negation of scalar `a`.
    fn neg(self, a: &Self) -> Self;

    /// [`one()`] sets to the multiplicative identity (`1`).
    fn one(self) -> Self;

    /// [`div()`] sets to the modular division of scalar a by scalar b.
    fn div(self, a: &Self, b: &Self) -> Self;

    /// [`inv()`] sets to the modular inverse of scalar a.
    fn inv(self, a: &Self) -> Self;

    /// [`pick()`] sets to a fresh random or pseudo-random scalar.
    fn pick(self, rand: &mut impl Stream) -> Self;

    /// [`set_bytes()`] sets the scalar from a byte-slice,
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

/// [`Point`] represents an element of a public-key cryptographic [`Group`].
/// For example,
/// this is a number modulo the prime P in a DSA-style Schnorr group,
/// or an (x, y) point on an elliptic curve.
/// A [`Point`] can contain a Diffie-Hellman public key, an ElGamal ciphertext, etc.
pub trait Point:
    Marshaling
    + Clone
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + Debug
    + Default
    + Serialize
    + DeserializeOwned
    + Debug
    + PartialEq
    + Display
{
    type SCALAR: Scalar;

    /// [`null()`] sets the receiver to the neutral identity element.
    fn null(self) -> Self;

    /// [`base()`] sets the receiver to this [`Group`]'s standard `base point`.
    fn base(self) -> Self;

    /// [`pick()`] sets the receiver to a fresh random or pseudo-random [`Point`].
    fn pick<S: Stream>(self, rand: &mut S) -> Self;

    /// [`set()`] sets the receiver equal to another [`Point`] `p`.
    fn set(&mut self, p: &Self) -> Self;

    /// [`embed_len()`] returns the maximum number of bytes that can be embedded in a single
    /// group element via [`pick()`].
    fn embed_len(&self) -> usize;

    /// [`embed()`] encodes a limited amount of specified data in the
    /// [`Point`], using `r` as a source of cryptographically secure
    /// random data. Implementations only embed the first `embed_len`
    /// bytes of the given data.
    fn embed<S: Stream>(self, data: Option<&[u8]>, rand: &mut S) -> Self;

    /// [`data()`] extracts data embedded in a [`Point`] chosen via [`embed()`].
    /// Returns an [`Error`](PointError) if doesn't represent valid embedded data.
    fn data(&self) -> Result<Vec<u8>, PointError>;

    /// [`add()`] adds [`points`](Point) so that their [`scalars`](Scalar) add homomorphically.
    fn add(self, a: &Self, b: &Self) -> Self;

    /// [`sub()`] subtracts [`points`](Point) so that their [`scalars`](Scalar) subtract homomorphically.
    fn sub(self, a: &Self, b: &Self) -> Self;

    /// Set to the negation of point a.
    fn neg(&mut self, a: &Self) -> Self;

    /// [`mul()`] multiplies point `p` by the scalar `s`.
    /// if `p == None`, multiply with the standard base point [`base()`].
    fn mul(self, s: &Self::SCALAR, p: Option<&Self>) -> Self;
}

//TODO: fully implement var time management
/// [`AllowsVarTime`] allows callers to determine if a given [`Scalar`]
/// or [`Point`] supports opting-in to variable time operations. If
/// an object implements [`AllowsVarTime`], then the caller can use
/// [`allow_var_time(true)`] in order to allow variable time operations on
/// that object until [`allow_var_time(false)`] is called. Variable time
/// operations may be faster, but also risk leaking information via a
/// timing side channel. Thus they are only safe to use on public
/// [`scalars`](Scalar) and [`points`](Point), never on secret ones.
pub trait AllowsVarTime {
    // fn allow_var_time(bool);
}

/// [`Group`] interface represents a mathematical group
/// usable for Diffie-Hellman key exchange, ElGamal encryption,
/// and the related body of public-key cryptographic algorithms
/// and zero-knowledge proof methods.
/// The [`Group`] interface is designed in particular to be a generic front-end
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
/// The caller must explicitly initialize or set a new [`Point`] or [`Scalar`] object
/// to some value before using it as an input to some other operation
/// involving [`Point`] and/or [`Scalar`] objects.
/// For example, to compare a point `P` against the neutral (identity) element,
/// you might use `P.eq(suite.point().null())`,
/// but not just `P.eq(suite.point())`.
///
/// It is expected that any implementation of this interface
/// should satisfy suitable hardness assumptions for the applicable group:
/// e.g., that it is cryptographically hard for an adversary to
/// take an encrypted [`Point`] and the known generator it was based on,
/// and derive the [`Scalar`] with which the [`Point`] was encrypted.
/// Any implementation is also expected to satisfy
/// the standard homomorphism properties that Diffie-Hellman
/// and the associated body of public-key cryptography are based on.
pub trait Group: Dh + Clone + Default {
    type POINT: Point;

    fn string(&self) -> String;

    /// [`scalar_len()`] returns the max length of scalars in bytes
    fn scalar_len(&self) -> usize;

    /// [`scalar()`] create new scalar
    fn scalar(&self) -> <Self::POINT as Point>::SCALAR;

    // [`point_len()`] returns the max length of point in bytes
    fn point_len(&self) -> usize;

    /// [`point()`] create new point
    fn point(&self) -> Self::POINT;

    /// [`is_prime_order()`] returns `Some(true)` if the group has a prime order,
    /// if `None` is returned is assumes that the group has a prime order
    fn is_prime_order(&self) -> Option<bool>;
}

/// A [`HashFactory`] is an interface that can be mixed in to local suite definitions.
pub trait HashFactory {
    type T: Hasher + HmacCompatible + Default + Update + Reset + FixedOutputReset + Clone + 'static;
    fn hash(&self) -> Self::T {
        Default::default()
    }
}

pub trait Hasher: Digest + Write {}

impl<T> Hasher for T
where
    T: Digest,
    T: Write,
{
}

#[derive(Error, Debug)]
pub enum PointError {
    #[error("invalid embedded data length")]
    EmbedDataLength,
}
