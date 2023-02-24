use core::fmt;
use lazy_static::lazy_static;
use num_bigint_dig as num_bigint;
use std::cmp::Ordering::{self, Equal, Greater};
use std::fmt::{Display, Formatter};
use thiserror::Error;

use num_bigint::algorithms::jacobi;
use num_bigint::Sign::Plus;
use num_bigint::{BigInt, ModInverse, ParseBigIntError, Sign};
use num_traits::{Num, Signed};

use crate::cipher::stream::Stream;
use crate::encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling, MarshallingError};
use crate::group::internal::marshalling;
use crate::group::Scalar;
use crate::util::random::random_int;
use serde::{Deserialize, Serialize};

use crate::group::integer_field::integer::ByteOrder::{BigEndian, LittleEndian};

lazy_static! {
    pub static ref ONE: BigInt = BigInt::from(1_i64);
    pub static ref TWO: BigInt = BigInt::from(2_i64);
}

const MARSHAL_INT_ID: [u8; 8] = [b'm', b'o', b'd', b'.', b'i', b'n', b't', b' '];

/// [`ByteOrder`] denotes the endianness of the operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}

impl From<ByteOrder> for bool {
    fn from(val: ByteOrder) -> Self {
        match val {
            LittleEndian => true,
            BigEndian => false,
        }
    }
}

impl From<bool> for ByteOrder {
    fn from(b: bool) -> Self {
        match b {
            true => LittleEndian,
            false => BigEndian,
        }
    }
}

/// [`Int`] is a generic implementation of finite field arithmetic
/// on `integer finite fields` with a given constant `modulus`,
/// built using [`num_bigint_dig`] crate.
/// The [`Scalar`] trait is implemented for [`Int`],
/// and hence serves as a basic implementation of [`Scalar`],
/// e.g., representing discrete-log exponents of `Schnorr groups`
/// or scalar multipliers for elliptic curves.
///
/// [`Int`] offers an API similar to and compatible with [`BigInt`],
/// but "carries around"  the relevant modulus
/// and automatically normalizes the value to that modulus
/// after all arithmetic operations, simplifying modular arithmetic.
/// Binary operations assume that the source(s)
/// have the same modulus, but do not check this assumption.
/// Unary and binary arithmetic operations may be performed on uninitialized
/// target objects, and receive the modulus of the first operand.
/// For efficiency the modulus field m is a pointer,
/// whose target is assumed never to change.
#[derive(Clone, Eq, Debug, Serialize, Deserialize)]
pub struct Int {
    /// integer value from `0` through `m-1`
    pub(crate) v: BigInt,
    /// modulus for finite field arithmetic
    pub(crate) m: BigInt,
    /// endianness which will be used on input and output
    pub bo: ByteOrder,
}

impl Default for Int {
    fn default() -> Self {
        Int {
            bo: LittleEndian,
            v: BigInt::from(0),
            m: BigInt::from(0),
        }
    }
}

impl Int {
    /// [`init64()`] creates an [`Int`] with an [`i64`] value and [`BigInt`] modulus.
    pub fn init64(mut self, v: i64, m: BigInt) -> Self {
        self.m = m.clone();
        self.bo = BigEndian;
        self.v = BigInt::from(v);
        // specify euclidean modulus for negative number
        match self.v.sign() {
            num_bigint::Sign::Minus => self.v = (self.v % m.clone()) + m.abs(),
            _ => self.v %= m,
        }
        self
    }

    /// [`init()`] a [`Int`] with a given [`BigInt`] `value` and a given [`BigInt`] `modulus`.
    fn init(mut self, v: BigInt, m: BigInt) -> Self {
        self.m = m.clone();
        self.bo = BigEndian;
        self.v = v % m;
        self
    }

    /// [`little_endian()`] encodes the value of this [`Int`] into a little-endian byte-slice
    /// at least `min` bytes but no more than `max` bytes long.
    /// Panics if max != 0 and the Int cannot be represented in max bytes.
    pub fn little_endian(&self, min: usize, max: usize) -> Result<Vec<u8>, IntError> {
        let mut act = self.marshal_size();
        let (_, v_bytes) = self.v.to_bytes_be();
        let v_size = v_bytes.len();
        if v_size < act {
            act = v_size;
        }
        let mut pad = act;
        if pad < min {
            pad = min
        }
        if max != 0 && pad > max {
            return Err(IntError::NotRepresentable);
        }

        let buf = vec![0; pad];
        let buf2 = &buf[0..act];
        Ok(reverse(buf2, &v_bytes))
    }

    /// [`new_int()`] creates a new [`Int`] with a given [`BigInt`] and a [`BigInt`] `modulus`.
    pub fn new_int(v: BigInt, m: BigInt) -> Int {
        Int::default().init(v, m)
    }

    /// [`new_int64()`] creates a new [`Int`] with a given [`i64`] value and [`BigInt`] `modulus`.
    pub fn new_int64(v: i64, m: BigInt) -> Int {
        Int::default().init64(v, m)
    }

    /// [`new_int_bytes()`] creates a new [`Int`] with a given slice of bytes and a [`BigInt`]
    /// `modulus`.
    pub fn new_int_bytes(a: &[u8], m: &BigInt, byte_order: ByteOrder) -> Int {
        Int::default().init_bytes(a, m, byte_order)
    }

    /// [`new_int_string()`] creates a new [`Int`] with a given [`String`] and a [`BigInt`] `modulus`.
    /// The value is set to a rational fraction n/d in a given base.
    pub fn new_int_string(n: String, d: String, base: i32, m: &BigInt) -> Int {
        Int::default().init_string(n, d, base, m)
    }

    /// [`equal()`] returns [`true`] if the two [`ints`](Int) are equal
    pub fn equal(&self, s2: &Self) -> bool {
        self.v.cmp(&s2.v) == Equal
    }

    /// [`cmpr()`] compares two [`ints`](Int) for equality or inequality
    pub fn cmpr(&self, s2: &Self) -> Ordering {
        self.v.cmp(&s2.v)
    }

    /// [`init_bytes()`] init the [`Int`] to a number represented in a `big-endian` byte string.
    pub fn init_bytes(self, a: &[u8], m: &BigInt, byte_order: ByteOrder) -> Self {
        Int {
            m: m.clone(),
            bo: byte_order,
            v: self.v,
        }
        .set_bytes(a)
    }

    /// [`init_string()`] inits the [`Int`] to a rational fraction n/d
    /// specified with a pair of [`strings`](String) in a given base.
    fn init_string(mut self, n: String, d: String, base: i32, m: &BigInt) -> Int {
        self.m = m.clone();
        self.bo = BigEndian;
        self.set_string(n, d, base)
            .expect("init_string: invalid fraction representation")
    }

    /// [`set_string()`] sets the [`Int`] to a rational fraction n/d represented by a pair of [`strings`](String).
    /// If `d == ""`, then the denominator is taken to be `1`.
    /// Returns the [`Int`] on success or an [`Error`](BigIntError)
    /// if the string failed to parse
    pub fn set_string(mut self, n: String, d: String, base: i32) -> Result<Self, IntError> {
        self.v = BigInt::from_str_radix(n.as_str(), base as u32)?;
        if !d.is_empty() {
            let mut di = Int {
                m: self.m.clone(),
                ..Default::default()
            };
            di = di.set_string(d, "".to_string(), base)?;
            return Ok(self.clone().div(&self, &di));
        }
        Ok(self)
    }
}

impl Display for Int {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.v.to_bytes_be().1))
    }
}

impl PartialEq for Int {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmpr(other)
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmpr(other))
    }
}

impl BinaryMarshaler for Int {
    /// [`marshal_binary()`] encodes the value of this [`Int`] into a byte-slice exactly [`self.marshal_size()`] bytes long.
    /// It uses `i`'s [`ByteOrder`] to determine which byte order to output.
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError> {
        let l = self.marshal_size();
        // may be shorter than l
        let (_, mut b) = self.v.to_bytes_be();
        let offset = l - b.len();

        if self.bo == LittleEndian {
            return self
                .little_endian(l, l)
                .map_err(|e| MarshallingError::InvalidInput(e.to_string()));
        }

        if offset != 0 {
            let mut nb = vec![0; l];
            nb.splice((offset).., b);
            b = nb;
        }
        Ok(b)
    }
}

impl BinaryUnmarshaler for Int {
    /// [`unmarshal_binary()`] tries to decode a [`Int`] from a byte-slice buffer.
    /// Returns an [`Error`](MarshallingError) if the buffer is not exactly [`self.marshal_size()`] bytes long
    /// or if the contents of the buffer represents an out-of-range integer.
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), MarshallingError> {
        let mut buf: Vec<u8> = data.to_vec();
        if buf.len() != self.marshal_size() {
            return Err(MarshallingError::InvalidInput(
                "unmarshal_binary: wrong size buffer".to_owned(),
            ));
        }
        // Still needed here because of the comparison with the modulo
        if self.bo == LittleEndian {
            buf = reverse(&vec![0_u8; buf.len()], &buf.to_vec());
        }
        self.v = BigInt::from_bytes_be(Plus, buf.as_slice());
        if matches!(self.v.cmp(&self.m), Greater | Equal) {
            return Err(MarshallingError::InvalidInput(
                "unmarshal_binary: value out of range".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Marshaling for Int {
    fn marshal_to(&self, w: &mut impl std::io::Write) -> Result<(), MarshallingError> {
        marshalling::scalar_marshal_to(self, w)
    }

    /// [`marshal_size()`] returns the length in bytes of encoded integers with modulus `m`.
    /// The length of encoded [`ints`](Int) depends only on the size of the modulus,
    /// and not on the the value of the encoded integer,
    /// making the encoding is fixed-length for simplicity and security.
    fn marshal_size(&self) -> usize {
        ((self.m.bits()) + 7) / 8
    }

    fn unmarshal_from(&mut self, r: &mut impl std::io::Read) -> Result<(), MarshallingError> {
        marshalling::scalar_unmarshal_from(self, r)
    }

    fn unmarshal_from_random(&mut self, r: &mut (impl std::io::Read + Stream)) {
        marshalling::scalar_unmarshal_from_random(self, r);
    }

    fn marshal_id(&self) -> [u8; 8] {
        MARSHAL_INT_ID
    }
}

use std::ops::{self, Sub};
impl_op_ex!(*|a: &Int, b: &Int| -> Int {
    let m = a.m.clone();
    let v = (a.v.clone() * b.v.clone()) % m.clone();
    let bo = a.bo;
    Int { v, m, bo }
});

impl_op_ex!(+|a: &Int, b: &Int| -> Int {
        let m = a.m.clone();
        let v = (a.v.clone() + b.v.clone()) % m.clone();
        let bo = a.bo;
        Int{v, m, bo}
});

impl Scalar for Int {
    /// [`set()`] sets both `value` and `modulus` to be equal to another [`Int`].
    /// Since this method copies the modulus as well,
    fn set(self, a: &Self) -> Self {
        let mut ai = self;
        ai.v = a.v.clone();
        ai.m = a.m.clone();
        ai
    }

    /// [`set_int64()`] sets the [`Int`] to an arbitrary 64-bit "small integer" value.
    /// The `modulus` must already be initialized.
    fn set_int64(self, v: i64) -> Self {
        let mut i = self;
        i.v = BigInt::from(v);
        // specify euclidean modulus for negative number
        match i.v.sign() {
            num_bigint::Sign::Minus => i.v = (i.v % i.m.clone()) + i.m.abs(),
            _ => i.v %= i.m.clone(),
        }
        i
    }

    /// [`zero()`] set the [`Int`] to the value `0`. The modulus must already be initialized.
    fn zero(self) -> Self {
        let mut i = self;
        i.v = BigInt::from(0_i64);
        i
    }

    /// [`sub()`] sets the target to `a - b mod m`.
    /// Target receives `a`'s modulus.
    fn sub(mut self, a: &Self, b: &Self) -> Self {
        self.m = a.m.clone();
        let sub = &a.v - &b.v;
        self.v = ((sub % &self.m) + &self.m) % &self.m;
        // i.V.Sub(&ai.V, &bi.V).Mod(&i.V, i.M)
        self
    }

    /// [`pick()`] a pseudo-random integer modulo `m`
    /// using bits from the given stream cipher.
    fn pick(self, rand: &mut impl Stream) -> Self {
        let mut s = self.clone();
        s.v.clone_from(&random_int(&self.m, rand));
        s
    }

    /// [`set_bytes()`] set the value value to a number represented
    /// by a byte string.
    /// `Endianness` depends on the endianess set in `i`.
    fn set_bytes(self, a: &[u8]) -> Self {
        let mut buff = a.to_vec();
        if self.bo == LittleEndian {
            buff = reverse(vec![0; buff.len()].as_ref(), a);
        }
        Int {
            m: self.m.clone(),
            v: BigInt::from_bytes_be(Plus, buff.as_ref()) % &self.m,
            bo: self.bo,
        }
    }

    /// [`one()`] sets the [`Int`] to the value `1`.  The `modulus` must already be initialized.
    fn one(self) -> Self {
        let mut i = self;
        i.v = BigInt::from(1_i64);
        i
    }

    /// [`div()`] sets the target to `a * b^-1 mod m`, where `b^-1` is the modular inverse of `b`.
    fn div(mut self, a: &Self, b: &Self) -> Self {
        let _t = BigInt::default();
        self.v = a.v.clone() * b.v.clone();
        self.v = self.v.clone() % self.m.clone();
        self
    }

    /// [`inv()`] sets the target to the modular inverse of a with respect to modulus `m`.
    fn inv(self, a: &Self) -> Self {
        let mut i = self;
        i.v = a.clone().v.mod_inverse(&a.m.clone()).unwrap();
        i.m = a.m.clone();
        i
    }

    /// [`neg()`] sets the target to `-a mod m`.
    fn neg(self, a: &Self) -> Self {
        let mut i = self;
        i.m = a.m.clone();
        i.v = match a.v.sign() {
            Plus => a.m.clone().sub(&a.v),
            _ => BigInt::from(0_u64),
        };
        i
    }
}

impl Int {
    /// [`nonzero()`] returns `true` if the integer value is `nonzero`.
    pub fn nonzero(&self) -> bool {
        self.v.sign() != Sign::NoSign
    }

    /// [`int64()`] returns the [`i64`] representation of the value.
    /// If the value is not representable in an [`i64`] the result is undefined.
    pub fn int64(&self) -> i64 {
        self.uint64() as i64
    }

    /// [`set_uint64()`] sets the Int to an arbitrary [`u64`] value.
    /// The modulus must already be initialized.
    pub fn set_uint64(&self, v: u64) -> Self {
        let mut i = self.clone();
        i.v = BigInt::from(v) % i.m.clone();
        i
    }

    /// [`uint64()`] returns the [`u64`] representation of the value.
    /// If the value is not representable in an [`u64`] the result is undefined.
    pub fn uint64(&self) -> u64 {
        let mut b = self.v.to_bytes_le().1;
        b.resize(8, 0_u8);
        let mut a = [0_u8; 8];
        for (i, _) in b.iter().enumerate() {
            a[i] = b[i];
        }
        let u = u64::from_le_bytes(a);
        match self.v.sign() {
            Sign::Minus => core::u64::MAX - u + 1,
            _ => u,
        }
    }

    /// [`exp()`] sets the target to `a^e mod m`,
    /// where `e` is an arbitrary [`BigInt`] exponent (not necessarily `0 <= e < m`).
    pub fn exp(mut self, a: &Self, e: &BigInt) -> Self {
        self.m = a.m.clone();
        // to protect against golang/go#22830
        self.v = self.v.modpow(e, &self.m);
        self
    }

    /// [`jacobi()`] computes the `Jacobi` symbol of `(a/m)`, which indicates whether a is
    /// `zero` (`0`), a positive square in `m` (`1`), or a non-square in `m` (`-1`).
    pub fn jacobi(&self, a_s: &Self) -> Self {
        let mut i = self.clone();
        i.m = a_s.m.clone();
        i.v = BigInt::from(jacobi(&a_s.v, &i.m) as i64);
        i
    }

    /// [`sqrt()`] computes some square root of a `mod m` of ONE exists.
    /// Assumes the modulus `m` is an `odd prime`.
    /// Returns `true` on success, `false` if input a is not a square.
    pub fn sqrt(&mut self, a_s: &Self) -> Result<(), IntError> {
        if a_s.v.sign() == Sign::Minus {
            return Err(IntError::ImaginaryRoot);
        }
        self.v = a_s.v.sqrt() % a_s.m.clone();
        self.m = a_s.m.clone();
        Ok(())
    }

    /// [`big_endian()`] encodes the value of this [`Int`] into a big-endian byte-slice
    /// at least `min` bytes but no more than `max` bytes long.
    /// Returns an [`Error`](IntError) if `max != 0` and the [`Int`] cannot be represented in `max` bytes.
    pub fn big_endian(&self, min: usize, max: usize) -> Result<Vec<u8>, IntError> {
        let act = self.marshal_size();
        let (mut pad, mut ofs) = (act, 0);
        if pad < min {
            (pad, ofs) = (min, min - act)
        }
        if max != 0 && pad > max {
            return Err(IntError::NotRepresentable);
        }
        let mut buf = vec![0_u8; pad];
        let b = self.v.to_bytes_be().1;
        buf[ofs..].copy_from_slice(&b);
        Ok(buf)
    }
}

/// [`reverse()`] copies `src` into `dst` in byte-reversed order and returns `dst`,
/// such that `src[0]` goes into `dst[len-1]` and vice versa.
/// `dst` and `src` may be the same slice but otherwise must not overlap.
fn reverse(dst: &[u8], src: &[u8]) -> Vec<u8> {
    let mut dst = dst.to_vec();
    let l = dst.len();
    for i in 0..(l + 1) / 2 {
        let j = l - 1 - i;
        (dst[i], dst[j]) = (src[j], src[i]);
    }
    dst.to_vec()
}

#[derive(Debug, Error)]
pub enum IntError {
    #[error("marshalling error")]
    MarshallingError(#[from] MarshallingError),
    #[error("parse big int error")]
    ParseBigIntError(#[from] ParseBigIntError),
    #[error("Int not representable in max bytes")]
    NotRepresentable,
    #[error("input is a negative number, square root is imaginary")]
    ImaginaryRoot,
}
