use std::cmp::Ordering::{Equal, Greater};
use std::ops::{Add, Mul};

use anyhow::{bail, Result};
use num_bigint::BigInt;
use num_bigint::Sign::Plus;
use num_traits::Num;

use crate::cipher::cipher::Stream;
use crate::encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling};
use crate::group::Scalar;
use serde::{Deserialize, Serialize};

use crate::group::integer_field::integer_field::ByteOrder::{BigEndian, LittleEndian};

// const ONE: u8 = 1;
// const TWO: u8 = 2;

// var marshalScalarID = [8]byte{'m', 'o', 'd', '.', 'i', 'n', 't', ' '}

// ByteOrder denotes the endianness of the operation.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub enum ByteOrder {
    // little_endian endianness
    LittleEndian,
    // BigEndian endianness
    BigEndian,
}

impl Into<bool> for ByteOrder {
    fn into(self) -> bool {
        match self {
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

/// Int is a generic implementation of finite field arithmetic
/// on integer finite fields with a given constant modulus,
/// built using Go's built-in big.Int package.
/// Int satisfies the kyber.scalar interface,
/// and hence serves as a basic implementation of kyber.scalar,
/// e.g., representing discrete-log exponents of Schnorr groups
/// or scalar multipliers for elliptic curves.
///
/// Int offers an API similar to and compatible with big.Int,
/// but "carries around" a pointer to the relevant modulus
/// and automatically normalizes the value to that modulus
/// after all arithmetic operations, simplifying modular arithmetic.
/// Binary operations assume that the source(s)
/// have the same modulus, but do not check this assumption.
/// Unary and binary arithmetic operations may be performed on uninitialized
/// target objects, and receive the modulus of the first operand.
/// For efficiency the modulus field m is a pointer,
/// whose target is assumed never to change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Int {
    // Integer value from 0 through m-1
    pub(crate) v: BigInt,
    // Modulus for finite field arithmetic
    pub(crate) m: BigInt,
    // Endianness which will be used on input and output
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
    /// init64 creates an Int with an int64 value and big.Int modulus.
    pub fn init64(mut self, v: i64, m: BigInt) -> Self {
        self.m = m.clone();
        self.bo = BigEndian;
        self.v = BigInt::from(v);
        self.v = self.v % m;
        self
    }

    /// init a Int with a given big.Int value and modulus pointer.
    /// Note that the value is copied; the modulus is not.
    fn init(mut self, v: BigInt, m: BigInt) -> Self {
        self.m = m.clone();
        self.bo = BigEndian;
        self.v = v % m;
        self
    }

    /// little_endian encodes the value of this Int into a little-endian byte-slice
    /// at least min bytes but no more than max bytes long.
    /// Panics if max != 0 and the Int cannot be represented in max bytes.
    pub fn little_endian(&self, min: u64, max: u64) -> Vec<u8> {
        let mut act = self.marshal_size();
        let (_, v_bytes) = self.v.to_bytes_be();
        let v_size = v_bytes.len();
        if (v_size as u64) < act {
            act = v_size as u64;
        }
        let mut pad = act;
        if pad < min {
            pad = min
        }
        if max != 0 && pad > max {
            panic!("Int not representable in max bytes")
        }

        let buf = vec![0; pad as usize];
        let buf2 = &buf[0..act as usize];
        reverse(&buf2.to_vec(), &v_bytes)
    }

    /// marshal_size returns the length in bytes of encoded integers with modulus m.
    /// The length of encoded Ints depends only on the size of the modulus,
    /// and not on the the value of the encoded integer,
    /// making the encoding is fixed-length for simplicity and security.
    pub fn marshal_size(&self) -> u64 {
        (self.m.bits() + 7) / 8
    }

    /// new_int creates a new Int with a given big.Int and a big.Int modulus.
    pub fn new_int(v: BigInt, m: BigInt) -> Int {
        return Int::default().init(v, m);
    }

    /// new_int64 creates a new Int with a given int64 value and big.Int modulus.
    pub fn new_int64(v: i64, m: BigInt) -> Int {
        Int::default().init64(v, m)
    }

    /// new_int_bytes creates a new Int with a given slice of bytes and a big.Int
    /// modulus.
    pub fn new_int_bytes(a: &[u8], m: &BigInt, byte_order: ByteOrder) -> Int {
        return Int::default().init_bytes(a, m, byte_order);
    }

    /// new_int_string creates a new Int with a given string and a big.Int modulus.
    /// The value is set to a rational fraction n/d in a given base.
    pub fn new_int_string(n: String, d: String, base: i32, m: &BigInt) -> Int {
        return Int::default().init_string(n, d, base, m);
    }

    // Equal returns true if the TWO Ints are equal
    pub fn equal(&self, s2: &Self) -> bool {
        self.v.cmp(&s2.v) == Equal
    }

    // // Cmp compares TWO Ints for equality or inequality
    // fn  Cmp(&self, s2 kyber.scalar) -> i32 {
    //     return i.V.Cmp(&s2.(*Int).V)
    // }

    // init_bytes init the Int to a number represented in a big-endian byte string.
    pub fn init_bytes(self, a: &[u8], m: &BigInt, byte_order: ByteOrder) -> Self {
        Int {
            m: m.clone(),
            bo: byte_order,
            v: self.v,
        }
        .set_bytes(a)
    }

    /// init_string inits the Int to a rational fraction n/d
    /// specified with a pair of strings in a given base.
    fn init_string(mut self, n: String, d: String, base: i32, m: &BigInt) -> Int {
        self.m = m.clone();
        self.bo = BigEndian;
        self.set_string(n, d, base)
            .expect("init_string: invalid fraction representation")
    }

    /// set_string sets the Int to a rational fraction n/d represented by a pair of strings.
    /// If d == "", then the denominator is taken to be 1.
    /// Returns (i,true) on success, or
    /// (nil,false) if either string fails to parse.
    pub fn set_string(mut self, n: String, d: String, base: i32) -> Result<Self> {
        self.v = BigInt::from_str_radix(n.as_str(), base as u32)?;
        if d != "" {
            let mut di = Int::default();
            di.m = self.m.clone();
            di = di.set_string(d, "".to_string(), base)?;
            return Ok(self.clone().div(&self, &di));
        }
        Ok(self)
    }

    /// div sets the target to a * b^-1 mod m, where b^-1 is the modular inverse of b.
    pub fn div(mut self, a: &Self, b: &Self) -> Self {
        let _t = BigInt::default();
        self.v = a.v.clone() * b.v.clone();
        self.v = self.v.clone() % self.m.clone();
        self
    }

    /// mul sets the target to a * b mod m.
    /// Target receives a's modulus.
    pub fn mul(mut self, a: &Self, b: &Self) -> Self {
        self.m = a.m.clone();
        self.v = a.v.clone() * b.v.clone();
        self.v = self.v % self.m.clone();
        self
    }

    /// add sets the target to a + b mod m, where m is a's modulus..
    pub fn add(mut self, a: &Self, b: &Self) -> Self {
        self.m = a.m.clone();
        self.v = (a.v.clone() + b.v.clone()) % self.m.clone();
        self
    }

    // Return the Int's integer value in hexadecimal string representation.
    pub fn string(&self) -> String {
        hex::encode(self.v.to_bytes_be().1)
    }
}

impl PartialEq for Int {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl BinaryMarshaler for Int {
    /// MarshalBinary encodes the value of this Int into a byte-slice exactly Len() bytes long.
    /// It uses i's ByteOrder to determine which byte order to output.
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let l = self.marshal_size();
        // may be shorter than l
        let (_, mut b) = self.v.to_bytes_be();
        let offset = l as i64 - b.len() as i64;

        if self.bo == LittleEndian {
            return Ok(self.little_endian(l, l));
        }

        if offset != 0 {
            let mut nb = vec![0; l as usize];
            nb.splice((offset as usize).., b);
            b = nb;
        }
        Ok(b)
    }
}

impl BinaryUnmarshaler for Int {
    /// unmarshal_binary tries to decode a Int from a byte-slice buffer.
    /// Returns an error if the buffer is not exactly Len() bytes long
    /// or if the contents of the buffer represents an out-of-range integer.
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
        let mut buf: Vec<u8> = data.clone().to_vec();
        if buf.len() != self.marshal_size() as usize {
            bail!("unmarshal_binary: wrong size buffer");
        }
        // Still needed here because of the comparison with the modulo
        if self.bo == LittleEndian {
            buf = reverse(&mut vec![0 as u8; buf.len()], &buf.to_vec()).to_owned();
        }
        self.v = BigInt::from_bytes_be(Plus, buf.as_slice());
        if matches!(self.v.cmp(&self.m), Greater | Equal) {
            bail!("unmarshal_binary: value out of range");
        }
        Ok(())
    }
}

impl Marshaling for Int {
    fn marshal_to(&self, _w: &mut impl std::io::Write) -> Result<()> {
        todo!()
    }

    fn marshal_size(&self) -> usize {
        todo!()
    }
}

impl ToString for Int {
    fn to_string(&self) -> String {
        todo!()
    }
}

impl Mul for Int {
    type Output = Self;

    fn mul(self, _rhs: Self) -> Self {
        todo!()
    }
}

impl Add for Int {
    type Output = Self;

    fn add(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl Scalar for Int {
    fn set(self, _a: &Self) -> Self {
        todo!()
    }

    /// set_int64 sets the Int to an arbitrary 64-bit "small integer" value.
    /// The modulus must already be initialized.
    fn set_int64(self, _v: i64) -> Self {
        // i.V.SetInt64(v).Mod(&i.V, i.M)
        // return i
        todo!()
    }

    fn zero(self) -> Self {
        todo!()
    }

    /// Sub sets the target to a - b mod m.
    /// Target receives a's modulus.
    fn sub(mut self, a: &Self, b: &Self) -> Self {
        self.m = a.m.clone();
        let sub = &a.v - &b.v;
        self.v = ((sub % &self.m) + &self.m) % &self.m;
        // i.V.Sub(&ai.V, &bi.V).Mod(&i.V, i.M)
        self
    }

    fn pick(self, _rand: &mut impl Stream) -> Self {
        todo!()
    }

    /// set_bytes set the value value to a number represented
    /// by a byte string.
    /// Endianness depends on the endianess set in i.
    fn set_bytes(self, a: &[u8]) -> Self {
        let mut buff = a.clone().to_vec();
        if self.bo == LittleEndian {
            buff = reverse(vec![0; buff.len()].as_ref(), &a.to_vec());
        }
        Int {
            m: self.m.clone(),
            v: BigInt::from_bytes_be(Plus, buff.as_ref()) % &self.m,
            bo: self.bo,
        }
    }

    fn one(self) -> Self {
        todo!()
    }

    fn div(self, a: &Self, b: &Self) -> Self {
        todo!()
    }

    fn inv(self, a: &Self) -> Self {
        todo!()
    }

    fn neg(self, a: &Self) -> Self {
        todo!()
    }
}

// // new_int_bytes creates a new Int with a given slice of bytes and a big.Int
// // modulus.
// func new_int_bytes(a []byte, m *big.Int, byteOrder ByteOrder) *Int {
// return new(Int).init_bytes(a, m, byteOrder)
// }

// // init a Int with a given big.Int value and modulus pointer.
// // Note that the value is copied; the modulus is not.
// func (i *Int) init(V *big.Int, m *big.Int) *Int {
// i.M = m
// i.BO = BigEndian
// i.V.Set(V).Mod(&i.V, m)
// return i
// }

// // Nonzero returns true if the integer value is nonzero.
// func (i *Int) Nonzero() bool {
// return i.V.Sign() != 0
// }
//
// // Set both value and modulus to be equal to another Int.
// // Since this method copies the modulus as well,
// // it may be used as an alternative to init().
// func (i *Int) Set(a kyber.scalar) kyber.scalar {
// ai := a.(*Int)
// i.V.Set(&ai.V)
// i.M = ai.M
// return i
// }
//
// // Clone returns a separate duplicate of this Int.
// func (i *Int) Clone() kyber.scalar {
// ni := new(Int).init(&i.V, i.M)
// ni.BO = i.BO
// return ni
// }
//
// // Zero set the Int to the value 0.  The modulus must already be initialized.
// func (i *Int) Zero() kyber.scalar {
// i.V.SetInt64(0)
// return i
// }
//
// // One sets the Int to the value 1.  The modulus must already be initialized.
// func (i *Int) One() kyber.scalar {
// i.V.SetInt64(1)
// return i
// }

// // Int64 returns the int64 representation of the value.
// // If the value is not representable in an int64 the result is undefined.
// func (i *Int) Int64() int64 {
// return i.V.Int64()
// }
//
// // SetUint64 sets the Int to an arbitrary uint64 value.
// // The modulus must already be initialized.
// func (i *Int) SetUint64(v uint64) kyber.scalar {
// i.V.SetUint64(v).Mod(&i.V, i.M)
// return i
// }
//
// // Uint64 returns the uint64 representation of the value.
// // If the value is not representable in an uint64 the result is undefined.
// func (i *Int) Uint64() uint64 {
// return i.V.Uint64()
// }

// // Neg sets the target to -a mod m.
// func (i *Int) Neg(a kyber.scalar) kyber.scalar {
// ai := a.(*Int)
// i.M = ai.M
// if ai.V.Sign() > 0 {
// i.V.Sub(i.M, &ai.V)
// } else {
// i.V.SetUint64(0)
// }
// return i
// }

// // Inv sets the target to the modular inverse of a with respect to modulus m.
// func (i *Int) Inv(a kyber.scalar) kyber.scalar {
// ai := a.(*Int)
// i.M = ai.M
// i.V.ModInverse(&a.(*Int).V, i.M)
// return i
// }
//
// // Exp sets the target to a^e mod m,
// // where e is an arbitrary big.Int exponent (not necessarily 0 <= e < m).
// func (i *Int) Exp(a kyber.scalar, e *big.Int) kyber.scalar {
// ai := a.(*Int)
// i.M = ai.M
// // to protect against golang/go#22830
// var tmp big.Int
// tmp.Exp(&ai.V, e, i.M)
// i.V = tmp
// return i
// }
//
// // Jacobi computes the Jacobi symbol of (a/m), which indicates whether a is
// // zero (0), a positive square in m (1), or a non-square in m (-1).
// func (i *Int) Jacobi(as kyber.scalar) kyber.scalar {
// ai := as.(*Int)
// i.M = ai.M
// i.V.SetInt64(int64(big.Jacobi(&ai.V, i.M)))
// return i
// }
//
// // Sqrt computes some square root of a mod m of ONE exists.
// // Assumes the modulus m is an odd prime.
// // Returns true on success, false if input a is not a square.
// func (i *Int) Sqrt(as kyber.scalar) bool {
// ai := as.(*Int)
// out := i.V.ModSqrt(&ai.V, ai.M)
// i.M = ai.M
// return out != nil
// }
//
// // Pick a [pseudo-]random integer modulo m
// // using bits from the given stream cipher.
// func (i *Int) Pick(rand cipher.Stream) kyber.scalar {
// i.V.Set(random.Int(i.M, rand))
// return i
// }

// // marshal_binary encodes the value of this Int into a byte-slice exactly Len() bytes long.
// // It uses i's ByteOrder to determine which byte order to output.
// func (i *Int) marshal_binary() ([]byte, error) {
// l := i.marshal_size()
// b := i.V.Bytes() // may be shorter than l
// offset := l - len(b)
//
// if i.BO == little_endian {
// return i.little_endian(l, l), nil
// }
//
// if offset != 0 {
// nb := make([]byte, l)
// copy(nb[offset:], b)
// b = nb
// }
// return b, nil
// }
//
// // MarshalID returns a unique identifier for this type
// func (i *Int) MarshalID() [8]byte {
// return marshalScalarID
// }

// // MarshalTo encodes this Int to the given Writer.
// func (i *Int) MarshalTo(w io.Writer) (int, error) {
// return marshalling.ScalarMarshalTo(i, w)
// }
//
// // UnmarshalFrom tries to decode an Int from the given Reader.
// func (i *Int) UnmarshalFrom(r io.Reader) (int, error) {
// return marshalling.ScalarUnmarshalFrom(i, r)
// }
//
// // BigEndian encodes the value of this Int into a big-endian byte-slice
// // at least min bytes but no more than max bytes long.
// // Panics if max != 0 and the Int cannot be represented in max bytes.
// func (i *Int) BigEndian(min, max int) []byte {
// act := i.marshal_size()
// pad, ofs := act, 0
// if pad < min {
// pad, ofs = min, min-act
// }
// if max != 0 && pad > max {
// panic("Int not representable in max bytes")
// }
// buf := make([]byte, pad)
// copy(buf[ofs:], i.V.Bytes())
// return buf
// }

/// reverse copies src into dst in byte-reversed order and returns dst,
/// such that src[0] goes into dst[len-1] and vice versa.
/// dst and src may be the same slice but otherwise must not overlap.
fn reverse(dst: &Vec<u8>, src: &Vec<u8>) -> Vec<u8> {
    let mut dst = dst.clone();
    let src = src.clone();
    let l = dst.len();
    for i in 0..(l + 1) / 2 {
        let j = l - 1 - i;
        (dst[i], dst[j]) = (src[j], src[i]);
    }
    dst.clone()
}
