use super::{Scalar, SuiteEd25519};
use crate::{encoding::MarshallingError, Group, Scalar as ScalarTrait, XOFFactory};
use criterion::{measurement::WallTime, BenchmarkGroup, Criterion};
use lazy_static::lazy_static;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::{
    cipher::Stream,
    encoding::{self, BinaryMarshaler, BinaryUnmarshaler, Marshaling},
};

use super::fe::{load3, load4};
use super::scalar::sc_mul_add;

lazy_static! {
    pub static ref ONE: Scalar = Scalar::default().set_int64(1);
    pub static ref ZERO: Scalar = Scalar::default().zero();
    pub static ref MINUS_ONE: Scalar = Scalar::default().set_bytes(&[
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10
    ]);
}

/// [`SimpleCTScalar`] implements the scalar operations only using [`sc_mul_add()`] by
/// playing with the parameters.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct SimpleCTScalar {
    s: Scalar,
}

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {
    fn marshal_to(&self, w: &mut impl std::io::Write) -> Result<(), MarshallingError> {
        self.s.marshal_to(w)
    }

    fn marshal_size(&self) -> usize {
        self.s.marshal_size()
    }

    fn unmarshal_from(&mut self, r: &mut impl std::io::Read) -> Result<(), MarshallingError> {
        self.s.unmarshal_from(r)
    }

    fn unmarshal_from_random(&mut self, r: &mut (impl std::io::Read + Stream)) {
        self.s.unmarshal_from_random(r)
    }

    fn marshal_id(&self) -> [u8; 8] {
        self.s.marshal_id()
    }
}

impl BinaryMarshaler for SimpleCTScalar {
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError> {
        encoding::marshal_binary(self)
    }
}

impl BinaryUnmarshaler for SimpleCTScalar {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), MarshallingError> {
        encoding::unmarshal_binary(self, data)
    }
}

impl ToString for SimpleCTScalar {
    fn to_string(&self) -> String {
        self.s.to_string()
    }
}

use std::ops::{self, DerefMut};
impl_op_ex!(
    *|a: &SimpleCTScalar, b: &SimpleCTScalar| -> SimpleCTScalar {
        // // a * b + c = a * b + 0
        let mut v = [0u8; 32];
        sc_mul_add(&mut v, &a.s.v, &b.s.v, &ZERO.v);
        SimpleCTScalar { s: Scalar { v } }
    }
);

impl_op_ex!(+|a: &SimpleCTScalar, b: &SimpleCTScalar| -> SimpleCTScalar {
        // a * b + c = a * 1 + c
        let mut v = [0u8; 32];
        sc_mul_add(&mut v, &a.s.v, &ONE.v, &b.s.v);
        SimpleCTScalar{s:Scalar{v}}
});

impl Deref for SimpleCTScalar {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}

impl DerefMut for SimpleCTScalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

impl ScalarTrait for SimpleCTScalar {
    fn set(mut self, a: &Self) -> Self {
        self.s = self.s.set(a);
        self
    }

    fn set_int64(mut self, v: i64) -> Self {
        self.s = self.s.set_int64(v);
        self
    }

    fn zero(mut self) -> Self {
        self.s = self.s.zero();
        self
    }

    fn pick(mut self, rand: &mut impl Stream) -> Self {
        self.s = self.s.pick(rand);
        self
    }

    fn set_bytes(mut self, bytes: &[u8]) -> Self {
        self.s = self.s.set_bytes(bytes);
        self
    }
    fn sub(self, s1: &Self, s2: &Self) -> Self {
        let mut s = self;
        // a * b + c = -1 * a + c
        sc_mul_add(&mut s.v, &MINUS_ONE.v, &s1.v, &s2.v);
        s
    }

    fn one(self) -> Self {
        Self { s: self.s.one() }
    }

    fn div(self, a: &Self, b: &Self) -> Self {
        Self {
            s: self.s.div(a, b),
        }
    }

    fn inv(self, a: &Self) -> Self {
        Self { s: self.s.inv(a) }
    }

    fn neg(self, a: &Self) -> Self {
        Self { s: self.s.neg(a) }
    }
}

/// [`FactoredScalar`] implements the scalar operations using a factored version or
/// [`sc_reduce_limbs()`] at the end of each operations.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct FactoredScalar {
    s: Scalar,
}

impl PartialEq for FactoredScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for FactoredScalar {
    fn marshal_to(&self, w: &mut impl std::io::Write) -> Result<(), MarshallingError> {
        self.s.marshal_to(w)
    }

    fn marshal_size(&self) -> usize {
        self.s.marshal_size()
    }

    fn unmarshal_from(&mut self, r: &mut impl std::io::Read) -> Result<(), MarshallingError> {
        self.s.unmarshal_from(r)
    }

    fn unmarshal_from_random(&mut self, r: &mut (impl std::io::Read + Stream)) {
        self.s.unmarshal_from_random(r)
    }

    fn marshal_id(&self) -> [u8; 8] {
        self.s.marshal_id()
    }
}

impl BinaryMarshaler for FactoredScalar {
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError> {
        encoding::marshal_binary(self)
    }
}

impl BinaryUnmarshaler for FactoredScalar {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), MarshallingError> {
        encoding::unmarshal_binary(self, data)
    }
}

impl ToString for FactoredScalar {
    fn to_string(&self) -> String {
        self.s.to_string()
    }
}

impl_op_ex!(
    *|a: &FactoredScalar, b: &FactoredScalar| -> FactoredScalar {
        let mut v = [0u8; 32];
        sc_mul_fact(&mut v, &a.s.v, &b.s.v);
        FactoredScalar { s: Scalar { v } }
    }
);

impl_op_ex!(+|a: &FactoredScalar, b: &FactoredScalar| -> FactoredScalar {
        let mut v = [0u8; 32];
        sc_add_fact(&mut v, &a.s.v, &b.s.v);
        FactoredScalar{s:Scalar{v}}
});

impl Deref for FactoredScalar {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}

impl DerefMut for FactoredScalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

impl ScalarTrait for FactoredScalar {
    fn set(mut self, a: &Self) -> Self {
        self.s = self.s.set(a);
        self
    }

    fn set_int64(mut self, v: i64) -> Self {
        self.s = self.s.set_int64(v);
        self
    }

    fn zero(mut self) -> Self {
        self.s = self.s.zero();
        self
    }

    fn pick(mut self, rand: &mut impl Stream) -> Self {
        self.s = self.s.pick(rand);
        self
    }

    fn set_bytes(mut self, bytes: &[u8]) -> Self {
        self.s = self.s.set_bytes(bytes);
        self
    }
    fn sub(self, s1: &Self, s2: &Self) -> Self {
        let mut s = self;
        sc_sub_fact(&mut s.v, &s1.v, &s2.v);
        s
    }

    fn one(self) -> Self {
        Self { s: self.s.one() }
    }

    fn div(self, a: &Self, b: &Self) -> Self {
        Self {
            s: self.s.div(a, b),
        }
    }

    fn inv(self, a: &Self) -> Self {
        Self { s: self.s.inv(a) }
    }

    fn neg(self, a: &Self) -> Self {
        Self { s: self.s.neg(a) }
    }
}

fn do_carry_uncentered(limbs: &mut [i64; 24], i: usize) {
    let carry = limbs[i] >> 21;
    limbs[i + 1] += carry;
    limbs[i] -= carry << 21;
}

/// Carry excess from the `i`-th limb into the `(i+1)`-th limb.
/// Postcondition: `-2^20 <= limbs[i] < 2^20`.
fn do_carry_centered(limbs: &mut [i64; 24], i: usize) {
    let carry = (limbs[i] + (1 << 20)) >> 21;
    limbs[i + 1] += carry;
    limbs[i] -= carry << 21;
}

fn do_reduction(limbs: &mut [i64; 24], i: usize) {
    limbs[i - 12] += limbs[i] * 666643;
    limbs[i - 11] += limbs[i] * 470296;
    limbs[i - 10] += limbs[i] * 654183;
    limbs[i - 9] -= limbs[i] * 997805;
    limbs[i - 8] += limbs[i] * 136657;
    limbs[i - 7] -= limbs[i] * 683901;
    limbs[i] = 0;
}

fn sc_reduce_limbs(limbs: &mut [i64; 24]) {
    for i in 0..23 {
        do_carry_centered(limbs, i);
    }
    for i in (1..23).filter(|x| x % 2 != 0) {
        do_carry_centered(limbs, i);
    }

    do_reduction(limbs, 23);
    do_reduction(limbs, 22);
    do_reduction(limbs, 21);
    do_reduction(limbs, 20);
    do_reduction(limbs, 19);
    do_reduction(limbs, 18);

    for i in (6..18).filter(|x| x % 2 == 0) {
        do_carry_centered(limbs, i);
    }

    for i in (6..16).filter(|x| x % 2 != 0) {
        do_carry_centered(limbs, i);
    }

    do_reduction(limbs, 17);
    do_reduction(limbs, 16);
    do_reduction(limbs, 15);
    do_reduction(limbs, 14);
    do_reduction(limbs, 13);
    do_reduction(limbs, 12);

    for i in (0..12).filter(|x| x % 2 == 0) {
        do_carry_centered(limbs, i);
    }

    for i in (0..12).filter(|x| x % 2 != 1) {
        do_carry_centered(limbs, i);
    }

    do_reduction(limbs, 12);

    for i in 0..12 {
        do_carry_uncentered(limbs, i)
    }

    do_reduction(limbs, 12);

    for i in 0..11 {
        do_carry_uncentered(limbs, i)
    }
}

fn sc_add_fact(_s: &mut [u8; 32], a: &[u8; 32], c: &[u8; 32]) {
    let a0 = 2097151 & load3(a);
    let a1 = 2097151 & (load4(&a[2..]) >> 5);
    let a2 = 2097151 & (load3(&a[5..]) >> 2);
    let a3 = 2097151 & (load4(&a[7..]) >> 7);
    let a4 = 2097151 & (load4(&a[10..]) >> 4);
    let a5 = 2097151 & (load3(&a[13..]) >> 1);
    let a6 = 2097151 & (load4(&a[15..]) >> 6);
    let a7 = 2097151 & (load3(&a[18..]) >> 3);
    let a8 = 2097151 & load3(&a[21..]);
    let a9 = 2097151 & (load4(&a[23..]) >> 5);
    let a10 = 2097151 & (load3(&a[26..]) >> 2);
    let a11 = load4(&a[28..]) >> 7;
    let c0 = 2097151 & load3(c);
    let c1 = 2097151 & (load4(&c[2..]) >> 5);
    let c2 = 2097151 & (load3(&c[5..]) >> 2);
    let c3 = 2097151 & (load4(&c[7..]) >> 7);
    let c4 = 2097151 & (load4(&c[10..]) >> 4);
    let c5 = 2097151 & (load3(&c[13..]) >> 1);
    let c6 = 2097151 & (load4(&c[15..]) >> 6);
    let c7 = 2097151 & (load3(&c[18..]) >> 3);
    let c8 = 2097151 & load3(&c[21..]);
    let c9 = 2097151 & (load4(&c[23..]) >> 5);
    let c10 = 2097151 & (load3(&c[26..]) >> 2);
    let c11 = load4(&c[28..]) >> 7;

    let mut limbs = [0_i64; 24];
    limbs[0] = c0 + a0;
    limbs[1] = c1 + a1;
    limbs[2] = c2 + a2;
    limbs[3] = c3 + a3;
    limbs[4] = c4 + a4;
    limbs[5] = c5 + a5;
    limbs[6] = c6 + a6;
    limbs[7] = c7 + a7;
    limbs[8] = c8 + a8;
    limbs[9] = c9 + a9;
    limbs[10] = c10 + a10;
    limbs[11] = c11 + a11;

    sc_reduce_limbs(&mut limbs);
}

fn sc_mul_fact(_s: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32]) {
    let a0 = 2097151 & load3(a);
    let a1 = 2097151 & (load4(&a[2..]) >> 5);
    let a2 = 2097151 & (load3(&a[5..]) >> 2);
    let a3 = 2097151 & (load4(&a[7..]) >> 7);
    let a4 = 2097151 & (load4(&a[10..]) >> 4);
    let a5 = 2097151 & (load3(&a[13..]) >> 1);
    let a6 = 2097151 & (load4(&a[15..]) >> 6);
    let a7 = 2097151 & (load3(&a[18..]) >> 3);
    let a8 = 2097151 & load3(&a[21..]);
    let a9 = 2097151 & (load4(&a[23..]) >> 5);
    let a10 = 2097151 & (load3(&a[26..]) >> 2);
    let a11 = load4(&a[28..]) >> 7;
    let b0 = 2097151 & load3(b);
    let b1 = 2097151 & (load4(&b[2..]) >> 5);
    let b2 = 2097151 & (load3(&b[5..]) >> 2);
    let b3 = 2097151 & (load4(&b[7..]) >> 7);
    let b4 = 2097151 & (load4(&b[10..]) >> 4);
    let b5 = 2097151 & (load3(&b[13..]) >> 1);
    let b6 = 2097151 & (load4(&b[15..]) >> 6);
    let b7 = 2097151 & (load3(&b[18..]) >> 3);
    let b8 = 2097151 & load3(&b[21..]);
    let b9 = 2097151 & (load4(&b[23..]) >> 5);
    let b10 = 2097151 & (load3(&b[26..]) >> 2);
    let b11 = load4(&b[28..]) >> 7;
    let c0 = 0_i64;
    let c1 = 0_i64;
    let c2 = 0_i64;
    let c3 = 0_i64;
    let c4 = 0_i64;
    let c5 = 0_i64;
    let c6 = 0_i64;
    let c7 = 0_i64;
    let c8 = 0_i64;
    let c9 = 0_i64;
    let c10 = 0_i64;
    let c11 = 0_i64;

    let mut limbs = [0_i64; 24];
    limbs[0] = c0 + a0 * b0;
    limbs[1] = c1 + a0 * b1 + a1 * b0;
    limbs[2] = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    limbs[3] = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    limbs[4] = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    limbs[5] = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    limbs[6] = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    limbs[7] = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    limbs[8] = c8
        + a0 * b8
        + a1 * b7
        + a2 * b6
        + a3 * b5
        + a4 * b4
        + a5 * b3
        + a6 * b2
        + a7 * b1
        + a8 * b0;
    limbs[9] = c9
        + a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;
    limbs[10] = c10
        + a0 * b10
        + a1 * b9
        + a2 * b8
        + a3 * b7
        + a4 * b6
        + a5 * b5
        + a6 * b4
        + a7 * b3
        + a8 * b2
        + a9 * b1
        + a10 * b0;
    limbs[11] = c11
        + a0 * b11
        + a1 * b10
        + a2 * b9
        + a3 * b8
        + a4 * b7
        + a5 * b6
        + a6 * b5
        + a7 * b4
        + a8 * b3
        + a9 * b2
        + a10 * b1
        + a11 * b0;
    limbs[12] = a1 * b11
        + a2 * b10
        + a3 * b9
        + a4 * b8
        + a5 * b7
        + a6 * b6
        + a7 * b5
        + a8 * b4
        + a9 * b3
        + a10 * b2
        + a11 * b1;
    limbs[13] = a2 * b11
        + a3 * b10
        + a4 * b9
        + a5 * b8
        + a6 * b7
        + a7 * b6
        + a8 * b5
        + a9 * b4
        + a10 * b3
        + a11 * b2;
    limbs[14] =
        a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    limbs[15] = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    limbs[16] = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    limbs[17] = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    limbs[18] = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    limbs[19] = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    limbs[20] = a9 * b11 + a10 * b10 + a11 * b9;
    limbs[21] = a10 * b11 + a11 * b10;
    limbs[22] = a11 * b11;

    sc_reduce_limbs(&mut limbs);
}

fn sc_sub_fact(_s: &mut [u8; 32], a: &[u8; 32], c: &[u8; 32]) {
    let a0 = 2097151 & load3(a);
    let a1 = 2097151 & (load4(&a[2..]) >> 5);
    let a2 = 2097151 & (load3(&a[5..]) >> 2);
    let a3 = 2097151 & (load4(&a[7..]) >> 7);
    let a4 = 2097151 & (load4(&a[10..]) >> 4);
    let a5 = 2097151 & (load3(&a[13..]) >> 1);
    let a6 = 2097151 & (load4(&a[15..]) >> 6);
    let a7 = 2097151 & (load3(&a[18..]) >> 3);
    let a8 = 2097151 & load3(&a[21..]);
    let a9 = 2097151 & (load4(&a[23..]) >> 5);
    let a10 = 2097151 & (load3(&a[26..]) >> 2);
    let a11 = load4(&a[28..]) >> 7;
    let c0 = 2097151 & load3(c);
    let c1 = 2097151 & (load4(&c[2..]) >> 5);
    let c2 = 2097151 & (load3(&c[5..]) >> 2);
    let c3 = 2097151 & (load4(&c[7..]) >> 7);
    let c4 = 2097151 & (load4(&c[10..]) >> 4);
    let c5 = 2097151 & (load3(&c[13..]) >> 1);
    let c6 = 2097151 & (load4(&c[15..]) >> 6);
    let c7 = 2097151 & (load3(&c[18..]) >> 3);
    let c8 = 2097151 & load3(&c[21..]);
    let c9 = 2097151 & (load4(&c[23..]) >> 5);
    let c10 = 2097151 & (load3(&c[26..]) >> 2);
    let c11 = load4(&c[28..]) >> 7;

    let mut limbs = [0_i64; 24];
    limbs[0] = 1916624 - c0 + a0;
    limbs[1] = 863866 - c1 + a1;
    limbs[2] = 18828 - c2 + a2;
    limbs[3] = 1284811 - c3 + a3;
    limbs[4] = 2007799 - c4 + a4;
    limbs[5] = 456654 - c5 + a5;
    limbs[6] = 5 - c6 + a6;
    limbs[7] = 0 - c7 + a7;
    limbs[8] = 0 - c8 + a8;
    limbs[9] = 0 - c9 + a9;
    limbs[10] = 0 - c10 + a10;
    limbs[11] = 0 - c11 + a11;
    limbs[12] = 16;

    sc_reduce_limbs(&mut limbs);
}

fn t_suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake3_sha256_ed25519()
}

fn bench_scalar_add<T: ScalarTrait>(
    c: &mut BenchmarkGroup<WallTime>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_ref()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + " add"), |b| {
        b.iter(|| s1.clone() + s2.clone())
    });
}

fn bench_scalar_mul<T: ScalarTrait>(
    c: &mut BenchmarkGroup<WallTime>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + " mul"), |b| {
        b.iter(|| s1.clone() * s2.clone())
    });
}

fn bench_scalar_sub<T: ScalarTrait>(
    c: &mut BenchmarkGroup<WallTime>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    let s3 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + " sub"), |b| {
        b.iter(|| s3.clone().sub(&s1, &s2))
    });
}

pub fn benchmark_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalar group");
    // addition
    bench_scalar_add(&mut group, || t_suite().scalar(), "implemented".to_owned());
    bench_scalar_add(&mut group, SimpleCTScalar::default, "simple".to_owned());
    bench_scalar_add(&mut group, FactoredScalar::default, "factored".to_owned());
    // multiplication
    bench_scalar_mul(&mut group, || t_suite().scalar(), "implemented".to_owned());
    bench_scalar_mul(&mut group, SimpleCTScalar::default, "simple".to_owned());
    bench_scalar_mul(&mut group, FactoredScalar::default, "factored".to_owned());
    // subtraction
    bench_scalar_sub(&mut group, || t_suite().scalar(), "implemented".to_owned());
    bench_scalar_sub(&mut group, SimpleCTScalar::default, "simple".to_owned());
    bench_scalar_sub(&mut group, FactoredScalar::default, "factored".to_owned());

    group.finish()
}
