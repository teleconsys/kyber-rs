use std::ops::DerefMut;

use anyhow::Result;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    cipher::cipher::Stream,
    encoding::{self, BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::Scalar,
};

use super::scalar::{sc_mul_add, Scalar as EdScalar};

lazy_static! {
    pub static ref ONE: EdScalar = EdScalar::default().set_int64(1);
    pub static ref ZERO: EdScalar = EdScalar::default().zero();
    pub static ref MINUS_ONE: EdScalar = EdScalar::default().set_bytes(&[0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]);
}

/// SimpleCTScalar implements the scalar operations only using `ScMulAdd` by
/// playing with the parameters.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct SimpleCTScalar {
    s: EdScalar,
}

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {
    fn marshal_to(&self, w: &mut impl std::io::Write) -> Result<()> {
        self.s.marshal_to(w)
    }

    fn marshal_size(&self) -> usize {
        self.s.marshal_size()
    }

    fn unmarshal_from(&mut self, r: &mut impl std::io::Read) -> Result<()> {
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
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

impl BinaryUnmarshaler for SimpleCTScalar {
    fn unmarshal_binary(&mut self, data: &[u8]) -> anyhow::Result<()> {
        encoding::unmarshal_binary(self, data)
    }
}

impl ToString for SimpleCTScalar {
    fn to_string(&self) -> String {
        self.s.to_string()
    }
}

use std::ops;
impl_op_ex!(*|a: &SimpleCTScalar, b: &SimpleCTScalar| -> SimpleCTScalar {
    // // a * b + c = a * b + 0
    let mut v = [0u8; 32];
    sc_mul_add(&mut v, &a.s.v, &b.s.v, &ZERO.v);
    SimpleCTScalar{s: EdScalar{v}}
});

impl_op_ex!(+|a: &SimpleCTScalar, b: &SimpleCTScalar| -> SimpleCTScalar {
        // a * b + c = a * 1 + c
        let mut v = [0u8; 32];
        sc_mul_add(&mut v, &a.s.v, &ONE.v, &b.s.v);
        SimpleCTScalar{s:EdScalar{v}}
});

use std::ops::Deref;
impl Deref for SimpleCTScalar {
    type Target = EdScalar;

    fn deref(&self) -> &Self::Target {
        &self.s
    }
}

impl DerefMut for SimpleCTScalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.s
    }
}

impl Scalar for SimpleCTScalar {
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
        Self{s: self.s.one()}
    }

    fn div(self, a: &Self, b: &Self) -> Self {
        Self{s: self.s.div(a, b)}
    }

    fn inv(self, a: &Self) -> Self {
        Self{s: self.s.inv(a)}
    }

    fn neg(self, a: &Self) -> Self {
        Self{s: self.s.neg(a)}
    }
}
