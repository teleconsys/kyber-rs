use std::ops::{Add, DerefMut, Mul};

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
}

/// SimpleCTScalar implements the scalar operations only using `ScMulAdd` by
/// playing with the parameters.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SimpleCTScalar {
    s: EdScalar,
}

impl Default for SimpleCTScalar {
    fn default() -> Self {
        SimpleCTScalar {
            s: EdScalar::default(),
        }
    }
}

impl Add for SimpleCTScalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // a * b + c = a * 1 + c
        let mut v = [0u8; 32];
        sc_mul_add(&mut v, &self.s.v, &ONE.v, &rhs.s.v);
        SimpleCTScalar { s: EdScalar { v } }
    }
}

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {
    fn marshal_to(&self, _w: &mut impl std::io::Write) -> Result<()> {
        todo!()
    }

    fn marshal_size(&self) -> usize {
        todo!()
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
        todo!()
    }
}

impl Mul for SimpleCTScalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        // // a * b + c = a * b + 0
        let mut v = [0u8; 32];
        sc_mul_add(&mut v, &self.s.v, &rhs.s.v, &ZERO.v);
        SimpleCTScalar { s: EdScalar { v } }
    }
}

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
    fn sub(self, _s1: &Self, _s2: &Self) -> Self {
        // sc1 := s1.(*SimpleCTScalar)
        // sc2 := s2.(*SimpleCTScalar)

        // // a * b + c = -1 * a + c
        // scMulAdd(&s.v, &minusOne.v, &sc1.v, &sc2.v)
        // return s
        todo!()
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
}
