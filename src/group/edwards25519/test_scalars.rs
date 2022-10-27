use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::{
    cipher::cipher::Stream,
    encoding::{self, BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::Scalar,
};

use super::scalar::{sc_mul_add, Scalar as EdScalar};

lazy_static! {
    pub static ref ONE: EdScalar = *EdScalar::default().set_int64(1);
    pub static ref ZERO: EdScalar = *EdScalar::default().zero();
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

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {
    fn MarshalTo(&self, w: &mut impl std::io::Write) -> anyhow::Result<usize> {
        todo!()
    }
}

impl BinaryMarshaler for SimpleCTScalar {
    fn marshal_binary(&self) -> anyhow::Result<Vec<u8>> {
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

impl Scalar for SimpleCTScalar {
    fn set(&mut self, _a: &Self) -> &mut Self {
        todo!()
    }

    fn set_int64(&mut self, v: i64) -> &mut Self {
        self.s.set_int64(v);
        self
    }

    fn zero(&mut self) -> &mut Self {
        todo!()
    }

    fn pick(&mut self, rand: &mut impl Stream) -> &mut Self {
        self.s.pick(rand);
        self
    }

    fn set_bytes(&mut self, _bytes: &[u8]) -> Self {
        todo!()
    }

    fn add(&mut self, s1: &Self, s2: &Self) -> &mut Self {
        // sc1 := s1.(*SimpleCTScalar)
        // sc2 := s2.(*SimpleCTScalar)

        // a * b + c = a * 1 + c
        sc_mul_add(&mut self.s.v, &s1.s.v, &ONE.v, &s2.s.v);
        self
    }

    fn mul(&mut self, s1: &Self, s2: &Self) -> &mut Self {
        // sc1 := s1.(*SimpleCTScalar)
        // sc2 := s2.(*SimpleCTScalar)

        // // a * b + c = a * b + 0
        sc_mul_add(&mut self.s.v, &s1.s.v, &s2.s.v, &ZERO.v);
        self
    }

    fn sub(&mut self, _s1: &Self, _s2: &Self) -> &mut Self {
        // sc1 := s1.(*SimpleCTScalar)
        // sc2 := s2.(*SimpleCTScalar)

        // // a * b + c = -1 * a + c
        // scMulAdd(&s.v, &minusOne.v, &sc1.v, &sc2.v)
        // return s
        todo!()
    }
}
