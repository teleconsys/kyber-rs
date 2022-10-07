use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::encoding;
use crate::encoding::{BinaryMarshaler, BinaryUnmarshaller, Marshaling};
use crate::group::edwards25519::scalar::Scalar;
use crate::group::group;

/// SimpleCTScalar implements the scalar operations only using `ScMulAdd` by
/// playing with the parameters.
#[derive(Clone, Serialize, Deserialize)]
struct SimpleCTScalar {
    s: Scalar,
}

impl SimpleCTScalar {
    fn new() -> SimpleCTScalar {
        SimpleCTScalar {
            s: Scalar::new()
        }
    }
}

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {}

impl BinaryMarshaler for SimpleCTScalar {
    fn marshal_binary(&self) -> anyhow::Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

impl BinaryUnmarshaller for SimpleCTScalar {
    fn unmarshal_binary(&mut self, data: &[u8]) -> anyhow::Result<()> {
        encoding::unmarshal_binary(self, data)
    }
}

impl group::Scalar for SimpleCTScalar {
    fn set(&mut self, a: &Self) -> &mut Self {
        self.s.set(&a.s);
        self
    }

    fn set_int64(&mut self, v: i64) -> &mut Self {
        self.s.set_int64(v);
        self
    }
}