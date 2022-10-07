use crate::encoding::Marshaling;
use crate::group::edwards25519::scalar::Scalar;
use crate::group::group;

/// SimpleCTScalar implements the scalar operations only using `ScMulAdd` by
/// playing with the parameters.
#[derive(Clone)]
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

impl Marshaling for SimpleCTScalar {}

impl group::Scalar for SimpleCTScalar {
    fn equal(&self, other: &Self) -> bool {
        self.s.equal(&other.s)
    }

    fn set(&mut self, a: &Self) -> &mut Self {
        self.s.set(&a.s);
        self
    }

    fn set_int64(&mut self, v: i64) -> &mut Self {
        self.s.set_int64(v);
        self
    }
}