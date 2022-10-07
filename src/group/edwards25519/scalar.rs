use crate::encoding::Marshaling;
use crate::group::group;

use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub struct Scalar {
    v: [u8; 32],
}

impl Scalar {
    pub fn new() -> Scalar {
        Scalar {
            v: [0; 32]
        }
    }

    // fn setInt(&mut self, i *mod.Int) -> &mut Self {
    // b := i.little_endian(32, 32)
    // copy(s.v[:], b)
    // return s
// }
}

impl group::Scalar for Scalar {
    /// Equality test for two Scalars derived from the same Group
    fn equal(&self, other: &Self) -> bool {
        bool::from(self.v.ct_eq(other.v.as_ref()))
    }

    // Set equal to another Scalar a
    fn set(&mut self, a: &Self) -> &mut Self {
        self.v = a.v.clone();
        self
    }

    /// SetInt64 sets the scalar to a small integer value.
    fn set_int64(&mut self, _v: i64) -> &mut Self {
        todo!()
        // s.setInt(mod.NewInt64(v, primeOrder))
    }
}

impl Marshaling for Scalar {}