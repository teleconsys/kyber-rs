use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler},
    util::random::Randstream,
    Group, Point, Scalar,
};

/// GroupBench is a generic benchmark suite for kyber.groups.
pub struct GroupBench<GROUP: Group> {
    g: GROUP,

    // Random secrets and points for testing
    x: <GROUP::POINT as Point>::SCALAR,
    y: <GROUP::POINT as Point>::SCALAR,
    x_caps: GROUP::POINT,
    y_caps: GROUP::POINT,
    xe: Vec<u8>,      // encoded Scalar
    xe_caps: Vec<u8>, // encoded Point
}

/// NewGroupBench returns a new GroupBench.
pub fn new_group_bench<GROUP: Group>(g: GROUP) -> GroupBench<GROUP> {
    let rng = &mut Randstream::default();
    let x = g.scalar().pick(rng);
    let y = g.scalar().pick(rng);
    let xe = x.marshal_binary().unwrap();
    let x_caps = g.point().pick(rng);
    let y_caps = g.point().pick(rng);
    let xe_caps = x_caps.marshal_binary().unwrap();
    return GroupBench {
        g,
        x,
        y,
        x_caps,
        y_caps,
        xe,
        xe_caps,
    };
}

impl<GROUP: Group> GroupBench<GROUP> {
    /// ScalarAdd benchmarks the addition operation for scalars
    fn scalar_add(&self, iters: usize) {
        for _ in 1..iters {
            _ = self.x.clone() + self.y.clone();
        }
    }

    /// ScalarSub benchmarks the substraction operation for scalars
    fn scalar_sub(&self, iters: usize) {
        for _ in 1..iters {
            self.x.clone().sub(&self.x, &self.y);
        }
    }

    /// ScalarNeg benchmarks the negation operation for scalars
    fn scalar_neg(&self, iters: usize) {
        for _ in 1..iters {
            self.x.clone().neg(&self.x);
        }
    }

    /// ScalarMul benchmarks the multiplication operation for scalars
    fn scalar_mul(&self, iters: usize) {
        for _ in 1..iters {
            _ = self.x.clone() * self.y.clone();
        }
    }

    /// ScalarDiv benchmarks the division operation for scalars
    fn scalar_div(&self, iters: usize) {
        for _ in 1..iters {
            self.x.clone().div(&self.x, &self.y);
        }
    }

    /// ScalarInv benchmarks the inverse operation for scalars
    fn scalar_inv(&self, iters: usize) {
        for _ in 1..iters {
            self.x.clone().inv(&self.x);
        }
    }

    /// ScalarPick benchmarks the Pick operation for scalars
    fn scalar_pick(&self, iters: usize) {
        let rng = &mut Randstream::default();
        for _ in 1..iters {
            self.x.clone().pick(rng);
        }
    }

    /// ScalarEncode benchmarks the marshalling operation for scalars
    fn scalar_encode(&self, iters: usize) {
        for _ in 1..iters {
            self.x.marshal_binary();
        }
    }

    /// ScalarDecode benchmarks the unmarshalling operation for scalars
    fn scalar_decode(&mut self, iters: usize) {
        for _ in 1..iters {
            self.x.unmarshal_binary(&self.xe);
        }
    }

    /// PointAdd benchmarks the addition operation for points
    fn point_add(&self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.clone().add(&self.x_caps, &self.y_caps);
        }
    }

    /// PointSub benchmarks the substraction operation for points
    fn point_sub(&self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.clone().sub(&self.x_caps, &self.y_caps);
        }
    }

    /// PointNeg benchmarks the negation operation for points
    fn point_neg(&mut self, iters: usize) {
        for _ in 1..iters {
            let x_clone = self.x_caps.clone();
            self.x_caps.neg(&x_clone);
        }
    }

    /// PointMul benchmarks the multiplication operation for points
    fn point_mul(&self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.clone().mul(&self.y, Some(&self.x_caps));
        }
    }

    /// PointBaseMul benchmarks the base multiplication operation for points
    fn point_base_mul(&self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.clone().mul(&self.y, None);
        }
    }

    /// PointPick benchmarks the pick-ing operation for points
    fn point_pick(&self, iters: usize) {
        let rng = &mut Randstream::default();
        for _ in 1..iters {
            self.x_caps.clone().pick(rng);
        }
    }

    /// PointEncode benchmarks the encoding operation for points
    fn point_encode(&self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.marshal_binary();
        }
    }

    /// PointDecode benchmarks the decoding operation for points
    fn point_decode(&mut self, iters: usize) {
        for _ in 1..iters {
            self.x_caps.unmarshal_binary(&self.xe_caps);
        }
    }
}