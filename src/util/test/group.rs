use criterion::{measurement::Measurement, BatchSize, BenchmarkGroup};

use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler},
    util::random::RandStream,
    Group, Point, Scalar,
};

/// GroupBench is a generic benchmark suite for kyber.groups.
pub struct GroupBench<GROUP: Group> {
    _g: GROUP,

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
    let rng = &mut RandStream::default();
    let x = g.scalar().pick(rng);
    let y = g.scalar().pick(rng);
    let xe = x.marshal_binary().unwrap();
    let x_caps = g.point().pick(rng);
    let y_caps = g.point().pick(rng);
    let xe_caps = x_caps.marshal_binary().unwrap();
    GroupBench {
        _g: g,
        x,
        y,
        x_caps,
        y_caps,
        xe,
        xe_caps,
    }
}

impl<GROUP: Group> GroupBench<GROUP> {
    /// ScalarAdd benchmarks the addition operation for scalars
    pub fn scalar_add<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_add", |b| {
            b.iter_batched(
                || (self.x.clone(), self.y.clone()),
                |s| s.0 + s.1,
                BatchSize::SmallInput,
            )
        });
    }

    /// ScalarSub benchmarks the substraction operation for scalars
    pub fn scalar_sub<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_sub", |b| {
            b.iter_batched(
                || self.x.clone(),
                |s| s.sub(&self.x, &self.y),
                BatchSize::SmallInput,
            )
        });
    }

    /// ScalarNeg benchmarks the negation operation for scalars
    pub fn scalar_neg<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_neg", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.neg(&self.x), BatchSize::SmallInput)
        });
    }

    /// ScalarMul benchmarks the multiplication operation for scalars
    pub fn scalar_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_mul", |b| {
            b.iter_batched(
                || (self.x.clone(), self.y.clone()),
                |s| s.0 * s.1,
                BatchSize::SmallInput,
            )
        });
    }

    /// ScalarDiv benchmarks the division operation for scalars
    pub fn scalar_div<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_div", |b| {
            b.iter_batched(
                || self.x.clone(),
                |s| s.div(&self.x, &self.y),
                BatchSize::SmallInput,
            )
        });
    }

    /// ScalarInv benchmarks the inverse operation for scalars
    pub fn scalar_inv<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_inv", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.inv(&self.x), BatchSize::SmallInput)
        });
    }

    /// ScalarPick benchmarks the Pick operation for scalars
    pub fn scalar_pick<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        let rng = &mut RandStream::default();
        c.bench_function("scalar_pick", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.pick(rng), BatchSize::SmallInput)
        });
    }

    /// ScalarEncode benchmarks the marshalling operation for scalars
    pub fn scalar_encode<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_encode", |b| {
            b.iter(|| self.x.marshal_binary().unwrap())
        });
    }

    /// ScalarDecode benchmarks the unmarshalling operation for scalars
    pub fn scalar_decode<M: Measurement>(&mut self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_decode", |b| {
            b.iter(|| self.x.unmarshal_binary(&self.xe).unwrap())
        });
    }

    /// PointAdd benchmarks the addition operation for points
    pub fn point_add<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_add", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |s| s.add(&self.x_caps, &self.y_caps),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointSub benchmarks the substraction operation for points
    pub fn point_sub<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_sub", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |s| s.sub(&self.x_caps, &self.y_caps),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointNeg benchmarks the negation operation for points
    pub fn point_neg<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_neg", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |mut s| s.neg(&self.x_caps),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointMul benchmarks the multiplication operation for points
    pub fn point_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_mul", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |s| s.mul(&self.y, Some(&self.x_caps)),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointBaseMul benchmarks the base multiplication operation for points
    pub fn point_base_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_base_mul", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |s| s.mul(&self.y, None),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointPick benchmarks the pick-ing operation for points
    pub fn point_pick<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        let rng = &mut RandStream::default();
        c.bench_function("point_pick", |b| {
            b.iter_batched(
                || self.x_caps.clone(),
                |s| s.pick(rng),
                BatchSize::SmallInput,
            )
        });
    }

    /// PointEncode benchmarks the encoding operation for points
    pub fn point_encode<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_encode", |b| {
            b.iter(|| self.x_caps.marshal_binary().unwrap())
        });
    }

    /// PointDecode benchmarks the decoding operation for points
    pub fn point_decode<M: Measurement>(&mut self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_decode", |b| {
            b.iter(|| self.x_caps.unmarshal_binary(&self.xe_caps).unwrap())
        });
    }
}
