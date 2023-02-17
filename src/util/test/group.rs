use criterion::{measurement::Measurement, BatchSize, BenchmarkGroup};

use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler},
    util::random::RandStream,
    Group, Point, Scalar,
};

/// [`GroupBench`] is a generic benchmark suite for [`groups`](Group).
pub struct GroupBench<GROUP: Group> {
    _g: GROUP,

    // Random secrets and points for testing
    x: <GROUP::POINT as Point>::SCALAR,
    y: <GROUP::POINT as Point>::SCALAR,
    x_p: GROUP::POINT,
    y_p: GROUP::POINT,
    /// encoded [`Scalar`]
    xe: Vec<u8>,
    /// encoded [`Point`]    
    xe_p: Vec<u8>,
}

/// [`new_group_bench`] returns a new [`GroupBench`].
pub fn new_group_bench<GROUP: Group>(g: GROUP) -> GroupBench<GROUP> {
    let rng = &mut RandStream::default();
    let x = g.scalar().pick(rng);
    let y = g.scalar().pick(rng);
    let xe = x.marshal_binary().unwrap();
    let x_p = g.point().pick(rng);
    let y_p = g.point().pick(rng);
    let xe_p = x_p.marshal_binary().unwrap();
    GroupBench {
        _g: g,
        x,
        y,
        x_p,
        y_p,
        xe,
        xe_p,
    }
}

impl<GROUP: Group> GroupBench<GROUP> {
    /// [`scalar_add()`] benchmarks the `addition` operation for [`scalars`](Scalar)
    pub fn scalar_add<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_add", |b| {
            b.iter_batched(
                || (self.x.clone(), self.y.clone()),
                |s| s.0 + s.1,
                BatchSize::SmallInput,
            )
        });
    }

    /// [`scalar_sub()`] benchmarks the `substraction` operation for [`scalars`](Scalar)
    pub fn scalar_sub<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_sub", |b| {
            b.iter_batched(
                || self.x.clone(),
                |s| s.sub(&self.x, &self.y),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`scalar_neg()`] benchmarks the `negation` operation for [`scalars`](Scalar)
    pub fn scalar_neg<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_neg", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.neg(&self.x), BatchSize::SmallInput)
        });
    }

    /// [`scalar_mul()`] benchmarks the `multiplication` operation for [`scalars`](Scalar)
    pub fn scalar_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_mul", |b| {
            b.iter_batched(
                || (self.x.clone(), self.y.clone()),
                |s| s.0 * s.1,
                BatchSize::SmallInput,
            )
        });
    }

    /// [`scalar_div()`] benchmarks the `division` operation for [`scalars`](Scalar)
    pub fn scalar_div<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_div", |b| {
            b.iter_batched(
                || self.x.clone(),
                |s| s.div(&self.x, &self.y),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`scalar_inv()`] benchmarks the `inverse` operation for [`scalars`](Scalar)
    pub fn scalar_inv<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_inv", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.inv(&self.x), BatchSize::SmallInput)
        });
    }

    /// [`scalar_pick()`] benchmarks the `pick-ing` operation for [`scalars`](Scalar)
    pub fn scalar_pick<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        let rng = &mut RandStream::default();
        c.bench_function("scalar_pick", |b| {
            b.iter_batched(|| self.x.clone(), |s| s.pick(rng), BatchSize::SmallInput)
        });
    }

    /// [`scalar_encode()`] benchmarks the `marshalling` operation for [`scalars`](Scalar)
    pub fn scalar_encode<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_encode", |b| {
            b.iter(|| self.x.marshal_binary().unwrap())
        });
    }

    /// [`scalar_decode()`] benchmarks the `unmarshalling` operation for [`scalars`](Scalar)
    pub fn scalar_decode<M: Measurement>(&mut self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("scalar_decode", |b| {
            b.iter(|| self.x.unmarshal_binary(&self.xe).unwrap())
        });
    }

    /// [`point_add()`] benchmarks the `addition` operation for [`points`](Point)
    pub fn point_add<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_add", |b| {
            b.iter_batched(
                || self.x_p.clone(),
                |s| s.add(&self.x_p, &self.y_p),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`point_sub()`] benchmarks the `substraction` operation for [`points`](Point)
    pub fn point_sub<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_sub", |b| {
            b.iter_batched(
                || self.x_p.clone(),
                |s| s.sub(&self.x_p, &self.y_p),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`point_neg()`] benchmarks the `negation` operation for [`points`](Point)
    pub fn point_neg<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_neg", |b| {
            b.iter_batched(
                || self.x_p.clone(),
                |mut s| s.neg(&self.x_p),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`point_mul()`] benchmarks the `multiplication` operation for [`points`](Point)
    pub fn point_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_mul", |b| {
            b.iter_batched(
                || self.x_p.clone(),
                |s| s.mul(&self.y, Some(&self.x_p)),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`point_base_mul()`] benchmarks the `base multiplication` operation for [`points`](Point)
    pub fn point_base_mul<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_base_mul", |b| {
            b.iter_batched(
                || self.x_p.clone(),
                |s| s.mul(&self.y, None),
                BatchSize::SmallInput,
            )
        });
    }

    /// [`point_pick()`` benchmarks the `pick-ing` operation for [`points()`](Point)
    pub fn point_pick<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        let rng = &mut RandStream::default();
        c.bench_function("point_pick", |b| {
            b.iter_batched(|| self.x_p.clone(), |s| s.pick(rng), BatchSize::SmallInput)
        });
    }

    /// [`point_encode()`] benchmarks the encoding operation for [`points`](Point)
    pub fn point_encode<M: Measurement>(&self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_encode", |b| {
            b.iter(|| self.x_p.marshal_binary().unwrap())
        });
    }

    /// [`point_decode()`] benchmarks the decoding operation for [`points`](Point)
    pub fn point_decode<M: Measurement>(&mut self, c: &mut BenchmarkGroup<M>) {
        c.bench_function("point_decode", |b| {
            b.iter(|| self.x_p.unmarshal_binary(&self.xe_p).unwrap())
        });
    }
}
