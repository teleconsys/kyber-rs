use criterion::{measurement::Measurement, BatchSize, BenchmarkGroup, Criterion};

use crate::{Group, Scalar, XOFFactory};

use super::{FactoredScalar, SimpleCTScalar, SuiteEd25519};

fn t_suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake3_sha256_ed25519()
}

fn bench_scalar_add<T: Scalar, M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_ref()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + "_add"), move |b| {
        b.iter_batched(
            || (s1.clone(), s2.clone()),
            |s| s.0 + s.1,
            BatchSize::SmallInput,
        )
    });
}

fn bench_scalar_mul<T: Scalar, M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + "_mul"), |b| {
        b.iter_batched(
            || (s1.clone(), s2.clone()),
            |s| s.0 * s.1,
            BatchSize::SmallInput,
        )
    });
}

fn bench_scalar_sub<T: Scalar, M: Measurement>(
    c: &mut BenchmarkGroup<M>,
    new: fn() -> T,
    scalar_name: String,
) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    let s3 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    c.bench_function(&(scalar_name + "_sub"), |b| {
        b.iter_batched(|| (s3.clone()), |s| s.sub(&s1, &s2), BatchSize::SmallInput)
    });
}

pub fn benchmark_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519_scalar_group");
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
