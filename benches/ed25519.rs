#[macro_use]
extern crate bencher;

use bencher::Bencher;
use kyber_rs::group::edwards25519::test_scalars::SimpleCTScalar;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::group::{Group, Scalar};
use kyber_rs::XOFFactory;
use lazy_static::lazy_static;

// lazy_static! {
//     pub static ref T_SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
// }

fn t_suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

fn bench_scalar_add<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_ref()));
    let mut s1 = new();
    let mut s2 = new();
    let mut s3 = new();
    s1.pick(&mut seed);
    s2.pick(&mut seed);

    bench.iter(|| {
        s3.add(&s1, &s2);
    });
}

benchmark_group!(
    benches,
    benchmark_ct_scalar_add,
    benchmark_ct_scalar_simple_add,
    benchmark_ct_scalar_sub,
    benchmark_ct_scalar_mul
);
benchmark_main!(benches);

fn bench_scalar_mul<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    let mut s3 = new();
    s1.pick(&mut seed);
    s2.pick(&mut seed);

    bench.iter(|| {
        s3.mul(&s1, &s2);
    });
}

fn bench_scalar_sub<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    let mut s3 = new();
    s1.pick(&mut seed);
    s2.pick(&mut seed);

    bench.iter(|| {
        s3.sub(&s1, &s2);
    });
}

// addition

fn benchmark_ct_scalar_add(bench: &mut Bencher) {
    bench_scalar_add(bench, || t_suite().scalar());
}

fn benchmark_ct_scalar_simple_add(bench: &mut Bencher) {
    bench_scalar_add(bench, || SimpleCTScalar::default());
}

// func BenchmarkCTScalarFactoredAdd(b *testing.B) { benchScalarAdd(b, newFactoredScalar) }
//

// multiplication

fn benchmark_ct_scalar_mul(bench: &mut Bencher) {
    bench_scalar_mul(bench, || t_suite().scalar());
}

// func BenchmarkCTScalarSimpleMul(b *testing.B) { benchScalarMul(b, newSimpleCTScalar) }
//
// func BenchmarkCTScalarFactoredMul(b *testing.B) { benchScalarMul(b, newFactoredScalar) }

// substraction

fn benchmark_ct_scalar_sub(bench: &mut Bencher) {
    bench_scalar_sub(bench, || t_suite().scalar());
}

// func BenchmarkCTScalarSimpleSub(b *testing.B) { benchScalarSub(b, newSimpleCTScalar) }
//
// func BenchmarkCTScalarFactoredSub(b *testing.B) { benchScalarSub(b, newFactoredScalar) }
