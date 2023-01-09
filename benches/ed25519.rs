#[macro_use]
extern crate bencher;

use bencher::Bencher;
use kyber_rs::group::edwards25519::scalar_test_types::SimpleCTScalar;
use kyber_rs::group::edwards25519::{SuiteEd25519, FactoredScalar};
use kyber_rs::group::{Group, Scalar};
use kyber_rs::XOFFactory;

// lazy_static! {
//     pub static ref T_SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
// }

fn t_suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

benchmark_group!(
    benches,
    benchmark_ct_scalar_add,
    benchmark_ct_scalar_simple_add,
    benchmark_ct_scalar_factored_add,
    benchmark_ct_scalar_mul,
    benchmark_ct_scalar_simple_mul,
    benchmark_ct_scalar_factored_mul,
    benchmark_ct_scalar_sub,
    benchmark_ct_scalar_simple_sub,
    benchmark_ct_scalar_factored_sub
);
benchmark_main!(benches);

fn bench_scalar_add<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_ref()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    bench.iter(|| {
        let _ = s1.clone() + s2.clone();
    });
}

fn bench_scalar_mul<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    bench.iter(move || {
        let _ = s1.clone() * s2.clone();
    });
}

fn bench_scalar_sub<T: Scalar>(bench: &mut Bencher, new: fn() -> T) {
    let mut seed = t_suite().xof(Some("hello world".as_bytes()));
    let mut s1 = new();
    let mut s2 = new();
    let s3 = new();
    s1 = s1.pick(&mut seed);
    s2 = s2.pick(&mut seed);

    bench.iter(|| {
        s3.clone().sub(&s1, &s2);
    });
}

// addition

fn benchmark_ct_scalar_add(bench: &mut Bencher) {
    bench_scalar_add(bench, || t_suite().scalar());
}

fn benchmark_ct_scalar_simple_add(bench: &mut Bencher) {
    bench_scalar_add(bench, SimpleCTScalar::default);
}

fn benchmark_ct_scalar_factored_add(bench: &mut Bencher) {
    bench_scalar_add(bench, FactoredScalar::default);
}

// multiplication

fn benchmark_ct_scalar_mul(bench: &mut Bencher) {
    bench_scalar_mul(bench, || t_suite().scalar());
}

fn benchmark_ct_scalar_simple_mul(bench: &mut Bencher) {
    bench_scalar_mul(bench, SimpleCTScalar::default);
}

fn benchmark_ct_scalar_factored_mul(bench: &mut Bencher) {
    bench_scalar_mul(bench, FactoredScalar::default);
}

// subtraction

fn benchmark_ct_scalar_sub(bench: &mut Bencher) {
    bench_scalar_sub(bench, || t_suite().scalar());
}

fn benchmark_ct_scalar_simple_sub(bench: &mut Bencher) {
    bench_scalar_sub(bench, SimpleCTScalar::default);
}

fn benchmark_ct_scalar_factored_sub(bench: &mut Bencher) {
    bench_scalar_sub(bench, FactoredScalar::default);
}
