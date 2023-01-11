#[macro_use]
extern crate criterion;

use kyber_rs::group::edwards25519::{benchmark_group, benchmark_scalar};

criterion_group!(benches, benchmark_scalar, benchmark_group);

criterion_main!(benches);
