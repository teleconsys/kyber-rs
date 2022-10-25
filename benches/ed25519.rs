#[macro_use]
extern crate bencher;

use bencher::Bencher;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::group::{Group, Scalar};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref T_SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
}

fn benchScalarAdd<T: Scalar>(n: usize, new: fn() -> T) {
    let mut seed = T_SUITE.xof("hello world".as_ref());
    let mut s1 = new();
    let mut s2 = new();
    let mut s3 = new();
    // s1.pick(&mut seed);
    // s2.pick(&mut seed);

    for _ in 0..n {
        s3.add(&s1, &s2);
    }
}

fn benchScalarAddG(b: &mut Bencher) {
    // const N: usize = 1024;
    const N: usize = 1;
    b.iter(|| benchScalarAdd(N, || T_SUITE.scalar()))
}

benchmark_group!(benches, benchScalarAddG);
benchmark_main!(benches);

// func benchScalarMul(b *testing.B, new func() kyber.scalar) {
// var seed = tSuite.XOF([]byte("hello world"))
// s1 := new()
// s2 := new()
// s3 := new()
// s1.Pick(seed)
// s2.Pick(seed)
//
// for i := 0; i < b.N; i++ {
// s3.Mul(s1, s2)
// }
// }
//
// func benchScalarSub(b *testing.B, new func() kyber.scalar) {
// var seed = tSuite.XOF([]byte("hello world"))
// s1 := new()
// s2 := new()
// s3 := new()
// s1.Pick(seed)
// s2.Pick(seed)
//
// for i := 0; i < b.N; i++ {
// s3.Sub(s1, s2)
// }
// }
//
// // addition

// fn benchmark_ct_scalar_add(bench: &mut Bencher) { benchScalarAdd(bench, T_SUITE.Scalar) }

// func BenchmarkCTScalarSimpleAdd(b *testing.B) { benchScalarAdd(b, newSimpleCTScalar) }
//
// func BenchmarkCTScalarFactoredAdd(b *testing.B) { benchScalarAdd(b, newFactoredScalar) }
//
// // multiplication
//
// func BenchmarkCTScalarMul(b *testing.B) { benchScalarMul(b, tSuite.scalar) }
//
// func BenchmarkCTScalarSimpleMul(b *testing.B) { benchScalarMul(b, newSimpleCTScalar) }
//
// func BenchmarkCTScalarFactoredMul(b *testing.B) { benchScalarMul(b, newFactoredScalar) }
//
// // substraction
//
// func BenchmarkCTScalarSub(b *testing.B) { benchScalarSub(b, tSuite.scalar) }
//
// func BenchmarkCTScalarSimpleSub(b *testing.B) { benchScalarSub(b, newSimpleCTScalar) }
//
// func BenchmarkCTScalarFactoredSub(b *testing.B) { benchScalarSub(b, newFactoredScalar) }
