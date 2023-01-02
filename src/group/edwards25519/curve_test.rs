use crate::util::test::{self, new_group_bench, GroupBench};

use super::SuiteEd25519;

fn _test_group() -> GroupBench<SuiteEd25519> {
    let t_suite = SuiteEd25519::new_blake_sha256ed25519();
    new_group_bench(t_suite)
}

impl test::Suite for SuiteEd25519 {}

#[test]
fn test_suite() {
    test::suite_test(SuiteEd25519::new_blake_sha256ed25519()).unwrap()
}

// func BenchmarkScalarAdd(b *testing.B)    { groupBench.ScalarAdd(b.N) }
// func BenchmarkScalarSub(b *testing.B)    { groupBench.ScalarSub(b.N) }
// func BenchmarkScalarNeg(b *testing.B)    { groupBench.ScalarNeg(b.N) }
// func BenchmarkScalarMul(b *testing.B)    { groupBench.ScalarMul(b.N) }
// func BenchmarkScalarDiv(b *testing.B)    { groupBench.ScalarDiv(b.N) }
// func BenchmarkScalarInv(b *testing.B)    { groupBench.ScalarInv(b.N) }
// func BenchmarkScalarPick(b *testing.B)   { groupBench.ScalarPick(b.N) }
// func BenchmarkScalarEncode(b *testing.B) { groupBench.ScalarEncode(b.N) }
// func BenchmarkScalarDecode(b *testing.B) { groupBench.ScalarDecode(b.N) }

// func BenchmarkPointAdd(b *testing.B)     { groupBench.PointAdd(b.N) }
// func BenchmarkPointSub(b *testing.B)     { groupBench.PointSub(b.N) }
// func BenchmarkPointNeg(b *testing.B)     { groupBench.PointNeg(b.N) }
// func BenchmarkPointMul(b *testing.B)     { groupBench.PointMul(b.N) }
// func BenchmarkPointBaseMul(b *testing.B) { groupBench.PointBaseMul(b.N) }
// func BenchmarkPointPick(b *testing.B)    { groupBench.PointPick(b.N) }
// func BenchmarkPointEncode(b *testing.B)  { groupBench.PointEncode(b.N) }
// func BenchmarkPointDecode(b *testing.B)  { groupBench.PointDecode(b.N) }
