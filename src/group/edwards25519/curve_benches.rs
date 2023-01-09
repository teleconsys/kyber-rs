use criterion::Criterion;

use crate::util::test::new_group_bench;

use super::SuiteEd25519;

pub fn benchmark_group(c: &mut Criterion) {
    let mut b_group = c.benchmark_group("ed25519_curve_group");
    let mut t = new_group_bench(SuiteEd25519::new_blake3_sha256_ed25519());

    // scalar
    t.scalar_add(&mut b_group);
    t.scalar_sub(&mut b_group);
    t.scalar_neg(&mut b_group);
    t.scalar_mul(&mut b_group);
    t.scalar_div(&mut b_group);
    t.scalar_inv(&mut b_group);
    t.scalar_pick(&mut b_group);
    t.scalar_encode(&mut b_group);
    t.scalar_decode(&mut b_group);

    // point
    t.point_add(&mut b_group);
    t.point_sub(&mut b_group);
    t.point_neg(&mut b_group);
    t.point_mul(&mut b_group);
    t.point_base_mul(&mut b_group);
    t.point_pick(&mut b_group);
    t.point_encode(&mut b_group);
    t.point_decode(&mut b_group);

    b_group.finish()
}
