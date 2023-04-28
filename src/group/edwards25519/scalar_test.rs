use std::ops::Add;

use num_bigint_dig::BigInt;

use super::{constants::PRIME_ORDER, FactoredScalar, SimpleCTScalar};
use crate::Scalar as ScalarTrait;
use crate::{
    encoding::Marshaling,
    group::{
        edwards25519::{scalar_test_types::ONE, Scalar},
        ScalarCanCheckCanonical,
    },
    util::random::random_stream,
};

#[test]
fn test_factored_scalar() {
    test_simple(FactoredScalar::default)
}

#[test]
fn test_simple_ct_scalar() {
    test_simple(SimpleCTScalar::default)
}

#[test]
fn test_string() {
    // Create a scalar that would trigger #262.
    let mut s = Scalar::default();
    s = s.set_int64(0x100);
    s = s + *ONE;
    assert_eq!(
        format!("{s:x}"),
        "0101000000000000000000000000000000000000000000000000000000000000",
        "unexpected result from string(): {s:x}"
    );
}

#[test]
fn test_negative_big_int() {
    // Create a scalar that would trigger #262.
    let mut s = Scalar::default();
    s = s.set_int64(-1);
    assert_eq!(
        format!("{s:x}"),
        "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        "unexpected result: {s:x}"
    );
}

#[test]
fn test_positive_big_int() {
    // Create a scalar that would trigger #262.
    let mut s = Scalar::default();
    s = s.set_int64(1);
    assert_eq!(
        format!("{s:x}"),
        "0100000000000000000000000000000000000000000000000000000000000000",
        "unexpected result: {s:x}"
    );
}

#[test]
fn test_scalar_marshal() {
    let s = Scalar::default();

    assert_eq!("ed.scala", std::str::from_utf8(&s.marshal_id()).unwrap());
}

#[test]
fn test_set_bytes_le() {
    let mut s = Scalar::default();
    s = s.set_bytes(&[0, 1, 2, 3]);
    assert_eq!(
        format!("{s:x}"),
        "0001020300000000000000000000000000000000000000000000000000000000",
        "unexpected result from string(): {s:x}"
    );
}

fn test_simple<T: ScalarTrait>(new: fn() -> T) {
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.set_int64(2);
    s2 = s2.pick(&mut random_stream::RandStream::default());

    let s22 = s2.clone() + s2.clone();

    assert_eq!(s1 * s2, s22);
}

/// Test_ScalarIsCanonical ensures that scalars >= primeOrder are
/// considered non canonical.
#[test]
fn test_scalar_is_canonical() {
    let mut candidate = BigInt::from(-2_i64);
    candidate = candidate.add(PRIME_ORDER.clone());
    let mut candidate_buf = candidate.to_bytes_le().1;

    let expected = [true, true, false, false];

    // We check in range [L-2, L+4)
    (0..4).for_each(|i| {
        assert_eq!(
            expected[i],
            Scalar::default().is_canonical(&candidate_buf),
            "`lMinus2 + {i}` does not pass canonicality test"
        );
        candidate_buf[0] += 1;
    });
}
