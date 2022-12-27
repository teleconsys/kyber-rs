use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::edwards25519::test_scalars::ONE;
use crate::group::Scalar;
use crate::util::random;

use super::test_scalars::SimpleCTScalar;

#[test]
fn test_string() {
    // Create a scalar that would trigger #262.
    let mut s = EdScalar::default();
    s = s.set_int64(0x100);
    s = s + ONE.clone();
    let _z = s.string();
    assert_eq!(
        s.string(),
        "0101000000000000000000000000000000000000000000000000000000000000",
        "unexpected result from string(): {}",
        s.string()
    );
}

#[test]
fn test_negative_big_int() {
    // Create a scalar that would trigger #262.
    let mut s = EdScalar::default();
    s = s.set_int64(-1);
    assert_eq!(
        s.string(),
        "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        "unexpected result: {}",
        s.string()
    );
}

#[test]
fn test_positive_big_int() {
    // Create a scalar that would trigger #262.
    let mut s = EdScalar::default();
    s = s.set_int64(1);
    assert_eq!(
        s.string(),
        "0100000000000000000000000000000000000000000000000000000000000000",
        "unexpected result: {}",
        s.string()
    );
}

#[test]
fn test_scalar_marshal() {
    let s = EdScalar::default();

    assert_eq!("ed.scala", std::str::from_utf8(&s.marshal_id()).unwrap());
}

#[test]
fn test_set_bytes_le() {
    let mut s = EdScalar::default();
    s = s.set_bytes(&[0, 1, 2, 3]);
    assert_eq!(
        s.string(),
        "0001020300000000000000000000000000000000000000000000000000000000",
        "unexpected result from string(): {}",
        s.string()
    );
}

fn test_simple<T: Scalar>(new: fn() -> T) {
    let mut s1 = new();
    let mut s2 = new();
    s1 = s1.set_int64(2);
    s2 = s2.pick(&mut random::Randstream::default());

    let s22 = s2.clone() + s2.clone();

    assert_eq!(s1 * s2, s22);
}

#[test]
fn test_factored_scalar() {
    // testSimple(newFactoredScalar)
}

#[test]
fn test_simple_ct_scalar() {
    test_simple(SimpleCTScalar::default)
}
