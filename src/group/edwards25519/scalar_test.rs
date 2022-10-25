use crate::cipher::cipher::Stream;
use crate::encoding;
use crate::encoding::{BinaryMarshaler, BinaryUnmarshaller, Marshaling};
use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::group::Scalar;
use crate::util::random;
use serde::{Deserialize, Serialize};

/// SimpleCTScalar implements the scalar operations only using `ScMulAdd` by
/// playing with the parameters.
#[derive(Clone, Serialize, Deserialize, Debug)]
struct SimpleCTScalar {
    s: EdScalar,
}

impl SimpleCTScalar {
    fn new() -> SimpleCTScalar {
        SimpleCTScalar {
            s: EdScalar::default(),
        }
    }
}

impl PartialEq for SimpleCTScalar {
    fn eq(&self, other: &Self) -> bool {
        self.s.eq(&other.s)
    }
}

impl Marshaling for SimpleCTScalar {}

impl BinaryMarshaler for SimpleCTScalar {
    fn marshal_binary(&self) -> anyhow::Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

impl BinaryUnmarshaller for SimpleCTScalar {
    fn unmarshal_binary(&mut self, data: &[u8]) -> anyhow::Result<()> {
        encoding::unmarshal_binary(self, data)
    }
}

impl Scalar for SimpleCTScalar {
    fn set(&mut self, a: &Self) -> &mut Self {
        self.s.set(&a.s);
        self
    }

    fn set_int64(&mut self, v: i64) -> &mut Self {
        self.s.set_int64(v);
        self
    }

    fn zero(&mut self) -> &mut Self {
        todo!()
    }

    fn add(&mut self, a: &Self, b: &Self) -> &mut Self {
        self.s.add(&a.s, &b.s);
        self
    }

    fn mul(&mut self, a: Self, b: Self) -> &mut Self {
        self.s.mul(a.s, b.s);
        self
    }

    fn pick(&mut self, rand: &mut impl Stream) -> &mut Self {
        self.s.pick(rand);
        self
    }

    fn set_bytes(&mut self, _bytes: &[u8]) -> Self {
        todo!()
    }
}

fn one() -> EdScalar {
    *EdScalar::default().set_int64(1)
}

fn zero() -> EdScalar {
    *EdScalar::default().zero()
}

#[test]
fn test_string() {
    // Create a scalar that would trigger #262.
    let mut s = EdScalar::default();
    s.set_int64(0x100);
    s.add(&s.clone(), &one());
    let _z = s.string();
    assert_eq!(
        s.string(),
        "0101000000000000000000000000000000000000000000000000000000000000",
        "unexpected result from string(): {}",
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
    s.set_bytes(&[0, 1, 2, 3]);
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
    let mut s3 = new();
    s1.set_int64(2);
    let mut r = random::New(vec![]);
    // s2.pick(&mut r);

    let mut tmp = new();
    let s22 = tmp.add(&s2, &s2);

    assert_eq!(s3.mul(s1, s2), s22);
}

#[test]
fn test_factored_scalar() {
    // testSimple(newFactoredScalar)
}

#[test]
fn test_simple_ct_scalar() {
    test_simple(SimpleCTScalar::new)
}
