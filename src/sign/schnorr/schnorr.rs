use std::io::{Read, Write};

use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    Group, Point, Random, Scalar,
};
use anyhow::{bail, Context, Error, Result};
use sha2::{Digest, Sha512};

/// Suite represents the set of functionalities needed by the package schnorr.
pub trait Suite: Group + Random {}

impl<T> Suite for T
where
    T: Group,
    T: Random,
{
}

/// Sign creates a Sign signature from a msg and a private key. This
/// signature can be verified with VerifySchnorr. It's also a valid EdDSA
/// signature when using the edwards25519 Group.
pub fn Sign<SUITE: Suite>(
    s: &SUITE,
    private: &<SUITE::POINT as Point>::SCALAR,
    msg: &[u8],
) -> Result<Vec<u8>> {
    // create random secret k and public point commitment R
    let k = s.scalar().pick(&mut s.random_stream());
    let R = s.point().mul(&k, None);

    // create hash(public || R || message)
    let public = s.point().mul(&private, None);
    let h = hash(s, &public, &R, msg)?;

    // compute response s = k + x*h
    let xh = private.clone() * h;
    let S = k + xh;

    // return R || s
    let mut b = vec![];
    R.marshal_to(&mut b)?;
    S.marshal_to(&mut b)?;
    Ok(b)
}

/// VerifyWithChecks uses a public key buffer, a message and a signature.
/// It will return nil if sig is a valid signature for msg created by
/// key public, or an error otherwise. Compared to `Verify`, it performs
/// additional checks around the canonicality and ensures the public key
/// does not have a small order when using `edwards25519` group.
fn VerifyWithChecks<GROUP>(g: GROUP, pubb: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>
where
    <GROUP::POINT as Point>::SCALAR: Scalar + ScalarCanCheckCanonical,
    GROUP::POINT: Point + PointCanCheckCanonicalAndSmallOrder,
    GROUP: Group,
{
    let mut R = g.point();
    let mut s = g.scalar();
    let pointSize = R.marshal_size();
    let scalarSize = s.marshal_size();
    let sigSize = scalarSize + pointSize;
    if sig.len() != sigSize {
        bail!(
            "schnorr: signature of invalid length {} instead of {}",
            sig.len(),
            sigSize
        );
    }
    R.unmarshal_binary(&sig[..pointSize])?;
    if !R.is_canonical(&sig[..pointSize]) {
        bail!("R is not canonical");
    }
    if R.has_small_order() {
        bail!("R has small order");
    }
    if !g.scalar().is_canonical(&sig[pointSize..]) {
        bail!("signature is not canonical");
    }
    s.unmarshal_binary(&sig[pointSize..])?;

    let mut public = g.point();
    public
        .unmarshal_binary(pubb)
        .context("schnorr: error unmarshalling public key")?;
    if !public.is_canonical(pubb) {
        bail!("public key is not canonical");
    }
    if public.has_small_order() {
        bail!("public key has small order");
    }
    // recompute hash(public || R || msg)
    let h = hash(&g, &public, &R, msg)?;

    // compute S = g^s
    let S = g.point().mul(&s, None);
    // compute RAh = R + A^h
    let Ah = g.point().mul(&h, Some(&public));
    let RAs = g.point().add(&R, &Ah);

    if !S.equal(&RAs) {
        bail!("schnorr: invalid signature");
    }

    Ok(())
}

/// Verify verifies a given Schnorr signature. It returns nil iff the
/// given signature is valid.
pub fn Verify<GROUP: Group>(g: GROUP, public: &GROUP::POINT, msg: &[u8], sig: &[u8]) -> Result<()>
where
    <GROUP::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    GROUP::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let p_buf = public
        .marshal_binary()
        .map_err(|op| Error::msg(format!("error unmarshalling public key: {}", op)))?;
    return VerifyWithChecks(g, &p_buf, msg, sig);
}

fn hash<GROUP: Group>(
    g: &GROUP,
    public: &GROUP::POINT,
    r: &GROUP::POINT,
    msg: &[u8],
) -> Result<<GROUP::POINT as Point>::SCALAR> {
    // h := sha512.New()
    let mut h = Sha512::new();
    r.marshal_to(&mut h)?;
    public.marshal_to(&mut h)?;
    h.write_all(msg)?;
    let b = h.finalize();
    Ok(g.scalar().set_bytes(b.as_slice()))
}
