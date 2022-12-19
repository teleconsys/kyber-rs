use std::io::Write;

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
pub fn sign<SUITE: Suite>(
    s: &SUITE,
    private: &<SUITE::POINT as Point>::SCALAR,
    msg: &[u8],
) -> Result<Vec<u8>> {
    // create random secret k and public point commitment R
    let k = s.scalar().pick(&mut s.random_stream());
    let r = s.point().mul(&k, None);

    // create hash(public || R || message)
    let public = s.point().mul(&private, None);
    let h = hash(s, &public, &r, msg)?;

    // compute response s = k + x*h
    let xh = private.clone() * h;
    let s = k + xh;

    // return R || s
    let mut b = vec![];
    r.marshal_to(&mut b)?;
    s.marshal_to(&mut b)?;
    Ok(b)
}

/// VerifyWithChecks uses a public key buffer, a message and a signature.
/// It will return nil if sig is a valid signature for msg created by
/// key public, or an error otherwise. Compared to `Verify`, it performs
/// additional checks around the canonicality and ensures the public key
/// does not have a small order when using `edwards25519` group.
fn verify_with_checks<GROUP: Group>(g: GROUP, pubb: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>
where
    <GROUP::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    GROUP::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let mut r = g.point();
    let mut s = g.scalar();
    let point_size = r.marshal_size();
    let scalar_size = s.marshal_size();
    let sig_size = scalar_size + point_size;
    if sig.len() != sig_size {
        bail!(
            "schnorr: signature of invalid length {} instead of {}",
            sig.len(),
            sig_size
        );
    }
    r.unmarshal_binary(&sig[..point_size])?;
    if !r.is_canonical(&sig[..point_size]) {
        bail!("R is not canonical");
    }
    if r.has_small_order() {
        bail!("R has small order");
    }
    if !g.scalar().is_canonical(&sig[point_size..]) {
        bail!("signature is not canonical");
    }
    s.unmarshal_binary(&sig[point_size..])?;

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
    let h = hash(&g, &public, &r, msg)?;

    // compute S = g^s
    let s_caps = g.point().mul(&s, None);
    // compute RAh = R + A^h
    let ah = g.point().mul(&h, Some(&public));
    let ras = g.point().add(&r, &ah);

    if !s_caps.equal(&ras) {
        bail!("schnorr: invalid signature");
    }

    Ok(())
}

/// Verify verifies a given Schnorr signature. It returns nil iff the
/// given signature is valid.
pub fn verify<GROUP: Group>(g: GROUP, public: &GROUP::POINT, msg: &[u8], sig: &[u8]) -> Result<()>
where
    <GROUP::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    GROUP::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let p_buf = public
        .marshal_binary()
        .map_err(|op| Error::msg(format!("error unmarshalling public key: {}", op)))?;
    return verify_with_checks(g, &p_buf, msg, sig);
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
