use std::io::Write;

use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    sign::error::SignatureError,
    Group, Point, Random, Scalar,
};

use sha2::{Digest, Sha512};

/// [`Suite`] represents the set of functionalities needed by the crate schnorr.
pub trait Suite: Group + Random {}

impl<T> Suite for T
where
    T: Group,
    T: Random,
{
}

/// [`sign()`] creates a signature from a `msg` and a `private key`. This
/// signature can be verified with [`verify_schnorr()`]. It's also a valid `EdDSA`
/// signature when using the `edwards25519` [`Group`].
pub fn sign<SUITE: Suite>(
    s: &SUITE,
    private: &<SUITE::POINT as Point>::SCALAR,
    msg: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    // create random secret k and public point commitment R
    let k = s.scalar().pick(&mut s.random_stream());
    let r = s.point().mul(&k, None);

    // create hash(public || R || message)
    let public = s.point().mul(private, None);
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

/// [`verify_with_checks()`] uses a `public key buffer`, a `message` and a `signature`.
/// It will return an [`Error`](SignatureError) if the signature is not valid.
/// Compared to [`verify()`], it performs additional checks around the `canonicality`
/// and ensures the public key does not have a `small order` when using `edwards25519` [`Group`].
fn verify_with_checks<GROUP: Group>(
    g: GROUP,
    pubb: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SignatureError>
where
    <GROUP::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    GROUP::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let mut r = g.point();
    let mut s = g.scalar();
    let point_size = r.marshal_size();
    let scalar_size = s.marshal_size();
    let sig_size = scalar_size + point_size;
    let sig_len = sig.len();
    if sig_len != sig_size {
        return Err(SignatureError::InvalidSignatureLength(format!(
            "schnorr: signature of invalid length {sig_len} instead of {sig_size}"
        )));
    }
    r.unmarshal_binary(&sig[..point_size])?;
    if !r.is_canonical(&sig[..point_size]) {
        return Err(SignatureError::RNotCanonical);
    }
    if r.has_small_order() {
        return Err(SignatureError::RSmallOrder);
    }
    if !g.scalar().is_canonical(&sig[point_size..]) {
        return Err(SignatureError::SignatureNotCanonical);
    }
    s.unmarshal_binary(&sig[point_size..])?;

    let mut public = g.point();
    public.unmarshal_binary(pubb)?;
    if !public.is_canonical(pubb) {
        return Err(SignatureError::PublicKeyNotCanonical);
    }
    if public.has_small_order() {
        return Err(SignatureError::PublicKeySmallOrder);
    }
    // recompute hash(public || R || msg)
    let h = hash(&g, &public, &r, msg)?;

    // compute S = g^s
    let s_p = g.point().mul(&s, None);
    // compute RAh = R + A^h
    let ah = g.point().mul(&h, Some(&public));
    let ras = g.point().add(&r, &ah);

    if !s_p.eq(&ras) {
        return Err(SignatureError::InvalidSignature(
            "reconstructed S is not equal to signature".to_owned(),
        ));
    }

    Ok(())
}

/// [`verify()`] verifies a given `Schnorr signature`. It returns an
/// [`Error`](SignatureError) if the signature is invalid.
pub fn verify<GROUP: Group>(
    g: GROUP,
    public: &GROUP::POINT,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), SignatureError>
where
    <GROUP::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    GROUP::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let p_buf = public.marshal_binary()?;
    verify_with_checks(g, &p_buf, msg, sig)
}

fn hash<GROUP: Group>(
    g: &GROUP,
    public: &GROUP::POINT,
    r: &GROUP::POINT,
    msg: &[u8],
) -> Result<<GROUP::POINT as Point>::SCALAR, SignatureError> {
    // h := sha512.New()
    let mut h = Sha512::new();
    r.marshal_to(&mut h)?;
    public.marshal_to(&mut h)?;
    h.write_all(msg)?;
    let b = h.finalize();
    Ok(g.scalar().set_bytes(b.as_slice()))
}
