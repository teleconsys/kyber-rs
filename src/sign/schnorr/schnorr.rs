use std::io::{Read, Write};

use crate::{Group, Point, Random, Scalar};
use anyhow::{bail, Error, Result};
use sha2::{Digest, Sha512};

/// Suite represents the set of functionalities needed by the package schnorr.
pub trait Suite<SCALAR, POINT>: Group<SCALAR, POINT> + Random
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
{
}

impl<T, SCALAR, POINT> Suite<SCALAR, POINT> for T
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    T: Group<SCALAR, POINT>,
    T: Random,
{
}

/// Sign creates a Sign signature from a msg and a private key. This
/// signature can be verified with VerifySchnorr. It's also a valid EdDSA
/// signature when using the edwards25519 Group.
pub fn Sign<SUITE: Suite<SCALAR, POINT>, SCALAR: Scalar, POINT: Point<SCALAR>>(
    s: SUITE,
    private: SCALAR,
    msg: &[u8],
) -> Result<Vec<u8>> {
    // var g kyber.Group = s
    // create random secret k and public point commitment R
    let k = s.scalar().pick(&mut s.random_stream());
    let R = s.point().mul(&k, None);

    // create hash(public || R || message)
    let public = s.point().mul(&private, None);
    let h = hash(s, public, R.clone(), msg)?;

    // compute response s = k + x*h
    let xh = private * h;
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
fn VerifyWithChecks<SCALAR, POINT, GROUP>(
    g: GROUP,
    public: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<()>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    // type scalarCanCheckCanonical interface {
    // 	IsCanonical(b []byte) bool
    // }

    // type pointCanCheckCanonicalAndSmallOrder interface {
    // 	HasSmallOrder() bool
    // 	IsCanonical(b []byte) bool
    // }

    let mut R = g.point();
    let s = g.scalar();
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
    // if p, ok := R.(pointCanCheckCanonicalAndSmallOrder); ok {
    // 	if !p.IsCanonical(sig[:pointSize]) {
    // 		return fmt.Errorf("R is not canonical")
    // 	}
    // 	if p.HasSmallOrder() {
    // 		return fmt.Errorf("R has small order")
    // 	}
    // }
    // if s, ok := g.Scalar().(scalarCanCheckCanonical); ok && !s.IsCanonical(sig[pointSize:]) {
    // 	return fmt.Errorf("signature is not canonical")
    // }
    // if err := s.UnmarshalBinary(sig[pointSize:]); err != nil {
    // 	return err
    // }

    // public := g.Point()
    // err := public.UnmarshalBinary(pub)
    // if err != nil {
    // 	return fmt.Errorf("schnorr: error unmarshalling public key")
    // }
    // if p, ok := public.(pointCanCheckCanonicalAndSmallOrder); ok {
    // 	if !p.IsCanonical(pub) {
    // 		return fmt.Errorf("public key is not canonical")
    // 	}
    // 	if p.HasSmallOrder() {
    // 		return fmt.Errorf("public key has small order")
    // 	}
    // }
    // // recompute hash(public || R || msg)
    // h, err := hash(g, public, R, msg)
    // if err != nil {
    // 	return err
    // }

    // // compute S = g^s
    // S := g.Point().Mul(s, nil)
    // // compute RAh = R + A^h
    // Ah := g.Point().Mul(h, public)
    // RAs := g.Point().Add(R, Ah)

    // if !S.Equal(RAs) {
    // 	return errors.New("schnorr: invalid signature")
    // }

    // return nil
    todo!()
}

/// Verify verifies a given Schnorr signature. It returns nil iff the
/// given signature is valid.
pub fn Verify<SCALAR, POINT, GROUP>(g: GROUP, public: POINT, msg: &[u8], sig: &[u8]) -> Result<()>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    let p_buf = public
        .marshal_binary()
        .map_err(|op| Error::msg(format!("error unmarshalling public key: {}", op)))?;
    return VerifyWithChecks(g, &p_buf, msg, sig);
}

fn hash<SCALAR, POINT, GROUP>(g: GROUP, public: POINT, r: POINT, msg: &[u8]) -> Result<SCALAR>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    // h := sha512.New()
    let mut h = Sha512::new();
    r.marshal_to(&mut h)?;
    public.marshal_to(&mut h)?;
    h.write_all(msg)?;
    let b = h.finalize();
    Ok(g.scalar().set_bytes(b.as_slice()))
}
