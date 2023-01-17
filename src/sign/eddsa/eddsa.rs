// Package eddsa implements the EdDSA signature algorithm according to
// RFC8032.

use anyhow::{bail, Result};
use digest::Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use crate::encoding::{BinaryMarshaler, BinaryUnmarshaler};

use crate::group::edwards25519::{Curve, Point as EdPoint, Scalar as EdScalar};
use crate::group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical};
use crate::util::key::Pair;
use crate::{Group, Point, Scalar};

/// EdDSA is a structure holding the data necessary to make a series of
/// EdDSA signatures.
#[derive(Debug, Serialize, Deserialize)]
pub struct EdDSA<GROUP: Group> {
    // Secret being already hashed + bit tweaked
    pub secret: <GROUP::POINT as Point>::SCALAR,
    // Public is the corresponding public key
    pub public: GROUP::POINT,
    pub seed: Vec<u8>,
    pub prefix: Vec<u8>,
}

const GROUP: Curve = Curve::new();

impl EdDSA<Curve> {
    /// NewEdDSA will return a freshly generated key pair to use for generating
    /// EdDSA signatures.
    pub fn new<S: crate::cipher::Stream>(stream: &mut S) -> Result<EdDSA<Curve>> {
        let (secret, buffer, prefix) = GROUP.new_key_and_seed(stream)?;
        let public = GROUP.point().mul(&secret, None);

        Ok(EdDSA::<Curve> {
            seed: buffer,
            prefix,
            secret,
            public,
        })
    }
}

impl Default for EdDSA<Curve> {
    fn default() -> Self {
        EdDSA::<Curve> {
            seed: vec![],
            prefix: vec![],
            secret: EdScalar::default(),
            public: EdPoint::default(),
        }
    }
}

impl PartialEq for EdDSA<Curve> {
    fn eq(&self, other: &Self) -> bool {
        if self.seed != other.seed {
            return false;
        }
        if self.prefix != other.prefix {
            return false;
        }
        if self.secret != other.secret {
            return false;
        }
        if self.public != other.public {
            return false;
        }
        true
    }
}

impl BinaryUnmarshaler for EdDSA<Curve> {
    /// UnmarshalBinary transforms a slice of bytes into a EdDSA signature.
    fn unmarshal_binary(&mut self, buff: &[u8]) -> Result<()> {
        if buff.len() != 64 {
            bail!("wrong length for decoding EdDSA private")
        }
        let (secret, _, prefix) = GROUP.new_key_and_seed_with_input(&buff[..32]);

        self.seed = buff[..32].to_vec();
        self.prefix = prefix;
        self.secret = secret;
        self.public = GROUP.point().mul(&self.secret, None);

        Ok(())
    }
}

impl BinaryMarshaler for EdDSA<Curve> {
    /// MarshalBinary will return the representation used by the reference
    /// implementation of SUPERCOP ref10, which is "seed || Public".
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let p_buff = self.public.marshal_binary()?;

        let mut eddsa = [0u8; 64];
        eddsa[..32].copy_from_slice(&self.seed);
        eddsa[32..].copy_from_slice(&p_buff);
        Ok(eddsa.to_vec())
    }
}

impl From<Pair<EdPoint>> for EdDSA<Curve> {
    fn from(pair: Pair<EdPoint>) -> Self {
        let g = Curve::default();
        Self {
            secret: g.scalar().set(&pair.private),
            public: g.point().set(&pair.public),
            seed: vec![],
            prefix: vec![],
        }
    }
}

impl EdDSA<Curve> {
    /// Sign will return a EdDSA signature of the message msg using Ed25519.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        let mut hash = Sha512::new();
        hash.update(self.prefix.clone());
        hash.update(msg);

        // deterministic random secret and its commit
        let r = GROUP.scalar().set_bytes(&hash.finalize_reset());
        let r_point = GROUP.point().mul(&r, None);

        // challenge
        // H( R || Public || Msg)
        let r_buff = r_point.marshal_binary()?;
        let a_buff = self.public.marshal_binary()?;

        hash.update(r_buff.clone());
        hash.update(a_buff);
        hash.update(msg);

        let h = GROUP.scalar().set_bytes(&hash.finalize());

        // response
        // s = r + h * s
        let s = r + self.secret.clone() * h;

        let s_buff = s.marshal_binary()?;

        // return R || s
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_buff);
        sig[32..].copy_from_slice(&s_buff);

        Ok(sig)
    }
}

/// verify_with_checks uses a public key buffer, a message and a signature.
/// It will return nil if sig is a valid signature for msg created by
/// key public, or an error otherwise. Compared to `Verify`, it performs
/// additional checks around the canonicality and ensures the public key
/// does not have a small order.
pub fn verify_with_checks(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != 64 {
        bail!("signature length invalid, expect 64 but got {}", sig.len())
    }

    if !GROUP.scalar().is_canonical(&sig[32..]) {
        bail!("signature is not canonical")
    }

    let mut r = GROUP.point();
    if !r.is_canonical(&sig[..32]) {
        bail!("R is not canonical")
    }
    r.unmarshal_binary(&sig[..32])?;

    if r.has_small_order() {
        bail!("R has small order")
    }

    let mut s = GROUP.scalar();
    s.unmarshal_binary(&sig[32..])?;

    let mut public = GROUP.point();
    if !public.is_canonical(public_key) {
        bail!("public key is not canonical")
    }
    public.unmarshal_binary(public_key)?;

    if public.has_small_order() {
        bail!("public key has small order")
    }

    // reconstruct h = H(R || Public || Msg)
    let mut hash = Sha512::new();
    hash.update(&sig[..32]);
    hash.update(public_key);
    hash.update(msg);

    let h = GROUP.scalar().set_bytes(&hash.finalize());
    // reconstruct S == k*A + R
    let s = GROUP.point().mul(&s, None);
    let ha = GROUP.point().mul(&h, Some(&public));
    let rha = GROUP.point().add(&r, &ha);

    if !rha.equal(&s) {
        bail!("reconstructed S is not equal to signature")
    }
    Ok(())
}

/// Verify uses a public key, a message and a signature. It will return nil if
/// sig is a valid signature for msg created by key public, or an error otherwise.
pub fn verify<POINT: Point>(public: &POINT, msg: &[u8], sig: &[u8]) -> Result<()> {
    let p_buf = public.marshal_binary()?;
    verify_with_checks(&p_buf, msg, sig)
}
