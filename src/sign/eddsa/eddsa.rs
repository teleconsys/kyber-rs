// // Package eddsa implements the EdDSA signature algorithm according to
// // RFC8032.

use anyhow::{bail, Result};
use blake2::Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use crate::encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling};
use crate::group::edwards25519::constants::{PRIME_ORDER, WEAK_KEYS};
use crate::group::edwards25519::{Curve, Point as EdPoint, Scalar as EdScalar};
use crate::group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical};
use crate::{Group, Point, Scalar};

const group: Curve = Curve::new();

/// EdDSA is a structure holding the data necessary to make a series of
/// EdDSA signatures.
#[derive(Debug, Serialize, Deserialize)]
pub struct EdDSA<POINT: Point> {
    // Secret being already hashed + bit tweaked
    pub secret: POINT::SCALAR,
    // Public is the corresponding public key
    pub public: POINT,
    pub seed: Vec<u8>,
    pub prefix: Vec<u8>,
}

impl EdDSA<EdPoint> {
    /// NewEdDSA will return a freshly generated key pair to use for generating
    /// EdDSA signatures.
    pub fn new<S: crate::cipher::Stream>(stream: &mut S) -> Result<EdDSA<EdPoint>> {
        let (secret, buffer, prefix) = group.new_key_and_seed(stream)?;
        let public = group.point().mul(&secret, None);

        Ok(EdDSA::<EdPoint> {
            seed: buffer,
            prefix: prefix,
            secret: secret,
            public: public,
        })
    }
}

impl Default for EdDSA<EdPoint> {
    fn default() -> Self {
        EdDSA::<EdPoint> {
            seed: vec![],
            prefix: vec![],
            secret: EdScalar::default(),
            public: EdPoint::default(),
        }
    }
}

impl PartialEq for EdDSA<EdPoint> {
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

impl BinaryUnmarshaler for EdDSA<EdPoint> {
    /// UnmarshalBinary transforms a slice of bytes into a EdDSA signature.
    fn unmarshal_binary(&mut self, buff: &[u8]) -> Result<()> {
        if buff.len() != 64 {
            bail!("wrong length for decoding EdDSA private")
        }
        let (secret, _, prefix) = group.new_key_and_seed_with_input(&buff[..32]);

        self.seed = buff[..32].to_vec();
        self.prefix = prefix;
        self.secret = secret;
        self.public = group.point().mul(&self.secret, None);

        Ok(())
    }
}

impl BinaryMarshaler for EdDSA<EdPoint> {
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

impl EdDSA<EdPoint> {
    /// Sign will return a EdDSA signature of the message msg using Ed25519.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        let mut hash = Sha512::new();
        hash.update(self.prefix.clone());
        hash.update(msg.clone());

        // deterministic random secret and its commit
        let r = group.scalar().set_bytes(&hash.finalize_reset());
        let r_point = group.point().mul(&r, None);

        // challenge
        // H( R || Public || Msg)
        let r_buff = r_point.marshal_binary()?;
        let a_buff = self.public.marshal_binary()?;

        hash.update(r_buff.clone());
        hash.update(a_buff);
        hash.update(msg);

        let h = group.scalar().set_bytes(&hash.finalize());

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

    // type scalarCanCheckCanonical interface {
    // 	IsCanonical(b []byte) bool
    // }

    if !group.scalar().is_canonical(&sig[32..]) {
        bail!("signature is not canonical")
    }

    // type pointCanCheckCanonicalAndSmallOrder interface {
    // 	HasSmallOrder() bool
    // 	IsCanonical(b []byte) bool
    // }

    let mut r = group.point();
    if !r.is_canonical(&sig[..32]) {
        bail!("R is not canonical")
    }
    r.unmarshal_binary(&sig[..32])?;
    // if err := R.UnmarshalBinary(sig[:32]); err != nil {
    // 	return fmt.Errorf("got R invalid point: %s", err)
    // }

    if r.has_small_order() {
        bail!("R has small order")
    }

    let mut s = group.scalar();
    s.unmarshal_binary(&sig[32..]);
    // if err := s.UnmarshalBinary(sig[32:]); err != nil {
    // 	return fmt.Errorf("schnorr: s invalid scalar %s", err)
    // }

    let mut public = group.point();
    if !public.is_canonical(public_key) {
        bail!("public key is not canonical")
    }
    public.unmarshal_binary(public_key)?;
    // if err := public.UnmarshalBinary(public_key); err != nil {
    // 	return fmt.Errorf("invalid public key: %s", err)
    // }
    if public.has_small_order() {
        bail!("public key has small order")
    }

    // reconstruct h = H(R || Public || Msg)
    let mut hash = Sha512::new();
    hash.update(&sig[..32]);
    hash.update(public_key);
    hash.update(msg);

    let h = group.scalar().set_bytes(&hash.finalize());
    // reconstruct S == k*A + R
    let s = group.point().mul(&s, None);
    let ha = group.point().mul(&h, Some(&public));
    let rha = group.point().add(&r, &ha);

    if !rha.equal(&s) {
        bail!("reconstructed S is not equal to signature")
    }
    Ok(())
}

/// Verify uses a public key, a message and a signature. It will return nil if
/// sig is a valid signature for msg created by key public, or an error otherwise.
pub fn verify<POINT: Point>(public: &POINT, msg: &[u8], sig: &[u8]) -> Result<()> {
    let p_buf = public.marshal_binary()?;
    // if err != nil {
    // 	return fmt.Errorf("error unmarshalling public key: %s", err)
    // }
    return verify_with_checks(&p_buf, msg, sig);
}
