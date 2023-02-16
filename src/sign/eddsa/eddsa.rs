// Crate eddsa implements the EdDSA signature algorithm according to
// RFC8032.

use digest::Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use crate::encoding::{BinaryMarshaler, BinaryUnmarshaler, MarshallingError};

use crate::group::edwards25519::{Curve, Point as EdPoint, Scalar as EdScalar};
use crate::group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical};
use crate::sign::error::SignatureError;
use crate::util::key::{KeyError, Pair};
use crate::{Group, Point, Scalar};

/// [`EdDSA`] is a structure holding the data necessary to make a series of
/// `EdDSA signatures`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EdDSA<GROUP: Group> {
    /// `secret` being already hashed + bit tweaked
    pub secret: <GROUP::POINT as Point>::SCALAR,
    /// `public` is the corresponding public key
    pub public: GROUP::POINT,
    pub seed: Vec<u8>,
    pub prefix: Vec<u8>,
}

const GROUP: Curve = Curve::new();

impl EdDSA<Curve> {
    /// [`new()`] will return a freshly generated key pair to use for generating
    /// EdDSA signatures.
    pub fn new<S: crate::cipher::Stream>(stream: &mut S) -> Result<EdDSA<Curve>, KeyError> {
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
    /// [`unmarshal_binary()`] transforms a slice of bytes into a EdDSA signature.
    fn unmarshal_binary(&mut self, buff: &[u8]) -> Result<(), MarshallingError> {
        if buff.len() != 64 {
            return Err(MarshallingError::InvalidInput(
                "wrong length for decoding EdDSA private".to_owned(),
            ));
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
    /// [`marshal_binary()`] will return the representation used by the reference
    /// implementation of `SUPERCOP ref10`, which is `"seed || Public"`.
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError> {
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
    /// [`sign()`] will return a EdDSA signature of the message msg using Ed25519.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignatureError> {
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

/// [`verify_with_checks()`] uses a `public key buffer`, a `message` and a `signature`.
/// It will return an [`Error`](SignatureError) if the signature is not valid.
/// Compared to [`verify()`], it performs additional checks around the `canonicality`
/// and ensures the public key does not have a `small order`.
pub fn verify_with_checks(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    let sig_len = sig.len();
    if sig_len != 64 {
        return Err(SignatureError::InvalidSignatureLength(format!(
            "expect 64 got {sig_len}"
        )));
    }

    if !GROUP.scalar().is_canonical(&sig[32..]) {
        return Err(SignatureError::SignatureNotCanonical);
    }

    let mut r = GROUP.point();
    if !r.is_canonical(&sig[..32]) {
        return Err(SignatureError::RNotCanonical);
    }
    r.unmarshal_binary(&sig[..32])?;

    if r.has_small_order() {
        return Err(SignatureError::RSmallOrder);
    }

    let mut s = GROUP.scalar();
    s.unmarshal_binary(&sig[32..])?;

    let mut public = GROUP.point();
    if !public.is_canonical(public_key) {
        return Err(SignatureError::PublicKeyNotCanonical);
    }
    public.unmarshal_binary(public_key)?;

    if public.has_small_order() {
        return Err(SignatureError::PublicKeySmallOrder);
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

    if !rha.eq(&s) {
        return Err(SignatureError::InvalidSignature(
            "reconstructed S is not equal to signature".to_owned(),
        ));
    }
    Ok(())
}

/// [`verify()`] verifies a given `Schnorr signature`. It returns an
/// [`Error`](SignatureError) if the signature is invalid.
pub fn verify<POINT: Point>(public: &POINT, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    let p_buf = public.marshal_binary()?;
    verify_with_checks(&p_buf, msg, sig)
}
