// // Package eddsa implements the EdDSA signature algorithm according to
// // RFC8032.
// package eddsa

// import (
// 	"crypto/cipher"
// 	"crypto/sha512"
// 	"errors"
// 	"fmt"

// 	"go.dedis.ch/kyber/v3"
// 	"go.dedis.ch/kyber/v3/group/edwards25519"
// )

// var group = new(edwards25519.Curve)



use anyhow::{Result, bail};
use blake2::Digest;
use sha2::Sha512;

use crate::encoding::BinaryMarshaler;
use crate::{Group, Point, Scalar, group::edwards25519::Curve};
use crate::group::edwards25519::{Point as EdPoint, Scalar as EdScalar};

fn new_group() -> Curve {
    Curve::default()
}

/// EdDSA is a structure holding the data necessary to make a series of
/// EdDSA signatures.
#[derive(Debug)]
pub struct EdDSA<POINT, SCALAR>
where
    POINT: Point<SCALAR>,
    SCALAR: Scalar,
{
    // Secret being already hashed + bit tweaked
    pub secret: SCALAR,
    // Public is the corresponding public key
    pub public: POINT,

    pub seed: Vec<u8>,
    pub prefix: Vec<u8>,
}

/// NewEdDSA will return a freshly generated key pair to use for generating
/// EdDSA signatures.
pub fn new_eddsa<S: crate::cipher::Stream>(stream: &mut S) -> Result<EdDSA<EdPoint, EdScalar>> {
    let group = new_group();

    let (secret, buffer, prefix ) = group.new_key_and_seed(stream)?;
	let public = group.point().mul(&secret, None);

	Ok(EdDSA::<EdPoint, EdScalar>{
        seed:   buffer,
		prefix: prefix,
		secret: secret,
		public: public,
    })
}

impl Default for EdDSA<EdPoint, EdScalar> {
    fn default() -> Self {
        EdDSA::<EdPoint, EdScalar>{
            seed:   vec![],
            prefix: vec![],
            secret: EdScalar::default(),
            public: EdPoint::default(),
        }
    }

}

impl PartialEq for EdDSA<EdPoint, EdScalar> {
    fn eq(&self, other: &Self) -> bool {
        if self.seed != other.seed {
            return false
        }
        if self.prefix != other.prefix {
            return false
        }
        if self.secret != other.secret {
            return false
        }
        if self.public != other.public {
            return false
        }
        true
    }
}

impl EdDSA<EdPoint, EdScalar> {

    /// MarshalBinary will return the representation used by the reference
    /// implementation of SUPERCOP ref10, which is "seed || Public".
    pub fn marshal_binary(&self) -> Result<[u8; 64]> {
        let p_buff = self.public.marshal_binary()?;

        let mut eddsa = [0u8;64];
        eddsa[..32].copy_from_slice(&self.seed);
        eddsa[32..].copy_from_slice(&p_buff);
        Ok(eddsa)
    }

    /// UnmarshalBinary transforms a slice of bytes into a EdDSA signature.
    pub fn unmarshal_binary(&mut self, buff: &[u8]) -> Result<()> {
        if buff.len() != 64 {
            bail!("wrong length for decoding EdDSA private")
        }
        let group = new_group();

    	let (secret, _, prefix) = group.new_key_and_seed_with_input(&buff[..32]);

    	self.seed = buff[..32].to_vec();
    	self.prefix = prefix;
    	self.secret = secret;
    	self.public = group.point().mul(&self.secret, None);

        Ok(())
    }

    // Sign will return a EdDSA signature of the message msg using Ed25519.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8;64]> {
        let group = new_group();

        let mut hash = Sha512::new();
        hash.update(self.prefix.clone());
        hash.update(msg.clone());


        // deterministic random secret and its commit
        let r = group.scalar().set_bytes(&hash.finalize_reset());
        let R = group.point().mul(&r, None);

        // challenge
        // H( R || Public || Msg)
        let R_buff = R.marshal_binary()?;
        let A_buff = self.public.marshal_binary()?;

        hash.update(R_buff.clone());
        hash.update(A_buff);
        hash.update(msg);

        let h = group.scalar().set_bytes(&hash.finalize());

        // response
        // s = r + h * s
        let s = r + self.secret.clone() * h; 

        let s_buff = s.marshal_binary()?;

        // return R || s
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&R_buff);
        sig[32..].copy_from_slice(&s_buff);

        Ok(sig)
    }
    
}


// // VerifyWithChecks uses a public key buffer, a message and a signature.
// // It will return nil if sig is a valid signature for msg created by
// // key public, or an error otherwise. Compared to `Verify`, it performs
// // additional checks around the canonicality and ensures the public key
// // does not have a small order.
// func VerifyWithChecks(pub, msg, sig []byte) error {
// 	if len(sig) != 64 {
// 		return fmt.Errorf("signature length invalid, expect 64 but got %v", len(sig))
// 	}

// 	type scalarCanCheckCanonical interface {
// 		IsCanonical(b []byte) bool
// 	}

// 	if !group.Scalar().(scalarCanCheckCanonical).IsCanonical(sig[32:]) {
// 		return fmt.Errorf("signature is not canonical")
// 	}

// 	type pointCanCheckCanonicalAndSmallOrder interface {
// 		HasSmallOrder() bool
// 		IsCanonical(b []byte) bool
// 	}

// 	R := group.Point()
// 	if !R.(pointCanCheckCanonicalAndSmallOrder).IsCanonical(sig[:32]) {
// 		return fmt.Errorf("R is not canonical")
// 	}
// 	if err := R.UnmarshalBinary(sig[:32]); err != nil {
// 		return fmt.Errorf("got R invalid point: %s", err)
// 	}
// 	if R.(pointCanCheckCanonicalAndSmallOrder).HasSmallOrder() {
// 		return fmt.Errorf("R has small order")
// 	}

// 	s := group.Scalar()
// 	if err := s.UnmarshalBinary(sig[32:]); err != nil {
// 		return fmt.Errorf("schnorr: s invalid scalar %s", err)
// 	}

// 	public := group.Point()
// 	if !public.(pointCanCheckCanonicalAndSmallOrder).IsCanonical(pub) {
// 		return fmt.Errorf("public key is not canonical")
// 	}
// 	if err := public.UnmarshalBinary(pub); err != nil {
// 		return fmt.Errorf("invalid public key: %s", err)
// 	}
// 	if public.(pointCanCheckCanonicalAndSmallOrder).HasSmallOrder() {
// 		return fmt.Errorf("public key has small order")
// 	}

// 	// reconstruct h = H(R || Public || Msg)
// 	hash := sha512.New()
// 	_, _ = hash.Write(sig[:32])
// 	_, _ = hash.Write(pub)
// 	_, _ = hash.Write(msg)

// 	h := group.Scalar().SetBytes(hash.Sum(nil))
// 	// reconstruct S == k*A + R
// 	S := group.Point().Mul(s, nil)
// 	hA := group.Point().Mul(h, public)
// 	RhA := group.Point().Add(R, hA)

// 	if !RhA.Equal(S) {
// 		return errors.New("reconstructed S is not equal to signature")
// 	}
// 	return nil
// }

// // Verify uses a public key, a message and a signature. It will return nil if
// // sig is a valid signature for msg created by key public, or an error otherwise.
// func Verify(public kyber.Point, msg, sig []byte) error {
// 	PBuf, err := public.MarshalBinary()
// 	if err != nil {
// 		return fmt.Errorf("error unmarshalling public key: %s", err)
// 	}
// 	return VerifyWithChecks(PBuf, msg, sig)
// }
