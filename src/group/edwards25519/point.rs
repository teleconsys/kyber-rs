// var marshalPointID = [8]byte{'e', 'd', '.', 'p', 'o', 'i', 'n', 't'}
use anyhow::{bail, Error, Result};
use serde::{Deserialize, Serialize};

use crate::{
    cipher::Stream,
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::{self, internal::marshalling, PointCanCheckCanonicalAndSmallOrder},
};

use super::{
    constants::{BASEEXT, COFACTOR_SCALAR, NULL_POINT, PRIME_ORDER_SCALAR, WEAK_KEYS},
    ge::{
        ge_scalar_mult, ge_scalar_mult_base, CachedGroupElement, CompletedGroupElement,
        ExtendedGroupElement,
    },
    ge_mult_vartime::ge_scalar_mult_vartime,
    Scalar,
};

const MARSHAL_POINT_ID: [u8; 8] = [b'e', b'd', b'.', b'p', b'o', b'i', b'n', b't'];

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Point {
    ge: ExtendedGroupElement,
    var_time: bool,
}

impl BinaryMarshaler for Point {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut b = [0_u8; 32];
        self.ge.to_bytes(&mut b);
        Ok(b.to_vec())
    }
}
impl BinaryUnmarshaler for Point {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
        if !self.ge.from_bytes(data) {
            return Err(Error::msg("invalid Ed25519 curve point"));
        }
        Ok(())
    }
}

impl Marshaling for Point {
    fn marshal_to(&self, w: &mut impl std::io::Write) -> Result<()> {
        marshalling::point_marshal_to(self, w)
    }

    fn marshal_size(&self) -> usize {
        32
    }
}

impl PartialEq for Point {
    /// Equality test for two Points on the same curve
    fn eq(&self, other: &Self) -> bool {
        let (mut b1, mut b2) = ([0u8; 32], [0u8; 32]);
        self.ge.to_bytes(&mut b1);
        other.ge.to_bytes(&mut b2);

        for i in 0..b1.len() {
            if b1[i] != b2[i] {
                return false;
            }
        }
        true
    }
}

impl group::Point for Point {
    type SCALAR = Scalar;

    /// Equality test for two Points on the same curve
    fn equal(&self, p2: &Self) -> bool {
        let mut b1 = [0_u8; 32];
        let mut b2 = [0_u8; 32];
        self.ge.to_bytes(&mut b1);
        p2.ge.to_bytes(&mut b2);
        for i in 0..b1.len() {
            if b1[i] != b2[i] {
                return false;
            }
        }
        true
    }

    /// Set to the neutral element, which is (0,1) for twisted Edwards curves.
    fn null(mut self) -> Self {
        self.ge.zero();
        self
    }

    /// Set to the standard base point for this curve
    fn base(mut self) -> Self {
        self.ge = BASEEXT;
        self
    }

    fn pick<S: crate::cipher::Stream>(self, rand: &mut S) -> Self {
        self.embed(None, rand)
    }

    fn set(&mut self, p: Self) -> Self {
        self.ge = p.ge;
        self.clone()
    }

    fn embed_len(&self) -> usize {
        // Reserve the most-significant 8 bits for pseudo-randomness.
        // Reserve the least-significant 8 bits for embedded data length.
        // (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
        (255 - 8 - 8) / 8
    }

    fn embed<S: Stream>(mut self, data: Option<&[u8]>, rand: &mut S) -> Self {
        // How many bytes to embed?
        let mut dl = self.embed_len();
        let data_len = match data {
            Some(d) => d.len(),
            None => 0,
        };
        if dl > data_len {
            dl = data_len;
        }

        loop {
            // Pick a random point, with optional embedded data
            let mut b = [0_u8; 32];
            rand.xor_key_stream(&mut b, &[0_u8; 32]).unwrap();
            if let Some(d) = data {
                // Encode length in low 8 bits
                b[0] = dl as u8;
                // Copy in data to embed
                b[1..1 + dl].copy_from_slice(&d[0..dl]);
            }
            // Try to decode
            if !self.ge.from_bytes(&b) {
                // invalid point, retry
                continue;
            }

            // If we're using the full group,
            // we just need any point on the curve, so we're done.
            //		if c.full {
            //			return P,data[dl:]
            //		}

            // We're using the prime-order subgroup,
            // so we need to make sure the point is in that subencoding.
            // If we're not trying to embed data,
            // we can convert our point into one in the subgroup
            // simply by multiplying it by the cofactor.
            if data.is_none() {
                // multiply by cofactor
                let old_self = &self.clone();
                self = self.mul(&COFACTOR_SCALAR, Some(old_self));
                if self.equal(&NULL_POINT) {
                    // unlucky; try again
                    continue;
                }
                // success
                return self;
            }

            // Since we need the point's y-coordinate to hold our data,
            // we must simply check if the point is in the subgroup
            // and retry point generation until it is.
            let mut q = Point::default();
            q = q.mul(&PRIME_ORDER_SCALAR, Some(&self));
            if q.equal(&NULL_POINT) {
                return self; // success
            }
            // Keep trying...
        }
    }

    fn data(&self) -> anyhow::Result<Vec<u8>> {
        let mut b = [0u8; 32];
        self.ge.to_bytes(&mut b);
        let dl = b[0] as usize; // extract length byte
        if dl > self.embed_len() {
            bail!("invalid embedded data length");
        }
        Ok(b[1..1 + dl].to_vec())
    }

    fn add(mut self, p1: &Self, p2: &Self) -> Self {
        let mut t2 = CachedGroupElement::default();
        let mut r = CompletedGroupElement::default();

        p2.ge.to_cached(&mut t2);
        r.add(&p1.ge, &t2);
        r.to_extended(&mut self.ge);

        self
    }

    fn sub(mut self, p1: &Self, p2: &Self) -> Self {
        let mut t2 = CachedGroupElement::default();
        let mut r = CompletedGroupElement::default();

        p2.ge.to_cached(&mut t2);
        r.sub(&p1.ge, &t2);
        r.to_extended(&mut self.ge);

        self
    }

    fn neg(&mut self, a: &Self) -> Self {
        self.ge.neg(&a.ge);
        self.clone()
    }

    /// Mul multiplies point p by scalar s using the repeated doubling method.
    fn mul(mut self, s: &Scalar, p: Option<&Self>) -> Self {
        let mut a = s.v;

        match p {
            None => {
                ge_scalar_mult_base(&mut self.ge, &mut a);
            }
            Some(a_caps) => {
                if self.var_time {
                    ge_scalar_mult_vartime(&mut self.ge, &mut a, &mut a_caps.clone().ge);
                } else {
                    ge_scalar_mult(&mut self.ge, &mut a, &mut a_caps.clone().ge);
                }
            }
        }

        self
    }
}

impl ToString for Point {
    fn to_string(&self) -> String {
        self.string()
    }
}

impl PointCanCheckCanonicalAndSmallOrder for Point {
    /// HasSmallOrder determines whether the group element has small order
    ///
    /// Provides resilience against malicious key substitution attacks (M-S-UEO)
    /// and message bound security (MSB) even for malicious keys
    /// See paper https://eprint.iacr.org/2020/823.pdf for definitions and theorems
    ///
    /// This is the same code as in
    /// https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1170
    fn has_small_order(&self) -> bool {
        let s = match self.marshal_binary() {
            Ok(v) => v,
            Err(_) => return false,
        };

        let mut c = [0u8; 5];

        (0..31).for_each(|j| {
            for i in 0..5 {
                c[i] |= s[j] ^ WEAK_KEYS[i][j];
            }
        });
        for i in 0..5 {
            c[i] |= (s[31] & 0x7f) ^ WEAK_KEYS[i][31];
        }

        // Constant time verification if one or more of the c's are zero
        let mut k = 0;
        (0..5).for_each(|i| {
            k |= (c[i] as u16) - 1;
        });

        (k >> 8) & 1 > 0
    }

    /// IsCanonical determines whether the group element is canonical
    ///
    /// Checks whether group element s is less than p, according to RFC8032§5.1.3.1
    /// https://tools.ietf.org/html/rfc8032#section-5.1.3
    ///
    /// Taken from
    /// https://github.com/jedisct1/libsodium/blob/4744636721d2e420f8bbe2d563f31b1f5e682229/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1113
    ///
    /// The method accepts a buffer instead of calling `MarshalBinary` on the receiver
    /// because that always returns a value modulo `prime`.
    fn is_canonical(&self, b: &[u8]) -> bool {
        if b.len() != 32 {
            return false;
        }

        let mut c = (b[31] & 0x7f) ^ 0x7f;
        for i in (1..=30).into_iter().rev() {
            c |= b[i] ^ 0xff;
        }

        // subtraction might underflow
        c = (((c as u16) - 1) >> 8) as u8;
        let d = ((0xEDu16.wrapping_sub(1u16.wrapping_sub(b[0] as u16))) >> 8) as u8;

        1 - (c & d & 1) == 1
    }
}

impl Point {
    pub fn string(&self) -> String {
        let mut b = [0u8; 32];
        self.ge.to_bytes(&mut b);
        hex::encode(b)
    }

    /// marshal_id returns the type tag used in encoding/decoding
    pub fn marshal_id(&self) -> [u8; 8] {
    	MARSHAL_POINT_ID
    }

    // func (P *point) UnmarshalFrom(r io.Reader) (int, error) {
    // 	return marshalling.PointUnmarshalFrom(P, r)
    // }
}
