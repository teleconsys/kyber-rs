// Group elements are members of the elliptic curve -x^2 + y^2 = 1 + d * x^2 *
// y^2 where d = -121665/121666.
//
// Several representations are used:
//   projectiveGroupElement: (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   extendedGroupElement: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   completedGroupElement: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   preComputedGroupElement: (y+x,y-x,2dxy)

use serde::{Deserialize, Serialize};

use super::{
    constants::{BASE, D, D2, SQRT_M1},
    fe::{
        fe_add, fe_c_move, fe_copy, fe_from_bytes, fe_invert, fe_is_negative, fe_is_non_zero,
        fe_mul, fe_neg, fe_one, fe_pow22523, fe_square, fe_square2, fe_sub, fe_to_bytes, fe_zero,
        FieldElement,
    },
};

#[derive(Default)]
pub struct ProjectiveGroupElement {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectiveGroupElement {
    fn zero(&mut self) {
        fe_zero(&mut self.x);
        fe_one(&mut self.y);
        fe_one(&mut self.z);
    }

    pub fn double(&self, r: &mut CompletedGroupElement) {
        let mut t0 = FieldElement::default();

        fe_square(&mut r.x, &self.x);
        fe_square(&mut r.z, &self.y);
        fe_square2(&mut r.t, &self.z);
        fe_add(&mut r.y, &self.x, &self.y);
        fe_square(&mut t0, &r.y);
        fe_add(&mut r.y, &r.z, &r.x);
        let r_z = r.z;
        fe_sub(&mut r.z, &r_z, &r.x);
        fe_sub(&mut r.x, &t0, &r.y);
        let r_t = r.t;
        fe_sub(&mut r.t, &r_t, &r.z);
    }

    fn to_bytes(&self, s: &mut [u8; 32]) {
        let mut recip = FieldElement::default();
        let mut x = FieldElement::default();
        let mut y = FieldElement::default();

        fe_invert(&mut recip, &self.z);
        fe_mul(&mut x, &self.x, &recip);
        fe_mul(&mut y, &self.y, &recip);
        fe_to_bytes(s, &y);
        s[31] ^= fe_is_negative(&x) << 7
    }
}

#[test]
fn test_from_bytes() {
    let arr: [u8; 32] = [
        132, 100, 171, 115, 11, 183, 255, 50, 148, 134, 171, 221, 113, 152, 106, 84, 177, 153, 88,
        19, 80, 57, 234, 7, 56, 227, 90, 220, 227, 87, 78, 223,
    ];
    let mut el = ExtendedGroupElement::default();
    assert!(el.from_bytes(&arr));
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct ExtendedGroupElement {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl ExtendedGroupElement {
    pub fn neg(&mut self, s: &Self) {
        fe_neg(&mut self.x, &s.x);
        fe_copy(&mut self.y, &s.y);
        fe_copy(&mut self.z, &s.z);
        fe_neg(&mut self.t, &s.t);
    }

    pub fn double(&mut self, r: &mut CompletedGroupElement) {
        let mut q = ProjectiveGroupElement::default();
        self.to_projective(&mut q);
        q.double(r);
    }

    pub fn to_cached(&self, r: &mut CachedGroupElement) {
        fe_add(&mut r.y_plus_x, &self.y, &self.x);
        fe_sub(&mut r.y_minus_x, &self.y, &self.x);
        fe_copy(&mut r.z, &self.z);
        fe_mul(&mut r.t2d, &self.t, &D2);
    }

    fn to_projective(&self, r: &mut ProjectiveGroupElement) {
        fe_copy(&mut r.x, &self.x);
        fe_copy(&mut r.y, &self.y);
        fe_copy(&mut r.z, &self.z);
    }

    pub fn to_bytes(&self, s: &mut [u8; 32]) {
        let mut recip = FieldElement::default();
        let mut x = FieldElement::default();
        let mut y = FieldElement::default();

        fe_invert(&mut recip, &self.z);
        fe_mul(&mut x, &self.x, &recip);
        fe_mul(&mut y, &self.y, &recip);
        fe_to_bytes(s, &y);
        s[31] ^= fe_is_negative(&x) << 7;
    }

    pub fn from_bytes(&mut self, s: &[u8]) -> bool {
        // println!("{:#?}", s);
        let mut u = FieldElement::default();
        let mut v = FieldElement::default();
        let mut v3 = FieldElement::default();
        let mut vxx = FieldElement::default();
        let mut check = FieldElement::default();

        if s.len() != 32 {
            return false;
        }
        fe_from_bytes(&mut self.y, s);
        fe_one(&mut self.z);
        fe_square(&mut u, &self.y);
        fe_mul(&mut v, &u, &D);
        let u_clone = u;
        fe_sub(&mut u, &u_clone, &self.z); // y = y^2-1
        let v_clone = v;
        fe_add(&mut v, &v_clone, &self.z); // v = dy^2+1

        fe_square(&mut v3, &v);
        let v3_clone = v3;
        fe_mul(&mut v3, &v3_clone, &v); // v3 = v^3
        fe_square(&mut self.x, &v3);
        let self_x_clone = self.x;
        fe_mul(&mut self.x, &self_x_clone, &v);
        let self_x_clone = self.x;
        fe_mul(&mut self.x, &self_x_clone, &u); // x = uv^7

        let self_x_clone = self.x;
        fe_pow22523(&mut self.x, &self_x_clone); // x = (uv^7)^((q-5)/8)
        let self_x_clone = self.x;
        fe_mul(&mut self.x, &self_x_clone, &v3);
        let self_x_clone = self.x;
        fe_mul(&mut self.x, &self_x_clone, &u); // x = uv^3(uv^7)^((q-5)/8)

        fe_square(&mut vxx, &self.x);
        let vxx_clone = vxx;
        fe_mul(&mut vxx, &vxx_clone, &v);
        fe_sub(&mut check, &vxx, &u); // vx^2-u
        if fe_is_non_zero(&check) == 1 {
            fe_add(&mut check, &vxx, &u); // vx^2+u
            if fe_is_non_zero(&check) == 1 {
                return false;
            }
            let self_x_clone = self.x;
            fe_mul(&mut self.x, &self_x_clone, &SQRT_M1)
        }

        if fe_is_negative(&self.x) != (s[31] >> 7) {
            let self_x_clone = self.x;
            fe_neg(&mut self.x, &self_x_clone);
        }

        fe_mul(&mut self.t, &self.x, &self.y);
        true
    }

    pub fn string(&self) -> String {
        return "extendedGroupElement{\n\t".to_owned()
            + &format!("{:?}", self.x)
            + ",\n\t"
            + &format!("{:?}", self.y)
            + ",\n\t"
            + &format!("{:?}", self.z)
            + ",\n\t"
            + &format!("{:?}", self.t)
            + ",\n}";
    }

    pub fn zero(&mut self) {
        fe_zero(&mut self.x);
        fe_one(&mut self.y);
        fe_one(&mut self.z);
        fe_zero(&mut self.t);
    }
}

#[derive(Default)]
pub struct CompletedGroupElement {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl CompletedGroupElement {
    pub fn to_projective(&self, r: &mut ProjectiveGroupElement) {
        fe_mul(&mut r.x, &self.x, &self.t);
        fe_mul(&mut r.y, &self.y, &self.z);
        fe_mul(&mut r.z, &self.z, &self.t);
    }

    pub fn add(&mut self, p: &ExtendedGroupElement, q: &CachedGroupElement) {
        let mut t0 = FieldElement::default();

        fe_add(&mut self.x, &p.y, &p.x);
        fe_sub(&mut self.y, &p.y, &p.x);
        fe_mul(&mut self.z, &self.x, &q.y_plus_x);
        let self_y = self.y;
        fe_mul(&mut self.y, &self_y, &q.y_minus_x);
        fe_mul(&mut self.t, &q.t2d, &p.t);
        fe_mul(&mut self.x, &p.z, &q.z);
        fe_add(&mut t0, &self.x, &self.x);
        fe_sub(&mut self.x, &self.z, &self.y);
        let self_y = self.y;
        fe_add(&mut self.y, &self.z, &self_y);
        fe_add(&mut self.z, &t0, &self.t);
        let self_t = self.t;
        fe_sub(&mut self.t, &t0, &self_t);
    }

    pub fn sub(&mut self, p: &ExtendedGroupElement, q: &CachedGroupElement) {
        let mut t0 = FieldElement::default();

        fe_add(&mut self.x, &p.y, &p.x);
        fe_sub(&mut self.y, &p.y, &p.x);
        fe_mul(&mut self.z, &self.x, &q.y_minus_x);
        let self_y = self.y;
        fe_mul(&mut self.y, &self_y, &q.y_plus_x);
        fe_mul(&mut self.t, &q.t2d, &p.t);
        fe_mul(&mut self.x, &p.z, &q.z);
        fe_add(&mut t0, &self.x, &self.x);
        fe_sub(&mut self.x, &self.z, &self.y);
        let self_y = self.y;
        fe_add(&mut self.y, &self.z, &self_y);
        fe_sub(&mut self.z, &t0, &self.t);
        let self_t = self.t;
        fe_add(&mut self.t, &t0, &self_t);
    }

    pub fn mixed_sub(&mut self, p: ExtendedGroupElement, q: PreComputedGroupElement) {
        let mut t0 = FieldElement::default();

        fe_add(&mut self.x, &p.y, &p.x);
        fe_sub(&mut self.y, &p.y, &p.x);
        fe_mul(&mut self.z, &self.x, &q.y_minus_x);
        let y_clone = self.y;
        fe_mul(&mut self.y, &y_clone, &q.y_plus_x);
        fe_mul(&mut self.t, &q.xy2d, &p.t);
        fe_add(&mut t0, &p.z, &p.z);
        fe_sub(&mut self.x, &self.z, &self.y);
        let y_clone = self.y;
        fe_add(&mut self.y, &self.z, &y_clone);
        fe_sub(&mut self.z, &t0, &self.t);
        let t_clone = self.t;
        fe_add(&mut self.t, &t0, &t_clone);
    }

    pub fn mixed_add(&mut self, p: &mut ExtendedGroupElement, q: &mut PreComputedGroupElement) {
        let mut t0 = FieldElement::default();

        fe_add(&mut self.x, &p.y, &p.x);
        fe_sub(&mut self.y, &p.y, &p.x);
        fe_mul(&mut self.z, &self.x, &q.y_plus_x);
        let self_y = self.y;
        fe_mul(&mut self.y, &self_y, &q.y_minus_x);
        fe_mul(&mut self.t, &q.xy2d, &p.t);
        fe_add(&mut t0, &p.z, &p.z);
        fe_sub(&mut self.x, &self.z, &self.y);
        let self_y = self.y;
        fe_add(&mut self.y, &self.z, &self_y);
        fe_add(&mut self.z, &t0, &self.t);
        let self_t = self.t;
        fe_sub(&mut self.t, &t0, &self_t);
    }

    pub fn to_extended(&self, r: &mut ExtendedGroupElement) {
        fe_mul(&mut r.x, &self.x, &self.t);
        fe_mul(&mut r.y, &self.y, &self.z);
        fe_mul(&mut r.z, &self.z, &self.t);
        fe_mul(&mut r.t, &self.x, &self.y);
    }
}

#[derive(Default)]
pub struct PreComputedGroupElement {
    pub y_plus_x: FieldElement,
    pub y_minus_x: FieldElement,
    pub xy2d: FieldElement,
}

impl PreComputedGroupElement {
    fn zero(&mut self) {
        fe_one(&mut self.y_plus_x);
        fe_one(&mut self.y_minus_x);
        fe_zero(&mut self.xy2d);
    }

    /// Set to u conditionally based on b
    fn cmove(&mut self, u: &PreComputedGroupElement, b: i32) {
        fe_c_move(&mut self.y_plus_x, &u.y_plus_x, b);
        fe_c_move(&mut self.y_minus_x, &u.y_minus_x, b);
        fe_c_move(&mut self.xy2d, &u.xy2d, b);
    }

    /// Set to negative of t
    fn neg(&mut self, t: &PreComputedGroupElement) {
        fe_copy(&mut self.y_plus_x, &t.y_minus_x);
        fe_copy(&mut self.y_minus_x, &t.y_plus_x);
        fe_neg(&mut self.xy2d, &t.xy2d);
    }
}

#[derive(Clone, Copy, Default)]
pub struct CachedGroupElement {
    y_plus_x: FieldElement,
    y_minus_x: FieldElement,
    z: FieldElement,
    t2d: FieldElement,
}

impl CachedGroupElement {
    fn zero(&mut self) {
        fe_one(&mut self.y_plus_x);
        fe_one(&mut self.y_minus_x);
        fe_one(&mut self.z);
        fe_zero(&mut self.t2d);
    }

    /// Set to u conditionally based on b
    fn cmove(&mut self, u: &CachedGroupElement, b: i32) {
        fe_c_move(&mut self.y_plus_x, &u.y_plus_x, b);
        fe_c_move(&mut self.y_minus_x, &u.y_minus_x, b);
        fe_c_move(&mut self.z, &u.z, b);
        fe_c_move(&mut self.t2d, &u.t2d, b);
    }

    /// Set to negative of t
    fn neg(&mut self, t: &CachedGroupElement) {
        fe_copy(&mut self.y_plus_x, &t.y_minus_x);
        fe_copy(&mut self.y_minus_x, &t.y_plus_x);
        fe_copy(&mut self.z, &t.z);
        fe_neg(&mut self.t2d, &t.t2d);
    }
}

/// Expand the 32-byte (256-bit) exponent in slice a into
/// a sequence of 256 multipliers, one per exponent bit position.
/// Clumps nearby 1 bits into multi-bit multipliers to reduce
/// the total number of add/sub operations in a point multiply;
/// each multiplier is either zero or an odd number between -15 and 15.
/// Assumes the target array r has been preinitialized with zeros
/// in case the input slice a is less than 32 bytes.
pub fn slide(r: &mut [i8; 256], a: &[u8; 32]) {
    // Explode the exponent a into a little-endian array, one bit per byte
    for (i, _) in a.iter().enumerate() {
        let mut ai = a[i] as i8;
        for j in 0..8 {
            r[i * 8 + j] = ai & 1;
            ai >>= 1;
        }
    }

    // Go through and clump sequences of 1-bits together wherever possible,
    // while keeping r[i] in the range -15 through 15.
    // Note that each nonzero r[i] in the result will always be odd,
    // because clumping is triggered by the first, least-significant,
    // 1-bit encountered in a clump, and that first bit always remains 1.
    for i in 0..r.len() {
        if r[i] != 0 {
            let mut b = 1;
            while b <= 6 && i + b < 256 {
                if r[i + b] != 0 {
                    if r[i] + (r[i + b] << b) <= 15 {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if r[i] - (r[i + b] << b) >= -15 {
                        r[i] -= r[i + b] << b;
                        for k in r.iter_mut().take(256).skip(i + b) {
                            if *k == 0 {
                                *k = 1;
                                break;
                            }
                            *k = 0;
                        }
                    } else {
                        break;
                    }
                }
                b += 1;
            }
        }
    }
}

/// equal returns 1 if b == c and 0 otherwise.
fn equal(b: i32, c: i32) -> i32 {
    let mut x = (b ^ c) as u32;
    x = x.wrapping_sub(1);
    (x >> 31) as i32
}

// negative returns 1 if b < 0 and 0 otherwise.
fn negative(b: i32) -> i32 {
    (b >> 31) & 1
}

fn select_pre_computed(t: &mut PreComputedGroupElement, pos: usize, b: i32) {
    let mut minus_t = PreComputedGroupElement::default();
    let b_negative = negative(b);
    let b_abs = b - (((-b_negative) & b) << 1);

    t.zero();
    for i in 0..8 {
        t.cmove(&BASE[pos][i], equal(b_abs, i as i32 + 1));
    }
    minus_t.neg(t);
    t.cmove(&minus_t, b_negative);
}

/// geScalarMultBase computes h = a*B, where
///   a = a[0]+256*a[1]+...+256^31 a[31]
///   B is the Ed25519 base point (x,4/5) with x positive.
///
/// Preconditions:
///   a[31] <= 127
pub fn ge_scalar_mult_base(h: &mut ExtendedGroupElement, a: &mut [u8; 32]) {
    let mut e = [0_i8; 64];

    for (i, v) in a.iter().enumerate() {
        e[2 * i] = (v & 15) as i8;
        e[2 * i + 1] = ((v >> 4) & 15) as i8;
    }

    // each e[i] is between 0 and 15 and e[63] is between 0 and 7.

    let mut carry = 0_i8;
    (0..63).for_each(|i| {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    });
    e[63] += carry;
    // each e[i] is between -8 and 8.

    h.zero();
    let mut t = PreComputedGroupElement::default();
    let mut r = CompletedGroupElement::default();
    for i in (1..64).filter(|x| x % 2 != 0) {
        select_pre_computed(&mut t, i / 2, (e[i]) as i32);
        r.mixed_add(h, &mut t);
        r.to_extended(h);
    }

    let mut s = ProjectiveGroupElement::default();

    h.double(&mut r);
    r.to_projective(&mut s);
    s.double(&mut r);
    r.to_projective(&mut s);
    s.double(&mut r);
    r.to_projective(&mut s);
    s.double(&mut r);
    r.to_extended(h);

    for i in (0..64).filter(|x| x % 2 == 0) {
        select_pre_computed(&mut t, i / 2, e[i] as i32);
        r.mixed_add(h, &mut t);
        r.to_extended(h);
    }
}

fn select_cached(c: &mut CachedGroupElement, ai: &[CachedGroupElement; 8], b: i32) {
    let b_negative = negative(b);
    let b_abs = b - (((-b_negative) & b) << 1);

    // in constant-time pick cached multiplier for exponent 0 through 8
    c.zero();
    (0..8).for_each(|i| c.cmove(&ai[i], equal(b_abs, i as i32 + 1)));

    // in constant-time compute negated version, conditionally use it
    let mut minus_c = CachedGroupElement::default();
    minus_c.neg(c);
    c.cmove(&minus_c, b_negative)
}

/// geScalarMult computes h = a*B, where
///   a = a[0]+256*a[1]+...+256^31 a[31]
///   B is the Ed25519 base point (x,4/5) with x positive.
///
/// Preconditions:
///   a[31] <= 127
pub fn ge_scalar_mult(
    h: &mut ExtendedGroupElement,
    a: &mut [u8; 32],
    a_caps: &mut ExtendedGroupElement,
) {
    let mut t = CompletedGroupElement::default();
    let mut u = ExtendedGroupElement::default();
    let mut r = ProjectiveGroupElement::default();
    let mut c = CachedGroupElement::default();
    let _i = 0;

    // Break the exponent into 4-bit nybbles.
    let mut e = [0_i8; 64];
    for (i, v) in a.iter().enumerate() {
        e[2 * i] = (v & 15) as i8;
        e[2 * i + 1] = ((v >> 4) & 15) as i8;
    }
    // each e[i] is between 0 and 15 and e[63] is between 0 and 7.

    let mut carry = 0_i8;
    (0..63).for_each(|i| {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    });
    e[63] += carry;
    // each e[i] is between -8 and 8.

    // compute cached array of multiples of A from 1A through 8A
    let mut ai = [CachedGroupElement::default(); 8]; // A,1A,2A,3A,4A,5A,6A,7A
    a_caps.to_cached(&mut ai[0]);
    for i in 0..7 {
        t.add(a_caps, &ai[i]);
        t.to_extended(&mut u);
        u.to_cached(&mut ai[i + 1]);
    }

    // special case for exponent nybble i == 63
    u.zero();
    select_cached(&mut c, &ai, (e[63]) as i32);
    t.add(&u, &c);

    for i in (0..63).rev() {
        // t <<= 4
        t.to_projective(&mut r);
        r.double(&mut t);
        t.to_projective(&mut r);
        r.double(&mut t);
        t.to_projective(&mut r);
        r.double(&mut t);
        t.to_projective(&mut r);
        r.double(&mut t);

        // Add next nybble
        t.to_extended(&mut u);
        select_cached(&mut c, &ai, (e[i]) as i32);
        t.add(&u, &c);
    }

    t.to_extended(h);
}
