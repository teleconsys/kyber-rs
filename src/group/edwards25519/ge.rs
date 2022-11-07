// Group elements are members of the elliptic curve -x^2 + y^2 = 1 + d * x^2 *
// y^2 where d = -121665/121666.
//
// Several representations are used:
//   projectiveGroupElement: (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   extendedGroupElement: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   completedGroupElement: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   preComputedGroupElement: (y+x,y-x,2dxy)

use super::{
    constants::{BASE, D, D2, SQRT_M1},
    fe::{
        feAdd, feCMove, feCopy, feFromBytes, feInvert, feIsNegative, feIsNonZero, feMul, feNeg,
        feOne, fePow22523, feSquare, feSquare2, feSub, feToBytes, feZero, FieldElement,
    },
};

pub struct projectiveGroupElement {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
}

impl Default for projectiveGroupElement {
    fn default() -> Self {
        Self {
            X: Default::default(),
            Y: Default::default(),
            Z: Default::default(),
        }
    }
}

impl projectiveGroupElement {
    // func (p *projectiveGroupElement) Zero() {
    // 	feZero(&p.X)
    // 	feOne(&p.Y)
    // 	feOne(&p.Z)
    // }

    fn Double(&self, r: &mut completedGroupElement) {
        let mut t0 = FieldElement::default();

        feSquare(&mut r.X, &self.X);
        feSquare(&mut r.Z, &self.Y);
        feSquare2(&mut r.T, &self.Z);
        feAdd(&mut r.Y, &self.X, &self.Y);
        feSquare(&mut t0, &r.Y);
        feAdd(&mut r.Y, &r.Z, &r.X);
        let r_z = r.Z.clone();
        feSub(&mut r.Z, &r_z, &r.X);
        feSub(&mut r.X, &t0, &r.Y);
        let r_t = r.T.clone();
        feSub(&mut r.T, &r_t, &r.Z);
    }

    // func (p *projectiveGroupElement) ToBytes(s *[32]byte) {
    // 	var recip, x, y fieldElement

    // 	feInvert(&recip, &p.Z)
    // 	feMul(&x, &p.X, &recip)
    // 	feMul(&y, &p.Y, &recip)
    // 	feToBytes(s, &y)
    // 	s[31] ^= feIsNegative(&x) << 7
    // }
}

#[test]
fn test_from_bytes() {
    let arr: [u8; 32] = [
        132, 100, 171, 115, 11, 183, 255, 50, 148, 134, 171, 221, 113, 152, 106, 84, 177, 153, 88,
        19, 80, 57, 234, 7, 56, 227, 90, 220, 227, 87, 78, 223,
    ];
    let mut el = extendedGroupElement::default();
    assert!(el.FromBytes(&arr));
}

#[derive(Clone, Copy)]
pub struct extendedGroupElement {
    pub X: FieldElement,
    pub Y: FieldElement,
    pub Z: FieldElement,
    pub T: FieldElement,
}

impl extendedGroupElement {
    // func (p *extendedGroupElement) Neg(s *extendedGroupElement) {
    // 	feNeg(&p.X, &s.X)
    // 	feCopy(&p.Y, &s.Y)
    // 	feCopy(&p.Z, &s.Z)
    // 	feNeg(&p.T, &s.T)
    // }

    fn Double(&mut self, r: &mut completedGroupElement) {
        let mut q = projectiveGroupElement::default();
        self.ToProjective(&mut q);
        q.Double(r);
    }

    pub fn ToCached(&self, r: &mut cachedGroupElement) {
        feAdd(&mut r.yPlusX, &self.Y, &self.X);
        feSub(&mut r.yMinusX, &self.Y, &self.X);
        feCopy(&mut r.Z, &self.Z);
        feMul(&mut r.T2d, &self.T, &D2);
    }

    fn ToProjective(&self, r: &mut projectiveGroupElement) {
        feCopy(&mut r.X, &self.X);
        feCopy(&mut r.Y, &self.Y);
        feCopy(&mut r.Z, &self.Z);
    }

    pub fn ToBytes(&self, s: &mut [u8; 32]) {
        let mut recip = FieldElement::default();
        let mut x = FieldElement::default();
        let mut y = FieldElement::default();

        feInvert(&mut recip, &self.Z);
        feMul(&mut x, &self.X, &recip);
        feMul(&mut y, &self.Y, &recip);
        feToBytes(s, &y);
        s[31] ^= feIsNegative(&x) << 7;
    }

    pub fn FromBytes(&mut self, s: &[u8]) -> bool {
        // println!("{:#?}", s);
        let mut u = FieldElement::default();
        let mut v = FieldElement::default();
        let mut v3 = FieldElement::default();
        let mut vxx = FieldElement::default();
        let mut check = FieldElement::default();

        if s.len() != 32 {
            return false;
        }
        feFromBytes(&mut self.Y, s);
        feOne(&mut self.Z);
        feSquare(&mut u, &self.Y);
        feMul(&mut v, &u, &D);
        let u_clone = u.clone();
        feSub(&mut u, &u_clone, &self.Z); // y = y^2-1
        let v_clone = v.clone();
        feAdd(&mut v, &v_clone, &self.Z); // v = dy^2+1

        feSquare(&mut v3, &v);
        let v3_clone = v3.clone();
        feMul(&mut v3, &v3_clone, &v); // v3 = v^3
        feSquare(&mut self.X, &v3);
        let self_x_clone = self.X.clone();
        feMul(&mut self.X, &self_x_clone, &v);
        let self_x_clone = self.X.clone();
        feMul(&mut self.X, &self_x_clone, &u); // x = uv^7

        let self_x_clone = self.X.clone();
        fePow22523(&mut self.X, &self_x_clone); // x = (uv^7)^((q-5)/8)
        let self_x_clone = self.X.clone();
        feMul(&mut self.X, &self_x_clone, &v3);
        let self_x_clone = self.X.clone();
        feMul(&mut self.X, &self_x_clone, &u); // x = uv^3(uv^7)^((q-5)/8)

        feSquare(&mut vxx, &self.X);
        let vxx_clone = vxx.clone();
        feMul(&mut vxx, &vxx_clone, &v);
        feSub(&mut check, &vxx, &u); // vx^2-u
        if feIsNonZero(&check) == 1 {
            feAdd(&mut check, &vxx, &u); // vx^2+u
            if feIsNonZero(&check) == 1 {
                return false;
            }
            let self_x_clone = self.X.clone();
            feMul(&mut self.X, &self_x_clone, &SQRT_M1)
        }

        if feIsNegative(&self.X) != (s[31] >> 7) {
            let self_x_clone = self.X.clone();
            feNeg(&mut self.X, &self_x_clone);
        }

        feMul(&mut self.T, &self.X, &self.Y);
        true
    }

    // func (p *extendedGroupElement) String() string {
    // 	return "extendedGroupElement{\n\t" +
    // 		p.X.String() + ",\n\t" +
    // 		p.Y.String() + ",\n\t" +
    // 		p.Z.String() + ",\n\t" +
    // 		p.T.String() + ",\n}"
    // }

    pub fn Zero(&mut self) {
        feZero(&mut self.X);
        feOne(&mut self.Y);
        feOne(&mut self.Z);
        feZero(&mut self.T);
    }
}

impl Default for extendedGroupElement {
    fn default() -> Self {
        Self {
            X: Default::default(),
            Y: Default::default(),
            Z: Default::default(),
            T: Default::default(),
        }
    }
}

pub struct completedGroupElement {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    T: FieldElement,
}

impl completedGroupElement {
    pub fn ToProjective(&self, r: &mut projectiveGroupElement) {
        feMul(&mut r.X, &self.X, &self.T);
        feMul(&mut r.Y, &self.Y, &self.Z);
        feMul(&mut r.Z, &self.Z, &self.T);
    }

    pub fn Add(&mut self, p: &extendedGroupElement, q: &cachedGroupElement) {
        let mut t0 = FieldElement::default();

        feAdd(&mut self.X, &p.Y, &p.X);
        feSub(&mut self.Y, &p.Y, &p.X);
        feMul(&mut self.Z, &self.X, &q.yPlusX);
        let self_y = self.Y.clone();
        feMul(&mut self.Y, &self_y, &q.yMinusX);
        feMul(&mut self.T, &q.T2d, &p.T);
        feMul(&mut self.X, &p.Z, &q.Z);
        feAdd(&mut t0, &self.X, &self.X);
        feSub(&mut self.X, &self.Z, &self.Y);
        let self_y = self.Y.clone();
        feAdd(&mut self.Y, &self.Z, &self_y);
        feAdd(&mut self.Z, &t0, &self.T);
        let self_t = self.T.clone();
        feSub(&mut self.T, &t0, &self_t);
    }

    // func (c *completedGroupElement) Sub(p *extendedGroupElement, q *cachedGroupElement) {
    // 	var t0 fieldElement

    // 	feAdd(&c.X, &p.Y, &p.X)
    // 	feSub(&c.Y, &p.Y, &p.X)
    // 	feMul(&c.Z, &c.X, &q.yMinusX)
    // 	feMul(&c.Y, &c.Y, &q.yPlusX)
    // 	feMul(&c.T, &q.T2d, &p.T)
    // 	feMul(&c.X, &p.Z, &q.Z)
    // 	feAdd(&t0, &c.X, &c.X)
    // 	feSub(&c.X, &c.Z, &c.Y)
    // 	feAdd(&c.Y, &c.Z, &c.Y)
    // 	feSub(&c.Z, &t0, &c.T)
    // 	feAdd(&c.T, &t0, &c.T)
    // }

    // func (c *completedGroupElement) MixedSub(p *extendedGroupElement, q *preComputedGroupElement) {
    // 	var t0 fieldElement

    // 	feAdd(&c.X, &p.Y, &p.X)
    // 	feSub(&c.Y, &p.Y, &p.X)
    // 	feMul(&c.Z, &c.X, &q.yMinusX)
    // 	feMul(&c.Y, &c.Y, &q.yPlusX)
    // 	feMul(&c.T, &q.xy2d, &p.T)
    // 	feAdd(&t0, &p.Z, &p.Z)
    // 	feSub(&c.X, &c.Z, &c.Y)
    // 	feAdd(&c.Y, &c.Z, &c.Y)
    // 	feSub(&c.Z, &t0, &c.T)
    // 	feAdd(&c.T, &t0, &c.T)
    // }

    pub fn MixedAdd(&mut self, p: &mut extendedGroupElement, q: &mut preComputedGroupElement) {
        let mut t0 = FieldElement::default();

        feAdd(&mut self.X, &p.Y, &p.X);
        feSub(&mut self.Y, &p.Y, &p.X);
        feMul(&mut self.Z, &self.X, &q.yPlusX);
        let self_y = self.Y.clone();
        feMul(&mut self.Y, &self_y, &q.yMinusX);
        feMul(&mut self.T, &q.xy2d, &p.T);
        feAdd(&mut t0, &p.Z, &p.Z);
        feSub(&mut self.X, &self.Z, &self.Y);
        let self_y = self.Y.clone();
        feAdd(&mut self.Y, &self.Z, &self_y);
        feAdd(&mut self.Z, &t0, &self.T);
        let self_t = self.T.clone();
        feSub(&mut self.T, &t0, &self_t);
    }

    pub fn ToExtended(&self, r: &mut extendedGroupElement) {
        feMul(&mut r.X, &self.X, &self.T);
        feMul(&mut r.Y, &self.Y, &self.Z);
        feMul(&mut r.Z, &self.Z, &self.T);
        feMul(&mut r.T, &self.X, &self.Y);
    }
}

impl Default for completedGroupElement {
    fn default() -> Self {
        Self {
            X: Default::default(),
            Y: Default::default(),
            Z: Default::default(),
            T: Default::default(),
        }
    }
}

pub struct preComputedGroupElement {
    pub yPlusX: FieldElement,
    pub yMinusX: FieldElement,
    pub xy2d: FieldElement,
}

impl preComputedGroupElement {
    fn Zero(&mut self) {
        feOne(&mut self.yPlusX);
        feOne(&mut self.yMinusX);
        feZero(&mut self.xy2d);
    }

    /// Set to u conditionally based on b
    fn CMove(&mut self, u: &preComputedGroupElement, b: i32) {
        feCMove(&mut self.yPlusX, &u.yPlusX, b);
        feCMove(&mut self.yMinusX, &u.yMinusX, b);
        feCMove(&mut self.xy2d, &u.xy2d, b);
    }

    /// Set to negative of t
    fn Neg(&mut self, t: &preComputedGroupElement) {
        feCopy(&mut self.yPlusX, &t.yMinusX);
        feCopy(&mut self.yMinusX, &t.yPlusX);
        feNeg(&mut self.xy2d, &t.xy2d);
    }
}

impl Default for preComputedGroupElement {
    fn default() -> Self {
        Self {
            yPlusX: Default::default(),
            yMinusX: Default::default(),
            xy2d: Default::default(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct cachedGroupElement {
    yPlusX: FieldElement,
    yMinusX: FieldElement,
    Z: FieldElement,
    T2d: FieldElement,
}

impl cachedGroupElement {
    fn Zero(&mut self) {
        feOne(&mut self.yPlusX);
        feOne(&mut self.yMinusX);
        feOne(&mut self.Z);
        feZero(&mut self.T2d);
    }

    // Set to u conditionally based on b
    fn CMove(&mut self, u: &cachedGroupElement, b: i32) {
        feCMove(&mut self.yPlusX, &u.yPlusX, b);
        feCMove(&mut self.yMinusX, &u.yMinusX, b);
        feCMove(&mut self.Z, &u.Z, b);
        feCMove(&mut self.T2d, &u.T2d, b);
    }

    // Set to negative of t
    fn Neg(&mut self, t: &cachedGroupElement) {
        feCopy(&mut self.yPlusX, &t.yMinusX);
        feCopy(&mut self.yMinusX, &t.yPlusX);
        feCopy(&mut self.Z, &t.Z);
        feNeg(&mut self.T2d, &t.T2d);
    }
}

impl Default for cachedGroupElement {
    fn default() -> Self {
        Self {
            yPlusX: Default::default(),
            yMinusX: Default::default(),
            Z: Default::default(),
            T2d: Default::default(),
        }
    }
}

// // Expand the 32-byte (256-bit) exponent in slice a into
// // a sequence of 256 multipliers, one per exponent bit position.
// // Clumps nearby 1 bits into multi-bit multipliers to reduce
// // the total number of add/sub operations in a point multiply;
// // each multiplier is either zero or an odd number between -15 and 15.
// // Assumes the target array r has been preinitialized with zeros
// // in case the input slice a is less than 32 bytes.
// func slide(r *[256]int8, a *[32]byte) {

// 	// Explode the exponent a into a little-endian array, one bit per byte
// 	for i := range a {
// 		ai := int8(a[i])
// 		for j := 0; j < 8; j++ {
// 			r[i*8+j] = ai & 1
// 			ai >>= 1
// 		}
// 	}

// 	// Go through and clump sequences of 1-bits together wherever possible,
// 	// while keeping r[i] in the range -15 through 15.
// 	// Note that each nonzero r[i] in the result will always be odd,
// 	// because clumping is triggered by the first, least-significant,
// 	// 1-bit encountered in a clump, and that first bit always remains 1.
// 	for i := range r {
// 		if r[i] != 0 {
// 			for b := 1; b <= 6 && i+b < 256; b++ {
// 				if r[i+b] != 0 {
// 					if r[i]+(r[i+b]<<uint(b)) <= 15 {
// 						r[i] += r[i+b] << uint(b)
// 						r[i+b] = 0
// 					} else if r[i]-(r[i+b]<<uint(b)) >= -15 {
// 						r[i] -= r[i+b] << uint(b)
// 						for k := i + b; k < 256; k++ {
// 							if r[k] == 0 {
// 								r[k] = 1
// 								break
// 							}
// 							r[k] = 0
// 						}
// 					} else {
// 						break
// 					}
// 				}
// 			}
// 		}
// 	}
// }

/// equal returns 1 if b == c and 0 otherwise.
fn equal(b: i32, c: i32) -> i32 {
    let mut x = (b ^ c) as u32;
    x -= 1;
    return (x >> 31) as i32;
}

// negative returns 1 if b < 0 and 0 otherwise.
fn negative(b: i32) -> i32 {
    (b >> 31) & 1
}

fn selectPreComputed(t: &mut preComputedGroupElement, pos: usize, b: i32) {
    let mut minusT = preComputedGroupElement::default();
    let bNegative = negative(b);
    let bAbs = b - (((-bNegative) & b) << 1);

    t.Zero();
    for i in 0..8 {
        t.CMove(&BASE[pos][i], equal(bAbs, i as i32 + 1));
    }
    minusT.Neg(t);
    t.CMove(&minusT, bNegative);
}

/// geScalarMultBase computes h = a*B, where
///   a = a[0]+256*a[1]+...+256^31 a[31]
///   B is the Ed25519 base point (x,4/5) with x positive.
///
/// Preconditions:
///   a[31] <= 127
pub fn geScalarMultBase(h: &mut extendedGroupElement, a: &mut [u8; 32]) {
    let mut e = [0 as i8; 64];

    for (i, v) in a.iter().enumerate() {
        e[2 * i] = (v & 15) as i8;
        e[2 * i + 1] = ((v >> 4) & 15) as i8;
    }

    // each e[i] is between 0 and 15 and e[63] is between 0 and 7.

    let mut carry = 0 as i8;
    for i in 0..62 {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    // each e[i] is between -8 and 8.

    h.Zero();
    let mut t = preComputedGroupElement::default();
    let mut r = completedGroupElement::default();
    for i in (1..64).filter(|x| x % 2 != 0) {
        selectPreComputed(&mut t, i / 2, (e[i as usize]) as i32);
        r.MixedAdd(h, &mut t);
        r.ToExtended(h);
    }

    let mut s = projectiveGroupElement::default();

    h.Double(&mut r);
    r.ToProjective(&mut s);
    s.Double(&mut r);
    r.ToProjective(&mut s);
    s.Double(&mut r);
    r.ToProjective(&mut s);
    s.Double(&mut r);
    r.ToExtended(h);

    for i in (0..64).filter(|x| x % 2 != 0) {
        selectPreComputed(&mut t, i / 2, e[i as usize] as i32);
        r.MixedAdd(h, &mut t);
        r.ToExtended(h);
    }
}

fn selectCached(c: &mut cachedGroupElement, Ai: &[cachedGroupElement; 8], b: i32) {
    let bNegative = negative(b);
    let bAbs = b - (((-bNegative) & b) << 1);

    // in constant-time pick cached multiplier for exponent 0 through 8
    c.Zero();
    for i in 0..8 {
        c.CMove(&Ai[i], equal(bAbs, i as i32 + 1))
    }

    // in constant-time compute negated version, conditionally use it
    let mut minusC = cachedGroupElement::default();
    minusC.Neg(c);
    c.CMove(&minusC, bNegative)
}

/// geScalarMult computes h = a*B, where
///   a = a[0]+256*a[1]+...+256^31 a[31]
///   B is the Ed25519 base point (x,4/5) with x positive.
///
/// Preconditions:
///   a[31] <= 127
pub fn geScalarMult(h: &mut extendedGroupElement, a: &mut [u8; 32], A: &mut extendedGroupElement) {
    let mut t = completedGroupElement::default();
    let mut u = extendedGroupElement::default();
    let mut r = projectiveGroupElement::default();
    let mut c = cachedGroupElement::default();
    let i = 0;

    // Break the exponent into 4-bit nybbles.
    let mut e = [0 as i8; 64];
    for (i, v) in a.iter().enumerate() {
        e[2 * i] = (v & 15) as i8;
        e[2 * i + 1] = ((v >> 4) & 15) as i8;
    }
    // each e[i] is between 0 and 15 and e[63] is between 0 and 7.

    let mut carry = 0 as i8;
    for i in 0..64 {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    // each e[i] is between -8 and 8.

    // compute cached array of multiples of A from 1A through 8A
    let mut Ai = [cachedGroupElement::default(); 8]; // A,1A,2A,3A,4A,5A,6A,7A
    A.ToCached(&mut Ai[0]);
    for i in 0..7 {
        t.Add(A, &Ai[i]);
        t.ToExtended(&mut u);
        u.ToCached(&mut Ai[i + 1]);
    }

    // special case for exponent nybble i == 63
    u.Zero();
    selectCached(&mut c, &Ai, (e[63]) as i32);
    t.Add(&u, &c);

    for i in (0..63).rev() {
        // t <<= 4
        t.ToProjective(&mut r);
        r.Double(&mut t);
        t.ToProjective(&mut r);
        r.Double(&mut t);
        t.ToProjective(&mut r);
        r.Double(&mut t);
        t.ToProjective(&mut r);
        r.Double(&mut t);

        // Add next nybble
        t.ToExtended(&mut u);
        selectCached(&mut c, &Ai, (e[i]) as i32);
        t.Add(&u, &c);
    }

    t.ToExtended(h);
}
