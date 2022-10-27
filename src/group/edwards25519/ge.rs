// Group elements are members of the elliptic curve -x^2 + y^2 = 1 + d * x^2 *
// y^2 where d = -121665/121666.
//
// Several representations are used:
//   projectiveGroupElement: (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   extendedGroupElement: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   completedGroupElement: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   preComputedGroupElement: (y+x,y-x,2dxy)

use super::fe::{feAdd, feCopy, feMul, feOne, feSquare, feSquare2, feSub, feZero, FieldElement};

struct projectiveGroupElement {
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

    fn Double(&mut self, r: &mut completedGroupElement) {
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

#[derive(Clone, Copy)]
pub struct extendedGroupElement {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    T: FieldElement,
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

    // func (p *extendedGroupElement) ToCached(r *cachedGroupElement) {
    // 	feAdd(&r.yPlusX, &p.Y, &p.X)
    // 	feSub(&r.yMinusX, &p.Y, &p.X)
    // 	feCopy(&r.Z, &p.Z)
    // 	feMul(&r.T2d, &p.T, &d2)
    // }

    fn ToProjective(&self, r: &mut projectiveGroupElement) {
        feCopy(&mut r.X, &self.X);
        feCopy(&mut r.Y, &self.Y);
        feCopy(&mut r.Z, &self.Z);
    }

    // func (p *extendedGroupElement) ToBytes(s *[32]byte) {
    // 	var recip, x, y fieldElement

    // 	feInvert(&recip, &p.Z)
    // 	feMul(&x, &p.X, &recip)
    // 	feMul(&y, &p.Y, &recip)
    // 	feToBytes(s, &y)
    // 	s[31] ^= feIsNegative(&x) << 7
    // }

    // func (p *extendedGroupElement) FromBytes(s []byte) bool {
    // 	var u, v, v3, vxx, check fieldElement

    // 	if len(s) != 32 {
    // 		return false
    // 	}
    // 	feFromBytes(&p.Y, s)
    // 	feOne(&p.Z)
    // 	feSquare(&u, &p.Y)
    // 	feMul(&v, &u, &d)
    // 	feSub(&u, &u, &p.Z) // y = y^2-1
    // 	feAdd(&v, &v, &p.Z) // v = dy^2+1

    // 	feSquare(&v3, &v)
    // 	feMul(&v3, &v3, &v) // v3 = v^3
    // 	feSquare(&p.X, &v3)
    // 	feMul(&p.X, &p.X, &v)
    // 	feMul(&p.X, &p.X, &u) // x = uv^7

    // 	fePow22523(&p.X, &p.X) // x = (uv^7)^((q-5)/8)
    // 	feMul(&p.X, &p.X, &v3)
    // 	feMul(&p.X, &p.X, &u) // x = uv^3(uv^7)^((q-5)/8)

    // 	feSquare(&vxx, &p.X)
    // 	feMul(&vxx, &vxx, &v)
    // 	feSub(&check, &vxx, &u) // vx^2-u
    // 	if feIsNonZero(&check) == 1 {
    // 		feAdd(&check, &vxx, &u) // vx^2+u
    // 		if feIsNonZero(&check) == 1 {
    // 			return false
    // 		}
    // 		feMul(&p.X, &p.X, &sqrtM1)
    // 	}

    // 	if feIsNegative(&p.X) != (s[31] >> 7) {
    // 		feNeg(&p.X, &p.X)
    // 	}

    // 	feMul(&p.T, &p.X, &p.Y)
    // 	return true
    // }

    // func (p *extendedGroupElement) String() string {
    // 	return "extendedGroupElement{\n\t" +
    // 		p.X.String() + ",\n\t" +
    // 		p.Y.String() + ",\n\t" +
    // 		p.Z.String() + ",\n\t" +
    // 		p.T.String() + ",\n}"
    // }

    fn Zero(&mut self) {
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

struct completedGroupElement {
    X: FieldElement,
    Y: FieldElement,
    Z: FieldElement,
    T: FieldElement,
}

impl completedGroupElement {
    fn ToProjective(&mut self, r: &mut projectiveGroupElement) {
        feMul(&mut r.X, &self.X, &self.T);
        feMul(&mut r.Y, &self.Y, &self.Z);
        feMul(&mut r.Z, &self.Z, &self.T);
    }

    // func (c *completedGroupElement) Add(p *extendedGroupElement, q *cachedGroupElement) {
    // 	var t0 fieldElement

    // 	feAdd(&c.X, &p.Y, &p.X)
    // 	feSub(&c.Y, &p.Y, &p.X)
    // 	feMul(&c.Z, &c.X, &q.yPlusX)
    // 	feMul(&c.Y, &c.Y, &q.yMinusX)
    // 	feMul(&c.T, &q.T2d, &p.T)
    // 	feMul(&c.X, &p.Z, &q.Z)
    // 	feAdd(&t0, &c.X, &c.X)
    // 	feSub(&c.X, &c.Z, &c.Y)
    // 	feAdd(&c.Y, &c.Z, &c.Y)
    // 	feAdd(&c.Z, &t0, &c.T)
    // 	feSub(&c.T, &t0, &c.T)
    // }

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

    fn MixedAdd(&mut self, p: &mut extendedGroupElement, q: &mut preComputedGroupElement) {
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

    fn ToExtended(&mut self, r: &mut extendedGroupElement) {
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

struct preComputedGroupElement {
    yPlusX: FieldElement,
    yMinusX: FieldElement,
    xy2d: FieldElement,
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

struct cachedGroupElement {
    yPlusX: FieldElement,
    yMinusX: FieldElement,
    Z: FieldElement,
    T2d: FieldElement,
}

// func (p *preComputedGroupElement) Zero() {
// 	feOne(&p.yPlusX)
// 	feOne(&p.yMinusX)
// 	feZero(&p.xy2d)
// }

// // preComputedGroupElement methods

// // Set to u conditionally based on b
// func (p *preComputedGroupElement) CMove(u *preComputedGroupElement, b int32) {
// 	feCMove(&p.yPlusX, &u.yPlusX, b)
// 	feCMove(&p.yMinusX, &u.yMinusX, b)
// 	feCMove(&p.xy2d, &u.xy2d, b)
// }

// // Set to negative of t
// func (p *preComputedGroupElement) Neg(t *preComputedGroupElement) {
// 	feCopy(&p.yPlusX, &t.yMinusX)
// 	feCopy(&p.yMinusX, &t.yPlusX)
// 	feNeg(&p.xy2d, &t.xy2d)
// }

// // cachedGroupElement methods

// func (r *cachedGroupElement) Zero() {
// 	feOne(&r.yPlusX)
// 	feOne(&r.yMinusX)
// 	feOne(&r.Z)
// 	feZero(&r.T2d)
// }

// // Set to u conditionally based on b
// func (r *cachedGroupElement) CMove(u *cachedGroupElement, b int32) {
// 	feCMove(&r.yPlusX, &u.yPlusX, b)
// 	feCMove(&r.yMinusX, &u.yMinusX, b)
// 	feCMove(&r.Z, &u.Z, b)
// 	feCMove(&r.T2d, &u.T2d, b)
// }

// // Set to negative of t
// func (r *cachedGroupElement) Neg(t *cachedGroupElement) {
// 	feCopy(&r.yPlusX, &t.yMinusX)
// 	feCopy(&r.yMinusX, &t.yPlusX)
// 	feCopy(&r.Z, &t.Z)
// 	feNeg(&r.T2d, &t.T2d)
// }

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

// // equal returns 1 if b == c and 0 otherwise.
// func equal(b, c int32) int32 {
// 	x := uint32(b ^ c)
// 	x--
// 	return int32(x >> 31)
// }

// // negative returns 1 if b < 0 and 0 otherwise.
// func negative(b int32) int32 {
// 	return (b >> 31) & 1
// }

fn selectPreComputed(t: &mut preComputedGroupElement, pos: i32, b: i32) {
    // var minusT preComputedGroupElement
    // bNegative := negative(b)
    // bAbs := b - (((-bNegative) & b) << 1)

    // t.Zero()
    // for i := int32(0); i < 8; i++ {
    // 	t.CMove(&base[pos][i], equal(bAbs, i+1))
    // }
    // minusT.Neg(t)
    // t.CMove(&minusT, bNegative)
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

// func selectCached(c *cachedGroupElement, Ai *[8]cachedGroupElement, b int32) {
// 	bNegative := negative(b)
// 	bAbs := b - (((-bNegative) & b) << 1)

// 	// in constant-time pick cached multiplier for exponent 0 through 8
// 	c.Zero()
// 	for i := int32(0); i < 8; i++ {
// 		c.CMove(&Ai[i], equal(bAbs, i+1))
// 	}

// 	// in constant-time compute negated version, conditionally use it
// 	var minusC cachedGroupElement
// 	minusC.Neg(c)
// 	c.CMove(&minusC, bNegative)
// }

/// geScalarMult computes h = a*B, where
///   a = a[0]+256*a[1]+...+256^31 a[31]
///   B is the Ed25519 base point (x,4/5) with x positive.
///
/// Preconditions:
///   a[31] <= 127
pub fn geScalarMult(h: &mut extendedGroupElement, a: &mut [u8; 32], A: &mut extendedGroupElement) {

    // var t completedGroupElement
    // var u extendedGroupElement
    // var r projectiveGroupElement
    // var c cachedGroupElement
    // var i int

    // // Break the exponent into 4-bit nybbles.
    // var e [64]int8
    // for i, v := range a {
    // 	e[2*i] = int8(v & 15)
    // 	e[2*i+1] = int8((v >> 4) & 15)
    // }
    // // each e[i] is between 0 and 15 and e[63] is between 0 and 7.

    // carry := int8(0)
    // for i := 0; i < 63; i++ {
    // 	e[i] += carry
    // 	carry = (e[i] + 8) >> 4
    // 	e[i] -= carry << 4
    // }
    // e[63] += carry
    // // each e[i] is between -8 and 8.

    // // compute cached array of multiples of A from 1A through 8A
    // var Ai [8]cachedGroupElement // A,1A,2A,3A,4A,5A,6A,7A
    // A.ToCached(&Ai[0])
    // for i := 0; i < 7; i++ {
    // 	t.Add(A, &Ai[i])
    // 	t.ToExtended(&u)
    // 	u.ToCached(&Ai[i+1])
    // }

    // // special case for exponent nybble i == 63
    // u.Zero()
    // selectCached(&c, &Ai, int32(e[63]))
    // t.Add(&u, &c)

    // for i = 62; i >= 0; i-- {

    // 	// t <<= 4
    // 	t.ToProjective(&r)
    // 	r.Double(&t)
    // 	t.ToProjective(&r)
    // 	r.Double(&t)
    // 	t.ToProjective(&r)
    // 	r.Double(&t)
    // 	t.ToProjective(&r)
    // 	r.Double(&t)

    // 	// Add next nybble
    // 	t.ToExtended(&u)
    // 	selectCached(&c, &Ai, int32(e[i]))
    // 	t.Add(&u, &c)
    // }

    // t.ToExtended(h)
}
