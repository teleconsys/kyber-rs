// This code is a port of the public domain, "ref10" implementation of ed25519
// from SUPERCOP.

/// FieldElement  represents an element of the field GF(2^255 - 19).  An element
/// t, entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
/// t[3]+2^102 t[4]+...+2^230 t[9].  Bounds on each t[i] vary depending on
/// context.
pub type FieldElement = [i32; 10];

pub fn feZero(fe: &mut FieldElement) {
    for i in 0..fe.len() {
        fe[i] = 0;
    }
}

pub fn feOne(fe: &mut FieldElement) {
    feZero(fe);
    fe[0] = 1;
}

pub fn feAdd(dst: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..dst.len() {
        dst[i] = a[i] + b[i];
    }
}

pub fn feSub(dst: &mut FieldElement, a: &FieldElement, b: &FieldElement) {
    for i in 0..dst.len() {
        dst[i] = a[i] - b[i];
    }
}

pub fn feCopy(dst: &mut FieldElement, src: &FieldElement) {
    for i in 0..dst.len() {
        dst[i] = src[i]
    }
}

// // Replace (f,g) with (g,g) if b == 1;
// // replace (f,g) with (f,g) if b == 0.
// //
// // Preconditions: b in {0,1}.
// func feCMove(f, g *fieldElement, b int32) {
// 	var x fieldElement
// 	b = -b
// 	for i := range x {
// 		x[i] = b & (f[i] ^ g[i])
// 	}
// 	for i := range f {
// 		f[i] ^= x[i]
// 	}
// }

// func load3(in []byte) int64 {
// 	r := int64(in[0])
// 	r |= int64(in[1]) << 8
// 	r |= int64(in[2]) << 16
// 	return r
// }

// func load4(in []byte) int64 {
// 	r := int64(in[0])
// 	r |= int64(in[1]) << 8
// 	r |= int64(in[2]) << 16
// 	r |= int64(in[3]) << 24
// 	return r
// }

// func feFromBytes(dst *fieldElement, src []byte) {
// 	h0 := load4(src[:])
// 	h1 := load3(src[4:]) << 6
// 	h2 := load3(src[7:]) << 5
// 	h3 := load3(src[10:]) << 3
// 	h4 := load3(src[13:]) << 2
// 	h5 := load4(src[16:])
// 	h6 := load3(src[20:]) << 7
// 	h7 := load3(src[23:]) << 5
// 	h8 := load3(src[26:]) << 4
// 	h9 := (load3(src[29:]) & 8388607) << 2

// 	var carry [10]int64
// 	carry[9] = (h9 + 1<<24) >> 25
// 	h0 += carry[9] * 19
// 	h9 -= carry[9] << 25
// 	carry[1] = (h1 + 1<<24) >> 25
// 	h2 += carry[1]
// 	h1 -= carry[1] << 25
// 	carry[3] = (h3 + 1<<24) >> 25
// 	h4 += carry[3]
// 	h3 -= carry[3] << 25
// 	carry[5] = (h5 + 1<<24) >> 25
// 	h6 += carry[5]
// 	h5 -= carry[5] << 25
// 	carry[7] = (h7 + 1<<24) >> 25
// 	h8 += carry[7]
// 	h7 -= carry[7] << 25

// 	carry[0] = (h0 + 1<<25) >> 26
// 	h1 += carry[0]
// 	h0 -= carry[0] << 26
// 	carry[2] = (h2 + 1<<25) >> 26
// 	h3 += carry[2]
// 	h2 -= carry[2] << 26
// 	carry[4] = (h4 + 1<<25) >> 26
// 	h5 += carry[4]
// 	h4 -= carry[4] << 26
// 	carry[6] = (h6 + 1<<25) >> 26
// 	h7 += carry[6]
// 	h6 -= carry[6] << 26
// 	carry[8] = (h8 + 1<<25) >> 26
// 	h9 += carry[8]
// 	h8 -= carry[8] << 26

// 	dst[0] = int32(h0)
// 	dst[1] = int32(h1)
// 	dst[2] = int32(h2)
// 	dst[3] = int32(h3)
// 	dst[4] = int32(h4)
// 	dst[5] = int32(h5)
// 	dst[6] = int32(h6)
// 	dst[7] = int32(h7)
// 	dst[8] = int32(h8)
// 	dst[9] = int32(h9)
// }

// // feToBytes marshals h to s.
// // Preconditions:
// //   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
// //
// // Write p=2^255-19; q=floor(h/p).
// // Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
// //
// // Proof:
// //   Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
// //   Also have |h-2^230 h9|<2^230 so |19 2^(-255)(h-2^230 h9)|<1/4.
// //
// //   Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
// //   Then 0<y<1.
// //
// //   Write r=h-pq.
// //   Have 0<=r<=p-1=2^255-20.
// //   Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
// //
// //   Write x=r+19(2^-255)r+y.
// //   Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
// //
// //   Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
// //   so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
// func feToBytes(s *[32]byte, h *fieldElement) {
// 	var carry [10]int32

// 	q := (19*h[9] + (1 << 24)) >> 25
// 	q = (h[0] + q) >> 26
// 	q = (h[1] + q) >> 25
// 	q = (h[2] + q) >> 26
// 	q = (h[3] + q) >> 25
// 	q = (h[4] + q) >> 26
// 	q = (h[5] + q) >> 25
// 	q = (h[6] + q) >> 26
// 	q = (h[7] + q) >> 25
// 	q = (h[8] + q) >> 26
// 	q = (h[9] + q) >> 25

// 	// Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20.
// 	h[0] += 19 * q
// 	// Goal: Output h-2^255 q, which is between 0 and 2^255-20.

// 	carry[0] = h[0] >> 26
// 	h[1] += carry[0]
// 	h[0] -= carry[0] << 26
// 	carry[1] = h[1] >> 25
// 	h[2] += carry[1]
// 	h[1] -= carry[1] << 25
// 	carry[2] = h[2] >> 26
// 	h[3] += carry[2]
// 	h[2] -= carry[2] << 26
// 	carry[3] = h[3] >> 25
// 	h[4] += carry[3]
// 	h[3] -= carry[3] << 25
// 	carry[4] = h[4] >> 26
// 	h[5] += carry[4]
// 	h[4] -= carry[4] << 26
// 	carry[5] = h[5] >> 25
// 	h[6] += carry[5]
// 	h[5] -= carry[5] << 25
// 	carry[6] = h[6] >> 26
// 	h[7] += carry[6]
// 	h[6] -= carry[6] << 26
// 	carry[7] = h[7] >> 25
// 	h[8] += carry[7]
// 	h[7] -= carry[7] << 25
// 	carry[8] = h[8] >> 26
// 	h[9] += carry[8]
// 	h[8] -= carry[8] << 26
// 	carry[9] = h[9] >> 25
// 	h[9] -= carry[9] << 25
// 	// h10 = carry9

// 	// Goal: Output h[0]+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
// 	// Have h[0]+...+2^230 h[9] between 0 and 2^255-1;
// 	// evidently 2^255 h10-2^255 q = 0.
// 	// Goal: Output h[0]+...+2^230 h[9].

// 	s[0] = byte(h[0] >> 0)
// 	s[1] = byte(h[0] >> 8)
// 	s[2] = byte(h[0] >> 16)
// 	s[3] = byte((h[0] >> 24) | (h[1] << 2))
// 	s[4] = byte(h[1] >> 6)
// 	s[5] = byte(h[1] >> 14)
// 	s[6] = byte((h[1] >> 22) | (h[2] << 3))
// 	s[7] = byte(h[2] >> 5)
// 	s[8] = byte(h[2] >> 13)
// 	s[9] = byte((h[2] >> 21) | (h[3] << 5))
// 	s[10] = byte(h[3] >> 3)
// 	s[11] = byte(h[3] >> 11)
// 	s[12] = byte((h[3] >> 19) | (h[4] << 6))
// 	s[13] = byte(h[4] >> 2)
// 	s[14] = byte(h[4] >> 10)
// 	s[15] = byte(h[4] >> 18)
// 	s[16] = byte(h[5] >> 0)
// 	s[17] = byte(h[5] >> 8)
// 	s[18] = byte(h[5] >> 16)
// 	s[19] = byte((h[5] >> 24) | (h[6] << 1))
// 	s[20] = byte(h[6] >> 7)
// 	s[21] = byte(h[6] >> 15)
// 	s[22] = byte((h[6] >> 23) | (h[7] << 3))
// 	s[23] = byte(h[7] >> 5)
// 	s[24] = byte(h[7] >> 13)
// 	s[25] = byte((h[7] >> 21) | (h[8] << 4))
// 	s[26] = byte(h[8] >> 4)
// 	s[27] = byte(h[8] >> 12)
// 	s[28] = byte((h[8] >> 20) | (h[9] << 6))
// 	s[29] = byte(h[9] >> 2)
// 	s[30] = byte(h[9] >> 10)
// 	s[31] = byte(h[9] >> 18)
// }

// func feIsNegative(f *fieldElement) byte {
// 	var s [32]byte
// 	feToBytes(&s, f)
// 	return s[0] & 1
// }

// func feIsNonZero(f *fieldElement) int32 {
// 	var s [32]byte
// 	feToBytes(&s, f)
// 	var x uint8
// 	for _, b := range s {
// 		x |= b
// 	}
// 	x |= x >> 4
// 	x |= x >> 2
// 	x |= x >> 1
// 	return int32(x & 1)
// }

// // feNeg sets h = -f
// //
// // Preconditions:
// //    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
// //
// // Postconditions:
// //    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
// func feNeg(h, f *fieldElement) {
// 	for i := range h {
// 		h[i] = -f[i]
// 	}
// }

/// feMul calculates h = f * g
/// Can overlap h with f or g.
///
/// Preconditions:
///    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
///    |g| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
///
/// Postconditions:
///    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
///
/// Notes on implementation strategy:
///
/// Using schoolbook multiplication.
/// Karatsuba would save a little in some cost models.
///
/// Most multiplications by 2 and 19 are 32-bit precomputations;
/// cheaper than 64-bit postcomputations.
///
/// There is one remaining multiplication by 19 in the carry chain;
/// one *19 precomputation can be merged into this,
/// but the resulting data flow is considerably less clean.
///
/// There are 12 carries below.
/// 10 of them are 2-way parallelizable and vectorizable.
/// Can get away with 11 carries, but then data flow is much deeper.
///
/// With tighter constraints on inputs can squeeze carries into int32.
pub fn feMul(h: &mut FieldElement, f: &FieldElement, g: &FieldElement) {
    let f0 = f[0];
    let f1 = f[1];
    let f2 = f[2];
    let f3 = f[3];
    let f4 = f[4];
    let f5 = f[5];
    let f6 = f[6];
    let f7 = f[7];
    let f8 = f[8];
    let f9 = f[9];
    let g0 = g[0];
    let g1 = g[1];
    let g2 = g[2];
    let g3 = g[3];
    let g4 = g[4];
    let g5 = g[5];
    let g6 = g[6];
    let g7 = g[7];
    let g8 = g[8];
    let g9 = g[9];
    let g1_19 = 19 * g1 /* 1.4*2^29 */;
    let g2_19 = 19 * g2 /* 1.4*2^30; still ok */;
    let g3_19 = 19 * g3;
    let g4_19 = 19 * g4;
    let g5_19 = 19 * g5;
    let g6_19 = 19 * g6;
    let g7_19 = 19 * g7;
    let g8_19 = 19 * g8;
    let g9_19 = 19 * g9;
    let f1_2 = 2 * f1;
    let f3_2 = 2 * f3;
    let f5_2 = 2 * f5;
    let f7_2 = 2 * f7;
    let f9_2 = 2 * f9;
    let f0g0 = (f0) as i64 * (g0) as i64;
    let f0g1 = (f0) as i64 * (g1) as i64;
    let f0g2 = (f0) as i64 * (g2) as i64;
    let f0g3 = (f0) as i64 * (g3) as i64;
    let f0g4 = (f0) as i64 * (g4) as i64;
    let f0g5 = (f0) as i64 * (g5) as i64;
    let f0g6 = (f0) as i64 * (g6) as i64;
    let f0g7 = (f0) as i64 * (g7) as i64;
    let f0g8 = (f0) as i64 * (g8) as i64;
    let f0g9 = (f0) as i64 * (g9) as i64;
    let f1g0 = (f1) as i64 * (g0) as i64;
    let f1g1_2 = (f1_2) as i64 * (g1) as i64;
    let f1g2 = (f1) as i64 * (g2) as i64;
    let f1g3_2 = (f1_2) as i64 * (g3) as i64;
    let f1g4 = (f1) as i64 * (g4) as i64;
    let f1g5_2 = (f1_2) as i64 * (g5) as i64;
    let f1g6 = (f1) as i64 * (g6) as i64;
    let f1g7_2 = (f1_2) as i64 * (g7) as i64;
    let f1g8 = (f1) as i64 * (g8) as i64;
    let f1g9_38 = (f1_2) as i64 * (g9_19) as i64;
    let f2g0 = (f2) as i64 * (g0) as i64;
    let f2g1 = (f2) as i64 * (g1) as i64;
    let f2g2 = (f2) as i64 * (g2) as i64;
    let f2g3 = (f2) as i64 * (g3) as i64;
    let f2g4 = (f2) as i64 * (g4) as i64;
    let f2g5 = (f2) as i64 * (g5) as i64;
    let f2g6 = (f2) as i64 * (g6) as i64;
    let f2g7 = (f2) as i64 * (g7) as i64;
    let f2g8_19 = (f2) as i64 * (g8_19) as i64;
    let f2g9_19 = (f2) as i64 * (g9_19) as i64;
    let f3g0 = (f3) as i64 * (g0) as i64;
    let f3g1_2 = (f3_2) as i64 * (g1) as i64;
    let f3g2 = (f3) as i64 * (g2) as i64;
    let f3g3_2 = (f3_2) as i64 * (g3) as i64;
    let f3g4 = (f3) as i64 * (g4) as i64;
    let f3g5_2 = (f3_2) as i64 * (g5) as i64;
    let f3g6 = (f3) as i64 * (g6) as i64;
    let f3g7_38 = (f3_2) as i64 * (g7_19) as i64;
    let f3g8_19 = (f3) as i64 * (g8_19) as i64;
    let f3g9_38 = (f3_2) as i64 * (g9_19) as i64;
    let f4g0 = (f4) as i64 * (g0) as i64;
    let f4g1 = (f4) as i64 * (g1) as i64;
    let f4g2 = (f4) as i64 * (g2) as i64;
    let f4g3 = (f4) as i64 * (g3) as i64;
    let f4g4 = (f4) as i64 * (g4) as i64;
    let f4g5 = (f4) as i64 * (g5) as i64;
    let f4g6_19 = (f4) as i64 * (g6_19) as i64;
    let f4g7_19 = (f4) as i64 * (g7_19) as i64;
    let f4g8_19 = (f4) as i64 * (g8_19) as i64;
    let f4g9_19 = (f4) as i64 * (g9_19) as i64;
    let f5g0 = (f5) as i64 * (g0) as i64;
    let f5g1_2 = (f5_2) as i64 * (g1) as i64;
    let f5g2 = (f5) as i64 * (g2) as i64;
    let f5g3_2 = (f5_2) as i64 * (g3) as i64;
    let f5g4 = (f5) as i64 * (g4) as i64;
    let f5g5_38 = (f5_2) as i64 * (g5_19) as i64;
    let f5g6_19 = (f5) as i64 * (g6_19) as i64;
    let f5g7_38 = (f5_2) as i64 * (g7_19) as i64;
    let f5g8_19 = (f5) as i64 * (g8_19) as i64;
    let f5g9_38 = (f5_2) as i64 * (g9_19) as i64;
    let f6g0 = (f6) as i64 * (g0) as i64;
    let f6g1 = (f6) as i64 * (g1) as i64;
    let f6g2 = (f6) as i64 * (g2) as i64;
    let f6g3 = (f6) as i64 * (g3) as i64;
    let f6g4_19 = (f6) as i64 * (g4_19) as i64;
    let f6g5_19 = (f6) as i64 * (g5_19) as i64;
    let f6g6_19 = (f6) as i64 * (g6_19) as i64;
    let f6g7_19 = (f6) as i64 * (g7_19) as i64;
    let f6g8_19 = (f6) as i64 * (g8_19) as i64;
    let f6g9_19 = (f6) as i64 * (g9_19) as i64;
    let f7g0 = (f7) as i64 * (g0) as i64;
    let f7g1_2 = (f7_2) as i64 * (g1) as i64;
    let f7g2 = (f7) as i64 * (g2) as i64;
    let f7g3_38 = (f7_2) as i64 * (g3_19) as i64;
    let f7g4_19 = (f7) as i64 * (g4_19) as i64;
    let f7g5_38 = (f7_2) as i64 * (g5_19) as i64;
    let f7g6_19 = (f7) as i64 * (g6_19) as i64;
    let f7g7_38 = (f7_2) as i64 * (g7_19) as i64;
    let f7g8_19 = (f7) as i64 * (g8_19) as i64;
    let f7g9_38 = (f7_2) as i64 * (g9_19) as i64;
    let f8g0 = (f8) as i64 * (g0) as i64;
    let f8g1 = (f8) as i64 * (g1) as i64;
    let f8g2_19 = (f8) as i64 * (g2_19) as i64;
    let f8g3_19 = (f8) as i64 * (g3_19) as i64;
    let f8g4_19 = (f8) as i64 * (g4_19) as i64;
    let f8g5_19 = (f8) as i64 * (g5_19) as i64;
    let f8g6_19 = (f8) as i64 * (g6_19) as i64;
    let f8g7_19 = (f8) as i64 * (g7_19) as i64;
    let f8g8_19 = (f8) as i64 * (g8_19) as i64;
    let f8g9_19 = (f8) as i64 * (g9_19) as i64;
    let f9g0 = (f9) as i64 * (g0) as i64;
    let f9g1_38 = (f9_2) as i64 * (g1_19) as i64;
    let f9g2_19 = (f9) as i64 * (g2_19) as i64;
    let f9g3_38 = (f9_2) as i64 * (g3_19) as i64;
    let f9g4_19 = (f9) as i64 * (g4_19) as i64;
    let f9g5_38 = (f9_2) as i64 * (g5_19) as i64;
    let f9g6_19 = (f9) as i64 * (g6_19) as i64;
    let f9g7_38 = (f9_2) as i64 * (g7_19) as i64;
    let f9g8_19 = (f9) as i64 * (g8_19) as i64;
    let f9g9_38 = (f9_2) as i64 * (g9_19) as i64;
    let mut h0 = f0g0
        + f1g9_38
        + f2g8_19
        + f3g7_38
        + f4g6_19
        + f5g5_38
        + f6g4_19
        + f7g3_38
        + f8g2_19
        + f9g1_38;
    let mut h1 =
        f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
    let mut h2 =
        f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
    let mut h3 =
        f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
    let mut h4 =
        f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
    let mut h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
    let mut h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
    let mut h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
    let mut h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
    let mut h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
    let mut carry = [0 as i64; 10];

    /*
      |h0| <= (1.1*1.1*2^52*(1+19+19+19+19)+1.1*1.1*2^50*(38+38+38+38+38))
        i.e. |h0| <= 1.2*2^59; narrower ranges for h2, h4, h6, h8
      |h1| <= (1.1*1.1*2^51*(1+1+19+19+19+19+19+19+19+19))
        i.e. |h1| <= 1.5*2^58; narrower ranges for h3, h5, h7, h9
    */
    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;
    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;
    /* |h0| <= 2^25 */
    /* |h4| <= 2^25 */
    /* |h1| <= 1.51*2^58 */
    /* |h5| <= 1.51*2^58 */
    carry[1] = (h1 + (1 << 24)) >> 25;
    h2 += carry[1];
    h1 -= carry[1] << 25;
    carry[5] = (h5 + (1 << 24)) >> 25;
    h6 += carry[5];
    h5 -= carry[5] << 25;
    /* |h1| <= 2^24; from now on fits into int32 */
    /* |h5| <= 2^24; from now on fits into int32 */
    /* |h2| <= 1.21*2^59 */
    /* |h6| <= 1.21*2^59 */
    carry[2] = (h2 + (1 << 25)) >> 26;
    h3 += carry[2];
    h2 -= carry[2] << 26;
    carry[6] = (h6 + (1 << 25)) >> 26;
    h7 += carry[6];
    h6 -= carry[6] << 26;
    /* |h2| <= 2^25; from now on fits into int32 unchanged */
    /* |h6| <= 2^25; from now on fits into int32 unchanged */
    /* |h3| <= 1.51*2^58 */
    /* |h7| <= 1.51*2^58 */
    carry[3] = (h3 + (1 << 24)) >> 25;
    h4 += carry[3];
    h3 -= carry[3] << 25;
    carry[7] = (h7 + (1 << 24)) >> 25;
    h8 += carry[7];
    h7 -= carry[7] << 25;
    /* |h3| <= 2^24; from now on fits into int32 unchanged */
    /* |h7| <= 2^24; from now on fits into int32 unchanged */
    /* |h4| <= 1.52*2^33 */
    /* |h8| <= 1.52*2^33 */
    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;
    carry[8] = (h8 + (1 << 25)) >> 26;
    h9 += carry[8];
    h8 -= carry[8] << 26;
    /* |h4| <= 2^25; from now on fits into int32 unchanged */
    /* |h8| <= 2^25; from now on fits into int32 unchanged */
    /* |h5| <= 1.01*2^24 */
    /* |h9| <= 1.51*2^58 */
    carry[9] = (h9 + (1 << 24)) >> 25;
    h0 += carry[9] * 19;
    h9 -= carry[9] << 25;
    /* |h9| <= 2^24; from now on fits into int32 unchanged */
    /* |h0| <= 1.8*2^37 */
    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;
    /* |h0| <= 2^25; from now on fits into int32 unchanged */
    /* |h1| <= 1.01*2^24 */
    h[0] = (h0) as i32;
    h[1] = (h1) as i32;
    h[2] = (h2) as i32;
    h[3] = (h3) as i32;
    h[4] = (h4) as i32;
    h[5] = (h5) as i32;
    h[6] = (h6) as i32;
    h[7] = (h7) as i32;
    h[8] = (h8) as i32;
    h[9] = (h9) as i32;
}

// feSquare calculates h = f*f. Can overlap h with f.
//
// Preconditions:
//    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
//
// Postconditions:
//    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
pub fn feSquare(h: &mut FieldElement, f: &FieldElement) {
    let f0 = f[0];
    let f1 = f[1];
    let f2 = f[2];
    let f3 = f[3];
    let f4 = f[4];
    let f5 = f[5];
    let f6 = f[6];
    let f7 = f[7];
    let f8 = f[8];
    let f9 = f[9];
    let f0_2 = 2 * f0;
    let f1_2 = 2 * f1;
    let f2_2 = 2 * f2;
    let f3_2 = 2 * f3;
    let f4_2 = 2 * f4;
    let f5_2 = 2 * f5;
    let f6_2 = 2 * f6;
    let f7_2 = 2 * f7;
    let f5_38 = 38 * f5; // 1.31*2^30
    let f6_19 = 19 * f6; // 1.31*2^30
    let f7_38 = 38 * f7; // 1.31*2^30
    let f8_19 = 19 * f8; // 1.31*2^30
    let f9_38 = 38 * f9; // 1.31*2^30
    let f0f0 = (f0) as i64 * (f0) as i64;
    let f0f1_2 = (f0_2) as i64 * (f1) as i64;
    let f0f2_2 = (f0_2) as i64 * (f2) as i64;
    let f0f3_2 = (f0_2) as i64 * (f3) as i64;
    let f0f4_2 = (f0_2) as i64 * (f4) as i64;
    let f0f5_2 = (f0_2) as i64 * (f5) as i64;
    let f0f6_2 = (f0_2) as i64 * (f6) as i64;
    let f0f7_2 = (f0_2) as i64 * (f7) as i64;
    let f0f8_2 = (f0_2) as i64 * (f8) as i64;
    let f0f9_2 = (f0_2) as i64 * (f9) as i64;
    let f1f1_2 = (f1_2) as i64 * (f1) as i64;
    let f1f2_2 = (f1_2) as i64 * (f2) as i64;
    let f1f3_4 = (f1_2) as i64 * (f3_2) as i64;
    let f1f4_2 = (f1_2) as i64 * (f4) as i64;
    let f1f5_4 = (f1_2) as i64 * (f5_2) as i64;
    let f1f6_2 = (f1_2) as i64 * (f6) as i64;
    let f1f7_4 = (f1_2) as i64 * (f7_2) as i64;
    let f1f8_2 = (f1_2) as i64 * (f8) as i64;
    let f1f9_76 = (f1_2) as i64 * (f9_38) as i64;
    let f2f2 = (f2) as i64 * (f2) as i64;
    let f2f3_2 = (f2_2) as i64 * (f3) as i64;
    let f2f4_2 = (f2_2) as i64 * (f4) as i64;
    let f2f5_2 = (f2_2) as i64 * (f5) as i64;
    let f2f6_2 = (f2_2) as i64 * (f6) as i64;
    let f2f7_2 = (f2_2) as i64 * (f7) as i64;
    let f2f8_38 = (f2_2) as i64 * (f8_19) as i64;
    let f2f9_38 = (f2) as i64 * (f9_38) as i64;
    let f3f3_2 = (f3_2) as i64 * (f3) as i64;
    let f3f4_2 = (f3_2) as i64 * (f4) as i64;
    let f3f5_4 = (f3_2) as i64 * (f5_2) as i64;
    let f3f6_2 = (f3_2) as i64 * (f6) as i64;
    let f3f7_76 = (f3_2) as i64 * (f7_38) as i64;
    let f3f8_38 = (f3_2) as i64 * (f8_19) as i64;
    let f3f9_76 = (f3_2) as i64 * (f9_38) as i64;
    let f4f4 = (f4) as i64 * (f4) as i64;
    let f4f5_2 = (f4_2) as i64 * (f5) as i64;
    let f4f6_38 = (f4_2) as i64 * (f6_19) as i64;
    let f4f7_38 = (f4) as i64 * (f7_38) as i64;
    let f4f8_38 = (f4_2) as i64 * (f8_19) as i64;
    let f4f9_38 = (f4) as i64 * (f9_38) as i64;
    let f5f5_38 = (f5) as i64 * (f5_38) as i64;
    let f5f6_38 = (f5_2) as i64 * (f6_19) as i64;
    let f5f7_76 = (f5_2) as i64 * (f7_38) as i64;
    let f5f8_38 = (f5_2) as i64 * (f8_19) as i64;
    let f5f9_76 = (f5_2) as i64 * (f9_38) as i64;
    let f6f6_19 = (f6) as i64 * (f6_19) as i64;
    let f6f7_38 = (f6) as i64 * (f7_38) as i64;
    let f6f8_38 = (f6_2) as i64 * (f8_19) as i64;
    let f6f9_38 = (f6) as i64 * (f9_38) as i64;
    let f7f7_38 = (f7) as i64 * (f7_38) as i64;
    let f7f8_38 = (f7_2) as i64 * (f8_19) as i64;
    let f7f9_76 = (f7_2) as i64 * (f9_38) as i64;
    let f8f8_19 = (f8) as i64 * (f8_19) as i64;
    let f8f9_38 = (f8) as i64 * (f9_38) as i64;
    let f9f9_38 = (f9) as i64 * (f9_38) as i64;
    let mut h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    let mut h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    let mut h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    let mut h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    let mut h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    let mut h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    let mut h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    let mut h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    let mut h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    let mut h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    let mut carry = [0 as i64; 10];

    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;
    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;

    carry[1] = (h1 + (1 << 24)) >> 25;
    h2 += carry[1];
    h1 -= carry[1] << 25;
    carry[5] = (h5 + (1 << 24)) >> 25;
    h6 += carry[5];
    h5 -= carry[5] << 25;

    carry[2] = (h2 + (1 << 25)) >> 26;
    h3 += carry[2];
    h2 -= carry[2] << 26;
    carry[6] = (h6 + (1 << 25)) >> 26;
    h7 += carry[6];
    h6 -= carry[6] << 26;

    carry[3] = (h3 + (1 << 24)) >> 25;
    h4 += carry[3];
    h3 -= carry[3] << 25;
    carry[7] = (h7 + (1 << 24)) >> 25;
    h8 += carry[7];
    h7 -= carry[7] << 25;

    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;
    carry[8] = (h8 + (1 << 25)) >> 26;
    h9 += carry[8];
    h8 -= carry[8] << 26;

    carry[9] = (h9 + (1 << 24)) >> 25;
    h0 += carry[9] * 19;
    h9 -= carry[9] << 25;

    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;

    h[0] = (h0) as i32;
    h[1] = (h1) as i32;
    h[2] = (h2) as i32;
    h[3] = (h3) as i32;
    h[4] = (h4) as i32;
    h[5] = (h5) as i32;
    h[6] = (h6) as i32;
    h[7] = (h7) as i32;
    h[8] = (h8) as i32;
    h[9] = (h9) as i32;
}

// feSquare2 sets h = 2 * f * f
//
// Can overlap h with f.
//
// Preconditions:
//    |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
//
// Postconditions:
//    |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
// See fe_mul.c for discussion of implementation strategy.
pub fn feSquare2(h: &mut FieldElement, f: &FieldElement) {
    let f0 = f[0];
    let f1 = f[1];
    let f2 = f[2];
    let f3 = f[3];
    let f4 = f[4];
    let f5 = f[5];
    let f6 = f[6];
    let f7 = f[7];
    let f8 = f[8];
    let f9 = f[9];
    let f0_2 = 2 * f0;
    let f1_2 = 2 * f1;
    let f2_2 = 2 * f2;
    let f3_2 = 2 * f3;
    let f4_2 = 2 * f4;
    let f5_2 = 2 * f5;
    let f6_2 = 2 * f6;
    let f7_2 = 2 * f7;
    let f5_38 = 38 * f5; // 1.959375*2^30
    let f6_19 = 19 * f6; // 1.959375*2^30
    let f7_38 = 38 * f7; // 1.959375*2^30
    let f8_19 = 19 * f8; // 1.959375*2^30
    let f9_38 = 38 * f9; // 1.959375*2^30
    let f0f0 = (f0) as i64 * (f0) as i64;
    let f0f1_2 = (f0_2) as i64 * (f1) as i64;
    let f0f2_2 = (f0_2) as i64 * (f2) as i64;
    let f0f3_2 = (f0_2) as i64 * (f3) as i64;
    let f0f4_2 = (f0_2) as i64 * (f4) as i64;
    let f0f5_2 = (f0_2) as i64 * (f5) as i64;
    let f0f6_2 = (f0_2) as i64 * (f6) as i64;
    let f0f7_2 = (f0_2) as i64 * (f7) as i64;
    let f0f8_2 = (f0_2) as i64 * (f8) as i64;
    let f0f9_2 = (f0_2) as i64 * (f9) as i64;
    let f1f1_2 = (f1_2) as i64 * (f1) as i64;
    let f1f2_2 = (f1_2) as i64 * (f2) as i64;
    let f1f3_4 = (f1_2) as i64 * (f3_2) as i64;
    let f1f4_2 = (f1_2) as i64 * (f4) as i64;
    let f1f5_4 = (f1_2) as i64 * (f5_2) as i64;
    let f1f6_2 = (f1_2) as i64 * (f6) as i64;
    let f1f7_4 = (f1_2) as i64 * (f7_2) as i64;
    let f1f8_2 = (f1_2) as i64 * (f8) as i64;
    let f1f9_76 = (f1_2) as i64 * (f9_38) as i64;
    let f2f2 = (f2) as i64 * (f2) as i64;
    let f2f3_2 = (f2_2) as i64 * (f3) as i64;
    let f2f4_2 = (f2_2) as i64 * (f4) as i64;
    let f2f5_2 = (f2_2) as i64 * (f5) as i64;
    let f2f6_2 = (f2_2) as i64 * (f6) as i64;
    let f2f7_2 = (f2_2) as i64 * (f7) as i64;
    let f2f8_38 = (f2_2) as i64 * (f8_19) as i64;
    let f2f9_38 = (f2) as i64 * (f9_38) as i64;
    let f3f3_2 = (f3_2) as i64 * (f3) as i64;
    let f3f4_2 = (f3_2) as i64 * (f4) as i64;
    let f3f5_4 = (f3_2) as i64 * (f5_2) as i64;
    let f3f6_2 = (f3_2) as i64 * (f6) as i64;
    let f3f7_76 = (f3_2) as i64 * (f7_38) as i64;
    let f3f8_38 = (f3_2) as i64 * (f8_19) as i64;
    let f3f9_76 = (f3_2) as i64 * (f9_38) as i64;
    let f4f4 = (f4) as i64 * (f4) as i64;
    let f4f5_2 = (f4_2) as i64 * (f5) as i64;
    let f4f6_38 = (f4_2) as i64 * (f6_19) as i64;
    let f4f7_38 = (f4) as i64 * (f7_38) as i64;
    let f4f8_38 = (f4_2) as i64 * (f8_19) as i64;
    let f4f9_38 = (f4) as i64 * (f9_38) as i64;
    let f5f5_38 = (f5) as i64 * (f5_38) as i64;
    let f5f6_38 = (f5_2) as i64 * (f6_19) as i64;
    let f5f7_76 = (f5_2) as i64 * (f7_38) as i64;
    let f5f8_38 = (f5_2) as i64 * (f8_19) as i64;
    let f5f9_76 = (f5_2) as i64 * (f9_38) as i64;
    let f6f6_19 = (f6) as i64 * (f6_19) as i64;
    let f6f7_38 = (f6) as i64 * (f7_38) as i64;
    let f6f8_38 = (f6_2) as i64 * (f8_19) as i64;
    let f6f9_38 = (f6) as i64 * (f9_38) as i64;
    let f7f7_38 = (f7) as i64 * (f7_38) as i64;
    let f7f8_38 = (f7_2) as i64 * (f8_19) as i64;
    let f7f9_76 = (f7_2) as i64 * (f9_38) as i64;
    let f8f8_19 = (f8) as i64 * (f8_19) as i64;
    let f8f9_38 = (f8) as i64 * (f9_38) as i64;
    let f9f9_38 = (f9) as i64 * (f9_38) as i64;
    let mut h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
    let mut h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
    let mut h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
    let mut h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
    let mut h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
    let mut h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
    let mut h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
    let mut h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
    let mut h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
    let mut h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
    let mut carry = [0 as i64; 10];

    h0 += h0;
    h1 += h1;
    h2 += h2;
    h3 += h3;
    h4 += h4;
    h5 += h5;
    h6 += h6;
    h7 += h7;
    h8 += h8;
    h9 += h9;

    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;
    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;

    carry[1] = (h1 + (1 << 24)) >> 25;
    h2 += carry[1];
    h1 -= carry[1] << 25;
    carry[5] = (h5 + (1 << 24)) >> 25;
    h6 += carry[5];
    h5 -= carry[5] << 25;

    carry[2] = (h2 + (1 << 25)) >> 26;
    h3 += carry[2];
    h2 -= carry[2] << 26;
    carry[6] = (h6 + (1 << 25)) >> 26;
    h7 += carry[6];
    h6 -= carry[6] << 26;

    carry[3] = (h3 + (1 << 24)) >> 25;
    h4 += carry[3];
    h3 -= carry[3] << 25;
    carry[7] = (h7 + (1 << 24)) >> 25;
    h8 += carry[7];
    h7 -= carry[7] << 25;

    carry[4] = (h4 + (1 << 25)) >> 26;
    h5 += carry[4];
    h4 -= carry[4] << 26;
    carry[8] = (h8 + (1 << 25)) >> 26;
    h9 += carry[8];
    h8 -= carry[8] << 26;

    carry[9] = (h9 + (1 << 24)) >> 25;
    h0 += carry[9] * 19;
    h9 -= carry[9] << 25;

    carry[0] = (h0 + (1 << 25)) >> 26;
    h1 += carry[0];
    h0 -= carry[0] << 26;

    h[0] = (h0) as i32;
    h[1] = (h1) as i32;
    h[2] = (h2) as i32;
    h[3] = (h3) as i32;
    h[4] = (h4) as i32;
    h[5] = (h5) as i32;
    h[6] = (h6) as i32;
    h[7] = (h7) as i32;
    h[8] = (h8) as i32;
    h[9] = (h9) as i32;
}

// func feInvert(out, z *fieldElement) {
// 	var t0, t1, t2, t3 fieldElement
// 	var i int

// 	feSquare(&t0, z)        // 2^1
// 	feSquare(&t1, &t0)      // 2^2
// 	for i = 1; i < 2; i++ { // 2^3
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t1, z, &t1)      // 2^3 + 2^0
// 	feMul(&t0, &t0, &t1)    // 2^3 + 2^1 + 2^0
// 	feSquare(&t2, &t0)      // 2^4 + 2^2 + 2^1
// 	feMul(&t1, &t1, &t2)    // 2^4 + 2^3 + 2^2 + 2^1 + 2^0
// 	feSquare(&t2, &t1)      // 5,4,3,2,1
// 	for i = 1; i < 5; i++ { // 9,8,7,6,5
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t1, &t2, &t1)     // 9,8,7,6,5,4,3,2,1,0
// 	feSquare(&t2, &t1)       // 10..1
// 	for i = 1; i < 10; i++ { // 19..10
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t2, &t2, &t1)     // 19..0
// 	feSquare(&t3, &t2)       // 20..1
// 	for i = 1; i < 20; i++ { // 39..20
// 		feSquare(&t3, &t3)
// 	}
// 	feMul(&t2, &t3, &t2)     // 39..0
// 	feSquare(&t2, &t2)       // 40..1
// 	for i = 1; i < 10; i++ { // 49..10
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t1, &t2, &t1)     // 49..0
// 	feSquare(&t2, &t1)       // 50..1
// 	for i = 1; i < 50; i++ { // 99..50
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t2, &t2, &t1)      // 99..0
// 	feSquare(&t3, &t2)        // 100..1
// 	for i = 1; i < 100; i++ { // 199..100
// 		feSquare(&t3, &t3)
// 	}
// 	feMul(&t2, &t3, &t2)     // 199..0
// 	feSquare(&t2, &t2)       // 200..1
// 	for i = 1; i < 50; i++ { // 249..50
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t1, &t2, &t1)    // 249..0
// 	feSquare(&t1, &t1)      // 250..1
// 	for i = 1; i < 5; i++ { // 254..5
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(out, &t1, &t0) // 254..5,3,1,0
// }

// func fePow22523(out, z *fieldElement) {
// 	var t0, t1, t2 fieldElement
// 	var i int

// 	feSquare(&t0, z)
// 	for i = 1; i < 1; i++ {
// 		feSquare(&t0, &t0)
// 	}
// 	feSquare(&t1, &t0)
// 	for i = 1; i < 2; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t1, z, &t1)
// 	feMul(&t0, &t0, &t1)
// 	feSquare(&t0, &t0)
// 	for i = 1; i < 1; i++ {
// 		feSquare(&t0, &t0)
// 	}
// 	feMul(&t0, &t1, &t0)
// 	feSquare(&t1, &t0)
// 	for i = 1; i < 5; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t0, &t1, &t0)
// 	feSquare(&t1, &t0)
// 	for i = 1; i < 10; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t1, &t1, &t0)
// 	feSquare(&t2, &t1)
// 	for i = 1; i < 20; i++ {
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t1, &t2, &t1)
// 	feSquare(&t1, &t1)
// 	for i = 1; i < 10; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t0, &t1, &t0)
// 	feSquare(&t1, &t0)
// 	for i = 1; i < 50; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t1, &t1, &t0)
// 	feSquare(&t2, &t1)
// 	for i = 1; i < 100; i++ {
// 		feSquare(&t2, &t2)
// 	}
// 	feMul(&t1, &t2, &t1)
// 	feSquare(&t1, &t1)
// 	for i = 1; i < 50; i++ {
// 		feSquare(&t1, &t1)
// 	}
// 	feMul(&t0, &t1, &t0)
// 	feSquare(&t0, &t0)
// 	for i = 1; i < 2; i++ {
// 		feSquare(&t0, &t0)
// 	}
// 	feMul(out, &t0, z)
// }

// func (fe *fieldElement) String() string {
// 	s := "fieldElement{"
// 	for i := range fe {
// 		if i > 0 {
// 			s += ", "
// 		}
// 		s += fmt.Sprintf("%d", fe[i])
// 	}
// 	s += "}"
// 	return s
// }

pub fn load3(input: &[u8]) -> i64 {
    let mut r = input[0] as i64;
    r |= (input[1] as i64) << 8;
    r |= (input[2] as i64) << 16;
    r
}

pub fn load4(input: &[u8]) -> i64 {
    let mut r = input[0] as i64;
    r |= (input[1] as i64) << 8;
    r |= (input[2] as i64) << 16;
    r |= (input[3] as i64) << 24;
    r
}
