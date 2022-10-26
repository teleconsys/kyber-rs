// This code is a port of the public domain, "ref10" implementation of ed25519
// from SUPERCOP.

/// FieldElement  represents an element of the field GF(2^255 - 19).  An element
/// t, entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
/// t[3]+2^102 t[4]+...+2^230 t[9].  Bounds on each t[i] vary depending on
/// context.
pub type FieldElement = [i32; 10];

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
