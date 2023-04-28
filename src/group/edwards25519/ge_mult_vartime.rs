use super::ge::{
    slide, CachedGroupElement, CompletedGroupElement, ExtendedGroupElement, ProjectiveGroupElement,
};

/// [`ge_scalar_mult_vartime()`] computes `h = a*B`, where
///   `a = a[0]+256*a[1]+...+256^31 a[31]`
///   `B` is the Ed25519 base point `(x,4/5)` with `x` positive.
///
/// Preconditions:
///   `a[31] <= 127`
pub fn ge_scalar_mult_vartime(
    h: &mut ExtendedGroupElement,
    a: &mut [u8; 32],
    a_p: &mut ExtendedGroupElement,
) {
    let mut a_slide = [0_i8; 256];
    let mut ai = [CachedGroupElement::default(); 8]; // A,3A,5A,7A,9A,11A,13A,15A
    let mut t = CompletedGroupElement::default();
    let mut u = ExtendedGroupElement::default();
    let mut a2 = ExtendedGroupElement::default();
    let mut r = ProjectiveGroupElement::default();

    // Slide through the scalar exponent clumping sequences of bits,
    // resulting in only zero or odd multipliers between -15 and 15.
    slide(&mut a_slide, a);

    // Form an array of odd multiples of A from 1A through 15A,
    // in addition-ready cached group element form.
    // We only need odd multiples of A because slide()
    // produces only odd-multiple clumps of bits.
    a_p.get_cached(&mut ai[0]);
    a_p.double(&mut t);
    t.to_extended(&mut a2);
    for i in 0..7 {
        t.add(&a2, &ai[i]);
        t.to_extended(&mut u);
        u.get_cached(&mut ai[i + 1]);
    }

    // Process the multiplications from most-significant bit downward
    let mut i = 255_usize;
    for j in (0..=256).rev() {
        if j == 0 {
            // no bits set
            h.zero();
            return;
        }
        if a_slide[j - 1] != 0 {
            i = j - 1;
            break;
        }
    }

    // first (most-significant) nonzero clump of bits
    u.zero();
    match a_slide[i] {
        a if a > 0 => t.add(&u, &ai[(a / 2) as usize]),
        a if a < 0 => t.sub(&u, &ai[((-a) / 2) as usize]),
        _ => (),
    }

    // remaining bits
    for j in (0..i).rev() {
        t.to_projective(&mut r);
        r.double(&mut t);

        match a_slide[j] {
            a if a > 0 => {
                t.to_extended(&mut u);
                t.add(&u, &ai[(a / 2) as usize])
            }
            a if a < 0 => {
                t.to_extended(&mut u);
                t.sub(&u, &ai[((-a) / 2) as usize])
            }
            _ => (),
        }
    }

    t.to_extended(h);
}
