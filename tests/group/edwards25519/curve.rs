use kyber_rs::{
    group::edwards25519::{Curve, SuiteEd25519},
    util::key::Generator,
    Random,
};

#[test]
fn test_curve_new_key() {
    let group = Curve::default();
    let t_suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let mut stream = t_suite.random_stream();

    for _ in 0..10u32.pow(6u32) {
        let s = group.new_key(&mut stream).unwrap().unwrap();

        // little-endian check of a multiple of 8
        assert_eq!(0u8, s.v[0] & 7)
    }
}
