use super::SuiteEd25519;
use crate::util::test;

impl test::Suite for SuiteEd25519 {}

#[test]
fn test_suite() {
    test::suite_test(SuiteEd25519::new_blake3_sha256_ed25519()).unwrap()
}
