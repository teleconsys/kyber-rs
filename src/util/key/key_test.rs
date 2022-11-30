use crate::{group::edwards25519::SuiteEd25519, Group, Point};

use super::new_key_pair;

#[test]
fn test_new_key_pair() {
    let suite = SuiteEd25519::new_blake_sha256ed25519();
    let keypair = new_key_pair(suite).unwrap();
    let public = suite.point().mul(&keypair.private, None);

    assert_eq!(public, keypair.public);
}

// // A type to test interface Generator by intentionally creating a fixed private key.
// struct FixedPrivSuiteEd25519(SuiteEd25519);

// impl Generator<EdScalar> for FixedPrivSuiteEd25519 {
//     fn new_key<S: crate::cipher::Stream>(self, stream: &mut S) -> anyhow::Result<EdScalar> {
//         Ok(self.0.scalar().set_int64(33))
//     }
// }

// impl FixedPrivSuiteEd25519 {
//     /// This is never called anyway, so it doesn't matter what it returns.
//     fn random_stream<S: crate::cipher::Stream>() {}
// }

// fn test_new_key_pair_gen() {
//     let suite = &FixedPrivSuiteEd25519::default();
//     let key = new_key_pair(suite);

//     let scalar33 = suite.scalar().set_int64(33);
//     assert_eq!(key.private, scalar33);
// }
