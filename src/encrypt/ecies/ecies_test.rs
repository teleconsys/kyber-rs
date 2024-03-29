use crate::{group::edwards25519::SuiteEd25519, util::random::RandStream, Group, Point, Scalar};

use super::{decrypt, encrypt};

#[test]
fn test_ecies() {
    let message = "Hello ECIES".as_bytes();
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let private = suite.scalar().pick(&mut RandStream::default());
    let public = suite.point().mul(&private, None);
    let ciphertext = encrypt(suite, public, message).unwrap();
    let plaintext = decrypt(suite, private, &ciphertext).unwrap();
    assert_eq!(message, plaintext);
}

#[test]
fn test_ecies_fail_point() {
    let message = "Hello ECIES".as_bytes();
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let private = suite.scalar().pick(&mut RandStream::default());
    let public = suite.point().mul(&private, None);
    let mut ciphertext = encrypt(suite, public, message).unwrap();
    ciphertext[0] ^= 0xff;
    // TODO: fix this check to get the specific error
    let res = decrypt(suite, private, &ciphertext);
    assert!(res.is_err())
}

#[test]
fn test_ecies_fail_ciphertext() {
    let message = "Hello ECIES".as_bytes();
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let private = suite.scalar().pick(&mut RandStream::default());
    let public = suite.point().mul(&private, None);
    let mut ciphertext = encrypt(suite, public, message).unwrap();
    let l = suite.point_len();
    ciphertext[l] ^= 0xff;
    // TODO: fix this check to get the specific error
    let res = decrypt(suite, private, &ciphertext);
    assert!(res.is_err())
}
