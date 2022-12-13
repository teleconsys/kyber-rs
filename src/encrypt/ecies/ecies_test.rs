use crate::{group::{edwards25519::SuiteEd25519, HashFactory}, util::random::Randstream, Group, Point, Scalar};

use super::{encrypt, decrypt};

#[test]
fn test_ecies() {
	let message = "Hello ECIES".as_bytes();
	let suite = SuiteEd25519::new_blake_sha256ed25519();
	let private = suite.scalar().pick(&mut Randstream::default());
	let public = suite.point().mul(&private, None);
	let ciphertext = encrypt(suite, public, message, None).unwrap(); // TODO should be some
	let plaintext = decrypt(suite, private, &ciphertext, None).unwrap(); // TODO should be some
    assert_eq!(message, plaintext);
}

#[test]
fn test_ecies_fail_point() {
	let message = "Hello ECIES".as_bytes();
	let suite = SuiteEd25519::new_blake_sha256ed25519();
	let private = suite.scalar().pick(&mut Randstream::default());
	let public = suite.point().mul(&private, None);
	let mut ciphertext = encrypt(suite, public, message, None).unwrap();
	ciphertext[0] ^= 0xff;
	let res = decrypt(suite, private, &ciphertext, None);
	assert!(res.is_err())
}

#[test]
fn test_ecies_fail_ciphertext() {
	let message = "Hello ECIES".as_bytes();
	let suite = SuiteEd25519::new_blake_sha256ed25519();
	let private = suite.scalar().pick(&mut Randstream::default());
	let public = suite.point().mul(&private, None);
	let mut ciphertext = encrypt(suite, public, message, None).unwrap();
	let l = suite.point_len();
	ciphertext[l] ^= 0xff;
	let res = decrypt(suite, private, &ciphertext, None);
	assert!(res.is_err())
}
