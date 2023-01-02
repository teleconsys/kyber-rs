use crate::{
    group::edwards25519::SuiteEd25519, util::random::Randstream, Group, Point, Random, Scalar,
};
use anyhow::Result;

pub fn el_gamal_encrypt<GROUP: Group>(
    group: GROUP,
    pubkey: &GROUP::POINT,
    message: &[u8],
) -> (GROUP::POINT, GROUP::POINT, Vec<u8>) {
    // Embed the message (or as much of it as will fit) into a curve point.
    let m = group
        .point()
        .embed(Some(message), &mut Randstream::default());
    let mut max = group.point().embed_len();
    if max > message.len() {
        max = message.len()
    }
    let remainder = message[max..].to_vec();
    // ElGamal-encrypt the point to produce ciphertext (K,C).
    let k = group.scalar().pick(&mut Randstream::default()); // ephemeral private key
    let k_caps = group.point().mul(&k, None); // ephemeral DH public key
    let s = group.point().mul(&k, Some(pubkey)); // ephemeral DH shared secret
    let c = s.clone().add(&s, &m); // message blinded with secret
    (k_caps, c, remainder)
}

pub fn el_gamal_decrypt<GROUP: Group>(
    group: GROUP,
    prikey: &<GROUP::POINT as Point>::SCALAR,
    k: GROUP::POINT,
    c: GROUP::POINT,
) -> Result<Vec<u8>> {
    // ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
    let s = group.point().mul(prikey, Some(&k)); // regenerate shared secret
    let p = group.point();
    let m = p.sub(&c, &s); // use to un-blind the message
    m.data()
}

/*
This example illustrates how the crypto toolkit may be used
to perform "pure" ElGamal encryption,
in which the message to be encrypted is small enough to be embedded
directly within a group element (e.g., in an elliptic curve point).
For basic background on ElGamal encryption see for example
http://en.wikipedia.org/wiki/ElGamal_encryption.

Most public-key crypto libraries tend not to support embedding data in points,
in part because for "vanilla" public-key encryption you don't need it:
one would normally just generate an ephemeral Diffie-Hellman secret
and use that to seed a symmetric-key crypto algorithm such as AES,
which is much more efficient per bit and works for arbitrary-length messages.
However, in many advanced public-key crypto algorithms it is often useful
to be able to embedded data directly into points and compute with them:
as just one of many examples,
the proactively verifiable anonymous messaging scheme prototyped in Verdict
(see http://dedis.cs.yale.edu/dissent/papers/verdict-abs).

For fancier versions of ElGamal encryption implemented in this toolkit
see for example anon.Encrypt, which encrypts a message for
one of several possible receivers forming an explicit anonymity set.
*/
#[test]
fn example_el_gamal_encryption() {
    let suite = SuiteEd25519::new_blake_sha256ed25519();

    // Create a public/private keypair
    let a = suite.scalar().pick(&mut suite.random_stream()); // Alice's private key
    let a_caps = suite.point().mul(&a, None); // Alice's public key

    // ElGamal-encrypt a message using the public key.
    let m = "The quick brown fox".as_bytes();
    let (k, c, _) = el_gamal_encrypt(suite, &a_caps, m);

    // Decrypt it using the corresponding private key.
    let dec_res = el_gamal_decrypt(suite, &a, k, c);

    // Make sure it worked!
    if dec_res.is_err() {
        panic!("decryption failed: {}", dec_res.err().unwrap())
    }
    let mm = dec_res.unwrap();
    if std::str::from_utf8(&mm).unwrap() != std::str::from_utf8(m).unwrap() {
        panic!(
            "decryption produced wrong output: {}",
            std::str::from_utf8(&mm).unwrap()
        );
    }
    println!(
        "Decryption succeeded: {}",
        std::str::from_utf8(&mm).unwrap()
    )

    // Output:
    // Decryption succeeded: The quick brown fox
}
