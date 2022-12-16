use flate2::read;
use scanner_rust::Scanner;
use std::fs::File;

use kyber_rs::{
    cipher::cipher,
    encoding::BinaryMarshaler,
    group::edwards25519::SuiteEd25519,
    sign::eddsa::{verify, EdDSA},
    util::random,
    Random,
};

use anyhow::Result;

/// Test the property of a EdDSA signature
#[test]
pub fn test_eddsa_signing_random() {
    let suite = SuiteEd25519::new_blake_sha256ed25519();

    for _ in 0..10000 {
        let ed = EdDSA::new(&mut suite.random_stream()).unwrap();

        let mut msg = [0u8; 32];
        random::bytes(&mut msg, &mut suite.random_stream()).unwrap();

        let sig = ed.sign(&msg).unwrap();

        // see https://tools.ietf.org/html/rfc8032#section-5.1.6 (item 6.)
        assert_eq!(0u8, sig[63] & 0xe0);
        verify(&ed.public, &msg, &sig).unwrap();
    }
}

/// Adapted from golang.org/x/crypto/ed25519.
#[test]
fn test_golden() {
    // sign.input.gz is a selection of test cases from
    // https://ed25519.cr.yp.to/python/sign.input
    let test_data_z = File::open("src/sign/eddsa/testdata/sign.input.gz").unwrap();
    let mut gz_decoder = read::GzDecoder::new(test_data_z);
    let mut scanner = Scanner::new(&mut gz_decoder);

    let mut line_no = 0;

    const SIGNATURE_SIZE: usize = 64;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;

    loop {
        let line = match scanner.next().unwrap() {
            Some(text) => text,
            None => break,
        };

        line_no += 1;

        let parts: Vec<&str> = line.split(":").collect();
        if parts.len() != 5 {
            panic!("bad number of parts on line {}", line_no)
        }

        let priv_bytes = hex::decode(parts[0]).unwrap();
        let pub_key = hex::decode(parts[1]).unwrap();
        let msg = hex::decode(parts[2]).unwrap();
        let mut sig = hex::decode(parts[3]).unwrap();
        // The signatures in the test vectors also include the message
        // at the end, but we just want R and S.
        sig = sig[..SIGNATURE_SIZE].to_vec();

        if pub_key.len() != PUBLIC_KEY_SIZE {
            panic!(
                "bad public key length on line {}: got {} bytes",
                line_no,
                pub_key.len()
            );
        }

        let mut priv_long = [0u8; PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE];
        priv_long.copy_from_slice(&priv_bytes);
        priv_long[32..].copy_from_slice(&pub_key);

        let mut stream = constant_stream(priv_bytes);
        let ed = EdDSA::new(&mut stream).unwrap();

        let data = ed.public.marshal_binary().unwrap();
        if data != pub_key {
            panic!(
                "Public not equal on line {}: {:?} vs {:?}",
                line_no, pub_key, data
            )
        }

        let sig2 = ed.sign(&msg).unwrap();

        if sig != sig2 {
            panic!(
                "different signature result on line {}: {:?} vs {:?}",
                line_no, sig, sig2
            )
        }

        verify(&ed.public, &msg, &sig2).unwrap();
    }
}

pub struct ConstantStream {
    pub seed: Vec<u8>,
}

impl cipher::Stream for ConstantStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], _: &[u8]) -> Result<()> {
        Ok(dst.copy_from_slice(&self.seed))
    }
}

// ConstantStream is a cipher.Stream which always returns
// the same value.
pub fn constant_stream(buff: Vec<u8>) -> Box<dyn cipher::Stream> {
    return Box::new(ConstantStream {
        seed: buff[..32].to_vec(),
    });
}
