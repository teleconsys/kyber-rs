use std::io::{Read, Write};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{cipher::cipher::Stream, util::random::New};

const SIZE: usize = 32;

#[test]
fn test_mixed_entropy() {
    let r = "some io.Reader stream to be used for testing".as_bytes();

    let rng_core = Box::new(StdRng::from_entropy()) as Box<dyn RngCore>;
    let mut cipher = New(vec![Box::new(r), Box::new(rng_core) as Box<dyn Read>]);

    let mut src = [0 as u8; SIZE];
    let sb = "source buffer".as_bytes();
    src[..sb.len()].copy_from_slice(&sb);
    let mut dst = [0 as u8; SIZE + 1];
    let dst_len = dst.len();
    dst[dst_len - 1] = 0xff;

    cipher
        .xor_key_stream(&mut dst[..dst_len - 1], &src)
        .unwrap();
    if src.len() > 0 && src == dst[0..src.len()] {
        assert!(false, "src and dst should not be equal");
    }
    assert_eq!(dst[dst.len() - 1], 0xff, "last byte of dst chagned");
}

#[test]
fn test_empty_reader() {
    let r = "too small io.Reader".as_bytes();
    let mut cipher = New(vec![Box::new(r)]);
    let mut src = [0 as u8; SIZE];
    let b = "hello".as_bytes();
    src[..b.len()].copy_from_slice(b);
    let dst = [0 as u8; SIZE];
    let result = cipher.xor_key_stream(&mut dst.clone(), &src);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "all readers failed");
}

#[test]
fn test_crypto_only() {
    let mut cipher = New(vec![]);
    let mut src = [0 as u8; SIZE];
    src.as_mut().write("hello".as_bytes()).unwrap();
    let mut dst1 = [0 as u8; SIZE];
    cipher.xor_key_stream(&mut dst1, &src).unwrap();
    let mut dst2 = [0 as u8; SIZE];
    cipher.xor_key_stream(&mut dst2, &src).unwrap();
    assert_ne!(dst1, dst2, "dst1 and dst2 should not be equal");
}

#[test]
fn test_user_only() {
    let seed = "some io.Reader stream to be used for testing".as_bytes();
    let mut cipher1 = New(vec![Box::new(seed)]);
    let mut src = [0 as u8; SIZE];
    src.as_mut().write("hello".as_bytes()).unwrap();
    let mut dst1 = [0 as u8; SIZE];
    cipher1.xor_key_stream(&mut dst1, &src).unwrap();
    let mut cipher2 = New(vec![Box::new(seed)]);
    let mut dst2 = [0 as u8; SIZE];
    cipher2.xor_key_stream(&mut dst2, &src).unwrap();
    assert_eq!(dst1, dst2, "dst1/dst2 should be equal");
}

#[test]
fn test_incorrect_size() {
    let rng_core = Box::new(StdRng::from_entropy()) as Box<dyn RngCore>;
    let mut cipher = New(vec![Box::new(rng_core) as Box<dyn Read>]);
    let mut src = [0 as u8; SIZE];
    src.as_mut().write("hello".as_bytes()).unwrap();
    let mut dst = [0 as u8; SIZE + 1];
    let result = cipher.xor_key_stream(&mut dst, &src);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "XORKeyStream: mismatched buffer lengths"
    );
}
