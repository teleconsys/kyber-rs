use crate::xof::blake;
use crate::xof::xof::{XOFFactory, XOF};

struct BlakeF {}

impl XOFFactory for BlakeF {
    fn xof(&self, seed: Option<&[u8]>) -> Box<dyn XOF> {
        // return blake2xb.New(seed)
        Box::new(blake::Xof::new(seed))
    }
}

struct KeccakF {}

impl XOFFactory for KeccakF {
    fn xof(&self, _seed: Option<&[u8]>) -> Box<dyn XOF> {
        todo!()
        // return keccak.New(seed);
    }
}

fn impls() -> Vec<Box<dyn XOFFactory>> {
    vec![Box::new(BlakeF {}) /*, Box::new(keccakF {})*/]
}

#[test]
fn test_enc_dec() {
    let lengths = vec![0, 1, 16, 1024, 8192_usize];

    for i in impls() {
        for l in &lengths {
            test_enc_dec_impl(i.as_ref(), l);
        }
    }
}

fn test_enc_dec_impl(s: &(impl XOFFactory + ?Sized), _size: &usize) {
    // t.Logf("implementation %T sz %v", s, size)
    let key = "key".as_bytes();

    let mut s1 = s.xof(Some(key));
    let mut s2 = s.xof(Some(key));

    const SRC: &[u8] = "hello".as_bytes();

    let mut dst = [0_u8; SRC.len() + 1];
    dst[dst.len() - 1] = 0xff;

    s1.xor_key_stream(&mut dst, SRC).unwrap();
    assert_ne!(SRC, dst, "SRC/dst should not be equal");
    assert_eq!(dst[dst.len() - 1], 0xff, "last byte of dst changed");

    let mut dst2 = [0_u8; SRC.len()];
    s2.xor_key_stream(&mut dst2, &dst[0..SRC.len()]).unwrap();
    assert_eq!(SRC, dst2, "SRC/dst2 should be equal");
}

#[test]
fn test_clone_impls() {
    for i in impls() {
        test_clone(i.as_ref());
    }
}

fn test_clone(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)
    let key = "key".as_bytes();

    let mut s1 = s.xof(Some(key));
    let mut s2 = s1.clone();

    let src = "hello".as_bytes();
    let mut dst = vec![0; src.len() + 1];
    let dst_len = dst.len();
    dst[dst_len - 1] = 0xff;

    s1.xor_key_stream(&mut dst, src).unwrap();
    assert_ne!(src, &dst[0..src.len()], "src/dst should not be equal");
    assert_eq!(dst[dst_len - 1], 0xff, "last byte of dst chagned");

    let mut dst2 = vec![0_u8; src.len()];
    s2.xor_key_stream(&mut dst2, &dst[0..src.len()]).unwrap();
    assert_eq!(src, dst2, "src/dst2 should be equal");
}

#[test]
fn test_errors_impls() {
    for i in impls() {
        test_errors(i.as_ref());
    }
}

fn test_errors(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)

    let key = "key".as_bytes();
    let mut s1 = s.xof(Some(key));
    let src = "hello".as_bytes();
    let dst: &mut [u8] = &mut [0; 100];
    s1.xor_key_stream(dst, src).unwrap();
    assert!(s1.write(src).is_err(), "write after read should error");

    let result = s1.as_mut().xor_key_stream(&mut dst[0..src.len() - 1], src);
    assert!(result.is_err(), "dst too short should error");
}

#[test]
fn test_random_impls() {
    for i in impls() {
        test_random(i.as_ref());
    }
}

fn test_random(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)
    let mut xof1 = s.xof(None);

    for _ in 0..1000 {
        let mut dst1 = [0_u8; 1024];
        xof1.read_exact(&mut dst1).unwrap();
        let mut dst2 = [0_u8; 1024];
        xof1.read_exact(&mut dst2).unwrap();
        let d = bit_diff(&dst1, &dst2);

        assert!((d - 0.50).abs() < 0.1, "bitDiff {}", d);
    }

    // Check that two seeds give expected mean bitdiff on first block
    let mut xof1 = s.xof(Some("a".as_bytes()));
    let mut xof2 = s.xof(Some("b".as_bytes()));
    let mut dst1 = [0_u8; 1024];
    xof1.read_exact(&mut dst1).unwrap();
    let mut dst2 = [0_u8; 1024];
    xof2.read_exact(&mut dst2).unwrap();
    let d = bit_diff(&dst1, &dst2);
    assert!((d - 0.50).abs() < 0.1, "two seed bitDiff {}", d);
}

/// bit_diff compares the bits between two arrays returning the fraction
/// of differences. If the two arrays are not of the same length
/// no comparison is made and a -1 is returned.
fn bit_diff(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() {
        return -1_f64;
    }

    let mut count = 0;
    for i in 0..a.len() {
        for j in 0..8 {
            count += (((a[i] ^ b[i]) >> (j as u64)) & 1) as i32;
        }
    }

    (count as f64) / ((a.len() * 8) as f64)
}

#[test]
fn test_no_seed_impls() {
    for i in impls() {
        test_no_seed(i.as_ref());
    }
}

fn test_no_seed(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)

    let mut xof1 = s.xof(None);
    let mut dst1 = [0_u8; 1024];
    xof1.read_exact(&mut dst1).unwrap();

    let mut xof2 = s.xof(Some(&[]));
    let mut dst2 = [0_u8; 1024];
    xof2.read_exact(&mut dst2).unwrap();
    assert_eq!(dst1, dst2, "hash with two flavors of zero seed not same");
}

#[test]
fn test_reseed_impls() {
    for i in impls() {
        test_reseed(i.as_ref());
    }
}

fn test_reseed(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)
    let seed = "seed".as_bytes();

    let mut xof1 = s.xof(Some(seed));
    let mut dst1 = [0_u8; 1024];
    xof1.read_exact(&mut dst1).unwrap();
    assert!(xof1.write(seed).is_err(), "without reseed should be Err");
    xof1.reseed();
    let mut xof2 = xof1.clone();
    assert!(xof1.write(seed).is_ok(), "after reseed should be Ok");

    let mut dst2 = [0_u8; 1024];
    xof2.read_exact(&mut dst2).unwrap();

    let d = bit_diff(&dst1, &dst2);
    assert!((d - 0.50).abs() < 0.1, "reseed bitDiff {}", d)
}

#[test]
fn test_enc_dec_mismatch_impls() {
    for i in impls() {
        test_enc_dec_mismatch(i.as_ref());
    }
}

fn test_enc_dec_mismatch(s: &(impl XOFFactory + ?Sized)) {
    // t.Logf("implementation %T", s)
    let seed = "seed".as_bytes();
    let mut x1 = s.xof(Some(seed));
    let mut x2 = s.xof(Some(seed));
    let msg = "hello world".as_bytes().to_vec();
    let mut enc = vec![0_u8; msg.len()];
    let mut dec = vec![0_u8; msg.len()];
    x1.xor_key_stream(&mut enc[0..3], &msg[0..3]).unwrap();
    x1.xor_key_stream(&mut enc[3..4], &msg[3..4]).unwrap();
    x1.xor_key_stream(&mut enc[4..], &msg[4..]).unwrap();
    x2.xor_key_stream(&mut dec[0..5], &enc[0..5]).unwrap();
    x2.xor_key_stream(&mut dec[5..], &enc[5..]).unwrap();
    assert_eq!(msg, dec, "wrong decode");
}
