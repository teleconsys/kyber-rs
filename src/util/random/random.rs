use std::{
    cmp::Ordering,
    io::{Read, Write},
};

use num_bigint::BigInt;
use num_bigint_dig as num_bigint;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{
    cipher::{cipher::Stream, StreamError},
    xof::blake3::Xof,
};

/// [`bits()`] chooses a uniform random [`BigInt`] with a given maximum `bit_len`.
/// If `exact` is `true`, choose a [`BigInt`] with _exactly_ that `bit_len`, not less
pub fn bits(bit_len: u64, exact: bool, rand: &mut impl Stream) -> Vec<u8> {
    let mut b: Vec<u8> = vec![0; ((bit_len + 7) / 8) as usize];
    let b_clone = b.clone();
    _ = rand.xor_key_stream(&mut b, &b_clone);
    let highbits = bit_len & 7;
    if highbits != 0 {
        b[0] &= !(0xff << highbits);
    }
    if exact {
        if highbits != 0 {
            b[0] |= 1 << (highbits - 1)
        } else {
            b[0] |= 0x80
        }
    }
    b
}

/// [`random_int()`] chooses a uniform random [`BigInt`] less than a given modulus
pub fn random_int(modulus: &BigInt, rand: &mut impl Stream) -> BigInt {
    let bitlen = modulus.bits();

    loop {
        let bits = bits(bitlen as u64, false, rand);
        let i = BigInt::from_bytes_be(num_bigint::Sign::Plus, bits.as_ref());
        if i.sign() == num_bigint::Sign::Plus && i.cmp(modulus) == Ordering::Less {
            return i;
        }
    }
}

// [`bytes()`] fills a slice with random bytes from `rand`.
pub fn bytes(b: &mut [u8], rand: &mut impl Stream) -> Result<(), StreamError> {
    let src_buff = vec![0u8; b.len()];
    rand.xor_key_stream(b, &src_buff)?;
    Ok(())
}

pub struct RandStream {
    readers: Vec<Box<dyn Read>>,
}

impl Default for RandStream {
    fn default() -> Self {
        let rng_core = Box::new(StdRng::from_entropy()) as Box<dyn RngCore>;
        let default: Box<dyn Read> = Box::new(rng_core) as Box<dyn Read>;
        RandStream {
            readers: vec![default],
        }
    }
}

impl RandStream {
    /// [`new()`] returns a new [`RandStream`] whih implements [`Stream`] that gets random data from the given
    /// [`readers`](Read). If no [`reader`](Read) was provided, a default [`RngCore`] is used.
    /// Otherwise, for each source, 32 bytes are read. They are concatenated and
    /// then hashed, and the resulting hash is used as a seed to a PRNG.
    /// The resulting [`RandStream`] can be used in multiple threads.
    pub fn new(readers: Vec<Box<dyn Read>>) -> RandStream {
        if readers.is_empty() {
            return RandStream::default();
        }
        RandStream {
            readers: readers
                .into_iter()
                .map(|r| Box::new(r) as Box<dyn Read>)
                .collect(),
        }
    }
}

impl Stream for RandStream {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), StreamError> {
        let l = dst.len();
        if src.len() != l {
            return Err(StreamError::WrongBufferLengths);
        }

        // readerBytes is how many bytes we expect from each source
        let reader_bytes = 32;

        // try to read readerBytes bytes from all readers and write them in a buffer
        let mut b = vec![];
        let mut nerr = 0_usize;
        let mut buff = vec![0_u8; reader_bytes];
        for reader in &mut self.readers {
            let result = reader.read_exact(&mut buff);
            if result.is_err() {
                nerr += 1;
                continue;
            }
            b.write_all(&buff[..buff.len()])?;
        }

        // we are ok with few sources being insecure (i.e., providing less than
        // readerBytes bytes), but not all of them
        if nerr == self.readers.len() {
            return Err(StreamError::ReadersFailure);
        }

        // create the XOF output, with hash of collected data as seed
        let mut h: Sha256 = Sha256::new();
        h.update(b);
        let seed = h.finalize();

        let mut blake = Xof::new(Some(&seed));
        blake.xor_key_stream(dst, src)
    }
}
