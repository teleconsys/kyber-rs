use std::fmt::Error;
// use crypto::digest::{Digest, XofReader};
use crate::cipher::cipher::Stream;
use blake2::digest::{Digest, Update, VariableOutput};
use blake2::Blake2bVar;

use crate::xof::xof;

pub struct XOF {
    // implementation: Box<dyn XofReader>,

    // key is here to not make excess garbage during repeated calls
    // to XORKeyStream.
    key: Vec<u8>,
}

impl Stream for XOF {
    fn XORKeyStream(&mut self, dst: &mut [u8], src: &[u8]) {
        // assert!(dst.len() > src.len(), "dst too short");
        if self.key.len() < src.len() {
            self.key = vec![0; src.len()];
        } else {
            self.key = self.key[0..src.len()].to_vec();
        }

        // self.Read(&mut self.key);

        // if err != nil {
        //     panic("blake xof error: " + err.Error())
        // }
        // if n != len(src) {
        //     panic("short read on key")
        // }

        for i in src {
            // dst[i] = src[i] ^ self.key[i];
        }
    }
}

impl xof::XOF for XOF {}

impl XOF {
    /// New creates a new XOF using the Blake2b hash.
    pub fn new(seed: &[u8]) -> Self {
        let mut seed1 = seed.clone();
        let seed2: &[u8];

        if seed.len() > blake2::Blake2b512::output_size() {
            seed1 = &seed[0..blake2::Blake2b512::output_size()];
            seed2 = &seed[blake2::Blake2b512::output_size()..];
        }

        let b = Blake2bVar::new(10).unwrap();
        print!("{:#?}", b);
        // let b = blake2b::Blake2b::new_keyed(0, seed1);
        // b, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed1)
        // if err != nil {
        // panic("blake2b.NewXOF should not return error: " + err.Error())
        // }

        // if seed2 != nil {
        // _, err := b.Write(seed2)
        // if err != nil {
        // panic("blake2b.XOF.Write should not return error: " + err.Error())
        // }
        // }
        // return &xof{impl: b}
        XOF {
            // implementation: Box::new(b),
            key: vec![0; 0],
        }
    }

    fn Read(&mut self, dst: &mut [u8]) {
        todo!()
        // self.implementation.read(dst)
    }
}

// func (x *xof) Clone() kyber.XOF {
// return &xof{impl: x.impl.Clone()}
// }
// func (x *xof) Write(src []byte) (int, error) {
// return x.impl.Write(src)
// }
//
// func (x *xof) Reseed() {
// // Use New to create a new one seeded with output from the old one.
// if len(x.key) < 128 {
// x.key = make([]byte, 128)
// } else {
// x.key = x.key[0:128]
// }
// x.Read(x.key)
// y := New(x.key)
// // Steal the XOF implementation, and put it inside of x.
// x.impl = y.(*xof).impl
// }
//
// func (x *xof) XORKeyStream(dst, src []byte) {
// if len(dst) < len(src) {
// panic("dst too short")
// }
// if len(x.key) < len(src) {
// x.key = make([]byte, len(src))
// } else {
// x.key = x.key[0:len(src)]
// }
//
// n, err := x.Read(x.key)
// if err != nil {
// panic("blake xof error: " + err.Error())
// }
// if n != len(src) {
// panic("short read on key")
// }
//
// for i := range src {
// dst[i] = src[i] ^ x.key[i]
// }
// }

// impl Default for XOF {
//     fn default() -> Self {
//         XOF { key: vec![] }
//     }
// }
