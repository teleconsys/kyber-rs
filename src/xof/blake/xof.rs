use std::io::{Read, Write};

use anyhow::Error;

use crate::cipher::cipher::Stream;

use crate::xof::xof;

#[derive(Clone)]
enum HashState {
    Readable { reader: blake3::OutputReader },
    Writeable { writer: blake3::Hasher },
}

pub struct XOF {
    implementation: HashState,

    // key is here to not make excess garbage during repeated calls
    // to XORKeyStream.
    key: Vec<u8>,
}

impl Stream for XOF {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        if dst.len() < src.len() {
            return Err(Error::msg("dst too short"));
        }
        if self.key.len() < src.len() {
            self.key = vec![0; src.len()];
        } else {
            self.key = self.key[0..src.len()].to_vec();
        }

        let mut new_key = self.key.clone();
        let n = self.read(&mut new_key).expect("blake xof error");
        if n != src.len() {
            return Err(Error::msg("short read on key"));
        }
        self.key = new_key;

        for (i, _) in src.iter().enumerate() {
            dst[i] = src[i] ^ self.key[i];
        }

        Ok(())
    }
}

impl std::io::Write for XOF {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.implementation {
            HashState::Readable { reader: _ } => Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "write after read",
            )),
            HashState::Writeable { writer } => writer.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.implementation {
            HashState::Readable { reader: _ } => {
                todo!()
                // Err(std::io::Error::new(std::io::ErrorKind::, "asdf"))
            }
            HashState::Writeable { writer: _ } => todo!(),
        }
        // self.implementation.flush()
    }
}
impl std::io::Read for XOF {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.implementation {
            HashState::Readable { reader } => reader.read(buf),
            HashState::Writeable { writer } => {
                self.implementation = HashState::Readable {
                    reader: writer.finalize_xof(),
                };
                self.read(buf)
            }
        }
    }
}

impl xof::XOF for XOF {
    fn clone(&self) -> Box<dyn xof::XOF> {
        Box::new(XOF {
            implementation: self.implementation.clone(),
            key: self.key.clone(),
        })
    }

    fn reseed(&mut self) {
        // Use New to create a new one seeded with output from the old one.
        if self.key.len() < 128 {
            self.key = vec![0 as u8; 128];
        } else {
            self.key = self.key[0..128].to_vec();
        }
        let mut k = self.key.clone();
        _ = self.read(&mut k);
        self.key = k;
        let y = XOF::new(Some(&self.key));
        // Steal the XOF implementation, and put it inside of x.
        self.implementation = y.implementation;
    }
}

impl XOF {
    /// New creates a new XOF using the Blake2b hash.
    pub fn new(seed: Option<&[u8]>) -> Self {
        let mut b = blake3::Hasher::new();
        if let Some(s) = seed {
            b.write(s).unwrap();
        }
        XOF {
            implementation: HashState::Writeable { writer: b },
            key: vec![0; 0],
        }
    }
}

// func (x *xof) Clone() kyber.XOF {
// return &xof{impl: x.impl.Clone()}
// }
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
