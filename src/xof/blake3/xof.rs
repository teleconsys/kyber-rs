use std::io::{Read, Write};

use thiserror::Error;

use crate::cipher::cipher::Stream;
use crate::cipher::StreamError;

use crate::xof::xof;

#[derive(Clone)]
enum HashState {
    Readable { reader: blake3::OutputReader },
    Writeable { writer: Box<blake3::Hasher> },
}

pub struct Xof {
    implementation: HashState,

    /// `key` is here to not make excess garbage during repeated calls
    /// to [`xor_key_stream()`].
    key: Vec<u8>,
}

impl Stream for Xof {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), StreamError> {
        if dst.len() < src.len() {
            return Err(StreamError::XOFError(XOFError::ShortDestination));
        }
        if self.key.len() < src.len() {
            self.key = vec![0; src.len()];
        } else {
            self.key = self.key[0..src.len()].to_vec();
        }

        let mut new_key = self.key.clone();
        let n = self.read(&mut new_key).expect("xor key stream read error");
        if n != src.len() {
            return Err(StreamError::XOFError(XOFError::ShortRead));
        }
        self.key = new_key;

        for (i, _) in src.iter().enumerate() {
            dst[i] = src[i] ^ self.key[i];
        }

        Ok(())
    }
}

impl std::io::Write for Xof {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        match &mut self.implementation {
            HashState::Readable { reader: _ } => Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "write after read",
            )),
            HashState::Writeable { writer } => writer.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
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
impl std::io::Read for Xof {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
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

impl xof::XOF for Xof {
    fn clone(&self) -> Box<dyn xof::XOF> {
        Box::new(Xof {
            implementation: self.implementation.clone(),
            key: self.key.clone(),
        })
    }

    fn reseed(&mut self) {
        if self.key.len() < 128 {
            self.key = vec![0_u8; 128];
        } else {
            self.key = self.key[0..128].to_vec();
        }
        let mut k = self.key.clone();
        _ = self.read(&mut k);
        self.key = k;

        // use new() to create a new one seeded with output from the old one.
        let y = Xof::new(Some(&self.key));

        // steal the XOF implementation, and put it inside of x.
        self.implementation = y.implementation;
    }
}

impl Xof {
    /// [`new()`] creates a new [`XOF`] using the `Blake3` hash.
    pub fn new(seed: Option<&[u8]>) -> Self {
        let mut b = blake3::Hasher::new();
        if let Some(s) = seed {
            b.write_all(s).unwrap();
        }
        Xof {
            implementation: HashState::Writeable {
                writer: Box::new(b),
            },
            key: vec![0; 0],
        }
    }
}

#[derive(Debug, Error)]
pub enum XOFError {
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("short read on key")]
    ShortRead,
    #[error("dst too short")]
    ShortDestination,
}
