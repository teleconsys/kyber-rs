use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, io};
use thiserror::Error;

/// Marshaling is a basic interface representing fixed-length (or known-length)
/// cryptographic objects or structures having a built-in binary encoding.
/// Implementors must ensure that calls to these methods do not modify
/// the underlying object so that other users of the object can access
/// it concurrently.
pub trait Marshaling: BinaryMarshaler + BinaryUnmarshaler {
    // String returns the human readable string representation of the object.
    // String() string

    /// Encoded length of this object in bytes.
    fn marshal_size(&self) -> usize;

    /// Encode the contents of this object and write it to an io.Writer.
    fn marshal_to(&self, w: &mut impl io::Write) -> Result<()>;

    // Decode the content of this object by reading from an io.Reader.
    // If r is an XOF, it uses r to pick a valid object pseudo-randomly,
    // which may entail reading more than Len bytes due to retries.
    // UnmarshalFrom(r io.Reader) (int, error)
}

// // Encoding represents an abstract interface to an encoding/decoding that can be
// // used to marshal/unmarshal objects to and from streams. Different Encodings
// // will have different constraints, of course. Two implementations are
// // available:
// //
// //   1. The protobuf encoding using the variable length Google Protobuf encoding
// //      scheme. The library is available at https://go.dedis.ch/protobuf
// //   2. The fixbuf encoding, a fixed length binary encoding of arbitrary
// //      structures. The library is available at https://go.dedis.ch/fixbuf.
// type Encoding interface {
// // Encode and write objects to an io.Writer.
// Write(w io.Writer, objs ...interface{}) error
//
// // Read and decode objects from an io.Reader.
// Read(r io.Reader, objs ...interface{}) error
// }

#[derive(Error, Debug)]
pub enum MarshallingError {
    #[error("could not serialize data")]
    Serialization(#[from] bincode::Error),
}

pub trait BinaryMarshaler {
    fn marshal_binary(&self) -> Result<Vec<u8>>;
}

pub trait BinaryUnmarshaler {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()>;
}

pub fn marshal_binary<T: Serialize>(x: &T) -> Result<Vec<u8>> {
    match bincode::serialize(x) {
        Ok(v) => Ok(v),
        Err(e) => {
            bail!(MarshallingError::Serialization(e))
        }
    }
}

pub fn unmarshal_binary<'de, T: Deserialize<'de>>(x: &mut T, data: &'de [u8]) -> Result<()> {
    *x = bincode::deserialize(data)?;
    Ok(())
}
