use serde::{Deserialize, Serialize};
use std::{fmt::Debug, io};
use thiserror::Error;

use crate::cipher::Stream;

/// [`Marshaling`] is a basic interface representing fixed-length (or known-length)
/// cryptographic objects or structures having a built-in binary encoding.
/// Implementors must ensure that calls to these methods do not modify
/// the underlying object so that other users of the object can access
/// it concurrently.
pub trait Marshaling: BinaryMarshaler + BinaryUnmarshaler {
    /// Encoded length of this object in bytes.
    fn marshal_size(&self) -> usize;

    /// Encode the contents of this object and write it to an [`io::Write`].
    fn marshal_to(&self, w: &mut impl io::Write) -> Result<(), MarshallingError>;

    /// Decode the content of this object by reading from a [`io::Read`].
    /// If `r` is an [`XOF`], it uses `r` to pick a valid object pseudo-randomly,
    /// which may entail reading more than `len` bytes due to retries.
    fn unmarshal_from(&mut self, r: &mut impl io::Read) -> Result<(), MarshallingError>;
    fn unmarshal_from_random(&mut self, r: &mut (impl io::Read + Stream));

    /// [`marshal_id()`] returns the type tag used in encoding/decoding
    fn marshal_id(&self) -> [u8; 8];
}

#[derive(Error, Debug)]
pub enum MarshallingError {
    #[error("could not serialize data")]
    Serialization(bincode::Error),
    #[error("could not deserialize data")]
    Deserialization(bincode::Error),
    #[error("input data is not valid")]
    InvalidInput(String),
    #[error("io error")]
    IoError(#[from] std::io::Error),
}

pub trait BinaryMarshaler {
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError>;
}

pub trait BinaryUnmarshaler {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), MarshallingError>;
}

pub fn marshal_binary<T: Serialize>(x: &T) -> Result<Vec<u8>, MarshallingError> {
    bincode::serialize(x).map_err(MarshallingError::Serialization)
}

pub fn unmarshal_binary<'de, T: Deserialize<'de>>(
    x: &mut T,
    data: &'de [u8],
) -> Result<(), MarshallingError> {
    *x = bincode::deserialize(data).map_err(MarshallingError::Deserialization)?;
    Ok(())
}
