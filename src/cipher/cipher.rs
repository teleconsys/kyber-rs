use thiserror::Error;

use crate::xof::blake::XOFError;

/// A Stream represents a stream cipher.
pub trait Stream {
    // xor_key_stream XORs each byte in the given slice with a byte from the
    // cipher's key stream. Dst and src must overlap entirely or not at all.
    //
    // If len(dst) < len(src), XORKeyStream should panic. It is acceptable
    // to pass a dst bigger than src, and in that case, XORKeyStream will
    // only update dst[:len(src)] and will not touch the rest of dst.
    //
    // Multiple calls to XORKeyStream behave as if the concatenation of
    // the src buffers was passed in a single run. That is, Stream
    // maintains state and does not reset at each XORKeyStream call.
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), StreamError>;
}

impl<S: Stream + ?Sized> Stream for Box<S> {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), StreamError> {
        self.as_mut().xor_key_stream(dst, src)
    }
}

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("XOF error")]
    XOFError(#[from] XOFError),
    #[error("mismatched buffer lengths")]
    WrongBufferLengths,
    #[error("all readers failed")]
    ReadersFailure,
}
