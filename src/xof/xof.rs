use std::io;

use crate::cipher::cipher::Stream;

/// An [`XOF`] is an extendable output function, which is a cryptographic
/// primitive that can take arbitrary input in the same way a hash
/// function does, and then create a stream of output, up to a limit
/// determined by the size of the internal state of the hash function
/// the underlies the [`XOF`].
///
/// When [`xor_key_stream()`] is called with zeros for the source, an [`XOF`]
/// also acts as a PRNG. If it is seeded with an appropriate amount
/// of keying material, it is a cryptographically secure source of random
/// bits.
///
/// [`XOF`] implements [`io::Write`] which absorbs more data into the hash's state.
/// It should throw an error if called after [`read()`]. Use [`reseed()`] to reset the xof
/// into a state where more data can be absorbed via [`io::Write`].
///
/// [`XOF`] implements [`io::Read`] which reads more output from the hash.
/// It returns a value `n != 0` if EOF has been reached.
///
/// [`XOF`] implements [`Stream`], so that callers can use [`xor_key_stream`]
/// to encrypt/decrypt data. The key stream is read from the [`XOF`] using
/// the [`io::Read`] trait. If [`read()`] returns an error, then [`xor_key_stream`]
/// will panic.
pub trait XOF: Stream + io::Write + io::Read {
    /// [`reseed()`] makes an [`XOF`] writeable again after it has been read from
    /// by sampling a key from it's output and initializing a fresh [`XOF`] implementation
    /// with that key.
    fn reseed(&mut self);

    /// [`clone()`] returns a copy of the [`XOF`] in its current state.
    fn clone(&self) -> Box<dyn XOF>;
}

impl<X: XOF + ?Sized> XOF for Box<X> {
    fn reseed(&mut self) {
        (**self).reseed()
    }

    fn clone(&self) -> Box<dyn XOF> {
        (**self).clone()
    }
}

/// An [`XOFFactory`] is a trait that can be mixed in to local suite definitions.
pub trait XOFFactory {
    /// [`xof()`] creates a new [`XOF`], feeding seed to it via it's [`write()`] method. If seed
    /// is `None` or empty, the [`XOF`] is left unseeded, it will produce a fixed, predictable
    /// stream of bits (Caution: this behavior is useful for testing but fatal for
    /// production use).
    fn xof(&self, seed: Option<&[u8]>) -> Box<dyn XOF>;
}
