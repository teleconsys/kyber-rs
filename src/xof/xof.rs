use std::io;

use crate::cipher::cipher::Stream;

/// An xof is an extendable output function, which is a cryptographic
/// primitive that can take arbitrary input in the same way a hash
/// function does, and then create a stream of output, up to a limit
/// determined by the size of the internal state of the hash function
/// the underlies the xof.
///
/// When XORKeyStream is called with zeros for the source, an xof
/// also acts as a PRNG. If it is seeded with an appropriate amount
/// of keying material, it is a cryptographically secure source of random
/// bits.
pub trait XOF: Stream + io::Write + io::Read {
    // /// Write absorbs more data into the hash's state. It panics if called
    // /// after Read. Use Reseed() to reset the xof into a state where more data
    // /// can be absorbed via Write.
    // io.Writer

    // /// Read reads more output from the hash. It returns io.EOF if the
    // /// limit of available data for reading has been reached.
    // io.Reader

    // /// An xof implements cipher.Stream, so that callers can use XORKeyStream
    // /// to encrypt/decrypt data. The key stream is read from the xof using
    // /// the io.Reader interface. If Read returns an error, then XORKeyStream
    // /// will panic.
    // cipher.Stream

    /// Reseed makes an xof writeable again after it has been read from
    /// by sampling a key from it's output and initializing a fresh xof implementation
    /// with that key.
    fn reseed(&mut self);

    /// clone returns a copy of the xof in its current state.
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

/// An XOFFactory is an interface that can be mixed in to local suite definitions.
pub trait XOFFactory {
    /// xof creates a new XOF, feeding seed to it via it's Write method. If seed
    /// is nil or []byte{}, the xof is left unseeded, it will produce a fixed, predictable
    /// stream of bits (Caution: this behavior is useful for testing but fatal for
    /// production use).
    fn xof(&self, seed: Option<&[u8]>) -> Box<dyn XOF>;
}
