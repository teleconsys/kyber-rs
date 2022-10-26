use crate::cipher;

// Random is an interface that can be mixed in to local suite definitions.
pub trait Random {
    /// RandomStream returns a cipher.Stream that produces a
    /// cryptographically random key stream. The stream must
    /// tolerate being used in multiple goroutines.
    fn RandomStream(&self) -> Box<dyn cipher::Stream>;
}
