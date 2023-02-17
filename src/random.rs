use crate::cipher;

/// [`Random`] is a trait that can be mixed in to local suite definitions.
pub trait Random {
    /// [`random_stream()`] returns a [`cipher::Stream`] that produces a
    /// cryptographically random key stream. The stream must
    /// tolerate being used in multiple goroutines.
    fn random_stream(&self) -> Box<dyn cipher::Stream>;
}
