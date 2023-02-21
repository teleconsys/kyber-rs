pub mod blake3;
mod traits;
#[cfg(test)]
mod xof_test;

pub use traits::{XOFFactory, XOF};
