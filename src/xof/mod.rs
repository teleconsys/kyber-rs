pub mod blake;
mod xof;
#[cfg(test)]
mod xof_test;

pub use xof::{XOFFactory, XOF};
