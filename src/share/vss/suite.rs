use crate::{Group, group::HashFactory, XOFFactory, Random};

/// Suite defines the capabilities required by the vss package.
pub trait Suite: Group + HashFactory + XOFFactory + Random + Clone + Default + Copy {}