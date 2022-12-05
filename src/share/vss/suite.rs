use crate::{group::HashFactory, Group, Random, XOFFactory};

/// Suite defines the capabilities required by the vss package.
pub trait Suite: Group + HashFactory + XOFFactory + Random + Clone + Default + Copy {}
