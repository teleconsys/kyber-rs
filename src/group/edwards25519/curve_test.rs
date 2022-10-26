use crate::group::edwards25519::suite::SuiteEd25519;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref T_SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
}
