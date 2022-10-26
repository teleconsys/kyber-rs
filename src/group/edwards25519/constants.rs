use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_traits::Num;

lazy_static! {
    /// prime modulus of underlying field = 2^255 - 19
    pub static ref PRIME: BigInt = BigInt::from_str_radix(
    "57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
    .unwrap();

    /// prime_order of base point = 2^252 + 27742317777372353535851937790883648493
    pub static ref PRIME_ORDER: BigInt = BigInt::from_str_radix(
    "7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
    .unwrap();
}
