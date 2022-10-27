use crate::group::edwards25519::scalar::Scalar;
use crate::group::group::Group;

use super::Point;

/// Curve represents the Ed25519 group.
/// There are no parameters and no initialization is required
/// because it supports only this one specific curve.
#[derive(Clone, Copy)]
pub struct Curve {}

impl Group<Scalar, Point> for Curve {
    /// Return the name of the curve, "Ed25519".
    fn string(&self) -> String {
        "Ed25519".to_string()
    }

    /// scalar creates a new scalar for the prime-order subgroup of the Ed25519 curve.
    /// The scalars in this package implement kyber.scalar's SetBytes
    /// method, interpreting the bytes as a little-endian integer, in order to remain
    /// compatible with other Ed25519 implementations, and with the standard implementation
    /// of the EdDSA signature.
    fn scalar(&self) -> Scalar {
        Scalar::default()
    }

    fn point(&self) -> Point {
        Point::default()
    }
}

// // ScalarLen returns 32, the size in bytes of an encoded scalar
// // for the Ed25519 curve.
// func (c *Curve) ScalarLen() int {
// return 32
// }
//
// // PointLen returns 32, the size in bytes of an encoded Point on the Ed25519 curve.
// func (c *Curve) PointLen() int {
// return 32
// }
//
// // Point creates a new Point on the Ed25519 curve.
// func (c *Curve) Point() kyber.Point {
// P := new(point)
// return P
// }
//
// // NewKeyAndSeedWithInput returns a formatted Ed25519 key (avoid subgroup attack by
// // requiring it to be a multiple of 8). It also returns the input and the digest used
// // to generate the key.
// func (c *Curve) NewKeyAndSeedWithInput(buffer []byte) (kyber.scalar, []byte, []byte) {
// digest := sha512.Sum512(buffer[:])
// digest[0] &= 0xf8
// digest[31] &= 0x7f
// digest[31] |= 0x40
//
// secret := c.scalar().(*scalar)
// copy(secret.v[:], digest[:])
// return secret, buffer, digest[32:]
// }
//
// // NewKeyAndSeed returns a formatted Ed25519 key (avoid subgroup attack by requiring
// // it to be a multiple of 8). It also returns the seed and the input used to generate
// // the key.
// func (c *Curve) NewKeyAndSeed(stream cipher.Stream) (kyber.scalar, []byte, []byte) {
// var buffer [32]byte
// random.Bytes(buffer[:], stream)
// return c.NewKeyAndSeedWithInput(buffer[:])
// }
//
// // NewKey returns a formatted Ed25519 key (avoiding subgroup attack by requiring
// // it to be a multiple of 8). NewKey implements the kyber/util/key.Generator interface.
// func (c *Curve) NewKey(stream cipher.Stream) kyber.scalar {
// secret, _, _ := c.NewKeyAndSeed(stream)
// return secret
// }

impl Default for Curve {
    fn default() -> Self {
        Curve {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a() {}
}
