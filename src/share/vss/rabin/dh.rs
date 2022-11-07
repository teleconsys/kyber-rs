/// dhExchange computes the shared key from a private key and a public key
pub fn dhExchange<SCALAR, POINT, SUITE>(
    suite: SUITE,
    ownPrivate: SCALAR,
    remotePublic: POINT,
) -> POINT
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    SUITE: Suite<SCALAR, POINT>,
{
    let sk = suite.point();
    sk.mul(&ownPrivate, Some(&remotePublic))
}

// var sharedKeyLength = 32

// // newAEAD returns the AEAD cipher to be use to encrypt a share
// fn newAEAD(fn func() hash.Hash, preSharedKey kyber.Point, context []byte) (cipher.AEAD, error) {
// 	preBuff, _ := preSharedKey.MarshalBinary()
// 	reader := hkdf.New(fn, preBuff, nil, context)

// 	sharedKey := make([]byte, sharedKeyLength)
// 	if _, err := reader.Read(sharedKey); err != nil {
// 		return nil, err
// 	}
// 	block, err := aes.NewCipher(sharedKey)
// 	if err != nil {
// 		return nil, err
// 	}
// 	gcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return gcm, nil
// }

use crate::{Point, Scalar, Suite};

// KEY_SIZE is arbitrary, make it long enough to seed the XOF
const KEY_SIZE: usize = 128;

/// context returns the context slice to be used when encrypting a share
pub fn context<SUITE, POINT, SCALAR>(
    suite: &SUITE,
    dealer: &POINT,
    verifiers: &Vec<POINT>,
) -> [u8; KEY_SIZE]
where
    SUITE: Suite<SCALAR, POINT>,
    POINT: Point<SCALAR>,
    SCALAR: Scalar,
{
    let mut h = suite.xof(Some("vss-dealer".as_bytes()));
    dealer.marshal_to(&mut h).unwrap();
    h.write("vss-verifiers".as_bytes()).unwrap();
    for v in verifiers {
        v.marshal_to(&mut h).unwrap();
    }
    let mut sum = [0 as u8; KEY_SIZE]; //make([]byte, keySize);
    h.read(&mut sum).unwrap();
    sum
}
