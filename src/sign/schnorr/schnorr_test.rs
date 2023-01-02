use crate::{group::edwards25519::SuiteEd25519, sign::eddsa, util::key};

use super::{sign, verify};

#[test]
fn test_schnorr_signature() {
    let msg = "Hello Schnorr".as_bytes();
    let suite = SuiteEd25519::new_blake_sha256ed25519();
    let kp = key::new_key_pair(&suite).unwrap();

    let s = sign(&suite, &kp.private, msg).unwrap();

    verify(suite, &kp.public, msg, &s).unwrap();

    // wrong size
    let mut larger = s.clone();
    let mut piece: Vec<u8> = vec![0x01, 0x02];
    larger.append(&mut piece);
    verify(suite, &kp.public, msg, &larger).unwrap_err();

    // wrong challenge
    let wrong_encoding: Vec<u8> = vec![
        243, 45, 180, 140, 73, 23, 41, 212, 250, 87, 157, 243, 242, 19, 114, 161, 145, 47, 76, 26,
        174, 150, 22, 177, 78, 79, 122, 30, 74, 42, 156, 203,
    ];
    let mut wr_chall = [0u8; 64];
    wr_chall[..32].copy_from_slice(&wrong_encoding);
    wr_chall[32..].copy_from_slice(&s[32..]);
    verify(suite, &kp.public, msg, &wr_chall).unwrap_err();

    // wrong response
    let mut wr_resp = [0u8; 64];
    wr_resp[32..].copy_from_slice(&wrong_encoding);
    wr_resp[..32].copy_from_slice(&s[..32]);
    verify(suite, &kp.public, msg, &wr_resp).unwrap_err();

    // wrong public key
    let wr_pk = key::new_key_pair(&suite).unwrap();
    verify(suite, &wr_pk.public, msg, &s).unwrap_err();
}

#[test]
fn test_eddsa_compatibility() {
    let msg = "Hello Schnorr".as_bytes();
    let suite = SuiteEd25519::new_blake_sha256ed25519();
    let kp = key::new_key_pair(&suite).unwrap();

    let s = sign(&suite, &kp.private, msg).unwrap();

    eddsa::verify(&kp.public, msg, &s).unwrap();
}

// // Simple random stream using the random instance provided by the testing tool
// type quickstream struct {
// 	rand *rand.Rand
// }

// func (s *quickstream) XORKeyStream(dst, src []byte) {
// 	s.rand.Read(dst)
// }

// func (s *quickstream) Generate(rand *rand.Rand, size int) reflect.Value {
// 	return reflect.ValueOf(&quickstream{rand: rand})
// }

// func TestQuickSchnorrSignature(t *testing.T) {
// 	f := func(rand *quickstream, msg []byte) bool {
// 		suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
// 		kp := key.NewKeyPair(suite)

// 		s, err := Sign(suite, kp.Private, msg)
// 		if err != nil {
// 			return false
// 		}

// 		return Verify(suite, kp.Public, msg, s) == nil
// 	}

// 	if err := quick.Check(f, nil); err != nil {
// 		t.Error(err)
// 	}
// }

#[test]
fn test_schnorr_malleability() {
    /* l = 2^252+27742317777372353535851937790883648493, prime order of the base point */
    let l: [u16; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut c = 0u16;

    let msg = "Hello Schnorr".as_bytes();
    let suite = SuiteEd25519::new_blake_sha256ed25519();
    let kp = key::new_key_pair(&suite).unwrap();

    let mut s = sign(&suite, &kp.private, msg).unwrap();

    verify(suite, &kp.public, msg, &s).unwrap();

    // Add l to signature
    for i in 0..32 {
        c += (s[32 + i] as u16) + l[i];
        s[32 + i] = c as u8;
        c >>= 8
    }
    eddsa::verify(&kp.public, msg, &s).unwrap_err();
    verify(suite, &kp.public, msg, &s).unwrap_err();
}
