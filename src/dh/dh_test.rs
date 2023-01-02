use sha2::Sha256;

use crate::dh::NONCE_SIZE;
use crate::encoding::BinaryUnmarshaler;
use crate::group::edwards25519::Point;

use super::Dh;

struct DhStandard {}
impl Dh for DhStandard {
    type H = Sha256;
}

#[test]
fn test_hkdf_sha256() {
    let known_key: Vec<u8> = vec![
        91, 40, 168, 166, 37, 163, 95, 209, 209, 251, 97, 73, 115, 22, 47, 183, 82, 8, 154, 172,
        252, 72, 53, 160, 250, 218, 33, 206, 68, 133, 154, 45,
    ];
    let hkdf_context: [u8; 32] = [
        88, 71, 70, 230, 74, 255, 157, 216, 162, 199, 155, 39, 83, 23, 60, 114, 54, 174, 227, 173,
        34, 184, 245, 220, 67, 205, 73, 222, 61, 176, 193, 214,
    ];
    let pre_shared_key: [u8; 32] = [
        58, 145, 129, 216, 77, 23, 213, 87, 74, 247, 11, 158, 48, 151, 45, 49, 33, 26, 222, 200,
        185, 0, 146, 44, 234, 119, 9, 71, 89, 36, 197, 161,
    ];

    let key = DhStandard::hkdf(&pre_shared_key, &hkdf_context, None).unwrap();

    assert_eq!(key.to_vec(), known_key);
}

#[test]
fn test_aes_gcm_interop() {
    let key = [
        91, 40, 168, 166, 37, 163, 95, 209, 209, 251, 97, 73, 115, 22, 47, 183, 82, 8, 154, 172,
        252, 72, 53, 160, 250, 218, 33, 206, 68, 133, 154, 45,
    ];

    let data = b"test-data".to_vec();
    let nonce = [0u8; NONCE_SIZE];

    let ciphertext = DhStandard::aes_encrypt(&key, &nonce, &data, None).unwrap();
    let decrypted = DhStandard::aes_decrypt(&key, &nonce, &ciphertext, None).unwrap();

    assert_eq!(decrypted, data)
}

#[test]
fn test_aes_gcm_encrypt() {
    let known_cyphertext: Vec<u8> = vec![
        60, 174, 109, 169, 173, 178, 76, 154, 41, 67, 113, 96, 181, 203, 173, 144, 50, 93, 198,
        112, 246, 196, 156, 9, 133, 41, 105, 52, 254, 226, 77, 153, 32, 226, 201, 14, 163, 153,
        126, 2, 213, 37, 82, 248, 189, 210, 109, 65, 147, 38, 81, 249, 91, 176, 180, 9, 54, 171,
        51, 27, 92, 221, 70, 167, 72, 15, 67, 56, 151, 44, 225, 86, 240, 167, 164, 196, 159, 59,
        38, 121, 92, 170, 172, 37, 47, 240, 95, 3, 233, 55, 126, 87, 221, 54, 142, 186, 16, 241,
        244, 5, 109, 90, 37, 188, 169, 246, 177, 183, 248, 126, 177, 220, 139, 112, 213, 168, 59,
        196, 12, 54, 116, 202, 186, 154, 2, 40, 228, 151, 9, 230, 105, 198, 185, 2, 158, 223, 246,
        97, 84, 52, 81, 10, 142, 158, 43, 54, 235, 236, 132, 236, 168, 31, 203, 172, 184, 234, 212,
        24, 26, 56, 79, 120, 6, 10, 78, 83, 143, 189, 36, 19, 174, 102, 177, 217, 105, 37, 10, 202,
        170, 254, 248, 228, 191, 147, 189, 231, 124, 59, 138, 107, 141, 210, 164, 207, 173, 24,
        174, 35, 166, 16, 109, 128, 136, 215, 102, 4, 99, 104, 204, 22, 152, 197, 191, 252, 246,
        176, 128, 72, 8, 139, 220, 18, 188, 11, 31, 17,
    ];

    let key = [
        188, 66, 220, 224, 28, 142, 199, 7, 67, 85, 91, 218, 124, 225, 198, 128, 129, 159, 237, 62,
        249, 246, 222, 34, 18, 195, 233, 214, 151, 169, 241, 205,
    ];
    let hdfk_context: [u8; 32] = [
        88, 71, 70, 230, 74, 255, 157, 216, 162, 199, 155, 39, 83, 23, 60, 114, 54, 174, 227, 173,
        34, 184, 245, 220, 67, 205, 73, 222, 61, 176, 193, 214,
    ];

    let data: Vec<u8> = vec![
        10, 32, 14, 172, 147, 2, 139, 97, 220, 249, 120, 24, 195, 3, 188, 186, 28, 79, 109, 223,
        235, 128, 173, 50, 75, 193, 227, 75, 255, 147, 64, 115, 80, 23, 18, 36, 8, 0, 18, 32, 179,
        74, 143, 12, 143, 206, 126, 36, 216, 58, 19, 128, 200, 39, 226, 27, 254, 232, 123, 58, 24,
        169, 155, 223, 8, 95, 220, 92, 150, 182, 128, 6, 24, 4, 34, 32, 224, 15, 220, 93, 76, 242,
        86, 129, 63, 49, 203, 150, 109, 135, 96, 126, 123, 232, 157, 203, 53, 173, 176, 44, 55,
        118, 149, 48, 247, 204, 70, 122, 34, 32, 226, 175, 77, 178, 219, 122, 5, 210, 236, 127, 13,
        70, 133, 115, 228, 17, 40, 88, 86, 249, 193, 167, 227, 217, 240, 187, 48, 33, 146, 228,
        251, 132, 34, 32, 150, 86, 157, 57, 152, 68, 32, 103, 195, 36, 45, 190, 128, 144, 217, 181,
        70, 31, 178, 181, 153, 170, 123, 85, 19, 244, 203, 111, 46, 31, 46, 240, 34, 32, 107, 27,
        175, 73, 104, 204, 142, 217, 190, 127, 58, 180, 87, 124, 161, 208, 18, 78, 75, 45, 136, 55,
        75, 48, 139, 93, 101, 9, 57, 172, 38, 192,
    ];
    let nonce = [0u8; NONCE_SIZE];

    let ciphertext = DhStandard::aes_encrypt(&key, &nonce, &data, Some(&hdfk_context)).unwrap();

    assert_eq!(ciphertext, known_cyphertext)
}

#[test]
fn test_aead_whole() {
    let known_encrypted: Vec<u8> = vec![
        60, 174, 109, 169, 173, 178, 76, 154, 41, 67, 113, 96, 181, 203, 173, 144, 50, 93, 198,
        112, 246, 196, 156, 9, 133, 41, 105, 52, 254, 226, 77, 153, 32, 226, 201, 14, 163, 153,
        126, 2, 213, 37, 82, 248, 189, 210, 109, 65, 147, 38, 81, 249, 91, 176, 180, 9, 54, 171,
        51, 27, 92, 221, 70, 167, 72, 15, 67, 56, 151, 44, 225, 86, 240, 167, 164, 196, 159, 59,
        38, 121, 92, 170, 172, 37, 47, 240, 95, 3, 233, 55, 126, 87, 221, 54, 142, 186, 16, 241,
        244, 5, 109, 90, 37, 188, 169, 246, 177, 183, 248, 126, 177, 220, 139, 112, 213, 168, 59,
        196, 12, 54, 116, 202, 186, 154, 2, 40, 228, 151, 9, 230, 105, 198, 185, 2, 158, 223, 246,
        97, 84, 52, 81, 10, 142, 158, 43, 54, 235, 236, 132, 236, 168, 31, 203, 172, 184, 234, 212,
        24, 26, 56, 79, 120, 6, 10, 78, 83, 143, 189, 36, 19, 174, 102, 177, 217, 105, 37, 10, 202,
        170, 254, 248, 228, 191, 147, 189, 231, 124, 59, 138, 107, 141, 210, 164, 207, 173, 24,
        174, 35, 166, 16, 109, 128, 136, 215, 102, 4, 99, 104, 204, 22, 152, 197, 191, 252, 246,
        176, 128, 72, 8, 139, 220, 18, 188, 11, 31, 17,
    ];

    let p: [u8; 32] = [
        148, 133, 31, 10, 139, 251, 166, 132, 139, 182, 246, 142, 130, 109, 28, 21, 160, 19, 112,
        29, 223, 67, 204, 22, 116, 70, 54, 185, 243, 252, 181, 105,
    ];
    let deal_buff: Vec<u8> = vec![
        10, 32, 14, 172, 147, 2, 139, 97, 220, 249, 120, 24, 195, 3, 188, 186, 28, 79, 109, 223,
        235, 128, 173, 50, 75, 193, 227, 75, 255, 147, 64, 115, 80, 23, 18, 36, 8, 0, 18, 32, 179,
        74, 143, 12, 143, 206, 126, 36, 216, 58, 19, 128, 200, 39, 226, 27, 254, 232, 123, 58, 24,
        169, 155, 223, 8, 95, 220, 92, 150, 182, 128, 6, 24, 4, 34, 32, 224, 15, 220, 93, 76, 242,
        86, 129, 63, 49, 203, 150, 109, 135, 96, 126, 123, 232, 157, 203, 53, 173, 176, 44, 55,
        118, 149, 48, 247, 204, 70, 122, 34, 32, 226, 175, 77, 178, 219, 122, 5, 210, 236, 127, 13,
        70, 133, 115, 228, 17, 40, 88, 86, 249, 193, 167, 227, 217, 240, 187, 48, 33, 146, 228,
        251, 132, 34, 32, 150, 86, 157, 57, 152, 68, 32, 103, 195, 36, 45, 190, 128, 144, 217, 181,
        70, 31, 178, 181, 153, 170, 123, 85, 19, 244, 203, 111, 46, 31, 46, 240, 34, 32, 107, 27,
        175, 73, 104, 204, 142, 217, 190, 127, 58, 180, 87, 124, 161, 208, 18, 78, 75, 45, 136, 55,
        75, 48, 139, 93, 101, 9, 57, 172, 38, 192,
    ];
    let hdfk_context: [u8; 32] = [
        88, 71, 70, 230, 74, 255, 157, 216, 162, 199, 155, 39, 83, 23, 60, 114, 54, 174, 227, 173,
        34, 184, 245, 220, 67, 205, 73, 222, 61, 176, 193, 214,
    ];
    let nonce = [0u8; NONCE_SIZE];

    let mut point = Point::default();
    point.unmarshal_binary(&p).unwrap();

    let encrypted = DhStandard::encrypt(&point, &hdfk_context, &nonce, &deal_buff).unwrap();
    assert_eq!(encrypted, known_encrypted);

    let decrypted = DhStandard::decrypt(&point, &hdfk_context, &nonce, &encrypted).unwrap();
    assert_eq!(decrypted, deal_buff);
}

// TODO: implement this test and understand why it doesn't work properly (it is fixed by chaning dh_exhange() but other things breaks
// sometimes, run tests many times to see what)
// #[test]
// fn test_aead_random() {
//     for i in 0..1000 {
//         let suite = SuiteEd25519::new_blake_sha256ed25519();

//         let keypair1 = key::new_key_pair(&suite).unwrap();
//         let keypair2 = key::new_key_pair(&suite).unwrap();
//         let priv1 = keypair1.private;
//         let priv2 = keypair2.private;
//         let pub1 = keypair1.public;
//         let pub2 = keypair2.public;

//         let mut message = [0u8; 64];
//         random::bytes(&mut message, &mut suite.random_stream()).unwrap();

//         let nonce = [0u8; NONCE_SIZE];

//         let pre = SuiteEd25519::dh_exchange(suite, priv1, pub2);
//         let gcm = AEAD::<SuiteEd25519>::new(pre, &[]).unwrap();

//         let ciphertext = gcm.seal(None, &nonce, &message, None).unwrap();

//         let pre2 = SuiteEd25519::dh_exchange(suite, priv2, pub1);
//         let gcm2 = AEAD::<SuiteEd25519>::new(pre2, &[]).unwrap();

//         let decrypted = gcm2
//             .open(None, &nonce, &ciphertext, None)
//             .unwrap_or_else(|_| panic!("decryption failed at iteration {}", i));

//         assert_eq!(decrypted, message, "assertion failed at iteration {}", i);
//     }
// }
