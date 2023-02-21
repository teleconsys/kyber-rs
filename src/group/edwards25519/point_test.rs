use crate::{
    encoding::{BinaryUnmarshaler, Marshaling},
    group::{
        edwards25519::{constants::WEAK_KEYS, Point},
        PointCanCheckCanonicalAndSmallOrder,
    },
};

#[test]
fn test_point_marshal() {
    let p = Point::default();

    assert_eq!("ed.point", std::str::from_utf8(&p.marshal_id()).unwrap());
}

/// [`test_point_has_small_order()`] ensures [`WEAK_KEYS`] are considered to have
/// a small order
#[test]
fn test_point_has_small_order() {
    for key in WEAK_KEYS {
        let mut p = Point::default();
        p.unmarshal_binary(&key).unwrap();
        assert!(p.has_small_order(), "weak keys should have a small order")
    }
}

// TODO: fix this test
//use super::constants::PRIME;
// /// [`test_point_is_canonical()`] ensures that elements `>= p` are considered
// /// non canonical
// #[test]
// fn test_point_is_canonical() {
//     // buffer stores the candidate points (in little endian) that we'll test
//     // against, starting with `PRIME`
//     let mut buffer = PRIME.to_bytes_le().1;

//     // Iterate over the 19*2 finite field elements
//     let mut p = Point::default();
//     let mut actual_non_canonical_count = 0;
//     let expected_non_canonical_count = 24;
//     for i in 0..19 {
//         buffer[0] = (237 + i) as u8;
//         buffer[31] = 127_u8;

//         // Check if it's a valid point on the curve that's
//         // not canonical
//         match p.unmarshal_binary(&buffer) {
//             Ok(_) => (),
//             Err(_) => if !p.is_canonical(&buffer) {
//                 actual_non_canonical_count += 1;
//             },
//         }

//         // flip bit
//     	buffer[31] |= 128;

//         // Check if it's a valid point on the curve that's
//         // not canonical
//         match p.unmarshal_binary(&buffer) {
//             Ok(_) => (),
//             Err(_) => if !p.is_canonical(&buffer) {
//                 actual_non_canonical_count += 1;
//             },
//         }
//     }
//     assert_eq!(expected_non_canonical_count, actual_non_canonical_count, "incorrect number of non canonical points detected")
// }
