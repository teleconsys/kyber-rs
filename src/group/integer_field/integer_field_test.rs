#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use num_bigint::Sign::Plus;
    use crate::encoding::{BinaryMarshaler, BinaryUnmarshaller};

    use crate::group::integer_field::integer_field::ByteOrder::{BigEndian, LittleEndian};
    use crate::group::integer_field::integer_field::Int;


    #[test]
    fn test_int_endianness() {
        let modulo = BigInt::from(65535 as i64);
        let v: i64 = 65500;

        // Let's assume it is bigendian and test that
        let mut i = Int::default().init64(v, modulo.clone());
        assert_eq!(i.bo, BigEndian);

        let buff1 = i.marshal_binary().unwrap();
        i.bo = BigEndian;
        let buff2 = i.marshal_binary().unwrap();
        assert_eq!(buff1, buff2);

        // Let's change endianness and check the result
        i.bo = LittleEndian;
        let buff3 = i.marshal_binary().unwrap();
        assert_ne!(buff2, buff3);

        // let's try little_endian function
        let buff4 = i.little_endian(0, 32);
        assert_eq!(buff3, buff4);
        // set endianess but using littleendian should not change anything
        i.bo = BigEndian;
        assert_eq!(buff4, i.little_endian(0, 32));

        // Try to reconstruct the int from the buffer
        i = Int::default().init64(v, modulo.clone());
        let mut i2 = Int::new_int64(0, modulo.clone());
        let mut buff = i.marshal_binary().unwrap();
        i2.unmarshal_binary(&*buff).unwrap();
        assert_eq!(i, i2);

        i.bo = LittleEndian;
        buff = i.marshal_binary().unwrap();
        i2.bo = LittleEndian;
        i2.unmarshal_binary(buff.as_slice()).unwrap();
        assert_eq!(i, i2);

        i2.bo = BigEndian;
        i2.unmarshal_binary(buff.as_slice()).unwrap();
        assert_ne!(i, i2);
    }

    #[test]
    fn test_int_endian_bytes() {
        let modulo = hex::decode("1000").unwrap();
        let modulo_i = BigInt::from_bytes_be(Plus, modulo.as_ref());
        let v = hex::decode("10").unwrap();
        let i = Int::default().init_bytes(v.as_ref(), &modulo_i, BigEndian);

        assert_eq!(2, i.marshal_size());
        i.little_endian(2, 2);
    }

    #[test]
    fn test_inits() {
        let i1 = Int::new_int64(65500, BigInt::from(65535 as i64));
        let i2 = Int::new_int(i1.v.clone(), i1.m.clone());
        assert_eq!(i1, i2);
        let b = i1.marshal_binary().unwrap();
        let i3 = Int::new_int_bytes(b.as_slice(), &i1.m, BigEndian);
        assert_eq!(i1, i3);
        let i4 = Int::new_int_string(i1.string(), "".to_string(), 16, &i1.m);
        assert_eq!(i1, i4);
    }

    #[test]
    fn test_init128bits() {
        let mut m = BigInt::from(1 as i32) << 128 as i32;
        m = m - BigInt::from(1 as i32);

        let i1 = Int::new_int(BigInt::from(1 as i32), m);
        // size in bytes
        assert_eq!(16, i1.marshal_size());
    }

    #[test]
    fn test_int_clone() {
        let modulo_i = BigInt::from_bytes_be(Plus, &[0x10, 0].as_slice());
        let base = Int::default().init_bytes(&[0x10], &modulo_i, BigEndian);
        let mut clone = base.clone();
        let tmp = clone.clone();
        clone = clone.add(&tmp, &tmp);
        let b1 = clone.marshal_binary().unwrap();
        let b2 = base.marshal_binary().unwrap();
        assert_ne!(b1, b2, "Should not be equal");
    }
}