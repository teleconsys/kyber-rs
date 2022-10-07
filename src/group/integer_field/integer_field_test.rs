#[cfg(test)]
mod test {
    use num_bigint::BigInt;
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

// func TestIntEndianBytes(t *testing.T) {
// modulo, err := hex.DecodeString("1000")
// moduloI := new(big.Int).SetBytes(modulo)
// assert.Nil(t, err)
// v, err := hex.DecodeString("10")
// assert.Nil(t, err)
//
// i := new(Int).InitBytes(v, moduloI, BigEndian)
//
// assert.Equal(t, 2, i.MarshalSize())
// assert.NotPanics(t, func() { i.little_endian(2, 2) })
// }
//
// func TestInits(t *testing.T) {
// i1 := NewInt64(int64(65500), big.NewInt(65535))
// i2 := NewInt(&i1.V, i1.M)
// assert.True(t, i1.Equal(i2))
// b, _ := i1.marshal_binary()
// i3 := NewIntBytes(b, i1.M, BigEndian)
// assert.True(t, i1.Equal(i3))
// i4 := NewIntString(i1.String(), "", 16, i1.M)
// assert.True(t, i1.Equal(i4))
// }
//
// func TestInit128bits(t *testing.T) {
// m := new(big.Int).Lsh(big.NewInt(1), 128)
// m = m.Sub(m, big.NewInt(1))
//
// i1 := NewInt(big.NewInt(1), m)
// // size in bytes
// require.Equal(t, 16, i1.MarshalSize())
// }
//
// func TestIntClone(t *testing.T) {
// moduloI := new(big.Int).SetBytes([]byte{0x10, 0})
// base := new(Int).InitBytes([]byte{0x10}, moduloI, BigEndian)
//
// clone := base.Clone()
// clone.Add(clone, clone)
// b1, _ := clone.marshal_binary()
// b2, _ := base.marshal_binary()
// if bytes.Equal(b1, b2) {
// t.Error("Should not be equal")
// }
// }
}