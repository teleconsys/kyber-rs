use anyhow::Result;
use std::io::{Write, Read};

use crate::{Point, Scalar, cipher::Stream};

/// PointMarshalTo provides a generic implementation of Point.EncodeTo
/// based on Point.Encode.
pub fn point_marshal_to(p: &impl Point, w: &mut impl Write) -> Result<()> {
    let buf = p.marshal_binary()?;
    w.write_all(&buf)?;
    Ok(())
}

/// PointUnmarshalFrom provides a generic implementation of Point.DecodeFrom,
/// based on Point.Decode, or Point.Pick if r is a Cipher or cipher.Stream.
/// The returned byte-count is valid only when decoding from a normal Reader,
/// not when picking from a pseudorandom source.
pub fn point_unmarshal_from(p: &mut impl Point, r: &mut impl Read) -> Result<()> {
	let mut buf = vec![0_u8; p.marshal_size()];
    r.read_exact(&mut buf)?;
    p.unmarshal_binary(&buf)
}

/// PointUnmarshalFromRandom provides a generic implementation of Point.DecodeFrom,
/// based on Point.Decode, or Point.Pick if r is a Cipher or cipher.Stream.
/// The returned byte-count is valid only when decoding from a normal Reader,
/// not when picking from a pseudorandom source.
pub fn point_unmarshal_from_random(p: &mut impl Point, r: &mut (impl Read + Stream)) {
		*p = p.clone().pick(r);
}

// ScalarMarshalTo provides a generic implementation of Scalar.EncodeTo
// based on Scalar.Encode.
pub fn scalar_marshal_to(s: &impl Scalar, w: &mut impl Write) -> Result<()> {
    let buf = s.marshal_binary()?;
    w.write_all(buf.as_slice())?;
    Ok(())
}

/// ScalarUnmarshalFrom provides a generic implementation of Scalar.DecodeFrom,
/// based on Scalar.Decode, or Scalar.Pick if r is a Cipher or cipher.Stream.
/// The returned byte-count is valid only when decoding from a normal Reader,
/// not when picking from a pseudorandom source.
pub fn scalar_unmarshal_from(s: &mut impl Scalar, r: &mut impl Read) -> Result<()> {
	let mut buf = vec![0_u8; s.marshal_size()];
    r.read_exact(&mut buf)?;
    s.unmarshal_binary(&buf)
}

/// ScalarUnmarshalFrom provides a generic implementation of Scalar.DecodeFrom,
/// based on Scalar.Decode, or Scalar.Pick if r is a Cipher or cipher.Stream.
/// The returned byte-count is valid only when decoding from a normal Reader,
/// not when picking from a pseudorandom source.
pub fn scalar_unmarshal_from_random(s: &mut impl Scalar, r: &mut (impl Read + Stream)) {
    *s = s.clone().pick(r);
}

// // Not used other than for reflect.TypeOf()
// var aScalar kyber.Scalar
// var aPoint kyber.Point

// var tScalar = reflect.TypeOf(&aScalar).Elem()
// var tPoint = reflect.TypeOf(&aPoint).Elem()

// // GroupNew is the Default implementation of reflective constructor for Group
// func GroupNew(g kyber.Group, t reflect.Type) interface{} {
// 	switch t {
// 	case tScalar:
// 		return g.Scalar()
// 	case tPoint:
// 		return g.Point()
// 	}
// 	return nil
// }