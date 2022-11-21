use anyhow::Result;
use std::io::Write;

use crate::{Point, Scalar};

/// PointMarshalTo provides a generic implementation of Point.EncodeTo
/// based on Point.Encode.
pub fn point_marshal_to<P: Point>(p: &P, w: &mut impl Write) -> Result<()> {
    let buf = p.marshal_binary()?;
    w.write_all(&buf)?;
    Ok(())
}

// ScalarMarshalTo provides a generic implementation of Scalar.EncodeTo
// based on Scalar.Encode.
pub fn scalar_marshal_to<'a>(s: &impl Scalar, w: &mut impl Write) -> Result<()> {
    let buf = s.marshal_binary()?;
    w.write_all(buf.as_slice())?;
    Ok(())
}
