use anyhow::Result;
use std::io::Write;

use crate::{Point, Scalar};

/// PointMarshalTo provides a generic implementation of Point.EncodeTo
/// based on Point.Encode.
pub fn point_marshal_to<P: Point<S>, S: Scalar>(p: P, w: &mut impl Write) -> Result<()> {
    let buf = p.marshal_binary()?;
    w.write_all(&buf)?;
    Ok(())
}
