use std::io::{Read, Write};

use crate::{cipher::Stream, encoding::MarshallingError, Point, Scalar};

// TODO: add support for other than binary
/// [`point_marshal_to()`] provides a generic implementation of [`Point`] encoding
pub fn point_marshal_to(p: &impl Point, w: &mut impl Write) -> Result<(), MarshallingError> {
    let buf = p.marshal_binary()?;
    w.write_all(&buf)?;
    Ok(())
}

// TODO: add support for other than binary
/// [`point_unmarshal_from()`] provides an implementation of [`Point`] decoding.
/// where `r` is a [`Read`]
pub fn point_unmarshal_from(p: &mut impl Point, r: &mut impl Read) -> Result<(), MarshallingError> {
    let mut buf = vec![0_u8; p.marshal_size()];
    r.read_exact(&mut buf)?;
    p.unmarshal_binary(&buf)
}

/// [`point_unmarshal_from_random()`] provides a generic implementation of [`Point`] decoding
/// where `r` is a [`Stream`] and a [`Read`].
pub fn point_unmarshal_from_random(p: &mut impl Point, r: &mut (impl Read + Stream)) {
    *p = p.clone().pick(r);
}

// TODO: add support for other than binary
/// [`scalar_marshal_to()`] provides a generic implementation of [`Scalar`] encoding.
pub fn scalar_marshal_to(s: &impl Scalar, w: &mut impl Write) -> Result<(), MarshallingError> {
    let buf = s.marshal_binary()?;
    w.write_all(buf.as_slice())?;
    Ok(())
}

// TODO: add support for other than binary
/// [`scalar_unmarshal_from()`] provides a generic implementation of [`Scalar`] decoding,
/// where `r` is a [`Read`]
pub fn scalar_unmarshal_from(
    s: &mut impl Scalar,
    r: &mut impl Read,
) -> Result<(), MarshallingError> {
    let mut buf = vec![0_u8; s.marshal_size()];
    r.read_exact(&mut buf)?;
    s.unmarshal_binary(&buf)
}

/// [`scalar_unmarshal_from()`] provides an implementation of [`Scalar`] decoding,
/// where `r` is a [`Stream`] and a [`Read`]
pub fn scalar_unmarshal_from_random(s: &mut impl Scalar, r: &mut (impl Read + Stream)) {
    *s = s.clone().pick(r);
}
