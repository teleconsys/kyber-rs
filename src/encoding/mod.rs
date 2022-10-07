mod encoding;

pub use encoding::{
    BinaryMarshaler,
    BinaryUnmarshaller,
    Marshaling,
    MarshallingError,
    unmarshal_binary,
    marshal_binary,
};