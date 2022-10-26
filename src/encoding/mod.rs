mod encoding;

pub use encoding::{
    marshal_binary, unmarshal_binary, BinaryMarshaler, BinaryUnmarshaler, Marshaling,
    MarshallingError,
};
