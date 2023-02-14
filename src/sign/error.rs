use thiserror::Error;

use crate::encoding::MarshallingError;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("marshalling error")]
    MarshallingError(#[from] MarshallingError),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("signature is not valid")]
    InvalidSignature(String),
    #[error("wrong signature length")]
    InvalidSignatureLength(String),
    #[error("signature is not canonical")]
    SignatureNotCanonical,
    #[error("R is not canonical")]
    RNotCanonical,
    #[error("R has small order")]
    RSmallOrder,
    #[error("public key is not canonical")]
    PublicKeyNotCanonical,
    #[error("public key has small order")]
    PublicKeySmallOrder,
}
