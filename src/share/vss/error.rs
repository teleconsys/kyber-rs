use thiserror::Error;

use crate::{
    dh::DhError, encoding::MarshallingError, share::poly::PolyError, sign::error::SignatureError,
};

#[derive(Debug, Error)]
pub enum VSSError {
    #[error("marshalling error")]
    MarshallingError(#[from] MarshallingError),
    #[error("dh error")]
    DhError(#[from] DhError),
    #[error("signature error")]
    SignatureError(#[from] SignatureError),
    #[error("polynomial error")]
    PolyError(#[from] PolyError),
    #[error("io error")]
    IoError(#[from] std::io::Error),
    #[error("invalid threshold")]
    InvalidThreshold(String),
    #[error("wrong index to generate encrypted deal")]
    DealerWrongIndex,
    #[error("receiving inconsistent sessionID in response")]
    ResponseInconsistentSessionId,
    #[error("index out of bounds in response")]
    ResponseIndexOutOfBounds,
    #[error("index out of bounds in complaint")]
    ComplaintIndexOutOfBounds,
    #[error("already existing response from same origin")]
    ResponseAlreadyExisting,
    #[error("missing aggregator")]
    MissingAggregator,
    #[error("no aggregator for verifier")]
    NoAggregatorForVerifier,
    #[error("public key not found in the list of verifiers")]
    PublicKeyNotFound,
    #[error("verifier got wrong index from deal")]
    DealWrongIndex,
    #[error("verifier already received a deal")]
    DealAlreadyProcessed,
    #[error("share does not verify against commitments in deal")]
    DealDoesNotVerify,
    #[error("invalid t received in deal")]
    DealInvalidThreshold,
    #[error("incompatible threshold - potential attack")]
    DealIncompatibleThreshold,
    #[error("found different sessionIDs from deal")]
    DealInvalidSessionId,
    #[error("not the same index for f and g share in deal")]
    DealInconsistentIndex,
    #[error("index out of bounds in deal")]
    DealIndexOutOfBounds,
    #[error("index out of bounds in justification")]
    JustificationIndexOutOfBounds,
    #[error("no complaints received for this justification")]
    JustificationNoComplaints,
    #[error("justification received for an approval")]
    JustificationForApproval,
    #[error("all deals need to have same session id")]
    DealsSameID,
}
