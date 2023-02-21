use thiserror::Error;

use crate::{
    dh::DhError,
    encoding::MarshallingError,
    share::{poly::PolyError, vss::VSSError},
    sign::error::SignatureError,
};

#[derive(Debug, Error)]
pub enum DKGError {
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
    #[error("vss error")]
    VSSError(#[from] VSSError),
    #[error("own public key not found in list of participants")]
    MissingOwnPublicKey,
    #[error("dist deal out of bounds index")]
    DistDealIndexOutOfBounds,
    #[error("already received dist deal from same index")]
    DistDealAlreadyProcessed,
    #[error("unexpected deal for unlisted dealer in new list")]
    DistDealFromUnlistedDealer,
    #[error("complaint received but no deal for it")]
    ComplaintWithoutDeal,
    #[error("justification received but no deal for it")]
    JustificationWithoutDeal,
    #[error("can't give secret commits if deal not certified")]
    DealNotCertified,
    #[error("commits should not be none")]
    MissingCommits,
    #[error("secret commits received with index out of bounds")]
    SecretCommitsOutOfBound,
    #[error("secret commits from a non QUAL member")]
    SecretCommitsFromNonQUAL,
    #[error("secret commits received with wrong session id")]
    SecretCommitsWrongId,
    #[error("verifier should exists")]
    MissingVerifier,
    #[error("deal should exists")]
    MissingDeal,
    #[error("commit complaint with unknown issuer")]
    CommitComplaintUnknownIssuer,
    #[error("commit complaint from non-qual member")]
    CommitComplaintNonQUAL,
    #[error("commit complaint linked to unknown verifier")]
    CommitComplaintUnknownVerifier,
    #[error("complaint about non received commitments")]
    CommitComplaintNoCommits,
    #[error("invalid complaint, deal verifying")]
    CommitComplaintInvalid,
    #[error("complaint linked to non certified deal")]
    CommitComplaintUncertifiedDeal,
    #[error("commitments not invalidated by any complaints")]
    CommitmentsNotInvalidated,
    #[error("reconstruct commits with invalid verifier index")]
    ReconstructCommitsInvalidVerifierIndex,
    #[error("reconstruct commits invalid session id")]
    ReconstructCommitsInvalidId,
    #[error("distributed key not certified")]
    DistributedKeyNotCertified,
    #[error("deals not found")]
    DealsNotFound,
    #[error("protocol not finished")]
    ProtocolNotFinished(String),
    #[error("can't run with empty node list")]
    EmptyNodeList,
    #[error("resharing config needs old nodes list")]
    ReshareMissingOldNodes,
    #[error("resharing case needs old threshold")]
    ReshareMissingOldThreshold,
    #[error("can't receive new shares without the public polynomial")]
    NoPublicPolys,
    #[error("public key not found in old list or new list")]
    PublicKeyNotFound,
    #[error("cannot process own deal")]
    CannotProcessOwnDeal(String),
    #[error("own deal gave a complaint")]
    OwnDealComplaint,
    #[error("responses received for unknown dealer")]
    ResponseFromUnknownDealer,
    #[error("should not expect to compute any dist. share")]
    ShouldReceive,
    #[error("share do not correspond to public polynomial")]
    ShareDoesNotMatchPublicPoly,
    #[error("duplicate public key in new nodes list")]
    DuplicatePublicKeyInNewList,
    #[error("wrong renewal function")]
    WrongRenewal,
    #[error("not the same party")]
    DifferentParty,
}
