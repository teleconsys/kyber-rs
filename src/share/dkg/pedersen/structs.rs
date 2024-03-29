use core::fmt::{Debug, Display, Formatter};
use serde::{Deserialize, Serialize};

use crate::{
    encoding::{self, BinaryMarshaler, MarshallingError},
    share::{
        poly::PriShare,
        vss::{
            pedersen::vss::{self, EncryptedDeal},
            suite::Suite,
        },
    },
    sign::dss,
    Point,
};

/// [`DistKeyShare`] holds the share of a distributed key for a participant.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DistKeyShare<SUITE: Suite> {
    /// `coefficients of the public polynomial` holding the public key.
    pub commits: Vec<SUITE::POINT>,
    /// `share` of the distributed secret which is private information.
    pub share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// `coefficients of the private polynomial` generated by the node holding the
    /// `share`. The final distributed polynomial is the sum of all these
    /// individual polynomials, but it is never computed.
    pub private_poly: Vec<<SUITE::POINT as Point>::SCALAR>,
}

impl<SUITE: Suite> Debug for DistKeyShare<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DistKeyShare")
            .field("commits", &self.commits)
            .finish()
    }
}

impl<SUITE: Suite> Display for DistKeyShare<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "DistKeyShare(")?;

        write!(f, " commits: [")?;
        let commits = self
            .commits
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}] )", commits)
    }
}

impl<SUITE: Suite> DistKeyShare<SUITE> {
    /// [`public()`] returns the public key associated with the distributed private key.
    pub fn public(&self) -> SUITE::POINT {
        self.commits[0].clone()
    }
}

impl<SUITE: Suite> dss::DistKeyShare<SUITE> for DistKeyShare<SUITE> {
    /// [`pri_share()`] implements the [`dss::DistKeyShare`] trait so either pedersen or
    /// rabin dkg can be used with dss.
    fn pri_share(&self) -> PriShare<<SUITE::POINT as Point>::SCALAR> {
        self.share.clone()
    }

    /// [`commitments()`] implements the [`dss::DistKeyShare`] trait so either pedersen or
    /// rabin dkg can be used with dss.
    fn commitments(&self) -> Vec<SUITE::POINT> {
        self.commits.clone()
    }
}

/// [`Deal`] holds the Deal for one participant as well as the index of the issuing
/// Dealer.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Deal<POINT: Point> {
    /// `index` of the Dealer in the list of participants
    pub index: u32,
    /// `deal` issued for another participant
    #[serde(deserialize_with = "EncryptedDeal::deserialize")]
    pub deal: EncryptedDeal<POINT>,
    /// `signature` over the whole message
    pub signature: Vec<u8>,
}

impl<POINT: Point> Display for Deal<POINT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Deal( index: {}, deal: {}, signature: 0x{} )",
            self.index,
            self.deal,
            hex::encode(&self.signature)
        )
    }
}

impl<POINT: Point> BinaryMarshaler for Deal<POINT> {
    fn marshal_binary(&self) -> Result<Vec<u8>, MarshallingError> {
        let mut deal = self.clone();
        deal.signature = Vec::new();
        encoding::marshal_binary(&deal)
    }
}

/// [`Response`] holds the Response from another participant as well as the index of
/// the target Dealer.
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// `index` of the Dealer for which this response is for
    pub index: u32,
    /// `response` issued from another participant
    pub response: vss::Response,
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Response( index: {}, response: {} )",
            self.index, self.response
        )
    }
}

/// [`Justification`] holds the Justification from a Dealer as well as the index of
/// the Dealer in question.
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct Justification<SUITE: Suite> {
    /// `index` of the Dealer who answered with this Justification
    pub index: u32,
    /// `justification` issued from the Dealer
    pub justification: vss::Justification<SUITE>,
}

impl<SUITE: Suite> Display for Justification<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Justification( index: {}, justification: {} )",
            self.index, self.justification
        )
    }
}
