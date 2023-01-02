use anyhow::Result;
use serde::Serialize;

use crate::{
    encoding::{self, BinaryMarshaler},
    share::{
        poly::PriShare,
        vss::{self, pedersen, suite::Suite},
    },
    sign::dss,
    Point,
};

/// DistKeyShare holds the share of a distributed key for a participant.
#[derive(Clone)]
pub struct DistKeyShare<SUITE: Suite> {
    /// Coefficients of the public polynomial holding the public key.
    pub commits: Vec<SUITE::POINT>,
    /// Share of the distributed secret which is private information.
    pub share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Coefficients of the private polynomial generated by the node holding the
    /// share. The final distributed polynomial is the sum of all these
    /// individual polynomials, but it is never computed.
    pub private_poly: Vec<<SUITE::POINT as Point>::SCALAR>,
}

impl<SUITE: Suite> DistKeyShare<SUITE> {
    /// Public returns the public key associated with the distributed private key.
    pub fn public(&self) -> SUITE::POINT {
        self.commits[0].clone()
    }
}

impl<SUITE: Suite> dss::DistKeyShare<SUITE> for DistKeyShare<SUITE> {
    /// PriShare implements the dss.DistKeyShare interface so either pedersen or
    /// rabin dkg can be used with dss.
    fn pri_share(&self) -> PriShare<<SUITE::POINT as Point>::SCALAR> {
        self.share.clone()
    }

    /// Commitments implements the dss.DistKeyShare interface so either pedersen or
    /// rabin dkg can be used with dss.
    fn commitments(&self) -> Vec<SUITE::POINT> {
        self.commits.clone()
    }
}

/// Deal holds the Deal for one participant as well as the index of the issuing
/// Dealer.
#[derive(Clone, Serialize)]
pub struct Deal<POINT: Point + Serialize> {
    /// Index of the Dealer in the list of participants
    pub index: u32,
    /// Deal issued for another participant
    pub deal: pedersen::vss::EncryptedDeal<POINT>,
    /// Signature over the whole message
    pub signature: Vec<u8>,
}

impl<POINT: Point + Serialize> BinaryMarshaler for Deal<POINT> {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        let mut deal = self.clone();
        deal.signature = Vec::new();
        encoding::marshal_binary(&deal)
        // 	var b bytes.Buffer
        // 	binary.Write(&b, binary.LittleEndian, d.Index)
        // 	b.Write(d.Deal.Cipher)
        // 	return b.Bytes(), nil
    }
}

/// Response holds the Response from another participant as well as the index of
/// the target Dealer.
#[derive(Clone)]
pub struct Response {
    /// Index of the Dealer for which this response is for
    pub index: u32,
    /// Response issued from another participant
    pub response: vss::pedersen::vss::Response,
}

/// Justification holds the Justification from a Dealer as well as the index of
/// the Dealer in question.
#[derive(Clone)]
pub struct Justification<SUITE: Suite> {
    /// Index of the Dealer who answered with this Justification
    pub index: u32,
    /// Justification issued from the Dealer
    pub justification: vss::pedersen::vss::Justification<SUITE>,
}
