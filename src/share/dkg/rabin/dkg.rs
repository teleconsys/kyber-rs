/// module [`rabin::dkg`] implements the protocol described in
/// "Secure Distributed Key Generation for Discrete-Log
/// Based Cryptosystems" by R. Gennaro, S. Jarecki, H. Krawczyk, and T. Rabin.
/// DKG enables a group of participants to generate a distributed key
/// with each participants holding only a share of the key. The key is also
/// never computed locally but generated distributively whereas the public part
/// of the key is known by every participants.
/// The underlying basis for this protocol is the VSS protocol implemented in the
/// share/vss package.
///
/// The protocol works as follow:
///
///   1. Each participant instantiates a [`DistKeyShare`] (DKS) struct.
///   2. Then each participant runs an instance of the VSS protocol:
///     - each participant generates their deals with the method [`deals()`] and then
///      sends them to the right recipient.
///     - each participant processes the received deal with [`process_deal()`] and
///      broadcasts the resulting response.
///     - each participant processes the response with [`process_response()`]. If a
///      justification is returned, it must be broadcasted.
///   3. Each participant can check if step 2. is done by calling
///   [`certified()`].Those participants where [`certified()`] returned true, belong to
///   the set of "qualified" participants who will generate the distributed
///   secret. To get the list of qualified participants, use [`qual()`].
///   4. Each QUAL participant generates their secret commitments calling
///    [`secret_commits()]` and broadcasts them to the QUAL set.
///   5. Each QUAL participant processes the received secret commitments using
///    [`secret_commits()]`. If there is an error, it can return a commitment complaint
///    ([`ComplaintCommits`]) that must be broadcasted to the QUAL set.
///   6. Each QUAL participant receiving a complaint can process it with
///    [`process_complaint_commits()` which returns the secret share
///    ([`ReconstructCommits`]) given from the malicious participant. This structure
///    must be broadcasted to all the QUAL participant.
///   7. At this point, every QUAL participant can issue the distributed key by
///    calling [`dist_key_share()`].
extern crate alloc;
use core::fmt::{Debug, Display, Formatter};
use std::collections::HashMap;

use byteorder::{LittleEndian, WriteBytesExt};
use digest::Digest;
use serde::{Deserialize, Serialize};

use crate::{
    encoding::{BinaryMarshaler, Marshaling},
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    share::{
        dkg::DKGError,
        poly::{recover_pri_poly, PriShare, PubPoly},
        vss::{
            rabin::vss::{self, EncryptedDeal},
            suite::Suite,
        },
    },
    sign::{dss, schnorr},
    Point, Scalar,
};

/// [`DistKeyShare`] holds the share of a distributed key for a participant.
#[derive(Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct DistKeyShare<SUITE: Suite> {
    /// `Coefficients` of the public polynomial holding the public key
    pub commits: Vec<SUITE::POINT>,
    /// `Share` of the distributed secret
    pub share: PriShare<<SUITE::POINT as Point>::SCALAR>,
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

    /// [`commitments()`] implements the [`dss::DistKeyShare`] interface so either pedersen or
    /// rabin dkg can be used with dss.
    fn commitments(&self) -> Vec<SUITE::POINT> {
        self.commits.clone()
    }
}

/// [`Deal`] holds the Deal for one participant as well as the index of the issuing
/// Dealer.
///  NOTE: Doing that in vss module would be possible but then the Dealer is always
///  assumed to be a member of the participants. It's only the case here.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct Deal<POINT: Point> {
    /// `Index` of the Dealer in the list of participants
    pub index: u32,
    /// `Deal` issued for another participant
    #[serde(deserialize_with = "EncryptedDeal::deserialize")]
    pub deal: EncryptedDeal<POINT>,
}

impl<POINT: Point> Display for Deal<POINT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Deal( index: {}, deal: {} )", self.index, self.deal)
    }
}

/// [`Response`] holds the Response from another participant as well as the index of
/// the target Dealer.
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// `Index` of the Dealer for which this response is for
    pub index: u32,
    /// `Response` issued from another participant
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
    /// Index of the Dealer who answered with this Justification
    pub index: u32,
    /// Justification issued from the Dealer
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

/// [`SecretCommits`] is sent during the distributed public key reconstruction phase,
/// basically a Feldman VSS scheme.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecretCommits<SUITE: Suite> {
    /// Index of the Dealer in the list of participants
    pub index: u32,
    /// Commitments generated by the Dealer
    pub commitments: Vec<SUITE::POINT>,
    /// SessionID generated by the Dealer tied to the Deal
    pub session_id: Vec<u8>,
    /// Signature from the Dealer
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> Display for SecretCommits<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretCommits( index: {},", self.index,)?;

        write!(f, " commitments: [")?;
        let commitments = self
            .commitments
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", commitments)?;

        write!(
            f,
            " session_id: 0x{}, signature: 0x{} )",
            hex::encode(&self.session_id),
            hex::encode(&self.signature)
        )
    }
}

impl<SUITE: Suite> SecretCommits<SUITE> {
    /// [`hash()`] returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>, DKGError> {
        let mut h = s.hash();
        h.update("secretcommits".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        for c in self.commitments.clone() {
            c.marshal_to(&mut h)?
        }
        Ok(h.finalize().to_vec())
    }
}

/// [`ComplaintCommits`] is sent if the secret commitments revealed by a peer are not
/// valid.
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct ComplaintCommits<SUITE: Suite> {
    /// `index` of the Verifier issuing the Complaint Commit
    pub index: u32,
    /// `dealer_index` being the index of the Dealer who issued the [`SecretCommits`]
    pub dealer_index: u32,
    /// [`Deal`] that has been given from the Dealer (at `dealer_index`) to this node
    /// (at `index`)
    pub deal: vss::Deal<SUITE>,
    /// `signature` made by the verifier
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> Display for ComplaintCommits<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ComplaintCommits( index: {}, dealer_index: {}, deal: {}, signature: 0x{} )",
            self.index,
            self.dealer_index,
            self.deal,
            hex::encode(&self.signature)
        )
    }
}

impl<SUITE: Suite> ComplaintCommits<SUITE> {
    /// [`hash()`] returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>, DKGError> {
        let mut h = s.hash();
        h.update("commitcomplaint".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.dealer_index)?;
        let buff = self.deal.marshal_binary()?;
        h.update(&buff);
        Ok(h.finalize().to_vec())
    }
}

/// [`ReconstructCommits`] holds the information given by a participant who reveals
/// the deal received from a peer that has received a Complaint Commits.
#[derive(Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct ReconstructCommits<SUITE: Suite> {
    /// `id` of the session
    pub session_id: Vec<u8>,
    /// `index` of the verifier who received the [`Deal`]
    pub index: u32,
    /// `dealer_index` is the index of the dealer who issued the [`Deal`]
    pub dealer_index: u32,
    /// `share` contained in the [`Deal`]
    pub share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// `signature` over all over fields generated by the issuing verifier
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> Debug for ReconstructCommits<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReconstructCommits")
            .field("session_id", &self.session_id)
            .field("index", &self.index)
            .field("dealer_index", &self.dealer_index)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<SUITE: Suite> Display for ReconstructCommits<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReconstructCommits( session_id: 0x{}, index: {}, dealer_index: {}, signature: 0x{} )",
            hex::encode(&self.session_id),
            self.index,
            self.dealer_index,
            hex::encode(&self.signature)
        )
    }
}

impl<SUITE: Suite> ReconstructCommits<SUITE> {
    /// [`hash()`] returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>, DKGError> {
        let mut h = s.hash();
        h.update("reconstructcommits".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.dealer_index)?;
        let share_buff = self.share.hash(*s)?;
        h.update(&share_buff);
        Ok(h.finalize().to_vec())
    }
}

/// [`DistKeyGenerator`] is the struct that runs the DKG protocol.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DistKeyGenerator<SUITE: Suite> {
    pub suite: SUITE,

    pub index: u32,
    pub long: <SUITE::POINT as Point>::SCALAR,
    pub pubb: SUITE::POINT,

    pub participants: Vec<SUITE::POINT>,

    pub t: usize,

    pub dealer: vss::Dealer<SUITE>,
    pub verifiers: HashMap<u32, vss::Verifier<SUITE>>,

    /// `list of commitments` to each secret polynomial
    pub commitments: HashMap<u32, PubPoly<SUITE>>,

    /// `map of deals` collected to reconstruct the full polynomial of a dealer.
    /// The key is index of the dealer. Once there are enough ReconstructCommits
    /// struct, this dkg will re-construct the polynomial and stores it into the
    /// list of commitments.
    pub pending_reconstruct: HashMap<u32, Vec<ReconstructCommits<SUITE>>>,
    pub reconstructed: HashMap<u32, bool>,
}

impl<SUITE: Suite> Debug for DistKeyGenerator<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DistKeyGenerator")
            .field("suite", &self.suite)
            .field("index", &self.index)
            .field("pubb", &self.pubb)
            .field("participants", &self.participants)
            .field("t", &self.t)
            .field("dealer", &self.dealer)
            .field("verifiers", &self.verifiers)
            .field("commitments", &self.commitments)
            .field("pending_reconstruct", &self.pending_reconstruct)
            .field("reconstructed", &self.reconstructed)
            .finish()
    }
}

impl<T: Suite> Display for DistKeyGenerator<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DistKeyGenerator( suite: {}, index: {}, public: {},",
            self.suite, self.index, self.pubb,
        )?;

        write!(f, " participants: [")?;
        let participants = self
            .participants
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", participants)?;

        write!(f, " threshold: {}, dealer: {},", self.t, self.dealer,)?;

        write!(f, " verifiers: [")?;
        let verifiers = self
            .verifiers
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", verifiers)?;

        write!(f, " commitments: [")?;
        let commitments = self
            .commitments
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", commitments)?;

        write!(f, " pending_reconstruct: [")?;
        let pending_reconstruct = self
            .pending_reconstruct
            .iter()
            .map(|c| {
                let vec_str =
                    c.1.iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                "(".to_string() + &c.0.to_string() + ", [" + &vec_str + "])"
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", pending_reconstruct)?;

        write!(f, " reconstructed: [")?;
        let reconstructed = self
            .reconstructed
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}] )", reconstructed)
    }
}

/// [`new_dist_key_generator()`] returns a [`DistKeyGenerator`] out of the suite,
/// the longterm secret key, the list of participants, and the
/// threshold t parameter. It returns an error if the secret key's
/// commitment can't be found in the list of participants.
pub fn new_dist_key_generator<SUITE: Suite>(
    suite: &SUITE,
    longterm: &<SUITE::POINT as Point>::SCALAR,
    participants: &[SUITE::POINT],
    t: usize,
) -> Result<DistKeyGenerator<SUITE>, DKGError> {
    let pubb = suite.point().mul(longterm, None);
    // find our index
    let mut found = false;
    let mut index = 0;
    for (i, p) in participants.iter().enumerate() {
        if p.eq(&pubb) {
            found = true;
            index = i as u32;
            break;
        }
    }
    if !found {
        return Err(DKGError::MissingOwnPublicKey);
    }
    // generate our dealer / deal
    let own_sec = suite.scalar().pick(&mut suite.random_stream());
    let dealer = vss::new_dealer(*suite, longterm.clone(), own_sec, participants, t)?;

    Ok(DistKeyGenerator {
        dealer,
        verifiers: HashMap::new(),
        commitments: HashMap::new(),
        pending_reconstruct: HashMap::new(),
        reconstructed: HashMap::new(),
        t,
        suite: *suite,
        long: longterm.clone(),
        pubb,
        participants: participants.to_vec(),
        index,
    })
}

impl<SUITE: Suite> DistKeyGenerator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    /// [`deals()`] returns all the [`deals`](Deal) that must be broadcasted to all
    /// participants. The deal corresponding to this DKG is already added
    /// to this DKG and is ommitted from the returned map. To know
    /// to which participant a deal belongs to, loop over the keys as indices in
    /// the list of participants:
    ///     
    /// for (i,dd) in dist_deals.iter().enumerate() {
    ///     send_to(participants[i],dd)
    /// }
    ///
    /// This method panics if it can't process its own deal.
    pub fn deals(&mut self) -> Result<HashMap<usize, Deal<SUITE::POINT>>, DKGError> {
        let deals = self.dealer.encrypted_deals()?;
        let mut dd = HashMap::new();
        for (i, _) in self.participants.clone().iter().enumerate() {
            let distd = Deal {
                index: self.index,
                deal: deals[i].clone(),
            };
            if i == self.index as usize {
                if self.verifiers.contains_key(&self.index) {
                    // already processed our own deal
                    continue;
                }

                let resp = self.process_deal(&distd)?;
                if !resp.response.approved {
                    panic!("dkg: own deal gave a complaint")
                }

                // If processed own deal correctly, set positive response in this
                // DKG's dealer's own verifier
                let idx_clone = self.index;
                self.dealer.unsafe_set_response_dkg(idx_clone, true);
                continue;
            }
            dd.insert(i, distd);
        }
        Ok(dd)
    }

    /// [`process_deal()`] takes a [`Deal`] created by [`deals()`] and stores and verifies it. It
    /// returns a [`Response`] to broadcast to every other participants. It returns an
    /// [`Error`](DKGError) in case the deal has already been stored, or if the deal is incorrect
    /// (see [`rabin::vss::Verifier.process_encrypted_deal()`]).
    pub fn process_deal(&mut self, dd: &Deal<SUITE::POINT>) -> Result<Response, DKGError> {
        // public key of the dealer
        let pubb = match find_pub(&self.participants, dd.index as usize) {
            Some(pubb) => pubb,
            None => return Err(DKGError::DistDealIndexOutOfBounds),
        };

        if self.verifiers.contains_key(&dd.index) {
            return Err(DKGError::DistDealAlreadyProcessed);
        }

        // verifier receiving the dealer's deal
        let mut ver = vss::new_verifier(&self.suite, &self.long, &pubb, &self.participants)?;

        let resp = ver.process_encrypted_deal(&dd.deal)?;

        // Set StatusApproval for the verifier that represents the participant
        // that distibuted the Deal
        ver.unsafe_set_response_dkg(dd.index, true);

        self.verifiers.insert(dd.index, ver);

        Ok(Response {
            index: dd.index,
            response: resp,
        })
    }

    /// [`process_response()`] takes a [`Response`] from every other peer.  If the response
    /// designates the [`Deal`] of another participants than this dkg, this dkg stores it
    /// and returns `None` with a possible [`Error`](DKGError) regarding the validity of the response.
    /// If the response designates a deal this dkg has issued, then the dkg will process
    /// the response, and returns a [`Justification`].
    pub fn process_response(
        &mut self,
        resp: &Response,
    ) -> Result<Option<Justification<SUITE>>, DKGError> {
        if !self.verifiers.contains_key(&resp.index) {
            return Err(DKGError::ComplaintWithoutDeal);
        }

        let v = self.verifiers.get_mut(&resp.index).unwrap();
        v.process_response(&resp.response)?;

        if resp.index != self.index {
            return Ok(None);
        }

        let j = match self.dealer.process_response(&resp.response)? {
            Some(justification) => justification,
            None => return Ok(None),
        };

        // a justification for our own deal, are we cheating !?
        v.process_justification(&j)?;

        Ok(Some(Justification::<SUITE> {
            index: self.index,
            justification: j,
        }))
    }

    /// [`process_justification()`] takes a [`Justification`] and validates it. It returns an
    /// [`Error`](DKGError) in case the justification is wrong.
    pub fn process_justification(&mut self, j: &Justification<SUITE>) -> Result<(), DKGError> {
        if !self.verifiers.contains_key(&j.index) {
            return Err(DKGError::JustificationWithoutDeal);
        }

        let v = match self.verifiers.get_mut(&j.index) {
            Some(v) => v,
            None => return Err(DKGError::MissingVerifier),
        };
        Ok(v.process_justification(&j.justification)?)
    }

    /// [`set_timeout()`] triggers the timeout on all verifiers, and thus makes sure
    /// all verifiers have either responded, or have a StatusComplaint response.
    pub fn set_timeout(&mut self) {
        for (_, v) in self.verifiers.iter_mut() {
            v.set_timeout()
        }
    }

    /// [`certified()`] returns `true` if at least `t` deals are certified (see
    /// [`rabin::vss::Verifier.deal_certified()`]). If the distribution is certified, the protocol
    /// can continue using [`d.secret_commits()`].
    pub fn certified(&self) -> bool {
        self.qual().len() >= self.t
    }

    /// [`qual()`] returns the index in the list of participants that forms the `QUALIFIED`
    /// set as described in the "New-DKG" protocol by Rabin. Basically, it consists
    /// of all participants that are not disqualified after having  exchanged all
    /// [`deals`](Deal), [`responses`](Response) and [`justifications`](Justification).
    /// This is the set that is used to extract the distributed public key with
    /// [`secret_commits()`] and [`process_secret_commits()`].
    pub fn qual(&self) -> Vec<usize> {
        let mut good = Vec::new();
        self.qual_iter(|i, _| {
            good.push(i as usize);
            true
        });
        good
    }

    pub fn is_in_qual(&self, idx: u32) -> bool {
        let mut found = false;
        self.qual_iter(|i, _| {
            if i == idx {
                found = true;
                false
            } else {
                true
            }
        });
        found
    }

    fn qual_iter<F>(&self, mut f: F)
    where
        F: FnMut(u32, &vss::Verifier<SUITE>) -> bool,
    {
        for (i, v) in self.verifiers.iter() {
            if v.deal_certified() && !f(*i, v) {
                break;
            }
        }
    }

    /// [`secret_commits()`] returns the commitments of the coefficients of the secret
    /// polynomials. This secret commits must be broadcasted to every other
    /// participant and must be processed by ProcessSecretCommits. In this manner,
    /// the coefficients are revealed through a Feldman VSS scheme.
    /// This dkg must have its deal certified, otherwise it returns an error. The
    /// [`SecretCommits`] returned is already added to this dkg's list of SecretCommits.
    pub fn secret_commits(&mut self) -> Result<SecretCommits<SUITE>, DKGError> {
        if !self.dealer.deal_certified() {
            return Err(DKGError::DealNotCertified);
        }

        let commitments = match self.dealer.commits() {
            Some(c) => c,
            None => return Err(DKGError::MissingCommits),
        };

        let mut sc = SecretCommits::<SUITE> {
            commitments,
            index: self.index,
            session_id: self.dealer.session_id(),
            signature: Vec::new(),
        };
        let msg = sc.hash(&self.suite)?;
        let sig = schnorr::sign(&self.suite, &self.long, &msg)?;

        sc.signature = sig;
        // adding our own commitments
        self.commitments.insert(
            self.index,
            PubPoly::new(
                &self.suite,
                Some(self.suite.point().base()),
                &sc.commitments,
            ),
        );
        Ok(sc)
    }

    /// [`process_secret_commits()`] takes a [`SecretCommits`] from every other participant and
    /// verifies and stores it. It returns an [`Error`](DKGError) in case the SecretCommits is
    /// invalid. In case the SecretCommits are valid, but this dkg can't verify its
    /// share, it returns a ComplaintCommits that must be broadcasted to every other
    /// participant. It returns `None` otherwise.
    pub fn process_secret_commits(
        &mut self,
        sc: &SecretCommits<SUITE>,
    ) -> Result<Option<ComplaintCommits<SUITE>>, DKGError> {
        let pubb = match find_pub(&self.participants, sc.index as usize) {
            Some(public) => public,
            None => return Err(DKGError::SecretCommitsOutOfBound),
        };

        if !self.is_in_qual(sc.index) {
            return Err(DKGError::SecretCommitsFromNonQUAL);
        }

        // mapping verified by isInQUAL
        let v = match self.verifiers.get(&sc.index) {
            Some(v) => v,
            None => return Err(DKGError::MissingVerifier),
        };

        if v.session_id() != sc.session_id {
            return Err(DKGError::SecretCommitsWrongId);
        }

        let msg = sc.hash(&self.suite)?;
        schnorr::verify(self.suite, &pubb, &msg, &sc.signature.clone())?;

        let deal = match v.deal() {
            Some(d) => d,
            None => return Err(DKGError::MissingDeal),
        };
        let poly = PubPoly::new(
            &self.suite,
            Some(self.suite.point().base()),
            &sc.commitments,
        );
        if !poly.check(&deal.sec_share) {
            let mut cc = ComplaintCommits::<SUITE> {
                index: self.index,
                dealer_index: sc.index,
                deal,
                signature: Vec::new(),
            };

            let msg = cc.hash(&self.suite)?;
            cc.signature = schnorr::sign(&self.suite, &self.long, &msg)?;
            return Ok(Some(cc));
        }
        // commitments are fine
        self.commitments.insert(sc.index, poly);
        Ok(None)
    }

    /// [`process_complaint_commits()`] takes any Complaint Commits revealed through
    /// [`process_secret_commits()`] from other participants in QUAL. It returns the
    /// [`ReconstructCommits`] message that must be  broadcasted to every other participant
    /// in QUAL so the polynomial in question can be reconstructed.
    pub fn process_complaint_commits(
        &mut self,
        cc: &ComplaintCommits<SUITE>,
    ) -> Result<ReconstructCommits<SUITE>, DKGError> {
        let issuer = match find_pub(&self.participants, cc.index as usize) {
            Some(issuer) => issuer,
            None => return Err(DKGError::CommitComplaintUnknownIssuer),
        };

        if !self.is_in_qual(cc.index) {
            return Err(DKGError::CommitComplaintNonQUAL);
        }

        let msg = cc.hash(&self.suite)?;
        let sig = cc.signature.clone();
        schnorr::verify(self.suite, &issuer, &msg, &sig)?;

        if !self.verifiers.contains_key(&cc.dealer_index) {
            return Err(DKGError::CommitComplaintUnknownVerifier);
        }

        let v = self.verifiers.get_mut(&cc.dealer_index).unwrap();

        // the verification should pass for the deal, and not with the secret
        // commits. Verification 4) in DKG Rabin's paper.
        v.verify_deal(&cc.deal, false)?;

        if !self.commitments.contains_key(&cc.dealer_index) {
            return Err(DKGError::CommitComplaintNoCommits);
        }

        let secret_commits = self.commitments.get(&cc.dealer_index).unwrap();

        // the secret commits check should fail. Verification 5) in DKG Rabin's
        // paper.
        if secret_commits.check(&cc.deal.sec_share) {
            return Err(DKGError::CommitComplaintInvalid);
        }

        let deal = match v.deal() {
            Some(deal) => deal,
            None => return Err(DKGError::CommitComplaintUncertifiedDeal),
        };

        self.commitments.remove(&cc.dealer_index);
        let mut rc = ReconstructCommits::<SUITE> {
            session_id: cc.deal.session_id.clone(),
            index: self.index,
            dealer_index: cc.dealer_index,
            share: deal.sec_share,
            signature: Vec::new(),
        };

        let msg = rc.hash(&self.suite)?;
        rc.signature = schnorr::sign(&self.suite, &self.long, &msg)?;

        self.pending_reconstruct
            .entry(cc.dealer_index)
            .or_insert_with(alloc::vec::Vec::new);
        self.pending_reconstruct
            .get_mut(&cc.dealer_index)
            .unwrap()
            .push(rc.clone());
        Ok(rc)
    }

    /// [`process_reconstruct_commits()`] takes a [`ReconstructCommits`] message and stores it
    /// along any others. If there are enough messages to recover the coefficients of
    /// the public polynomials of the malicious dealer in question, then the
    /// polynomial is recovered.
    pub fn process_reconstruct_commits(
        &mut self,
        rc: &ReconstructCommits<SUITE>,
    ) -> Result<(), DKGError> {
        if self.reconstructed.contains_key(&rc.dealer_index) {
            // commitments already reconstructed, no need for other shares
            return Ok(());
        }
        if self.commitments.contains_key(&rc.dealer_index) {
            return Err(DKGError::CommitmentsNotInvalidated);
        }

        let pubb = match find_pub(&self.participants, rc.index as usize) {
            Some(public) => public,
            None => return Err(DKGError::ReconstructCommitsInvalidVerifierIndex),
        };

        let msg = rc.hash(&self.suite)?;
        schnorr::verify(self.suite, &pubb, &msg, &rc.signature.clone())?;

        self.pending_reconstruct
            .entry(rc.dealer_index)
            .or_insert_with(alloc::vec::Vec::new);
        let arr = self.pending_reconstruct.get_mut(&rc.dealer_index).unwrap();
        // check if packet is already received or not
        // or if the session ID does not match the others
        for r in arr.iter() {
            if r.index == rc.index {
                return Ok(());
            }
            if r.session_id != rc.session_id {
                return Err(DKGError::ReconstructCommitsInvalidId);
            }
        }
        // add it to list of pending shares
        arr.push(rc.clone());

        // check if we can reconstruct commitments
        if arr.len() >= self.t {
            let mut shares = Vec::with_capacity(arr.len());
            for _ in 0..arr.len() {
                shares.push(None);
            }
            for (i, r) in arr.iter().enumerate() {
                shares[i] = Some(r.share.clone());
            }
            // error only happens when you have less than t shares, but we ensure
            // there are more just before
            let pri = recover_pri_poly(&self.suite, &shares, self.t, self.participants.len())?;
            self.commitments.insert(
                rc.dealer_index,
                pri.commit(Some(&self.suite.point().base())),
            );
            // note it has been reconstructed.
            self.reconstructed.insert(rc.dealer_index, true);
            self.pending_reconstruct.remove(&rc.dealer_index);
        }
        Ok(())
    }

    /// [`finished()`] returns `true` if the DKG has operated the protocol correctly and has
    /// all necessary information to generate the [`dist_key_share()`] by itself. It
    /// returns `false` otherwise.
    pub fn finished(&self) -> bool {
        let mut ret = true;
        let mut nb = 0;
        self.qual_iter(|i, _| {
            nb += 1;
            // ALL QUAL members should have their commitments by now either given or
            // reconstructed.
            if !self.commitments.contains_key(&i) {
                ret = false;
                return false;
            }
            true
        });
        nb >= self.t && ret
    }

    /// [`dist_key_share()`] generates the distributed key relative to this receiver
    /// It throws an [`Error`](DKGError) if something is wrong such as not enough deals received.
    /// The shared secret can be computed when all deals have been sent and
    /// basically consists of a public point and a share. The public point is the sum
    /// of all aggregated individual public commits of each individual secrets.
    /// the share is evaluated from the global Private Polynomial, basically SUM of
    /// `fj(i)` for a receiver `i`.
    pub fn dist_key_share(&self) -> Result<DistKeyShare<SUITE>, DKGError> {
        if !self.certified() {
            return Err(DKGError::DistributedKeyNotCertified);
        }

        let mut sh = self.suite.scalar().zero();
        let mut pubb: Option<PubPoly<SUITE>> = None;

        // TODO: fix this weird error management
        let mut error: Option<DKGError> = None;

        self.qual_iter(|i, v| {
            // share of dist. secret = sum of all share received.
            let s = match v.deal() {
                Some(deal) => deal.sec_share.v,
                None => {
                    error = Some(DKGError::DealsNotFound);
                    return false;
                }
            };

            let sh_clone = sh.clone();
            sh = sh_clone + s;
            // Dist. public key = sum of all revealed commitments
            if !self.commitments.contains_key(&i) {
                error = Some(DKGError::ProtocolNotFinished(format!(
                    "{i} commitments missing"
                )));
                return false;
            }
            let poly = self.commitments.get(&i).unwrap();
            match &pubb {
                Some(pubb_val) => match pubb_val.add(poly) {
                    Ok(res) => pubb = Some(res),
                    Err(e) => error = Some(DKGError::PolyError(e)),
                },
                None => {
                    // first polynomial we see (instead of generating n empty commits)
                    pubb = Some(poly.clone());
                    return true;
                }
            }
            error.is_none()
        });

        if let Some(e) = error {
            return Err(e);
        }
        let (_, commits) = pubb.unwrap().info();

        Ok(DistKeyShare {
            commits,
            share: PriShare {
                i: self.index as usize,
                v: sh,
            },
        })
    }
}

fn find_pub<POINT: Point>(list: &[POINT], i: usize) -> Option<POINT> {
    if i >= list.len() {
        return None;
    }
    Some(list[i].clone())
}
