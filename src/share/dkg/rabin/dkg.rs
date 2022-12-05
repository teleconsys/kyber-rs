/// Package dkg implements the protocol described in
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
///   1. Each participant instantiates a DistKeyShare (DKS) struct.
///   2. Then each participant runs an instance of the VSS protocol:
///     - each participant generates their deals with the method `Deals()` and then
///      sends them to the right recipient.
///     - each participant processes the received deal with `ProcessDeal()` and
///      broadcasts the resulting response.
///     - each participant processes the response with `ProcessResponse()`. If a
///      justification is returned, it must be broadcasted.
///   3. Each participant can check if step 2. is done by calling
///   `Certified()`.Those participants where Certified() returned true, belong to
///   the set of "qualified" participants who will generate the distributed
///   secret. To get the list of qualified participants, use QUAL().
///   4. Each QUAL participant generates their secret commitments calling
///    `SecretCommits()` and broadcasts them to the QUAL set.
///   5. Each QUAL participant processes the received secret commitments using
///    `SecretCommits()`. If there is an error, it can return a commitment complaint
///    (ComplaintCommits) that must be broadcasted to the QUAL set.
///   6. Each QUAL participant receiving a complaint can process it with
///    `ProcessComplaintCommits()` which returns the secret share
///    (ReconstructCommits) given from the malicious participant. This structure
///    must be broadcasted to all the QUAL participant.
///   7. At this point, every QUAL participant can issue the distributed key by
///    calling `DistKeyShare()`.
use std::collections::HashMap;

use byteorder::{LittleEndian, WriteBytesExt};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    encoding::{BinaryMarshaler, Marshaling},
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    share::{
        poly::{recover_pri_poly, PriShare, PubPoly},
        vss::{self, suite::Suite},
    },
    sign::{dss, schnorr},
    Point, Scalar,
};

use anyhow::{bail, Result};

/// DistKeyShare holds the share of a distributed key for a participant.
#[derive(Clone)]
pub struct DistKeyShare<POINT: Point> {
    /// Coefficients of the public polynomial holding the public key
    pub commits: Vec<POINT>,
    /// Share of the distributed secret
    pub share: PriShare<POINT::SCALAR>,
}

impl<POINT: Point> DistKeyShare<POINT> {
    /// Public returns the public key associated with the distributed private key.
    pub fn public(&self) -> POINT {
        return self.commits[0].clone();
    }
}

impl<POINT: Point> dss::DistKeyShare<POINT> for DistKeyShare<POINT> {
    /// PriShare implements the dss.DistKeyShare interface so either pedersen or
    /// rabin dkg can be used with dss.
    fn pri_share(&self) -> PriShare<POINT::SCALAR> {
        return self.share.clone();
    }

    /// Commitments implements the dss.DistKeyShare interface so either pedersen or
    /// rabin dkg can be used with dss.
    fn commitments(&self) -> Vec<POINT> {
        return self.commits.clone();
    }
}

/// Deal holds the Deal for one participant as well as the index of the issuing
/// Dealer.
///  NOTE: Doing that in vss.go would be possible but then the Dealer is always
///  assumed to be a member of the participants. It's only the case here.
#[derive(Clone)]
pub struct Deal<POINT: Point + Serialize> {
    /// Index of the Dealer in the list of participants
    pub index: u32,
    /// Deal issued for another participant
    pub deal: vss::EncryptedDeal<POINT>,
}

/// Response holds the Response from another participant as well as the index of
/// the target Dealer.
#[derive(Clone)]
pub struct Response {
    /// Index of the Dealer for which this response is for
    pub index: u32,
    /// Response issued from another participant
    pub response: vss::Response,
}

/// Justification holds the Justification from a Dealer as well as the index of
/// the Dealer in question.
#[derive(Clone)]
pub struct Justification<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Index of the Dealer who answered with this Justification
    pub index: u32,
    /// Justification issued from the Dealer
    pub justification: vss::Justification<SUITE>,
}

/// SecretCommits is sent during the distributed public key reconstruction phase,
/// basically a Feldman VSS scheme.
#[derive(Clone, Debug)]
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

impl<SUITE: Suite> SecretCommits<SUITE> {
    /// Hash returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.update("secretcommits".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        for c in self.commitments.clone() {
            c.marshal_to(&mut h)?
        }
        Ok(h.finalize().to_vec())
    }
}

/// ComplaintCommits is sent if the secret commitments revealed by a peer are not
/// valid.
#[derive(Clone)]
pub struct ComplaintCommits<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Index of the Verifier _issuing_ the ComplaintCommit
    pub index: u32,
    /// DealerIndex being the index of the Dealer who issued the SecretCommits
    pub dealer_index: u32,
    /// Deal that has been given from the Dealer (at DealerIndex) to this node
    /// (at Index)
    pub deal: vss::Deal<SUITE>,
    /// Signature made by the verifier
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> ComplaintCommits<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Hash returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.update("commitcomplaint".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.dealer_index)?;
        let buff = self.deal.marshal_binary()?;
        h.update(&buff);
        Ok(h.finalize().to_vec())
    }
}

/// ReconstructCommits holds the information given by a participant who reveals
/// the deal received from a peer that has received a ComplaintCommits.
#[derive(Clone)]
pub struct ReconstructCommits<SUITE: Suite> {
    /// Id of the session
    pub session_id: Vec<u8>,
    /// Index of the verifier who received the deal
    pub index: u32,
    /// DealerIndex is the index of the dealer who issued the Deal
    pub dealer_index: u32,
    /// Share contained in the Deal
    pub share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Signature over all over fields generated by the issuing verifier
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> ReconstructCommits<SUITE> {
    /// Hash returns the hash value of this struct used in the signature process.
    pub fn hash(&self, s: &SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.update("reconstructcommits".as_bytes());
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.dealer_index)?;
        let share_buff = self.share.hash(*s)?;
        h.update(&share_buff);
        Ok(h.finalize().to_vec())
    }
}

/// DistKeyGenerator is the struct that runs the DKG protocol.
pub struct DistKeyGenerator<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    suite: SUITE,

    pub index: u32,
    pub long: <SUITE::POINT as Point>::SCALAR,
    pub pubb: SUITE::POINT,

    pub participants: Vec<SUITE::POINT>,

    t: usize,

    pub dealer: vss::Dealer<SUITE>,
    pub verifiers: HashMap<u32, vss::Verifier<SUITE>>,

    /// list of commitments to each secret polynomial
    pub commitments: HashMap<u32, PubPoly<SUITE>>,

    /// Map of deals collected to reconstruct the full polynomial of a dealer.
    /// The key is index of the dealer. Once there are enough ReconstructCommits
    /// struct, this dkg will re-construct the polynomial and stores it into the
    /// list of commitments.
    pub pending_reconstruct: HashMap<u32, Vec<ReconstructCommits<SUITE>>>,
    pub reconstructed: HashMap<u32, bool>,
}

impl<SUITE: Suite> Default for DistKeyGenerator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self {
            suite: Default::default(),
            index: Default::default(),
            long: Default::default(),
            pubb: Default::default(),
            participants: Default::default(),
            t: Default::default(),
            dealer: Default::default(),
            verifiers: Default::default(),
            commitments: Default::default(),
            pending_reconstruct: Default::default(),
            reconstructed: Default::default(),
        }
    }
}

/// NewDistKeyGenerator returns a DistKeyGenerator out of the suite,
/// the longterm secret key, the list of participants, and the
/// threshold t parameter. It returns an error if the secret key's
/// commitment can't be found in the list of participants.
pub fn new_dist_key_generator<SUITE: Suite>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    participants: &[SUITE::POINT],
    t: usize,
) -> Result<DistKeyGenerator<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let pubb = suite.point().mul(&longterm, None);
    // find our index
    let mut found = false;
    let mut index = 0;
    for (i, p) in participants.iter().enumerate() {
        if p.equal(&pubb) {
            found = true;
            index = i as u32;
            break;
        }
    }
    if !found {
        bail!("dkg: own public key not found in list of participants")
    }
    // generate our dealer / deal
    let own_sec = suite.scalar().pick(&mut suite.random_stream());
    let dealer = vss::new_dealer(suite, longterm.clone(), own_sec, participants.clone(), t)?;

    Ok(DistKeyGenerator {
        dealer: dealer,
        verifiers: HashMap::new(),
        commitments: HashMap::new(),
        pending_reconstruct: HashMap::new(),
        reconstructed: HashMap::new(),
        t: t,
        suite: suite,
        long: longterm,
        pubb: pubb,
        participants: participants.to_vec(),
        index: index,
    })
}

impl<SUITE: Suite> DistKeyGenerator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned + ScalarCanCheckCanonical,
    SUITE::POINT: Serialize + DeserializeOwned + PointCanCheckCanonicalAndSmallOrder,
{
    /// Deals returns all the deals that must be broadcasted to all
    /// participants. The deal corresponding to this DKG is already added
    /// to this DKG and is ommitted from the returned map. To know
    /// to which participant a deal belongs to, loop over the keys as indices in
    /// the list of participants:
    ///
    ///   for i,dd := range distDeals {
    ///      sendTo(participants[i],dd)
    ///   }
    ///
    /// This method panics if it can't process its own deal.
    pub fn deals(&mut self) -> Result<HashMap<usize, Deal<SUITE::POINT>>> {
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
                let idx_clone = self.index.clone();
                self.dealer.unsafe_set_response_dkg(idx_clone, true);
                continue;
            }
            dd.insert(i, distd);
        }
        Ok(dd)
    }

    /// ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
    /// returns a Response to broadcast to every other participants. It returns an
    /// error in case the deal has already been stored, or if the deal is incorrect
    /// (see `vss.Verifier.ProcessEncryptedDeal()`).
    pub fn process_deal(&mut self, dd: &Deal<SUITE::POINT>) -> Result<Response> {
        // public key of the dealer
        let pubb = match find_pub(&self.participants, dd.index as usize) {
            Some(pubb) => pubb,
            None => bail!("dkg: dist deal out of bounds index"),
        };

        if self.verifiers.contains_key(&dd.index) {
            bail!("dkg: already received dist deal from same index")
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

    /// ProcessResponse takes a response from every other peer.  If the response
    /// designates the deal of another participants than this dkg, this dkg stores it
    /// and returns nil with a possible error regarding the validity of the response.
    /// If the response designates a deal this dkg has issued, then the dkg will process
    /// the response, and returns a justification.
    pub fn process_response(&mut self, resp: &Response) -> Result<Option<Justification<SUITE>>> {
        if !self.verifiers.contains_key(&resp.index) {
            bail!("dkg: complaint received but no deal for it");
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

    /// ProcessJustification takes a justification and validates it. It returns an
    /// error in case the justification is wrong.
    pub fn process_justification(&mut self, j: &Justification<SUITE>) -> Result<()> {
        if !self.verifiers.contains_key(&j.index) {
            bail!("dkg: Justification received but no deal for it");
        }

        let v = self.verifiers.get_mut(&j.index).unwrap();
        v.process_justification(&j.justification)
    }

    /// SetTimeout triggers the timeout on all verifiers, and thus makes sure
    /// all verifiers have either responded, or have a StatusComplaint response.
    pub fn set_timeout(&mut self) {
        for (_, v) in self.verifiers.iter_mut() {
            v.set_timeout()
        }
    }

    /// Certified returns true if at least t deals are certified (see
    /// vss.Verifier.DealCertified()). If the distribution is certified, the protocol
    /// can continue using d.SecretCommits().
    pub fn certified(&self) -> bool {
        return self.qual().len() >= self.t;
    }

    /// QUAL returns the index in the list of participants that forms the QUALIFIED
    /// set as described in the "New-DKG" protocol by Rabin. Basically, it consists
    /// of all participants that are not disqualified after having  exchanged all
    /// deals, responses and justification. This is the set that is used to extract
    /// the distributed public key with SecretCommits() and ProcessSecretCommits().
    pub fn qual(&self) -> Vec<usize> {
        let mut good = Vec::new();
        self.qual_iter(|i, _| {
            good.push(i as usize);
            return true;
        });
        return good;
    }

    pub fn is_in_qual(&self, idx: u32) -> bool {
        let mut found = false;
        self.qual_iter(|i, _| {
            if i == idx {
                found = true;
                return false;
            } else {
                return true;
            }
        });
        return found;
    }

    fn qual_iter<F>(&self, mut f: F)
    where
        F: FnMut(u32, &vss::Verifier<SUITE>) -> bool,
    {
        for (i, v) in self.verifiers.iter() {
            if v.deal_certified() {
                if !f(i.clone(), v) {
                    break;
                }
            }
        }
    }

    /// SecretCommits returns the commitments of the coefficients of the secret
    /// polynomials. This secret commits must be broadcasted to every other
    /// participant and must be processed by ProcessSecretCommits. In this manner,
    /// the coefficients are revealed through a Feldman VSS scheme.
    /// This dkg must have its deal certified, otherwise it returns an error. The
    /// SecretCommits returned is already added to this dkg's list of SecretCommits.
    pub fn secret_commits(&mut self) -> Result<SecretCommits<SUITE>> {
        if !self.dealer.deal_certified() {
            bail!("dkg: can't give SecretCommits if deal not certified")
        }
        let mut sc = SecretCommits::<SUITE> {
            commitments: self
                .dealer
                .commits()
                .expect("dkg: commits should not be none"),
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

    /// ProcessSecretCommits takes a SecretCommits from every other participant and
    /// verifies and stores it. It returns an error in case the SecretCommits is
    /// invalid. In case the SecretCommits are valid, but this dkg can't verify its
    /// share, it returns a ComplaintCommits that must be broadcasted to every other
    /// participant. It returns (nil,nil) otherwise.
    pub fn process_secret_commits(
        &mut self,
        sc: &SecretCommits<SUITE>,
    ) -> Result<Option<ComplaintCommits<SUITE>>> {
        let pubb = match find_pub(&self.participants, sc.index as usize) {
            Some(public) => public,
            None => bail!("dkg: secretcommits received with index out of bounds"),
        };

        if !self.is_in_qual(sc.index) {
            bail!("dkg: secretcommits from a non QUAL member")
        }

        // mapping verified by isInQUAL
        let v = self
            .verifiers
            .get(&sc.index)
            .expect("dkg: verifier should exists");

        if v.session_id() != sc.session_id {
            bail!("dkg: secretcommits received with wrong session id")
        }

        let msg = sc.hash(&self.suite)?;
        schnorr::verify(self.suite, &pubb, &msg, &sc.signature.clone())?;

        let deal = v.deal().expect("dkg: deal should exists");
        let poly = PubPoly::new(
            &self.suite,
            Some(self.suite.point().base()),
            &sc.commitments,
        );
        if !poly.check(&deal.sec_share) {
            let mut cc = ComplaintCommits::<SUITE> {
                index: self.index,
                dealer_index: sc.index,
                deal: deal,
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

    // ProcessComplaintCommits takes any ComplaintCommits revealed through
    // ProcessSecretCommits() from other participants in QUAL. It returns the
    // ReconstructCommits message that must be  broadcasted to every other participant
    // in QUAL so the polynomial in question can be reconstructed.
    pub fn process_complaint_commits(
        &mut self,
        cc: &ComplaintCommits<SUITE>,
    ) -> Result<ReconstructCommits<SUITE>> {
        let issuer = match find_pub(&self.participants, cc.index as usize) {
            Some(issuer) => issuer,
            None => bail!("dkg: commitcomplaint with unknown issuer"),
        };

        if !self.is_in_qual(cc.index) {
            bail!("dkg: complaintcommit from non-qual member")
        }

        let msg = cc.hash(&self.suite)?;
        let sig = cc.signature.clone();
        schnorr::verify(self.suite, &issuer, &msg, &sig)?;

        if !self.verifiers.contains_key(&cc.dealer_index) {
            bail!("dkg: commitcomplaint linked to unknown verifier");
        }

        let v = self.verifiers.get_mut(&cc.dealer_index).unwrap();

        // the verification should pass for the deal, and not with the secret
        // commits. Verification 4) in DKG Rabin's paper.
        v.verify_deal(&cc.deal, false)?;

        if !self.commitments.contains_key(&cc.dealer_index) {
            bail!("dkg: complaint about non received commitments");
        }

        let secret_commits = self.commitments.get(&cc.dealer_index).unwrap();

        // the secret commits check should fail. Verification 5) in DKG Rabin's
        // paper.
        if secret_commits.check(&cc.deal.sec_share) {
            bail!("dkg: invalid complaint, deal verifying")
        }

        let deal = match v.deal() {
            Some(deal) => deal,
            None => bail!("dkg: complaint linked to non certified deal"),
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

        if !self.pending_reconstruct.contains_key(&cc.dealer_index) {
            self.pending_reconstruct.insert(cc.dealer_index, vec![]);
        }
        self.pending_reconstruct
            .get_mut(&cc.dealer_index)
            .unwrap()
            .push(rc.clone());
        Ok(rc)
    }

    /// ProcessReconstructCommits takes a ReconstructCommits message and stores it
    /// along any others. If there are enough messages to recover the coefficients of
    /// the public polynomials of the malicious dealer in question, then the
    /// polynomial is recovered.
    pub fn process_reconstruct_commits(&mut self, rc: &ReconstructCommits<SUITE>) -> Result<()> {
        if self.reconstructed.contains_key(&rc.dealer_index) {
            // commitments already reconstructed, no need for other shares
            return Ok(());
        }
        if self.commitments.contains_key(&rc.dealer_index) {
            bail!("dkg: commitments not invalidated by any complaints")
        }

        let pubb = match find_pub(&self.participants, rc.index as usize) {
            Some(public) => public,
            None => bail!("dkg: reconstruct commits with invalid verifier index"),
        };

        let msg = rc.hash(&self.suite)?;
        schnorr::verify(self.suite, &pubb, &msg, &rc.signature.clone())?;

        if !self.pending_reconstruct.contains_key(&rc.dealer_index) {
            self.pending_reconstruct.insert(rc.dealer_index, vec![]);
        }
        let arr = self.pending_reconstruct.get_mut(&rc.dealer_index).unwrap();
        // check if packet is already received or not
        // or if the session ID does not match the others
        for r in arr.iter() {
            if r.index == rc.index {
                return Ok(());
            }
            if r.session_id != rc.session_id {
                bail!("dkg: reconstruct commits invalid session id")
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

    /// Finished returns true if the DKG has operated the protocol correctly and has
    /// all necessary information to generate the DistKeyShare() by itself. It
    /// returns false otherwise.
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
            return true;
        });
        return nb >= self.t && ret;
    }

    /// DistKeyShare generates the distributed key relative to this receiver
    /// It throws an error if something is wrong such as not enough deals received.
    /// The shared secret can be computed when all deals have been sent and
    /// basically consists of a public point and a share. The public point is the sum
    /// of all aggregated individual public commits of each individual secrets.
    /// the share is evaluated from the global Private Polynomial, basically SUM of
    /// fj(i) for a receiver i.
    pub fn dist_key_share(&self) -> Result<DistKeyShare<SUITE::POINT>> {
        if !self.certified() {
            bail!("dkg: distributed key not certified")
        }

        let mut sh = self.suite.scalar().zero();
        let mut tmp_pubb = None;
        let mut pubb: Option<PubPoly<SUITE>> = None;

        // TODO: fix this weird error management and the messy pubb
        let mut error: Option<anyhow::Error> = None;

        self.qual_iter(|i, v| {
            // share of dist. secret = sum of all share received.
            let s = match v.deal() {
                Some(deal) => deal.sec_share.v,
                None => {
                    error = Some(anyhow::Error::msg("dkg: deals not found"));
                    return false;
                }
            };

            let sh_clone = sh.clone();
            sh = sh_clone + s;
            // Dist. public key = sum of all revealed commitments
            if !self.commitments.contains_key(&i) {
                error = Some(anyhow::Error::msg(format!(
                    "dkg: protocol not finished: {} commitments missing",
                    i
                )));
                return false;
            }
            let poly = self.commitments.get(&i).unwrap();
            if pubb.is_none() && tmp_pubb.is_none() {
                // first polynomial we see (instead of generating n empty commits)
                tmp_pubb = Some(poly);
                return true;
            }
            if pubb.is_none() {
                match tmp_pubb.unwrap().add(&poly) {
                    Ok(p) => pubb = Some(p),
                    Err(e) => error = Some(anyhow::Error::msg(e.to_string())),
                }
            } else {
                match pubb.as_ref().unwrap().add(&poly) {
                    Ok(p) => pubb = Some(p),
                    Err(e) => error = Some(anyhow::Error::msg(e.to_string())),
                }
            };
            return error.is_none();
        });

        if error.is_some() {
            return Err(error.unwrap());
        }
        let (_, commits) = pubb.unwrap().info();

        Ok(DistKeyShare {
            commits: commits,
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
    return Some(list[i].clone());
}
