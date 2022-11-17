// Package vss implements the verifiable secret sharing scheme from the
// paper "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold
// Scheme for Implicit Certificates".
// VSS enables a dealer to share a secret securely and verifiably among n
// participants out of which at least t are required for its reconstruction.
// The verifiability of the process prevents a
// malicious dealer from influencing the outcome to his advantage as each
// verifier can check the validity of the received share. The protocol has the
// following steps:
//
//   1) The dealer send a Deal to every verifiers using `Deals()`. Each deal must
//   be sent securely to one verifier whose public key is at the same index than
//   the index of the Deal.
//
//   2) Each verifier processes the Deal with `ProcessDeal`.
//   This function returns a Response which can be twofold:
//   - an approval, to confirm a correct deal
//   - a complaint to announce an incorrect deal notifying others that the
//     dealer might be malicious.
//	 All Responses must be broadcasted to every verifiers and the dealer.
//   3) The dealer can respond to each complaint by a justification revealing the
//   share he originally sent out to the accusing verifier. This is done by
//   calling `ProcessResponse` on the `Dealer`.
//   4) The verifiers refuse the shared secret and abort the protocol if there
//   are at least t complaints OR if a Justification is wrong. The verifiers
//   accept the shared secret if there are at least t approvals at which point
//   any t out of n verifiers can reveal their shares to reconstruct the shared
//   secret.

use core::fmt;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::encoding::{self, unmarshal_binary, BinaryMarshaler, Marshaling};
use crate::group::{HashFactory, PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical};
use crate::share::poly::{self, NewPriPoly, PriShare, PubPoly};
use crate::share::vss::rabin::dh::AEAD;
use crate::sign::schnorr;
use crate::{share, Scalar};
use crate::{Group, Point, Random, XOFFactory};

use anyhow::__private::kind::TraitKind;
use anyhow::{bail, Error, Ok, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use digest::DynDigest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

use super::dh::{context, dhExchange};

/// Suite defines the capabilities required by the vss package.
pub trait Suite: Group + HashFactory + XOFFactory + Random + Clone + Copy {}

/// Dealer encapsulates for creating and distributing the shares and for
/// replying to any Responses.
pub struct Dealer<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    suite: SUITE,
    // reader: STREAM,
    // long is the longterm key of the Dealer
    pub(crate) long: <SUITE::POINT as Point>::SCALAR,
    pub(crate) pubb: SUITE::POINT,
    pub secret: <SUITE::POINT as Point>::SCALAR,
    secret_commits: Vec<SUITE::POINT>,
    pub(crate) verifiers: Vec<SUITE::POINT>,
    hkdf_context: Vec<u8>,
    // threshold of shares that is needed to reconstruct the secret
    t: usize,
    // sessionID is a unique identifier for the whole session of the scheme
    session_id: Vec<u8>,
    // list of deals this Dealer has generated
    deals: Vec<Deal<SUITE>>,
    aggregator: Aggregator<SUITE>,
}

impl<SUITE: Suite> Deref for Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    type Target = Aggregator<SUITE>;

    fn deref(&self) -> &Self::Target {
        &self.aggregator
    }
}

impl<SUITE: Suite> DerefMut for Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.aggregator
    }
}

/// Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
#[derive(Serialize, Deserialize, Clone)]
pub struct Deal<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Unique session identifier for this protocol run
    session_id: Vec<u8>,
    /// Private share generated by the dealer
    sec_share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Random share generated by the dealer
    rnd_share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Threshold used for this secret sharing run
    t: usize,
    // Commitments are the coefficients used to verify the shares against
    commitments: Vec<SUITE::POINT>,
}

impl<SUITE: Suite> Default for Deal<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self {
            session_id: Default::default(),
            sec_share: Default::default(),
            rnd_share: Default::default(),
            t: Default::default(),
            commitments: Default::default(),
        }
    }
}

impl<SUITE: Suite> Deal<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn decode(s: SUITE, buff: &[u8]) -> Result<Deal<SUITE>> {
        // constructors := make(protobuf.Constructors)
        // var point kyber.Point
        // var secret kyber.Scalar
        // constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return s.Point() }
        // constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return s.Scalar() }
        // return protobuf.DecodeWithConstructors(buff, d, constructors)
        let mut d = Deal::default();
        unmarshal_binary(&mut d, buff)?;
        Ok(d)
    }
}

impl<SUITE> BinaryMarshaler for Deal<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Point + Serialize + DeserializeOwned,
    SUITE: Suite,
{
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

/// EncryptedDeal contains the deal in a encrypted form only decipherable by the
/// correct recipient. The encryption is performed in a similar manner as what is
/// done in TLS. The dealer generates a temporary key pair, signs it with its
/// longterm secret key.
pub struct EncryptedDeal<POINT: Point> {
    /// Ephemeral Diffie Hellman key
    dhkey: POINT,
    /// Signature of the DH key by the longterm key of the dealer
    signature: Vec<u8>,
    /// Nonce used for the encryption
    nonce: Vec<u8>,
    /// AEAD encryption of the deal marshalled by protobuf
    cipher: Vec<u8>,
}

/// Response is sent by the verifiers to all participants and holds each
/// individual validation or refusal of a Deal.
#[derive(Clone, Debug)]
pub struct Response {
    /// SessionID related to this run of the protocol
    pub session_id: Vec<u8>,
    /// Index of the verifier issuing this Response
    pub index: u32,
    /// Approved is true if the Response is valid
    pub approved: bool,
    /// Signature over the whole packet
    pub signature: Vec<u8>,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            session_id: Default::default(),
            index: Default::default(),
            approved: Default::default(),
            signature: Default::default(),
        }
    }
}

impl Response {
    /// Hash returns the Hash representation of the Response
    fn hash<SUITE: Suite>(&self, s: SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.write("response".as_bytes())?;
        h.write(&self.session_id)?;
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.approved as u32)?;
        // binary.Write(h, binary.LittleEndian, self.index);
        // binary.Write(h, binary.LittleEndian, self.approved);
        Ok(h.finalize().to_vec())
    }
}

/// Justification is a message that is broadcasted by the Dealer in response to
/// a Complaint. It contains the original Complaint as well as the shares
/// distributed to the complainer.
#[derive(Clone)]
pub struct Justification<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// SessionID related to the current run of the protocol
    session_id: Vec<u8>,
    /// Index of the verifier who issued the Complaint,i.e. index of this Deal
    index: u32,
    /// Deal in cleartext
    deal: Deal<SUITE>,
    /// Signature over the whole packet
    signature: Vec<u8>,
}

impl<SUITE: Suite> Justification<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Hash returns the hash of a Justification.
    fn hash(self, s: SUITE) -> Vec<u8> {
        let mut h = s.hash();
        h.update("justification".as_bytes());
        h.update(&self.session_id);

        // _ = binary.Write(h, binary.LittleEndian, j.Index)
        // buff, _ := protobuf.Encode(j.Deal)
        // _, _ = h.Write(buff)
        // return h.Sum(nil)
        todo!()
    }
}

/// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
/// does not have to be trusted by other Verifiers. The security parameter t is
/// the number of shares required to reconstruct the secret. It is HIGHLY
/// RECOMMENDED to use a threshold higher or equal than what the method
/// MinimumT() returns, otherwise it breaks the security assumptions of the whole
/// scheme. It returns an error if the t is inferior or equal to 2.
pub fn NewDealer<SUITE: Suite>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    secret: <SUITE::POINT as Point>::SCALAR,
    verifiers: Vec<SUITE::POINT>,
    t: usize,
) -> Result<Dealer<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
    // STREAM: Stream,
{
    if !validT(t, &verifiers) {
        bail!("dealer: t {} invalid", t);
    }

    let H = deriveH(suite, &verifiers);
    let f = NewPriPoly(suite, t, Some(secret.clone()), suite.random_stream());
    let g = NewPriPoly(suite, t, None, suite.random_stream());
    let d_pubb = suite.point().mul(&longterm, None);

    // Compute public polynomial coefficients
    let F = f.Commit(suite.point().base());
    let (_, secret_commits) = F.Info();
    let G = g.Commit(H);

    let C = F.Add(&G)?;
    let (_, commitments) = C.Info();

    let session_id = sessionID(&suite, &d_pubb, &verifiers, &commitments, t)?;

    let aggregator = newAggregator(
        suite,
        d_pubb.clone(),
        verifiers.clone(),
        commitments.clone(),
        t,
        &session_id,
    );
    // C = F + G
    let mut deals: Vec<Deal<SUITE>> = vec![];
    for i in 0..verifiers.len() {
        let fi = f.Eval(i);
        let gi = g.Eval(i);
        deals.push(Deal {
            session_id: session_id.clone(),
            sec_share: fi,
            rnd_share: gi,
            commitments: commitments.clone(),
            t: t,
        });
    }

    let hkdf_context = context(&suite, &d_pubb, &verifiers).to_vec();

    Ok(Dealer {
        suite: suite,
        long: longterm,
        secret: secret,
        verifiers: verifiers,
        pubb: d_pubb,
        secret_commits,
        hkdf_context,
        t,
        session_id,
        aggregator,
        deals,
    })
}

impl<SUITE: Suite> Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// PlaintextDeal returns the plaintext version of the deal destined for peer i.
    /// Use this only for testing.
    fn PlaintextDeal(&self, i: usize) -> Result<Deal<SUITE>> {
        if i >= self.deals.len() {
            bail!("dealer: PlaintextDeal given wrong index");
        }
        let d = &self.deals[i];
        Ok(d.clone())
    }

    /// EncryptedDeal returns the encryption of the deal that must be given to the
    /// verifier at index i.
    /// The dealer first generates a temporary Diffie Hellman key, signs it using its
    /// longterm key, and computes the shared key depending on its longterm and
    /// ephemeral key and the verifier's public key.
    /// This shared key is then fed into a HKDF whose output is the key to a AEAD
    /// (AES256-GCM) scheme to encrypt the deal.
    pub fn EncryptedDeal(&self, i: usize) -> Result<EncryptedDeal<SUITE::POINT>> {
        let vPub = findPub(&self.verifiers, i)
            .ok_or(Error::msg("dealer: wrong index to generate encrypted deal"))?;
        // gen ephemeral key
        let dhSecret = self.suite.scalar().pick(&mut self.suite.random_stream());
        let dhPublic = self.suite.point().mul(&dhSecret, None);
        // signs the public key
        let dhPublicBuff = dhPublic.marshal_binary()?;
        let signature = schnorr::Sign(self.suite, self.long.clone(), &dhPublicBuff)?;

        // AES128-GCM
        let pre = dhExchange(self.suite, dhSecret, vPub);
        let gcm = AEAD::new(pre, &self.hkdf_context)?;

        let nonce = [0u8; AEAD::nonce_size()];
        // let dealBuff = protobuf.Encode(self.deals[i])?;
        let deal_buf = self.deals[i].marshal_binary()?;
        let encrypted = gcm.seal(None, &nonce, &deal_buf, Some(&self.hkdf_context))?;
        return Ok(EncryptedDeal {
            dhkey: dhPublic,
            signature,
            nonce: nonce.try_into().unwrap(),
            cipher: encrypted,
        });
    }

    /// encrypted_deals calls `EncryptedDeal` for each index of the verifier and
    /// returns the list of encrypted deals. Each index in the returned slice
    /// corresponds to the index in the list of verifiers.
    pub fn encrypted_deals(&self) -> Result<Vec<EncryptedDeal<SUITE::POINT>>> {
        // deals := make([]*EncryptedDeal, len(d.verifiers));
        let mut deals = vec![];
        // var err error
        for i in 0..self.verifiers.len() {
            let deal = self.EncryptedDeal(i)?;
            deals.push(deal);
        }
        Ok(deals)
    }

    /// process_response analyzes the given Response. If it's a valid complaint, then
    /// it returns a Justification. This Justification must be broadcasted to every
    /// participants. If it's an invalid complaint, it returns an error about the
    /// complaint. The verifiers will also ignore an invalid Complaint.
    pub fn process_response(&self, r: &Response) -> Result<Option<Justification<SUITE>>> {
        self.aggregator.verify_response(r)?;

        if r.approved {
            return Ok(None);
        }

        let mut j = Justification {
            session_id: self.session_id.clone(),
            // index is guaranteed to be good because of d.verifyResponse before
            index: r.index,
            deal: self.deals[r.index as usize].clone(),
            signature: vec![],
        };

        let sig = schnorr::Sign(self.suite, self.long.clone(), &j.clone().hash(self.suite))?;
        j.signature = sig;

        Ok(Some(j))
    }

    /// SecretCommit returns the commitment of the secret being shared by this
    /// dealer. This function is only to be called once the deal has enough approvals
    /// and is verified otherwise it returns nil.
    fn secret_commit(self) -> Option<SUITE::POINT> {
        if !self.aggregator.clone().enough_approvals() || !self.aggregator.deal_certified() {
            return None;
        }
        return Some(self.suite.point().mul(&self.secret, None));
    }

    /// Commits returns the commitments of the coefficient of the secret polynomial
    /// the Dealer is sharing.
    fn commits(self) -> Option<Vec<SUITE::POINT>> {
        if !self.aggregator.clone().enough_approvals() || !self.aggregator.deal_certified() {
            return None;
        }
        return Some(self.secret_commits);
    }

    /// Key returns the longterm key pair used by this Dealer.
    fn key(self) -> (<SUITE::POINT as Point>::SCALAR, SUITE::POINT) {
        return (self.long, self.pubb);
    }

    /// SessionID returns the current sessionID generated by this dealer for this
    /// protocol run.
    fn session_id(self) -> Vec<u8> {
        return self.session_id;
    }

    /// SetTimeout tells this dealer to consider this moment the maximum time limit.
    /// it calls cleanVerifiers which will take care of all Verifiers who have not
    /// responded until now.
    fn set_timeout(&mut self) {
        self.aggregator.cleanVerifiers();
    }

    /// deal_certified returns true if there has been less than t complaints, all
    /// Justifications were correct and if EnoughApprovals() returns true.
    pub fn deal_certified(&self) -> bool {
        self.aggregator.deal_certified()
    }
}

/// Verifier receives a Deal from a Dealer, can reply with a Complaint, and can
/// collaborate with other Verifiers to reconstruct a secret.
pub struct Verifier<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    pubb: SUITE::POINT,
    dealer: SUITE::POINT,
    pub(crate) index: usize,
    verifiers: Vec<SUITE::POINT>,
    hkdfContext: Vec<u8>,
    pub(crate) aggregator: Option<Aggregator<SUITE>>,
}

/// NewVerifier returns a Verifier out of:
/// - its longterm secret key
/// - the longterm dealer public key
/// - the list of public key of verifiers. The list MUST include the public key
/// of this Verifier also.
/// The security parameter t of the secret sharing scheme is automatically set to
/// a default safe value. If a different t value is required, it is possible to set
/// it with `verifier.SetT()`.
pub fn NewVerifier<SUITE: Suite>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    dealer_key: SUITE::POINT,
    verifiers: Vec<SUITE::POINT>,
) -> Result<Verifier<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let p = suite.point();
    let pubb = p.mul(&longterm, None);
    let mut ok = false;
    let mut index = 0;
    for (i, v) in verifiers.iter().enumerate() {
        if v.equal(&pubb) {
            ok = true;
            index = i;
            break;
        }
    }
    if !ok {
        bail!("vss: public key not found in the list of verifiers");
    }
    let c = context(&suite, &dealer_key, &verifiers);
    Ok(Verifier {
        suite,
        longterm,
        dealer: dealer_key,
        verifiers,
        pubb,
        index,
        hkdfContext: Vec::from(c),
        aggregator: None,
    })
}

impl<SUITE: Suite> Deref for Verifier<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    type Target = Aggregator<SUITE>;

    fn deref(&self) -> &Self::Target {
        self.aggregator.as_ref().unwrap()
    }
}

impl<SUITE: Suite> DerefMut for Verifier<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.aggregator.as_mut().unwrap()
    }
}

impl<SUITE: Suite> Verifier<SUITE>
where
    <SUITE::POINT as Point>::SCALAR:
        Scalar + ScalarCanCheckCanonical + Serialize + DeserializeOwned,
    SUITE::POINT: Point + PointCanCheckCanonicalAndSmallOrder + Serialize + DeserializeOwned,
{
    /// process_encrypted_deal decrypt the deal received from the Dealer.
    /// If the deal is valid, i.e. the verifier can verify its shares
    /// against the public coefficients and the signature is valid, an approval
    /// response is returned and must be broadcasted to every participants
    /// including the dealer.
    /// If the deal itself is invalid, it returns a complaint response that must be
    /// broadcasted to every other participants including the dealer.
    /// If the deal has already been received, or the signature generation of the
    /// response failed, it returns an error without any responses.
    pub fn process_encrypted_deal(&mut self, e: &EncryptedDeal<SUITE::POINT>) -> Result<Response> {
        let d = self.decryptDeal(e)?;
        if d.sec_share.i != self.index {
            bail!("vss: verifier got wrong index from deal");
        }

        let t = d.t;

        let sid = sessionID(
            &self.suite,
            &self.dealer,
            &self.verifiers,
            &d.commitments,
            t,
        )?;

        if self.aggregator.is_none() {
            self.aggregator = Some(newAggregator(
                self.suite,
                self.dealer.clone(),
                self.verifiers.clone(),
                d.commitments.clone(),
                t,
                &d.session_id,
            ));
        }

        let mut r = Response {
            session_id: sid,
            index: self.index as u32,
            approved: true,
            ..Default::default()
        };
        let result = self.verify_deal(&d, true);

        if let Err(err) = result {
            r.approved = false;
            match err {
                VerifyDealError::DealAlreadyProcessedError => bail!(err),
                VerifyDealError::TextError(e) => bail!(e),
            }
        }

        r.signature = schnorr::Sign(
            self.suite,
            self.longterm.clone(),
            r.hash(self.suite)?.as_slice(),
        )?;

        self.aggregator.as_mut().unwrap().add_response(r.clone())?;
        Ok(r)
    }

    fn decryptDeal(&self, e: &EncryptedDeal<SUITE::POINT>) -> Result<Deal<SUITE>> {
        let ephBuff = e.dhkey.marshal_binary()?;
        // verify signature
        schnorr::Verify(
            self.suite,
            &self.dealer.clone(),
            ephBuff.as_slice(),
            &e.signature,
        )?;

        // compute shared key and AES526-GCM cipher
        let pre = dhExchange(self.suite, self.longterm.clone(), e.dhkey.clone());
        let gcm = AEAD::new(pre, &self.hkdfContext)?;
        let decrypted = gcm.open(
            None,
            e.nonce.as_slice().try_into().unwrap(),
            &e.cipher,
            Some(self.hkdfContext.as_slice()),
        )?;
        Deal::decode(self.suite, &decrypted)
    }

    /// ProcessResponse analyzes the given response. If it's a valid complaint, the
    /// verifier should expect to see a Justification from the Dealer. It returns an
    /// error if it's not a valid response.
    /// Call `v.DealCertified()` to check if the whole protocol is finished.
    pub fn process_response(&self, resp: &Response) -> Result<()> {
        let aggregator = self.aggregator.clone();
        if aggregator.is_none() {
            bail!("no aggregator for verifier")
        }
        aggregator.unwrap().verify_response(resp)
    }

    /// deal returns the Deal that this verifier has received. It returns
    /// nil if the deal is not certified or there is not enough approvals.
    pub fn deal(&self) -> Option<Deal<SUITE>> {
        if self.aggregator.clone().is_none() {
            return None;
        }
        if !self.aggregator.clone().unwrap().enough_approvals()
            || !self.aggregator.clone().unwrap().deal_certified()
        {
            return None;
        }
        return self.deal.clone();
    }

    /// ProcessJustification takes a DealerResponse and returns an error if
    /// something went wrong during the verification. If it is the case, that
    /// probably means the Dealer is acting maliciously. In order to be sure, call
    /// `v.EnoughApprovals()` and if true, `v.DealCertified()`.
    fn process_justification(self, dr: Justification<SUITE>) -> Result<()> {
        if self.aggregator.clone().is_none() {
            bail!("no aggregator for verifier")
        }
        return self.aggregator.unwrap().verify_justification(dr);
    }

    /// Key returns the longterm key pair this verifier is using during this protocol
    /// run.
    fn key(self) -> (<SUITE::POINT as Point>::SCALAR, SUITE::POINT) {
        return (self.longterm, self.pubb);
    }

    /// Index returns the index of the verifier in the list of participants used
    /// during this run of the protocol.
    fn index(&self) -> usize {
        return self.index;
    }

    /// SessionID returns the session id generated by the Dealer. WARNING: it returns
    /// an nil slice if the verifier has not received the Deal yet !
    fn session_id(&self) -> Vec<u8> {
        return self.sid.clone();
    }

    /// SetTimeout tells this verifier to consider this moment the maximum time limit.
    /// it calls cleanVerifiers which will take care of all Verifiers who have not
    /// responded until now.
    pub fn SetTimeout(&mut self) {
        if let Some(a) = self.aggregator.as_mut() {
            a.cleanVerifiers()
        }
    }
}

/// Aggregator is used to collect all deals, and responses for one protocol run.
/// It brings common functionalities for both Dealer and Verifier structs.
#[derive(Clone)]
pub struct Aggregator<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    suite: SUITE,
    dealer: SUITE::POINT,
    verifiers: Vec<SUITE::POINT>,
    commits: Vec<SUITE::POINT>,

    pub(crate) responses: HashMap<u32, Response>,
    sid: Vec<u8>,
    deal: Option<Deal<SUITE>>,
    pub(crate) t: usize,
    pub(crate) bad_dealer: bool,
}

fn newAggregator<SUITE: Suite>(
    suite: SUITE,
    dealer: SUITE::POINT,
    verifiers: Vec<SUITE::POINT>,
    commitments: Vec<SUITE::POINT>,
    t: usize,
    sid: &[u8],
) -> Aggregator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    Aggregator {
        suite: suite,
        dealer: dealer,
        verifiers: verifiers,
        commits: commitments,
        t,
        sid: sid.clone().to_vec(),
        responses: HashMap::new(),
        deal: None,
        bad_dealer: false,
    }
}

#[derive(Debug, Clone)]
enum VerifyDealError {
    DealAlreadyProcessedError,
    TextError(String),
}

impl fmt::Display for VerifyDealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyDealError::DealAlreadyProcessedError => write!(f, "{}", self),
            VerifyDealError::TextError(t) => write!(f, "{}", t),
        }
    }
}

impl std::error::Error for VerifyDealError {}

#[derive(Debug, Clone)]
struct DealAlreadyProcessedError;

impl fmt::Display for DealAlreadyProcessedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "vss: verifier already received a deal")
    }
}

impl<SUITE: Suite> Aggregator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// verify_deal analyzes the deal and returns an error if it's incorrect. If
    /// inclusion is true, it also returns an error if it the second time this struct
    /// analyzes a Deal.
    fn verify_deal(&mut self, d: &Deal<SUITE>, inclusion: bool) -> Result<(), VerifyDealError> {
        if self.deal.is_some() && inclusion {
            return Err(VerifyDealError::DealAlreadyProcessedError);
        }
        if self.deal.is_none() {
            self.commits = d.commitments.clone();
            self.sid = d.session_id.clone();
            self.deal = Some(d.clone());
        }

        if !validT(d.t, &self.verifiers) {
            return Err(VerifyDealError::TextError(
                "vss: invalid t received in Deal".to_string(),
            ));
        }

        if !(self.sid == d.session_id) {
            return Err(VerifyDealError::TextError(
                "vss: find different sessionIDs from Deal".to_string(),
            ));
        }

        let fi = &d.sec_share;
        let gi = &d.rnd_share;
        if fi.i != gi.i {
            return Err(VerifyDealError::TextError(
                "vss: not the same index for f and g share in Deal".to_string(),
            ));
        }
        if fi.i < 0 || fi.i >= self.verifiers.len() {
            return Err(VerifyDealError::TextError(
                "vss: index out of bounds in Deal".to_string(),
            ));
        }
        // compute fi * G + gi * H
        let fig = self.suite.point().base().mul(&fi.v, None);
        let H = deriveH(self.suite, &self.verifiers);
        let gih = self.suite.point().mul(&gi.v, Some(&H));
        let ci = self.suite.point().add(&fig, &gih);

        let commitPoly = PubPoly::new(self.suite, None, d.commitments.clone());

        let pubShare = commitPoly.Eval(fi.i);
        if ci != pubShare.v {
            return Err(VerifyDealError::TextError(
                "vss: share does not verify against commitments in Deal".to_string(),
            ));
        }
        Result::Ok(())
    }

    /// cleanVerifiers checks the aggregator's response array and creates a StatusComplaint
    /// response for all verifiers who have no response in the array.
    fn cleanVerifiers(&mut self) {
        for i in 0..self.verifiers.len() {
            if self.responses.contains_key(&(i as u32)) {
                self.responses.insert(
                    i as u32,
                    Response {
                        session_id: self.sid.clone(),
                        index: i as u32,
                        approved: false,
                        ..Response::default()
                    },
                );
            }
        }
    }

    pub fn verify_response(&self, r: &Response) -> Result<()> {
        if r.session_id != self.sid {
            bail!("vss: receiving inconsistent sessionID in response")
        }

        let public = findPub(&self.verifiers, r.index as usize);
        if public.is_none() {
            bail!("vss: index out of bounds in response")
        }

        let msg = r.hash(self.suite)?;

        //schnorr::Verify(self.suite, public.unwrap(), &msg, &r.signature)?;
        //Ok(())
        todo!()
    }

    fn verify_justification(mut self, j: Justification<SUITE>) -> Result<()> {
        let pubb = findPub(&self.verifiers, j.index as usize);
        if pubb.is_none() {
            bail!("vss: index out of bounds in justification")
        }

        if !self.responses.contains_key(&j.index) {
            bail!("vss: no complaints received for this justification")
        }
        todo!("TAKE R AS CLONE BUT SHOULD BE MODIFIED LATER");
        let mut r = self.responses[&j.index].clone();

        if r.approved {
            bail!("vss: justification received for an approval")
        }

        let verification = self.verify_deal(&j.deal, false);
        if verification.is_err() {
            self.bad_dealer = true;
        } else {
            r.approved = true
        }
        return verification.map_err(|e| Error::msg(e.to_string()));
    }

    pub fn add_response(&mut self, r: Response) -> Result<()> {
        if findPub(&self.verifiers, r.index as usize).is_none() {
            bail!("vss: index out of bounds in Complaint");
        }
        if self.responses.get(&(r.index as u32)).is_some() {
            bail!("vss: already existing response from same origin")
        }
        self.responses.insert(r.index, r);
        Ok(())
    }

    /// EnoughApprovals returns true if enough verifiers have sent their approval for
    /// the deal they received.
    fn enough_approvals(self) -> bool {
        let mut app = 0usize;
        for (_, r) in self.responses {
            if r.approved {
                app += 1;
            }
        }
        return app >= self.t;
    }

    /// deal_certified returns true if there has been less than t complaints, all
    /// Justifications were correct and if EnoughApprovals() returns true.
    pub fn deal_certified(&self) -> bool {
        todo!();
        // a can be nil if we're calling it before receiving a deal
        // if a == nil {
        // 	return false
        // }

        let verifiers_unstable = 0usize;
        // Check either a StatusApproval or StatusComplaint for all known verifiers
        // i.e. make sure all verifiers are either timed-out or OK.
        for (i, _) in self.verifiers.into_iter().enumerate() {
            if !self.responses.contains_key(&(i as u32)) {
                verifiers_unstable += 1;
            }
        }

        let too_much_complaints = verifiers_unstable > 0 || self.bad_dealer;
        return self.enough_approvals() && !too_much_complaints;
    }

    /// UnsafeSetResponseDKG is an UNSAFE bypass method to allow DKG to use VSS
    /// that works on basis of approval only.
    fn UnsafeSetResponseDKG(&mut self, idx: u32, approval: bool) -> Result<()> {
        let r = Response {
            session_id: self.sid.clone(),
            index: idx,
            approved: approval,
            signature: vec![],
        };

        self.add_response(r)
    }
}

/// minimum_t returns the minimum safe T that is proven to be secure with this
/// protocol. It expects n, the total number of participants.
/// WARNING: Setting a lower T could make
/// the whole protocol insecure. Setting a higher T only makes it harder to
/// reconstruct the secret.
pub fn minimum_t(n: usize) -> usize {
    return (n + 1) / 2;
}

fn validT<POINT: Point>(t: usize, verifiers: &Vec<POINT>) -> bool {
    return t >= 2 && t <= verifiers.len() && (t as u32) as i64 == t as i64;
}

fn deriveH<SUITE: Suite>(suite: SUITE, verifiers: &Vec<SUITE::POINT>) -> SUITE::POINT {
    let mut b = vec![];
    for v in verifiers {
        v.marshal_to(&mut b).unwrap();
    }
    let base = suite.point().pick(&mut suite.xof(Some(&b)));
    base
}

fn findPub<POINT: Point>(verifiers: &Vec<POINT>, idx: usize) -> Option<POINT> {
    verifiers.get(idx).map(|x| x.clone())
}

fn sessionID<SUITE: Suite>(
    suite: &SUITE,
    dealer: &SUITE::POINT,
    verifiers: &Vec<SUITE::POINT>,
    commitments: &Vec<SUITE::POINT>,
    t: usize,
) -> Result<Vec<u8>> {
    let mut h = suite.hash();
    dealer.marshal_to(&mut h)?;

    for v in verifiers {
        v.marshal_to(&mut h)?;
    }

    for c in commitments {
        c.marshal_to(&mut h)?;
    }

    h.write_u32::<LittleEndian>(t as u32)?;

    Ok(h.finalize().to_vec())
}

/// RecoverSecret recovers the secret shared by a Dealer by gathering at least t
/// Deals from the verifiers. It returns an error if there is not enough Deals or
/// if all Deals don't have the same SessionID.
pub fn RecoverSecret<SUITE: Suite>(
    suite: SUITE,
    deals: Vec<Deal<SUITE>>,
    n: usize,
    t: usize,
) -> Result<<SUITE::POINT as Point>::SCALAR>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let mut shares: Vec<PriShare<<SUITE::POINT as Point>::SCALAR>> = vec![];
    let d0_sid = deals[0].session_id.clone();
    for (i, deal) in deals.into_iter().enumerate() {
        // all sids the same
        if deal.session_id == d0_sid {
            shares[i] = deal.sec_share.clone();
        } else {
            bail!("vss: all deals need to have same session id");
        }
    }
    poly::recover_secret(suite, shares, t, n)
}
