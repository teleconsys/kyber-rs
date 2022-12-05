/// Package vss implements the verifiable secret sharing scheme from the
/// paper "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold
/// Scheme for Implicit Certificates".
/// VSS enables a dealer to share a secret securely and verifiably among n
/// participants out of which at least t are required for its reconstruction.
/// The verifiability of the process prevents a
/// malicious dealer from influencing the outcome to his advantage as each
/// verifier can check the validity of the received share. The protocol has the
/// following steps:
///
///   1) The dealer send a Deal to every verifiers using `Deals()`. Each deal must
///   be sent securely to one verifier whose public key is at the same index than
///   the index of the Deal.
///
///   2) Each verifier processes the Deal with `ProcessDeal`.
///   This function returns a Response which can be twofold:
///   - an approval, to confirm a correct deal
///   - a complaint to announce an incorrect deal notifying others that the
///     dealer might be malicious.
///	 All Responses must be broadcasted to every verifiers and the dealer.
///   3) The dealer can respond to each complaint by a justification revealing the
///   share he originally sent out to the accusing verifier. This is done by
///   calling `ProcessResponse` on the `Dealer`.
///   4) The verifiers refuse the shared secret and abort the protocol if there
///   are at least t complaints OR if a Justification is wrong. The verifiers
///   accept the shared secret if there are at least t approvals at which point
///   any t out of n verifiers can reveal their shares to reconstruct the shared
///   secret.
use core::fmt;
use std::collections::HashMap;

use crate::encoding::{self, unmarshal_binary, BinaryMarshaler, Marshaling};
use crate::group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical};
use crate::share::poly::{self, new_pri_poly, PriShare, PubPoly};
use crate::share::vss::dh::{AEAD, context, dh_exchange};
use crate::share::vss::suite::Suite;
use crate::sign::schnorr;
use crate::Scalar;
use crate::Point;

use anyhow::{bail, Error, Ok, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

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
    pub(crate) deals: Vec<Deal<SUITE>>,
    pub(crate) aggregator: Aggregator<SUITE>,
}

impl<SUITE: Suite> Default for Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self {
            suite: Default::default(),
            long: Default::default(),
            pubb: Default::default(),
            secret: Default::default(),
            secret_commits: Default::default(),
            verifiers: Default::default(),
            hkdf_context: Default::default(),
            t: Default::default(),
            session_id: Default::default(),
            deals: Default::default(),
            aggregator: Default::default(),
        }
    }
}

impl<SUITE: Suite> Deref for Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    type Target = Aggregator<SUITE>;

    fn deref(&self) -> &Self::Target {
        &self.aggregator
    }
}

impl<SUITE: Suite> DerefMut for Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
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
    pub(crate) session_id: Vec<u8>,
    /// Private share generated by the dealer
    pub(crate) sec_share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Random share generated by the dealer
    pub(crate) rnd_share: PriShare<<SUITE::POINT as Point>::SCALAR>,
    /// Threshold used for this secret sharing run
    pub(crate) t: usize,
    // Commitments are the coefficients used to verify the shares against
    pub(crate) commitments: Vec<SUITE::POINT>,
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
    fn decode(buff: &[u8]) -> Result<Deal<SUITE>> {
        let mut d = Deal::default();
        unmarshal_binary(&mut d, buff)?;
        Ok(d)
    }
}

impl<SUITE: Suite> BinaryMarshaler for Deal<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

/// EncryptedDeal contains the deal in a encrypted form only decipherable by the
/// correct recipient. The encryption is performed in a similar manner as what is
/// done in TLS. The dealer generates a temporary key pair, signs it with its
/// longterm secret key.
#[derive(Clone, Serialize)]
pub struct EncryptedDeal<POINT: Point + Serialize> {
    /// Ephemeral Diffie Hellman key
    pub(crate) dhkey: POINT,
    /// Signature of the DH key by the longterm key of the dealer
    pub(crate) signature: Vec<u8>,
    /// Nonce used for the encryption
    nonce: Vec<u8>,
    /// AEAD encryption of the deal marshalled by protobuf
    pub(crate) cipher: Vec<u8>,
}

impl<POINT: Point + Serialize> BinaryMarshaler for EncryptedDeal<POINT> {
    fn marshal_binary(&self) -> Result<Vec<u8>> {
        encoding::marshal_binary(self)
    }
}

/// Response is sent by the verifiers to all participants and holds each
/// individual validation or refusal of a Deal.
#[derive(Clone, Debug, PartialEq)]
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
    pub fn hash<SUITE: Suite>(&self, s: &SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.write("response".as_bytes())?;
        h.write(&self.session_id)?;
        h.write_u32::<LittleEndian>(self.index)?;
        h.write_u32::<LittleEndian>(self.approved as u32)?;
        Ok(h.finalize().to_vec())
    }
}

/// Justification is a message that is broadcasted by the Dealer in response to
/// a Complaint. It contains the original Complaint as well as the shares
/// distributed to the complainer.
#[derive(Clone)]
pub struct Justification<SUITE: Suite>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// SessionID related to the current run of the protocol
    session_id: Vec<u8>,
    /// Index of the verifier who issued the Complaint,i.e. index of this Deal
    index: u32,
    /// Deal in cleartext
    pub(crate) deal: Deal<SUITE>,
    /// Signature over the whole packet
    signature: Vec<u8>,
}

impl<SUITE: Suite> Justification<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// Hash returns the hash of a Justification.
    fn hash(self, s: SUITE) -> Result<Vec<u8>> {
        let mut h = s.hash();
        h.update("justification".as_bytes());
        h.update(&self.session_id);

        h.write_u32::<LittleEndian>(self.index)?;
        let buff = self.deal.marshal_binary()?;
        h.update(&buff);

        Ok(h.finalize().to_vec())
    }
}

/// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
/// does not have to be trusted by other Verifiers. The security parameter t is
/// the number of shares required to reconstruct the secret. It is HIGHLY
/// RECOMMENDED to use a threshold higher or equal than what the method
/// MinimumT() returns, otherwise it breaks the security assumptions of the whole
/// scheme. It returns an error if the t is inferior or equal to 2.
pub fn new_dealer<SUITE: Suite>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    secret: <SUITE::POINT as Point>::SCALAR,
    verifiers: &[SUITE::POINT],
    t: usize,
) -> Result<Dealer<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    if !valid_t(t, verifiers) {
        bail!("dealer: t {} invalid", t);
    }

    let h = derive_h(suite, verifiers);
    let f = new_pri_poly(suite, t, Some(secret.clone()), suite.random_stream());
    let g = new_pri_poly(suite, t, None, suite.random_stream());
    let d_pubb = suite.point().mul(&longterm, None);

    // Compute public polynomial coefficients
    let f_caps = f.commit(Some(&suite.point().base()));
    let (_, secret_commits) = f_caps.info();
    let g_caps = g.commit(Some(&h));

    let c = f_caps.add(&g_caps)?;
    let (_, commitments) = c.info();

    let session_id = session_id(&suite, &d_pubb, &verifiers, &commitments, t)?;

    let aggregator = new_aggregator(&suite, &d_pubb, &verifiers, &commitments, t, &session_id);
    // C = F + G
    let mut deals: Vec<Deal<SUITE>> = vec![];
    for i in 0..verifiers.len() {
        let fi = f.eval(i);
        let gi = g.eval(i);
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
        verifiers: verifiers.to_vec(),
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
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    /// PlaintextDeal returns the plaintext version of the deal destined for peer i.
    /// Use this only for testing.
    pub fn plaintext_deal(&mut self, i: usize) -> Result<&mut Deal<SUITE>> {
        if i >= self.deals.len() {
            bail!("dealer: PlaintextDeal given wrong index");
        }
        let d = &mut self.deals[i];
        Ok(d)
    }

    /// EncryptedDeal returns the encryption of the deal that must be given to the
    /// verifier at index i.
    /// The dealer first generates a temporary Diffie Hellman key, signs it using its
    /// longterm key, and computes the shared key depending on its longterm and
    /// ephemeral key and the verifier's public key.
    /// This shared key is then fed into a HKDF whose output is the key to a AEAD
    /// (AES256-GCM) scheme to encrypt the deal.
    pub fn encrypted_deal(&self, i: usize) -> Result<EncryptedDeal<SUITE::POINT>> {
        let v_pub = find_pub(&self.verifiers, i)
            .ok_or(Error::msg("dealer: wrong index to generate encrypted deal"))?;
        // gen ephemeral key
        let dh_secret = self.suite.scalar().pick(&mut self.suite.random_stream());
        let dh_public = self.suite.point().mul(&dh_secret, None);
        // signs the public key
        let dh_public_buff = dh_public.marshal_binary()?;
        let signature = schnorr::sign(&self.suite, &self.long, &dh_public_buff)?;

        // AES128-GCM
        let pre = dh_exchange(self.suite, dh_secret, v_pub);
        let gcm = AEAD::new(pre, &self.hkdf_context)?;

        let nonce = [0u8; AEAD::nonce_size()];
        // let dealBuff = protobuf.Encode(self.deals[i])?;
        let deal_buf = self.deals[i].marshal_binary()?;
        let encrypted = gcm.seal(None, &nonce, &deal_buf, Some(&self.hkdf_context))?;
        return Ok(EncryptedDeal {
            dhkey: dh_public,
            signature,
            nonce: nonce.to_vec(),
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
            let deal = self.encrypted_deal(i)?;
            deals.push(deal);
        }
        Ok(deals)
    }

    /// process_response analyzes the given Response. If it's a valid complaint, then
    /// it returns a Justification. This Justification must be broadcasted to every
    /// participants. If it's an invalid complaint, it returns an error about the
    /// complaint. The verifiers will also ignore an invalid Complaint.
    pub fn process_response(&mut self, r: &Response) -> Result<Option<Justification<SUITE>>>
    where
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    {
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

        let msg = &j.clone().hash(self.suite)?;
        let sig = schnorr::sign(&self.suite, &self.long, msg)?;
        j.signature = sig;

        Ok(Some(j))
    }

    /// SecretCommit returns the commitment of the secret being shared by this
    /// dealer. This function is only to be called once the deal has enough approvals
    /// and is verified otherwise it returns nil.
    pub fn secret_commit(&self) -> Option<SUITE::POINT> {
        if !self.aggregator.clone().enough_approvals() || !self.aggregator.deal_certified() {
            return None;
        }
        return Some(self.suite.point().mul(&self.secret, None));
    }

    /// Commits returns the commitments of the coefficient of the secret polynomial
    /// the Dealer is sharing.
    pub fn commits(&self) -> Option<Vec<SUITE::POINT>> {
        if !self.aggregator.clone().enough_approvals() || !self.aggregator.deal_certified() {
            return None;
        }
        return Some(self.secret_commits.clone());
    }

    /// Key returns the longterm key pair used by this Dealer.
    fn key(self) -> (<SUITE::POINT as Point>::SCALAR, SUITE::POINT) {
        return (self.long, self.pubb);
    }

    /// SessionID returns the current sessionID generated by this dealer for this
    /// protocol run.
    pub fn session_id(&self) -> Vec<u8> {
        return self.session_id.clone();
    }

    /// SetTimeout tells this dealer to consider this moment the maximum time limit.
    /// it calls cleanVerifiers which will take care of all Verifiers who have not
    /// responded until now.
    pub fn set_timeout(&mut self) {
        self.aggregator.clean_verifiers();
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
    pub(crate) longterm: <SUITE::POINT as Point>::SCALAR,
    pub(crate) pubb: SUITE::POINT,
    dealer: SUITE::POINT,
    pub(crate) index: usize,
    verifiers: Vec<SUITE::POINT>,
    hkdf_context: Vec<u8>,
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
pub fn new_verifier<SUITE: Suite>(
    suite: &SUITE,
    longterm: &<SUITE::POINT as Point>::SCALAR,
    dealer_key: &SUITE::POINT,
    verifiers: &[SUITE::POINT],
) -> Result<Verifier<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let pubb = suite.point().mul(&longterm, None);
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
    let c = context(suite, dealer_key, verifiers);
    Ok(Verifier {
        suite: *suite,
        longterm: longterm.clone(),
        dealer: dealer_key.clone(),
        verifiers: verifiers.to_vec(),
        pubb,
        index,
        hkdf_context: Vec::from(c),
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
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
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
    pub fn process_encrypted_deal(&mut self, e: &EncryptedDeal<SUITE::POINT>) -> Result<Response>
    where
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    {
        let d = self.decrypt_deal(e)?;
        if d.sec_share.i != self.index {
            bail!("vss: verifier got wrong index from deal");
        }

        let t = d.t;

        let sid = session_id(
            &self.suite,
            &self.dealer,
            &self.verifiers,
            &d.commitments,
            t,
        )?;

        if self.aggregator.is_none() {
            self.aggregator = Some(new_aggregator(
                &self.suite,
                &self.dealer,
                &self.verifiers,
                &d.commitments,
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
            // TODO: manage error
            match err {
                VerifyDealError::DealAlreadyProcessedError => bail!(err),
                VerifyDealError::TextError(e) => {
                    if !e.eq("vss: share does not verify against commitments in Deal") {
                        bail!(e)
                    }
                }
            }
        }

        r.signature = schnorr::sign(
            &self.suite,
            &self.longterm.clone(),
            r.hash(&self.suite)?.as_slice(),
        )?;

        self.aggregator.as_mut().unwrap().add_response(&r)?;
        Ok(r)
    }

    pub fn decrypt_deal(&self, e: &EncryptedDeal<SUITE::POINT>) -> Result<Deal<SUITE>>
    where
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    {
        let eph_buff = e.dhkey.marshal_binary()?;
        // verify signature
        schnorr::verify(
            self.suite,
            &self.dealer.clone(),
            eph_buff.as_slice(),
            &e.signature,
        )?;

        // compute shared key and AES526-GCM cipher
        let pre = dh_exchange(self.suite, self.longterm.clone(), e.dhkey.clone());
        let gcm = AEAD::new(pre, &self.hkdf_context)?;
        let decrypted = gcm.open(
            None,
            e.nonce.as_slice().try_into().unwrap(),
            &e.cipher,
            Some(self.hkdf_context.as_slice()),
        )?;
        Deal::decode(&decrypted)
    }

    /// ProcessResponse analyzes the given response. If it's a valid complaint, the
    /// verifier should expect to see a Justification from the Dealer. It returns an
    /// error if it's not a valid response.
    /// Call `v.DealCertified()` to check if the whole protocol is finished.
    pub fn process_response(&mut self, resp: &Response) -> Result<()>
    where
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    {
        match &mut self.aggregator {
            Some(aggregator) => aggregator.verify_response(resp),
            None => bail!("no aggregator for verifier"),
        }
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
    pub fn process_justification(&mut self, dr: &Justification<SUITE>) -> Result<()> {
          match &mut self.aggregator {
            Some(a) => a.verify_justification(dr),
            None => bail!("missing aggregator"),
        }
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
    pub fn session_id(&self) -> Vec<u8> {
        return self.sid.clone();
    }

    /// SetTimeout tells this verifier to consider this moment the maximum time limit.
    /// it calls cleanVerifiers which will take care of all Verifiers who have not
    /// responded until now.
    pub fn set_timeout(&mut self) {
        if let Some(a) = self.aggregator.as_mut() {
            a.clean_verifiers()
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
    pub(crate) sid: Vec<u8>,
    pub(crate) deal: Option<Deal<SUITE>>,
    pub(crate) t: usize,
    pub(crate) bad_dealer: bool,
}

impl<SUITE: Suite> Default for Aggregator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    fn default() -> Self {
        Self {
            suite: Default::default(),
            dealer: Default::default(),
            verifiers: Default::default(),
            commits: Default::default(),
            responses: Default::default(),
            sid: Default::default(),
            deal: Default::default(),
            t: Default::default(),
            bad_dealer: Default::default(),
        }
    }
}

fn new_aggregator<SUITE: Suite>(
    suite: &SUITE,
    dealer: &SUITE::POINT,
    verifiers: &[SUITE::POINT],
    commitments: &[SUITE::POINT],
    t: usize,
    sid: &[u8],
) -> Aggregator<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    Aggregator {
        suite: *suite,
        dealer: dealer.clone(),
        verifiers: verifiers.to_vec(),
        commits: commitments.to_vec(),
        t,
        sid: sid.clone().to_vec(),
        responses: HashMap::new(),
        deal: None,
        bad_dealer: false,
    }
}

#[derive(Debug, Clone)]
pub enum VerifyDealError {
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
    pub fn verify_deal(&mut self, d: &Deal<SUITE>, inclusion: bool) -> Result<(), VerifyDealError> {
        if self.deal.is_some() && inclusion {
            return Err(VerifyDealError::DealAlreadyProcessedError);
        }
        if self.deal.is_none() {
            self.commits = d.commitments.clone();
            self.sid = d.session_id.clone();
            self.deal = Some(d.clone());
        }

        if !valid_t(d.t, &self.verifiers) {
            return Err(VerifyDealError::TextError(
                "vss: invalid t received in Deal".to_string(),
            ));
        }

        if self.sid != d.session_id {
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
        if fi.i >= self.verifiers.len() {
            return Err(VerifyDealError::TextError(
                "vss: index out of bounds in Deal".to_string(),
            ));
        }
        // compute fi * G + gi * H
        let fig = self.suite.point().base().mul(&fi.v, None);
        let h = derive_h(self.suite, &self.verifiers);
        let gih = self.suite.point().mul(&gi.v, Some(&h));
        let ci = self.suite.point().add(&fig, &gih);

        let commit_poly = PubPoly::new(&self.suite, None, &d.commitments);

        let pub_share = commit_poly.eval(fi.i);
        if ci != pub_share.v {
            return Err(VerifyDealError::TextError(
                "vss: share does not verify against commitments in Deal".to_string(),
            ));
        }
        Result::Ok(())
    }

    /// cleanVerifiers checks the aggregator's response array and creates a StatusComplaint
    /// response for all verifiers who have no response in the array.
    pub fn clean_verifiers(&mut self) {
        for i in 0..self.verifiers.len() {
            if !self.responses.contains_key(&(i as u32)) {
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

    pub fn verify_response(&mut self, r: &Response) -> Result<()>
    where
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    {
        if r.session_id != self.sid {
            bail!("vss: receiving inconsistent sessionID in response")
        }

        let public = find_pub(&self.verifiers, r.index as usize);
        if public.is_none() {
            bail!("vss: index out of bounds in response")
        }

        let msg = r.hash(&self.suite)?;

        schnorr::verify(self.suite, &public.unwrap(), &msg, &r.signature)?;

        self.add_response(&r)
    }

    fn verify_justification(&mut self, j: &Justification<SUITE>) -> Result<()> {
        let pubb = find_pub(&self.verifiers, j.index as usize);
        if pubb.is_none() {
            bail!("vss: index out of bounds in justification")
        }

        if !self.responses.contains_key(&j.index) {
            bail!("vss: no complaints received for this justification")
        }

        // clone the resp here
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

        // add the updated resp
        self.responses.insert(j.index, r);

        return verification.map_err(|e| Error::msg(e.to_string()));
    }

    pub fn add_response(&mut self, r: &Response) -> Result<()> {
        if find_pub(&self.verifiers, r.index as usize).is_none() {
            bail!("vss: index out of bounds in Complaint");
        }
        if self.responses.get(&(r.index as u32)).is_some() {
            bail!("vss: already existing response from same origin")
        }
        self.responses.insert(r.index, r.clone());
        Ok(())
    }

    /// EnoughApprovals returns true if enough verifiers have sent their approval for
    /// the deal they received.
    pub fn enough_approvals(&self) -> bool {
        let mut app = 0usize;
        for (_, r) in &self.responses {
            if r.approved {
                app += 1;
            }
        }
        return app >= self.t;
    }

    /// deal_certified returns true if there has been less than t complaints, all
    /// Justifications were correct and if EnoughApprovals() returns true.
    pub fn deal_certified(&self) -> bool {
        let mut verifiers_unstable = 0usize;
        // Check either a StatusApproval or StatusComplaint for all known verifiers
        // i.e. make sure all verifiers are either timed-out or OK.
        for (i, _) in self.verifiers.iter().enumerate() {
            if !self.responses.contains_key(&(i as u32)) {
                verifiers_unstable += 1;
            }
        }

        let too_much_complaints = verifiers_unstable > 0 || self.bad_dealer;
        return self.enough_approvals() && !too_much_complaints;
    }

    /// UnsafeSetResponseDKG is an UNSAFE bypass method to allow DKG to use VSS
    /// that works on basis of approval only.
    #[allow(unused_must_use)]
    pub fn unsafe_set_response_dkg(&mut self, idx: u32, approval: bool) {
        let r = Response {
            session_id: self.sid.clone(),
            index: idx,
            approved: approval,
            signature: vec![],
        };

        self.add_response(&r);
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

fn valid_t<POINT: Point>(t: usize, verifiers: &[POINT]) -> bool {
    return t >= 2 && t <= verifiers.len() && (t as u32) as i64 == t as i64;
}

fn derive_h<SUITE: Suite>(suite: SUITE, verifiers: &[SUITE::POINT]) -> SUITE::POINT {
    let mut b = vec![];
    for v in verifiers {
        v.marshal_to(&mut b).unwrap();
    }
    let base = suite.point().pick(&mut suite.xof(Some(&b)));
    base
}

pub(crate) fn find_pub<POINT: Point>(verifiers: &Vec<POINT>, idx: usize) -> Option<POINT> {
    verifiers.get(idx).map(|x| x.clone())
}

pub(crate) fn session_id<SUITE: Suite>(
    suite: &SUITE,
    dealer: &SUITE::POINT,
    verifiers: &[SUITE::POINT],
    commitments: &[SUITE::POINT],
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
pub fn recover_secret<SUITE: Suite>(
    suite: SUITE,
    deals: Vec<Deal<SUITE>>,
    n: usize,
    t: usize,
) -> Result<<SUITE::POINT as Point>::SCALAR>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let mut shares = Vec::with_capacity(deals.len());
    for deal in &deals {
        // all sids the same
        if deal.session_id == deals[0].session_id {
            shares.push(Some(deal.sec_share.clone()));
        } else {
            bail!("vss: all deals need to have same session id");
        }
    }
    poly::recover_secret(suite, &shares, t, n)
}
