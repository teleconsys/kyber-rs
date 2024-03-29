use core::fmt::{Debug, Display, Formatter};
/// module dss implements the Distributed Schnorr Signature protocol from the
/// paper "Provably Secure Distributed Schnorr Signatures and a (t, n)
/// Threshold Scheme for Implicit Certificates".
/// https://dl.acm.org/citation.cfm?id=678297
/// To generate a distributed signature from a group of participants, the group
/// must first generate one longterm distributed secret with the dkg module
/// and then one random secret to be used only once.
/// Each participant then creates a DSS struct, that can issue partial signatures
/// with `partial_sig()`. These partial signatures can be broadcasted to
/// the whole group or to a trusted combiner. Once one has collected enough
/// partial signatures, it is possible to compute the distributed signature with
/// the `signature` method.
/// The resulting signature is compatible with the EdDSA verification function.
/// against the longterm distributed key.
use digest::Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::collections::HashMap;

use crate::{
    encoding::Marshaling,
    group::{HashFactory, PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    share::poly::{self, PolyError, PriShare, PubPoly},
    sign::{eddsa, error::SignatureError, schnorr},
    Group, Point, Random, Scalar,
};

use thiserror::Error;

/// [`Suite`] represents the functionalities needed by the dss module
pub trait Suite: Group + HashFactory + Random + Clone {}

/// [`DistKeyShare`] is an abstraction to allow one to use distributed key share
/// from different schemes easily into this distributed threshold Schnorr
/// signature framework.
pub trait DistKeyShare<GROUP: Group>: Clone {
    fn pri_share(&self) -> PriShare<<GROUP::POINT as Point>::SCALAR>;
    fn commitments(&self) -> Vec<GROUP::POINT>;
}

/// [`DSS`] holds the information used to issue partial signatures as well as to
/// compute the distributed schnorr signature.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DSS<SUITE: Suite, DKS: DistKeyShare<SUITE>> {
    suite: SUITE,
    pub(crate) secret: <SUITE::POINT as Point>::SCALAR,
    pub public: SUITE::POINT,
    pub index: usize,
    pub participants: Vec<SUITE::POINT>,
    pub t: usize,
    long: DKS,
    random: DKS,
    long_poly: PubPoly<SUITE>,
    random_poly: PubPoly<SUITE>,
    pub msg: Vec<u8>,
    pub partials: Vec<Option<PriShare<<SUITE::POINT as Point>::SCALAR>>>,
    partials_idx: HashMap<usize, bool>,
    signed: bool,
    pub session_id: Vec<u8>,
}

impl<SUITE: Suite, DKS: DistKeyShare<SUITE> + Debug> Debug for DSS<SUITE, DKS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DSS")
            .field("suite", &self.suite)
            .field("public", &self.public)
            .field("index", &self.index)
            .field("participants", &self.participants)
            .field("t", &self.t)
            .field("long_poly", &self.long_poly)
            .field("random_poly", &self.random_poly)
            .field("msg", &self.msg)
            .field("partials", &self.partials)
            .field("partials_idx", &self.partials_idx)
            .field("signed", &self.signed)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl<SUITE: Suite, DKS: DistKeyShare<SUITE> + Display> Display for DSS<SUITE, DKS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DSS( suite: {}, public_key: {}, index: {},",
            self.suite, self.public, self.index
        )?;

        write!(f, " participants: [")?;
        let participants = self
            .participants
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", participants)?;

        write!(
            f,
            "threshold: {}, long_polynomial: {}, random_polynomial: {}, message: 0x{},",
            self.t,
            self.long_poly,
            self.random_poly,
            hex::encode(&self.msg)
        )?;

        write!(f, " partials: [")?;
        let partials = self
            .partials
            .iter()
            .map(|c| match c {
                Some(p) => "Some(".to_string() + &p.to_string() + ")",
                None => "None".to_string(),
            })
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", partials)?;

        write!(f, " partials_indexes: [")?;
        let partials_indexes = self
            .partials_idx
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", partials_indexes)?;

        write!(
            f,
            "signed: {}, session_id: 0x{} )",
            self.signed,
            hex::encode(&self.session_id)
        )
    }
}

/// [`PartialSig`] is partial representation of the final distributed signature. It
/// must be sent to each of the other participants.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PartialSig<SUITE: Suite> {
    pub partial: PriShare<<SUITE::POINT as Point>::SCALAR>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
}

impl<SUITE: Suite> PartialSig<SUITE> {
    /// [`hash()`] returns the hash representation of this [`PartialSig`] to be used in a
    /// signature.
    pub fn hash(&self, s: SUITE) -> Result<Vec<u8>, DSSError> {
        let mut h = s.hash();
        h.update(
            &self
                .partial
                .hash(s)
                .map_err(DSSError::PartialSignatureHash)?,
        );
        h.update(&self.session_id);
        Ok(h.finalize().to_vec())
    }
}

/// [`new_dss`] returns a [`DSS`] struct out of the [`Suite`], the `longterm secret` of this
/// node, the `list of participants`, the `longterm` and `random` distributed key
/// (generated by the dkg module), the `message` to sign and finally the `T
/// threshold`. It returns an [`Error`](DSSError) if the public key of the secret can't be found
/// in the list of participants.
pub fn new_dss<SUITE: Suite, DKS: DistKeyShare<SUITE>>(
    suite: SUITE,
    secret: &<SUITE::POINT as Point>::SCALAR,
    participants: &[SUITE::POINT],
    long: &DKS,
    random: &DKS,
    msg: &[u8],
    t: usize,
) -> Result<DSS<SUITE, DKS>, DSSError> {
    let public = suite.point().mul(secret, None);
    let mut i = 0;
    let mut found = false;
    for (j, p) in participants.iter().enumerate() {
        if p.eq(&public) {
            found = true;
            i = j;
            break;
        }
    }
    if !found {
        return Err(DSSError::PublicKeyNotInParticipants);
    }

    Ok(DSS::<SUITE, DKS> {
        suite: suite.clone(),
        secret: secret.clone(),
        public,
        index: i,
        participants: participants.to_vec(),
        long: long.clone(),
        long_poly: PubPoly::new(&suite, Some(suite.point().base()), &long.commitments()),
        random: random.clone(),
        random_poly: PubPoly::new(&suite, Some(suite.point().base()), &random.commitments()),
        msg: msg.to_vec(),
        t,
        partials_idx: HashMap::new(),
        session_id: session_id(suite, long, random)?,
        partials: Vec::new(),
        signed: false,
    })
}

impl<SUITE: Suite, DKS: DistKeyShare<SUITE>> DSS<SUITE, DKS> {
    /// [`partial_sig()`] generates the partial signature related to this [`DSS`]. This
    /// [`PartialSig`] can be broadcasted to every other participant or only to a
    /// trusted combiner as described in the paper.
    /// The signature format is compatible with EdDSA verification implementations.
    pub fn partial_sig(&mut self) -> Result<PartialSig<SUITE>, DSSError> {
        // following the notations from the paper
        let alpha = self.long.pri_share().v;
        let beta = self.random.pri_share().v;
        let hash = self.hash_sig()?;
        let right = hash * alpha;
        let mut ps = PartialSig {
            partial: PriShare {
                v: right + beta,
                i: self.index,
            },
            session_id: self.session_id.clone(),
            signature: Vec::new(),
        };
        let msg = ps.hash(self.suite.clone())?;
        ps.signature = schnorr::sign(&self.suite, &self.secret, &msg)?;
        if !self.signed {
            self.partials_idx.insert(self.index, true);
            self.partials.push(Some(ps.partial.clone()));
            self.signed = true
        }
        Ok(ps)
    }

    /// [`process_partial_sig()`] takes a [`PartialSig`] from another participant and stores it
    /// for generating the distributed signature. It returns an [`Error`](DSSError) if the index is
    /// wrong, or the signature is invalid or if a partial signature has already been
    /// received by the same peer. To know whether the distributed signature can be
    /// computed after this call, one can use the [`enough_partial_sig()`] method.
    pub fn process_partial_sig(&mut self, ps: PartialSig<SUITE>) -> Result<(), DSSError>
    where
        <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
        SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    {
        let public = find_pub(&self.participants, ps.partial.i)?;

        let msg = ps.hash(self.suite.clone())?;
        schnorr::verify(self.suite.clone(), &public, &msg, &ps.signature)?;

        // nothing secret here
        if ps.session_id != self.session_id {
            return Err(DSSError::InvalidSessionId);
        }

        if self.partials_idx.contains_key(&ps.partial.i) {
            return Err(DSSError::PartialAlreadyReceived);
        }

        let hash = self.hash_sig()?;
        let idx = ps.partial.i;
        let rand_share = self.random_poly.eval(idx);
        let long_share = self.long_poly.eval(idx);
        let mut right = self.suite.point().mul(&hash, Some(&long_share.v));
        let right_clone = right.clone();
        right = right.add(&rand_share.v, &right_clone);
        let left = self.suite.point().mul(&ps.partial.v, None);
        if !left.eq(&right) {
            return Err(DSSError::InvalidPartialSignature);
        }
        self.partials_idx.insert(ps.partial.i, true);
        self.partials.push(Some(ps.partial));
        Ok(())
    }

    /// [`enough_partial_sig()`] returns `true` if there are enough partial signature to compute
    /// the distributed signature. It returns `false` otherwise. If there are enough
    /// partial signatures, one can issue the signature with [`signature()`].
    pub fn enough_partial_sig(&self) -> bool {
        self.partials.len() >= self.t
    }

    /// [`signature()`] computes the distributed signature from the `list of partial
    /// signatures` received. It returns an [`Error`](DSSError) if there are not enough partial
    /// signatures. The signature is compatible with the EdDSA verification
    /// alrogithm.
    pub fn signature(&self) -> Result<Vec<u8>, DSSError> {
        if !self.enough_partial_sig() {
            return Err(DSSError::NotEnoughPartials);
        }
        let gamma = poly::recover_secret(
            self.suite.clone(),
            &self.partials,
            self.t,
            self.participants.len(),
        )
        .map_err(DSSError::RecoverSecretError)?;
        // RandomPublic || gamma
        let mut buff = Vec::new();
        self.random.commitments()[0]
            .marshal_to(&mut buff)
            .map_err(SignatureError::MarshallingError)?;
        gamma
            .marshal_to(&mut buff)
            .map_err(SignatureError::MarshallingError)?;
        Ok(buff)
    }

    fn hash_sig(&self) -> Result<<SUITE::POINT as Point>::SCALAR, DSSError> {
        // H(R || A || msg) with
        //  * R = distributed random "key"
        //  * A = distributed public key
        //  * msg = msg to sign
        let mut h = Sha512::new();
        self.random.commitments()[0]
            .marshal_to(&mut h)
            .map_err(SignatureError::MarshallingError)?;
        self.long.commitments()[0]
            .marshal_to(&mut h)
            .map_err(SignatureError::MarshallingError)?;
        h.update(self.msg.clone());
        Ok(self.suite.scalar().set_bytes(&h.finalize()))
    }
}

/// [`verify()`] takes a `public key`, a `message` and a `signature` and returns an [`Error`](SignatureError) if
/// the signature is invalid.
pub fn verify<POINT: Point>(public: &POINT, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
    eddsa::verify(public, msg, sig)
}

fn find_pub<POINT: Point>(list: &[POINT], i: usize) -> Result<POINT, DSSError> {
    if i >= list.len() {
        return Err(DSSError::InvalidIndex);
    }
    Ok(list[i].clone())
}

fn session_id<SUITE: Suite, DKS: DistKeyShare<SUITE>>(
    s: SUITE,
    a: &DKS,
    b: &DKS,
) -> Result<Vec<u8>, DSSError> {
    let mut h = s.hash();
    for p in a.commitments() {
        p.marshal_to(&mut h)
            .map_err(SignatureError::MarshallingError)?;
    }

    for p in b.commitments() {
        p.marshal_to(&mut h)
            .map_err(SignatureError::MarshallingError)?;
    }

    Ok(h.finalize().to_vec())
}

#[derive(Error, Debug)]
pub enum DSSError {
    #[error("signature error")]
    SignatureError(#[from] SignatureError),
    #[error("public key not found in the list of participants")]
    PublicKeyNotInParticipants,
    #[error("invalid index")]
    InvalidIndex,
    #[error("not enough partial signature to sign")]
    NotEnoughPartials,
    #[error("could not recover secret")]
    RecoverSecretError(PolyError),
    #[error("could not hash partial signature")]
    PartialSignatureHash(PolyError),
    #[error("session id do not match")]
    InvalidSessionId,
    #[error("partial signature already received from peer")]
    PartialAlreadyReceived,
    #[error("partial signature not valid")]
    InvalidPartialSignature,
}
