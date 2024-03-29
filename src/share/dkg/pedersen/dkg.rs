/// module [`pedersen::dkg`] implements a general distributed key generation (DKG) framework.
/// This module serves two functionalities: (1) to run a fresh new DKG from
/// scratch and (2) to reshare old shares to a potentially distinct new set of
/// nodes (the "resharing" protocol). The former protocol is described in "A
/// threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
/// https://dl.acm.org/citation.cfm?id=1754929. The latter protocol is
/// implemented in "Verifiable Secret Redistribution for Threshold Signing
/// Schemes", by T. Wong et
/// al.(https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf)
/// For an example how to use it please have a look at examples/dkg_test.rs
use core::fmt::{Debug, Display, Formatter};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Read};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    encoding::BinaryMarshaler,
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    share::{
        self,
        dkg::DKGError,
        vss::{pedersen::vss, suite::Suite},
    },
    sign::schnorr,
    util::random::RandStream,
    Point, Scalar,
};

use super::structs::{Deal, DistKeyShare, Justification, Response};

/// [`Config`] holds all required information to run a fresh DKG protocol or a
/// resharing protocol. In the case of a new fresh DKG protocol, one must fill
/// the following fields: `suite`, `longterm`, `new_nodes`, `threshold` (opt). In the case
/// of a resharing protocol, one must fill the following: `suite`, `longterm`,
/// `old_nodes`, `new_nodes`. If the node using this config is creating new shares
/// (i.e. it belongs to the current group), the `share` field must be filled in
/// with the current share of the node. If the node using this config is a new
/// addition and thus has no current share, the `public_coeffs` field be must be
/// filled in.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config<SUITE: Suite, READ: Read + Clone> {
    pub suite: SUITE,

    /// `longterm` is the longterm secret key.
    pub longterm: <SUITE::POINT as Point>::SCALAR,

    /// Current group of share holders. It will be empty for new DKG. These nodes
    /// will have invalid shares after the protocol has been run. To be able to issue
    /// new shares to a new group, the group member's public key must be inside this
    /// list and in the `share` field. Keys can be disjoint or not with respect to the
    /// `new_nodes` list.
    pub old_nodes: Vec<SUITE::POINT>,

    /// `public_coeffs` are the coefficients of the distributed polynomial needed
    /// during the resharing protocol. The first coefficient is the key. It is
    /// required for new share holders.  It should be `None` for a new DKG.
    pub public_coeffs: Option<Vec<SUITE::POINT>>,

    /// Expected new group of share holders. These public-key designated nodes
    /// will be in possession of new shares after the protocol has been run. To be a
    /// receiver of a new share, one's public key must be inside this list. Keys
    /// can be disjoint or not with respect to the `old_nodes` list.
    pub new_nodes: Vec<SUITE::POINT>,

    /// `share` to refresh. It must be `None` for a new node wishing to
    /// join or create a group. To be able to issue new fresh shares to a new group,
    /// one's share must be specified here, along with the public key inside the
    /// `old_nodes` field.
    pub share: Option<DistKeyShare<SUITE>>,

    /// The `threshold` to use in order to reconstruct the secret with the produced
    /// shares. This threshold is with respect to the number of nodes in the
    /// NewNodes list. If unspecified, default is set to
    /// [`vss::minimum_t(new_nodes.len()))`]. This threshold indicates the degree of the
    /// polynomials used to create the shares, and the minimum number of
    /// verification required for each deal.
    pub threshold: usize,

    /// [`old_threshold`] holds the `threshold` value that was used in the previous
    /// configuration. This field MUST be specified when doing resharing, but is
    /// not needed when doing a fresh DKG. This value is required to gather a
    /// correct number of valid deals before creating the distributed key share.
    /// NOTE: this field is always required (instead of taking the default when
    /// absent) when doing a resharing to avoid a downgrade attack, where a resharing
    /// the number of deals required is less than what it is supposed to be.
    pub old_threshold: usize,

    /// [`reader`] is an optional field that can hold a user-specified entropy source.
    /// If it is set, `reader`'s data will be combined with random data from [`rand`]
    /// to create a random stream which will pick the dkg's secret coefficient. Otherwise,
    /// the random stream will only use [`rand`]'s entropy.
    pub reader: Option<READ>,

    /// When `user_reader_only` it set to `true`, only the user-specified entropy source
    /// reader will be used. This should only be used in tests, allowing reproducibility.
    pub user_reader_only: bool,
}

impl<SUITE: Suite, READ: Read + Clone> Debug for Config<SUITE, READ> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("suite", &self.suite)
            .field("old_nodes", &self.old_nodes)
            .field("public_coeffs", &self.public_coeffs)
            .field("new_nodes", &self.new_nodes)
            .field("share", &self.share)
            .field("threshold", &self.threshold)
            .field("old_threshold", &self.old_threshold)
            .field("reader", &self.reader.is_some())
            .field("user_reader_only", &self.user_reader_only)
            .finish()
    }
}

impl<SUITE: Suite, READ: Read + Clone> Display for Config<SUITE, READ> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Config( suite: {},", self.suite,)?;

        write!(f, " old_nodes: [")?;
        let old_nodes = self
            .old_nodes
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", old_nodes)?;

        match self.public_coeffs {
            Some(ref p) => {
                write!(f, "Some([")?;
                let coeffs = p
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                write!(f, "{}]),", coeffs)?;
            }
            None => write!(f, "None,")?,
        };

        write!(f, " new_nodes: [")?;
        let new_nodes = self
            .new_nodes
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{}],", new_nodes)?;

        write!(f, " share: ")?;
        match self.share {
            Some(ref s) => write!(f, "Some({})", s),
            None => write!(f, "None"),
        }?;
        write!(f, ",")?;

        write!(
            f,
            "threshold: {}, old_threshold: {}, reader: {}, user_reader_only: {} )",
            self.threshold,
            self.old_threshold,
            self.reader.is_some(),
            self.user_reader_only
        )
    }
}

/// [`DistKeyGenerator`] is the struct that runs the DKG protocol.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DistKeyGenerator<SUITE: Suite, READ: Read + Clone> {
    /// `config` driving the behavior of DistKeyGenerator
    pub c: Config<SUITE, READ>,
    pub suite: SUITE,

    pub long: <SUITE::POINT as Point>::SCALAR,
    pub pubb: SUITE::POINT,
    pub dpub: share::poly::PubPoly<SUITE>,
    pub dealer: vss::Dealer<SUITE>,
    /// `verifiers` indexed by dealer index
    pub verifiers: HashMap<u32, vss::Verifier<SUITE>>,
    /// performs the part of the response verification for `old nodes`
    pub old_aggregators: HashMap<u32, vss::Aggregator<SUITE>>,
    /// `index` in the old list of nodes
    pub oidx: usize,
    /// `index` in the new list of nodes
    pub nidx: usize,
    /// `old threshold` used in the previous DKG
    pub old_t: usize,
    /// `new threshold` to use in this round
    pub new_t: usize,
    /// indicates whether we are in the re-sharing protocol or basic DKG
    pub is_resharing: bool,
    /// indicates whether we are able to issue shares or not
    pub can_issue: bool,
    /// indicates whether we are able to receive a new share or not
    pub can_receive: bool,
    /// indicates whether the node holding the pub key is present in the new list
    pub new_present: bool,
    /// indicates whether the node is present in the old list
    pub old_present: bool,
    /// already processed our own deal
    pub processed: bool,
    /// did the timeout / period / already occured or not
    pub timeout: bool,
}

impl<SUITE: Suite, READ: Read + Clone> Debug for DistKeyGenerator<SUITE, READ> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DistKeyGenerator")
            .field("c", &self.c)
            .field("suite", &self.suite)
            .field("pubb", &self.pubb)
            .field("dpub", &self.dpub)
            .field("dealer", &self.dealer)
            .field("verifiers", &self.verifiers)
            .field("old_aggregators", &self.old_aggregators)
            .field("oidx", &self.oidx)
            .field("nidx", &self.nidx)
            .field("old_t", &self.old_t)
            .field("new_t", &self.new_t)
            .field("is_resharing", &self.is_resharing)
            .field("can_issue", &self.can_issue)
            .field("can_receive", &self.can_receive)
            .field("new_present", &self.new_present)
            .field("old_present", &self.old_present)
            .field("processed", &self.processed)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<SUITE: Suite, READ: Read + Clone> Display for DistKeyGenerator<SUITE, READ> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write! {f, "DistKeyGenerator( config: {}, suite: {}, public_key: {}, distributed_public_key: {},
            dealer: {},",
            self.c,
            self.suite,
            self.pubb,
            self.dpub,
            self.dealer,
        }?;

        write!(f, " verifiers: [")?;
        let verifiers = self
            .verifiers
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", verifiers)?;

        write!(f, " old_aggregators: [")?;
        let old_aggregators = self
            .old_aggregators
            .iter()
            .map(|c| "(".to_string() + &c.0.to_string() + ", " + &c.1.to_string() + ")")
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}],", old_aggregators)?;

        write!(f, " old_index: {}, new_index: {}, old_threshold: {}, new_threshold: {}, is_resharing: {}, can_issue: {}, can_receive: {}, new_present: {}, old_present: {}, processed: {}, timeout: {} )",
            self.oidx,
            self.nidx,
            self.old_t,
            self.new_t,
            self.is_resharing,
            self.can_issue,
            self.can_receive,
            self.new_present,
            self.old_present,
            self.processed,
            self.timeout
        )
    }
}

/// [`new_dist_key_handler()`] takes a [`Config`] and returns a [`DistKeyGenerator`] that is able
/// to drive the DKG or resharing protocol.
pub fn new_dist_key_handler<SUITE: Suite, READ: Read + Clone + 'static>(
    mut c: Config<SUITE, READ>,
) -> Result<DistKeyGenerator<SUITE, READ>, DKGError>
where
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
{
    if c.new_nodes.is_empty() && c.old_nodes.is_empty() {
        return Err(DKGError::EmptyNodeList);
    }

    let mut is_resharing = false;
    if c.share.is_some() || c.public_coeffs.is_some() {
        is_resharing = true;
    }
    if is_resharing {
        if c.old_nodes.is_empty() {
            return Err(DKGError::ReshareMissingOldNodes);
        }
        if c.old_threshold == 0 {
            return Err(DKGError::ReshareMissingOldThreshold);
        }
    }
    // can_receive is true by default since in the default DKG mode everyone
    // participates
    let mut can_receive = true;
    let pubb = c.suite.point().mul(&c.longterm, None);
    let (mut oidx, mut old_present) = find_pub(&c.old_nodes, &pubb);
    let (nidx, new_present) = find_pub(&c.new_nodes, &pubb);
    if !old_present && !new_present {
        return Err(DKGError::PublicKeyNotFound);
    }

    let new_threshold = if c.threshold != 0 {
        c.threshold
    } else {
        vss::minimum_t(c.new_nodes.len())
    };

    let mut dealer = vss::Dealer::default();
    let mut can_issue = false;
    if c.share.is_some() {
        // resharing case
        let secret_coeff = c.share.clone().unwrap().share.v;
        dealer = vss::new_dealer(
            c.suite,
            c.longterm.clone(),
            secret_coeff,
            &c.new_nodes,
            new_threshold,
        )?;
        can_issue = true;
    } else if !is_resharing && new_present {
        // fresh DKG case
        let mut random_stream = RandStream::default();
        //if the user provided a reader, use it alone or combined with rand
        if c.reader.is_some() && !c.user_reader_only {
            let mut r_vec = Vec::new();
            let r = Box::new(c.reader.clone().unwrap()) as Box<dyn Read>;
            r_vec.push(r);
            let rng_core = Box::new(StdRng::from_entropy()) as Box<dyn RngCore>;
            r_vec.push(Box::new(rng_core) as Box<dyn Read>);
            random_stream = RandStream::new(r_vec); //, rand reader
        } else if c.reader.is_some() && c.user_reader_only {
            let mut r_vec = Vec::new();
            let r = Box::new(c.reader.clone().unwrap()) as Box<dyn Read>;
            r_vec.push(r);
            random_stream = RandStream::new(r_vec);
        }
        let secret_coeff = c.suite.scalar().pick(&mut random_stream);
        dealer = vss::new_dealer(
            c.suite,
            c.longterm.clone(),
            secret_coeff,
            &c.new_nodes,
            new_threshold,
        )?;
        can_issue = true;
        c.old_nodes = c.new_nodes.clone();
        (oidx, old_present) = find_pub(&c.old_nodes, &pubb);
    }

    let mut dpub = share::poly::PubPoly::<SUITE>::default();
    let mut old_threshold = 0;
    if !new_present {
        // if we are not in the new list of nodes, then we definitely can't
        // receive anything
        can_receive = false;
    } else if is_resharing && new_present {
        if c.public_coeffs.is_none() && c.share.is_none() {
            return Err(DKGError::NoPublicPolys);
        } else if c.public_coeffs.is_some() {
            dpub = share::poly::PubPoly::new(
                &c.suite,
                Some(c.suite.point().base()),
                &c.public_coeffs.clone().unwrap(),
            );
        } else if c.share.is_some() {
            // take the commits of the share, no need to duplicate information
            c.public_coeffs = Some(c.share.clone().unwrap().commits);
            dpub = share::poly::PubPoly::new(
                &c.suite,
                Some(c.suite.point().base()),
                &c.public_coeffs.clone().unwrap(),
            )
        }
        // old_threshold is only useful in the context of a new share holder, to
        // make sure there are enough correct deals from the old nodes.
        can_receive = true;
        old_threshold = c.public_coeffs.clone().unwrap().len();
    }
    let dkg = DistKeyGenerator::<SUITE, READ> {
        dealer,
        old_aggregators: HashMap::new(),
        suite: c.suite,
        long: c.longterm.clone(),
        pubb,
        can_receive,
        can_issue,
        is_resharing,
        dpub,
        oidx,
        nidx,
        c: c.clone(),
        old_t: old_threshold,
        new_t: new_threshold,
        new_present,
        old_present,
        verifiers: HashMap::new(),
        processed: false,
        timeout: false,
    };
    if new_present {
        let mut dkg_try = dkg.clone();
        let res_init = dkg_try.init_verifiers(c);
        if res_init.is_ok() {
            return Ok(dkg_try);
        }
    }
    Ok(dkg)
}

/// [`new_dist_key_generator()`] returns a dist key generator ready to create a fresh
/// distributed key with the regular DKG protocol.
pub fn new_dist_key_generator<SUITE: Suite, READ: Read + Clone + 'static>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    participants: &[SUITE::POINT],
    t: usize,
) -> Result<DistKeyGenerator<SUITE, READ>, DKGError>
where
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
{
    let c = Config {
        suite,
        longterm,
        new_nodes: participants.to_vec(),
        threshold: t,
        old_nodes: Vec::new(),
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        reader: None,
        user_reader_only: false,
    };
    new_dist_key_handler(c)
}

impl<SUITE: Suite, READ: Read + Clone + 'static> DistKeyGenerator<SUITE, READ>
where
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    /// [`deals()`] returns all the [`deals`](Deal) that must be broadcasted to all participants in
    /// the new list. The deal corresponding to this DKG is already added to this DKG
    /// and is ommitted from the returned map. To know which participant a deal
    /// belongs to, loop over the keys as indices in the list of new participants:
    ///
    /// for (i,dd) in dist_deals.iter().enumerate() {
    ///     send_to(participants[i],dd)
    /// }
    ///
    /// If this method cannot process its own Deal, that indicates a
    /// severe problem with the configuration or implementation and
    /// results in a panic.
    pub fn deals(&mut self) -> Result<HashMap<usize, Deal<SUITE::POINT>>, DKGError> {
        if !self.can_issue {
            // We do not hold a share, so we cannot make a deal, so
            // return an empty map and no error. This makes callers not
            // need to care if they are in a resharing context or not.
            return Ok(HashMap::new());
        }
        let deals = self.dealer.encrypted_deals()?;
        let mut dd = HashMap::new();
        for (i, _) in self.c.new_nodes.clone().iter().enumerate() {
            let mut distd = Deal {
                index: self.oidx as u32,
                deal: deals[i].clone(),
                signature: Vec::new(),
            };
            // sign the deal
            let buff = distd.marshal_binary()?;
            distd.signature = schnorr::sign(&self.suite, &self.long, &buff)?;

            // if there is a resharing in progress, nodes that stay must send their
            // deals to the old nodes, otherwise old nodes won't get responses from
            // staying nodes and won't be certified.
            if i == self.nidx && self.new_present && !self.is_resharing {
                if self.processed {
                    continue;
                }
                self.processed = true;
                let resp = self.process_deal(&distd);
                match resp {
                    Ok(r) => {
                        if r.response.status != vss::STATUS_APPROVAL {
                            return Err(DKGError::OwnDealComplaint);
                        }
                    }
                    Err(e) => return Err(DKGError::CannotProcessOwnDeal(e.to_string())),
                };
                continue;
            }
            dd.insert(i, distd);
        }
        Ok(dd)
    }

    /// [`process_deal()`] takes a [`Deal`] created by [`deals()`] and stores and verifies it. It
    /// returns a [`Response`] to broadcast to every other participant, including the old
    /// participants. It returns an error in case the deal has already been stored,
    /// or if the deal is incorrect (see [`pedersen::vss::Verifier.process_encrypted_deal()`]).
    pub fn process_deal(&mut self, dd: &Deal<SUITE::POINT>) -> Result<Response, DKGError> {
        if !self.new_present {
            return Err(DKGError::DistDealFromUnlistedDealer);
        }
        let pubb;
        let ok;
        if self.is_resharing {
            (pubb, ok) = get_pub(&self.c.old_nodes, dd.index as usize);
        } else {
            (pubb, ok) = get_pub(&self.c.new_nodes, dd.index as usize);
        }
        // public key of the dealer
        if !ok {
            return Err(DKGError::DistDealIndexOutOfBounds);
        }

        // verify signature
        let buff = dd.marshal_binary()?;
        schnorr::verify(self.suite, &pubb, &buff, &dd.signature)?;

        let resp;
        {
            let ver = self.verifiers.get_mut(&dd.index).unwrap();
            resp = ver.process_encrypted_deal(&dd.deal)?;
        }

        if self.is_resharing && self.can_receive {
            // verify share integrity wrt to the dist. secret
            let deal_commits;
            {
                let ver = self.verifiers.get_mut(&dd.index).unwrap();
                deal_commits = ver.commits();
            }
            let mut reject = || {
                let mut resp = resp.clone();
                let (idx, present) = find_pub(&self.c.new_nodes, &pubb.clone());
                if present {
                    // the dealer is present in both list, so we set its own response
                    // (as a verifier) to a complaint since he won't do it himself
                    self.verifiers
                        .get_mut(&dd.index)
                        .unwrap()
                        .unsafe_set_response_dkg(idx as u32, vss::STATUS_COMPLAINT);
                }
                // indicate to VSS that this dkg's new status is complaint for this
                // deal
                self.verifiers
                    .get_mut(&dd.index)
                    .unwrap()
                    .unsafe_set_response_dkg(self.nidx as u32, vss::STATUS_COMPLAINT);
                resp.status = vss::STATUS_COMPLAINT;
                let msg = resp.hash(&self.suite)?;
                resp.signature = schnorr::sign(&self.suite, &self.long, &msg)?;
                Ok(Response {
                    index: dd.index,
                    response: resp,
                })
            };
            // Check that the received committed share is equal to the one we
            // generate from the known public polynomial
            let expected_pub_share = self.dpub.eval(dd.index as usize);
            if !expected_pub_share.v.eq(&deal_commits.unwrap()[0]) {
                return reject();
            }
        }

        // If the dealer in the old list is also present in the new list, then set
        // his response to approval since he won't issue his own response for his
        // own deal.
        // In the case of resharing the dealer will issue his own response in order
        // for the old comities to get responses and be certified, which is why we
        // don't add it manually there.
        let (new_idx, found) = find_pub(&self.c.new_nodes, &pubb);
        if found && !self.is_resharing {
            self.verifiers
                .get_mut(&dd.index)
                .unwrap()
                .unsafe_set_response_dkg(new_idx as u32, vss::STATUS_APPROVAL);
        }

        Ok(Response {
            index: dd.index,
            response: resp,
        })
    }

    /// [`process_response()`] takes a [`Response`] from every other peer.  If the response
    /// designates the [`Deal`] of another participant than this dkg, this dkg stores it
    /// and returns nil with a possible error regarding the validity of the response.
    /// If the response designates a deal this dkg has issued, then the dkg will process
    /// the response, and returns a [`Justification`].
    pub fn process_response(
        &mut self,
        resp: &Response,
    ) -> Result<Option<Justification<SUITE>>, DKGError> {
        if self.is_resharing && self.can_issue && !self.new_present {
            return self.process_resharing_response(resp);
        }

        if !self.verifiers.contains_key(&resp.index) {
            return Err(DKGError::ResponseFromUnknownDealer);
        }
        let v = match self.verifiers.get_mut(&resp.index) {
            Some(v) => v,
            None => return Err(DKGError::MissingVerifier),
        };
        v.process_response(&resp.response)?;

        let my_idx = self.oidx as u32;
        if !self.can_issue || resp.index != my_idx {
            // no justification if we dont issue deals or the deal's not from us
            return Ok(None);
        }

        let j = self.dealer.process_response(&resp.response)?;
        if j.is_none() {
            return Ok(None);
        }
        let just = j.unwrap();
        v.process_justification(&just)?;

        Ok(Some(Justification {
            index: self.oidx as u32,
            justification: just,
        }))
    }

    /// special case when an node that is present in the old list but not in the
    /// new,i.e. leaving the group. This node does not have any verifiers since it
    /// can't receive shares. This function makes some check on the response and
    /// returns a justification if the response is invalid.
    fn process_resharing_response(
        &mut self,
        resp: &Response,
    ) -> Result<Option<Justification<SUITE>>, DKGError> {
        let agg = match self.old_aggregators.contains_key(&resp.index) {
            true => self.old_aggregators.get_mut(&resp.index).unwrap(),
            false => {
                let mut agg = vss::Aggregator::<SUITE>::default();
                agg.verifiers = self.c.new_nodes.clone();
                agg.suite = self.suite;
                self.old_aggregators.insert(resp.index, agg);
                self.old_aggregators.get_mut(&resp.index).unwrap()
            }
        };

        agg.process_response(resp.response.clone())?;
        if resp.index as usize != self.oidx {
            return Ok(None);
        }

        if resp.response.status == vss::STATUS_APPROVAL {
            return Ok(None);
        }

        let s_id = self.dealer.session_id();
        // status is complaint and it is about our deal
        let deal = self.dealer.plaintext_deal(resp.response.index as usize)?; // dkg: resharing response can't get deal. BUG - REPORT"

        let j = Justification {
            index: self.oidx as u32,
            justification: vss::Justification {
                session_id: s_id,
                index: resp.response.index, // good index because of signature check
                deal: deal.clone(),
                signature: Vec::new(),
            },
        };
        Ok(Some(j))
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
    /// all verifiers have either responded, or have a Status Complaint [`Response`].
    pub fn set_timeout(&mut self) {
        self.timeout = true;
        for (_, v) in self.verifiers.iter_mut() {
            v.set_timeout()
        }
    }

    /// [`threshold_certified()`] returns true if a `THRESHOLD` of [`deals`](Deal) are certified. To know the
    /// list of correct receiver, one can call [`d.qual()`]
    /// NOTE:
    /// This method should only be used after a certain timeout - mimicking the
    /// synchronous assumption of the Pedersen's protocol. One can call
    /// [`certified()`] to check if the DKG is finished and stops it pre-emptively
    /// if all deals are correct.  If called *before* the timeout, there may be
    /// inconsistencies in the shares produced. For example, node 1 could have
    /// aggregated shares from 1, 2, 3 and node 2 could have aggregated shares from
    /// 2, 3 and 4.
    pub fn threshold_certified(&self) -> bool {
        if self.is_resharing {
            // in resharing case, we have two threshold. Here we want the number of
            // deals to be at least what the old threshold was. (and for each deal,
            // we want the number of approval to be a least what the new threshold
            // is).
            return self.qual().len() >= self.c.old_threshold;
        }
        // in dkg case, the threshold is symmetric -> # verifiers = # dealers
        self.qual().len() >= self.c.threshold
    }

    /// [`certified()`] returns `true` if *all* deals are certified. This method should
    /// be called before the timeout occurs, as to pre-emptively stop the DKG
    /// protocol if it is already finished before the timeout.
    pub fn certified(&self) -> bool {
        let mut good = Vec::new();
        if self.is_resharing && self.can_issue && !self.new_present {
            self.old_qual_iter(|i, v| {
                if !v.missing_responses().is_empty() {
                    return false;
                }
                good.push(i as usize);
                true
            });
        }
        self.qual_iter(|i, v| {
            if !v.missing_responses().is_empty() {
                return false;
            }
            good.push(i as usize);
            true
        });

        good.len() >= self.c.old_nodes.len()
    }

    /// [`qualified_shares()`] returns the set of shares holder index that are considered
    /// valid. In particular, it computes the list of common share holders that
    /// replied with an `approval` (or with a complaint later on justified) for each
    /// deal received. These indexes represent the new share holders with valid (or
    /// justified) shares from certified deals.  Detailed explanation:
    /// To compute this list, we consider the scenario where a share holder replied
    /// to one share but not the other, as invalid, as the library is not currently
    /// equipped to deal with that scenario.
    /// 1.  If there is a valid complaint non-justified for a [`Deal`], the deal is deemed
    /// invalid
    /// 2. if there are no [`Response`] from a share holder, the share holder is
    /// removed from the list.
    pub fn qualified_shares(&self) -> Vec<usize> {
        let mut invalid_sh = HashMap::new();
        let mut invalid_deals = HashMap::new();
        // compute list of invalid deals according to 1.
        for (dealer_index, verifier) in self.verifiers.iter() {
            let responses = verifier.responses();
            if responses.is_empty() {
                // don't analyzes "empty" deals - i.e. dealers that never sent
                // their deal in the first place.
                invalid_deals.insert(dealer_index, true);
            }
            for (holder_index, _) in self.c.new_nodes.iter().enumerate() {
                match responses.contains_key(&(holder_index as u32)) {
                    true => {
                        let resp = responses.get(&(holder_index as u32)).unwrap();
                        if resp.status == vss::STATUS_COMPLAINT {
                            // 1. rule
                            invalid_deals.insert(dealer_index, true);
                            break;
                        }
                    }
                    false => (),
                }
            }
        }

        // compute list of invalid share holders for valid deals
        for (dealer_index, verifier) in self.verifiers.iter() {
            // skip analyze of invalid deals
            if invalid_deals.contains_key(&dealer_index) {
                continue;
            }
            let responses = verifier.responses();
            for (holder_index, _) in self.c.new_nodes.iter().enumerate() {
                if !responses.contains_key(&(holder_index as u32)) {
                    // 2. rule - absent response
                    invalid_sh.insert(holder_index, true);
                }
            }
        }

        let mut valid_holders = Vec::new();
        for (i, _) in self.c.new_nodes.iter().enumerate() {
            if invalid_sh.contains_key(&i) {
                continue;
            }
            valid_holders.push(i);
        }
        valid_holders
    }

    /// [`expected_deals()`] returns the number of [`deals`](Deal) that this node will
    /// receive from the other participants.
    pub fn expected_deals(&self) -> usize {
        match self.new_present {
            true => match self.old_present {
                true => self.c.old_nodes.len() - 1,
                false => self.c.old_nodes.len(),
            },
            false => 0,
        }
    }

    /// [`qual()`] returns the index in the list of participants that forms the `QUALIFIED`
    /// set, i.e. the list of Certified [`deals`](Deal).
    /// It does NOT take into account any malicious share holder which share may have
    /// been revealed, due to invalid complaint.
    pub fn qual(&self) -> Vec<usize> {
        let mut good = Vec::new();
        if self.is_resharing && self.can_issue && !self.new_present {
            self.old_qual_iter(|i, _| {
                good.push(i as usize);
                true
            });
            return good;
        }
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

    fn old_qual_iter<F>(&self, mut f: F)
    where
        F: FnMut(u32, &vss::Aggregator<SUITE>) -> bool,
    {
        for (i, v) in self.old_aggregators.iter() {
            if v.deal_certified() && !f(*i, v) {
                break;
            }
        }
    }

    /// [`dist_key_share()`] generates the distributed key relative to this receiver.
    /// It throws an [`Error`](DKGError) if something is wrong such as not enough [`deals`](Deal) received.
    /// The shared secret can be computed when all deals have been sent and
    /// basically consists of a public point and a share. The public point is the sum
    /// of all aggregated individual public commits of each individual secrets.
    /// The share is evaluated from the global Private Polynomial, basically SUM of
    /// `fj(i)` for a receiver `i`.
    pub fn dist_key_share(&self) -> Result<DistKeyShare<SUITE>, DKGError> {
        if !self.threshold_certified() {
            return Err(DKGError::DistributedKeyNotCertified);
        }
        if !self.can_receive {
            return Err(DKGError::ShouldReceive);
        }

        if self.is_resharing {
            return self.resharing_key();
        }

        self.dkg_key()
    }

    fn dkg_key(&self) -> Result<DistKeyShare<SUITE>, DKGError> {
        let mut sh = self.suite.scalar().zero();
        let mut pubb: Option<share::poly::PubPoly<SUITE>> = None;
        // TODO: fix this weird error management
        let mut error: Option<DKGError> = None;
        self.qual_iter(|_i, v| {
            // share of dist. secret = sum of all share received.
            let (s, deal) = match v.deal() {
                Some(deal) => (deal.clone().sec_share.v, deal),
                None => {
                    error = Some(DKGError::DealsNotFound);
                    return false;
                }
            };
            let sh_clone = sh.clone();
            sh = sh_clone + s;
            // Dist. public key = sum of all revealed commitments
            let poly = share::poly::PubPoly::new(
                &self.suite,
                Some(self.suite.point().base()),
                &deal.commitments,
            );
            match &pubb {
                Some(pubb_val) => match pubb_val.add(&poly) {
                    Ok(res) => pubb = Some(res),
                    Err(e) => error = Some(DKGError::PolyError(e)),
                },
                None => {
                    // first polynomial we see (instead of generating n empty commits)
                    pubb = Some(poly);
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
            share: share::poly::PriShare {
                i: self.nidx,
                v: sh,
            },
            private_poly: self.dealer.private_poly().coefficients(),
        })
    }

    fn resharing_key(&self) -> Result<DistKeyShare<SUITE>, DKGError> {
        let cap = self.verifiers.len();
        // only old nodes sends shares
        let mut shares = Vec::with_capacity(cap);
        for _ in 0..cap {
            shares.push(None);
        }
        let mut coeffs = Vec::with_capacity(cap);
        for _ in 0..cap {
            coeffs.push(None);
        }
        let mut error = None;
        self.qual_iter(|i, v| {
            let mut deal = match v.deal() {
                Some(deal) => deal,
                None => {
                    error = Some(DKGError::DealsNotFound);
                    return false;
                }
            };
            coeffs[i as usize] = Some(deal.commitments);
            // share of dist. secret. Invertion of rows/column
            deal.sec_share.i = i as usize;
            shares[i as usize] = Some(deal.sec_share);
            true
        });

        // the private polynomial is generated from the old nodes, thus inheriting
        // the old threshold condition
        let pri_poly = share::poly::recover_pri_poly(
            &self.suite,
            &shares,
            self.old_t,
            self.c.old_nodes.len(),
        )?;
        let private_share = share::poly::PriShare {
            i: self.nidx,
            v: pri_poly.secret(),
        };

        // recover public polynomial by interpolating coefficient-wise all
        // polynomials
        // the new public polynomial must however have "new_t" coefficients since it
        // will be held by the new nodes.
        let mut final_coeffs = Vec::with_capacity(self.new_t);
        for i in 0..self.new_t {
            let mut tmp_coeffs = Vec::with_capacity(coeffs.len());
            // take all i-th coefficients
            for (j, _) in coeffs.iter().enumerate() {
                if coeffs[j].is_none() {
                    tmp_coeffs.push(None);
                    continue;
                }
                tmp_coeffs.push(Some(share::poly::PubShare {
                    i: j,
                    v: coeffs[j].clone().unwrap()[i].clone(),
                }));
            }

            // using the old threshold / length because there are at most
            // len(d.c.old_nodes) i-th coefficients since they are the one generating one
            // each, thus using the old threshold.
            let coeff = share::poly::recover_commit(
                self.suite,
                &tmp_coeffs,
                self.old_t,
                self.c.old_nodes.len(),
            )?;
            final_coeffs.push(coeff);
        }

        // Reconstruct the final public polynomial
        let pub_poly = share::poly::PubPoly::new(&self.suite, None, &final_coeffs);

        if !pub_poly.check(&private_share) {
            return Err(DKGError::ShareDoesNotMatchPublicPoly);
        }
        Ok(DistKeyShare {
            commits: final_coeffs,
            share: private_share,
            private_poly: pri_poly.coefficients(),
        })
    }

    // [`verifiers()`] returns the verifiers keeping state of each deals
    pub fn verifiers(&self) -> &HashMap<u32, vss::Verifier<SUITE>> {
        &self.verifiers
    }

    fn init_verifiers(&mut self, c: Config<SUITE, READ>) -> Result<(), DKGError> {
        let mut already_taken = HashMap::new();
        let verifier_list = c.new_nodes;
        let dealer_list = c.old_nodes;
        let mut verifiers = HashMap::new();
        for (i, pubb) in dealer_list.iter().enumerate() {
            if already_taken.contains_key(&format! {"{pubb}"}) {
                return Err(DKGError::DuplicatePublicKeyInNewList);
            }
            already_taken.insert(format! {"{pubb}"}, true);
            let mut ver = vss::new_verifier(c.suite, &c.longterm, pubb, &verifier_list)?;
            // set that the number of approval for this deal must be at the given
            // threshold regarding the new nodes. (see config.
            ver.set_threshold(c.threshold);
            verifiers.insert(i as u32, ver);
        }
        self.verifiers = verifiers;
        Ok(())
    }
}

impl<SUITE: Suite> DistKeyShare<SUITE> {
    /// [`renew()`] adds the new distributed key share `g` (with secret `0`) to the distributed key share `d`.
    pub fn renew(
        &self,
        suite: SUITE,
        g: DistKeyShare<SUITE>,
    ) -> Result<DistKeyShare<SUITE>, DKGError> {
        // Check G(0) = 0*G.
        if !g
            .public()
            .eq(&suite.point().base().mul(&suite.scalar().zero(), None))
        {
            return Err(DKGError::WrongRenewal);
        }

        // Check whether they have the same index
        if self.share.i != g.share.i {
            return Err(DKGError::DifferentParty);
        }

        let new_share = self.share.v.clone() + g.share.v;
        let mut new_commits = Vec::with_capacity(self.commits.len());
        for i in 0..self.commits.len() {
            new_commits.push(suite.point().add(&self.commits[i], &g.commits[i]));
        }
        Ok(DistKeyShare {
            commits: new_commits,
            share: share::poly::PriShare {
                i: self.share.i,
                v: new_share,
            },
            private_poly: Vec::new(),
        })
    }
}

fn get_pub<POINT: Point>(list: &[POINT], i: usize) -> (POINT, bool) {
    if i >= list.len() {
        return (Default::default(), false);
    }
    (list[i].clone(), true)
}

fn find_pub<POINT: Point>(list: &[POINT], to_find: &POINT) -> (usize, bool) {
    for (i, p) in list.iter().enumerate() {
        if p.eq(to_find) {
            return (i, true);
        }
    }
    (0, false)
}

pub fn checks_deal_certified<SUITE: Suite>(_i: u32, v: vss::Verifier<SUITE>) -> bool
where
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
{
    v.deal_certified()
}
