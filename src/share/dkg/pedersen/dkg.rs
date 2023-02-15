use std::{collections::HashMap, io::Read};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::{
    encoding::BinaryMarshaler,
    group::{PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical},
    share::{
        self,
        vss::{self, suite::Suite},
    },
    sign::schnorr,
    util::random::Randstream,
    Point, Scalar,
};

use super::structs::{Deal, DistKeyShare, Justification, Response};

use anyhow::{bail, Result};

/// Package dkg implements a general distributed key generation (DKG) framework.
/// This package serves two functionalities: (1) to run a fresh new DKG from
/// scratch and (2) to reshare old shares to a potentially distinct new set of
/// nodes (the "resharing" protocol). The former protocol is described in "A
/// threshold cryptosystem without a trusted party" by Torben Pryds Pedersen.
/// https://dl.acm.org/citation.cfm?id=1754929. The latter protocol is
/// implemented in "Verifiable Secret Redistribution for Threshold Signing
/// Schemes", by T. Wong et
/// al.(https://www.cs.cmu.edu/~wing/publications/Wong-Wing02b.pdf)
/// For an example how to use it please have a look at examples/dkg_test.go

/// Config holds all required information to run a fresh DKG protocol or a
/// resharing protocol. In the case of a new fresh DKG protocol, one must fill
/// the following fields: Suite, Longterm, NewNodes, Threshold (opt). In the case
/// of a resharing protocol, one must fill the following: Suite, Longterm,
/// OldNodes, NewNodes. If the node using this config is creating new shares
/// (i.e. it belongs to the current group), the Share field must be filled in
/// with the current share of the node. If the node using this config is a new
/// addition and thus has no current share, the PublicCoeffs field be must be
/// filled in.
#[derive(Clone)]
pub struct Config<SUITE: Suite, READ: Read + Clone> {
    pub suite: SUITE,

    /// Longterm is the longterm secret key.
    pub longterm: <SUITE::POINT as Point>::SCALAR,

    /// Current group of share holders. It will be nil for new DKG. These nodes
    /// will have invalid shares after the protocol has been run. To be able to issue
    /// new shares to a new group, the group member's public key must be inside this
    /// list and in the Share field. Keys can be disjoint or not with respect to the
    /// NewNodes list.
    pub old_nodes: Vec<SUITE::POINT>,

    /// PublicCoeffs are the coefficients of the distributed polynomial needed
    /// during the resharing protocol. The first coefficient is the key. It is
    /// required for new share holders.  It should be nil for a new DKG.
    pub public_coeffs: Option<Vec<SUITE::POINT>>,

    /// Expected new group of share holders. These public-key designated nodes
    /// will be in possession of new shares after the protocol has been run. To be a
    /// receiver of a new share, one's public key must be inside this list. Keys
    /// can be disjoint or not with respect to the OldNodes list.
    pub new_nodes: Vec<SUITE::POINT>,

    /// Share to refresh. It must be nil for a new node wishing to
    /// join or create a group. To be able to issue new fresh shares to a new group,
    /// one's share must be specified here, along with the public key inside the
    /// OldNodes field.
    pub share: Option<DistKeyShare<SUITE>>,

    /// The threshold to use in order to reconstruct the secret with the produced
    /// shares. This threshold is with respect to the number of nodes in the
    /// NewNodes list. If unspecified, default is set to
    /// `vss.MinimumT(len(NewNodes))`. This threshold indicates the degree of the
    /// polynomials used to create the shares, and the minimum number of
    /// verification required for each deal.
    pub threshold: usize,

    /// OldThreshold holds the threshold value that was used in the previous
    /// configuration. This field MUST be specified when doing resharing, but is
    /// not needed when doing a fresh DKG. This value is required to gather a
    /// correct number of valid deals before creating the distributed key share.
    /// NOTE: this field is always required (instead of taking the default when
    /// absent) when doing a resharing to avoid a downgrade attack, where a resharing
    /// the number of deals required is less than what it is supposed to be.
    pub old_threshold: usize,

    /// Reader is an optional field that can hold a user-specified entropy source.
    /// If it is set, Reader's data will be combined with random data from crypto/rand
    /// to create a random stream which will pick the dkg's secret coefficient. Otherwise,
    /// the random stream will only use crypto/rand's entropy.
    pub reader: Option<READ>,

    /// When UserReaderOnly it set to true, only the user-specified entropy source
    /// Reader will be used. This should only be used in tests, allowing reproducibility.
    pub user_reader_only: bool,
}

impl<SUITE: Suite, READ: Read + Clone> Default for Config<SUITE, READ> {
    fn default() -> Self {
        Self {
            suite: Default::default(),
            longterm: Default::default(),
            old_nodes: Default::default(),
            public_coeffs: Default::default(),
            new_nodes: Default::default(),
            share: Default::default(),
            threshold: Default::default(),
            old_threshold: Default::default(),
            reader: Default::default(),
            user_reader_only: Default::default(),
        }
    }
}

/// DistKeyGenerator is the struct that runs the DKG protocol.
#[derive(Clone)]
pub struct DistKeyGenerator<SUITE: Suite, READ: Read + Clone> {
    /// config driving the behavior of DistKeyGenerator
    pub c: Config<SUITE, READ>,
    suite: SUITE,

    pub long: <SUITE::POINT as Point>::SCALAR,
    pub pubb: SUITE::POINT,
    dpub: share::poly::PubPoly<SUITE>,
    pub dealer: vss::pedersen::vss::Dealer<SUITE>,
    /// verifiers indexed by dealer index
    pub verifiers: HashMap<u32, vss::pedersen::vss::Verifier<SUITE>>,
    /// performs the part of the response verification for old nodes
    old_aggregators: HashMap<u32, vss::pedersen::vss::Aggregator<SUITE>>,
    /// index in the old list of nodes
    pub oidx: usize,
    /// index in the new list of nodes
    pub nidx: usize,
    /// old threshold used in the previous DKG
    old_t: usize,
    /// new threshold to use in this round
    new_t: usize,
    /// indicates whether we are in the re-sharing protocol or basic DKG
    pub is_resharing: bool,
    /// indicates whether we are able to issue shares or not
    pub can_issue: bool,
    /// Indicates whether we are able to receive a new share or not
    pub can_receive: bool,
    /// indicates whether the node holding the pub key is present in the new list
    pub new_present: bool,
    /// indicates whether the node is present in the old list
    pub old_present: bool,
    /// already processed our own deal
    processed: bool,
    /// did the timeout / period / already occured or not
    timeout: bool,
}

impl<SUITE: Suite, READ: Read + Clone> Default for DistKeyGenerator<SUITE, READ> {
    fn default() -> Self {
        Self {
            c: Default::default(),
            suite: Default::default(),
            long: Default::default(),
            pubb: Default::default(),
            dpub: Default::default(),
            dealer: Default::default(),
            verifiers: Default::default(),
            old_aggregators: Default::default(),
            oidx: Default::default(),
            nidx: Default::default(),
            old_t: Default::default(),
            new_t: Default::default(),
            is_resharing: Default::default(),
            can_issue: Default::default(),
            can_receive: Default::default(),
            new_present: Default::default(),
            old_present: Default::default(),
            processed: Default::default(),
            timeout: Default::default(),
        }
    }
}

/// NewDistKeyHandler takes a Config and returns a DistKeyGenerator that is able
/// to drive the DKG or resharing protocol.
pub fn new_dist_key_handler<SUITE: Suite, READ: Read + Clone + 'static>(
    mut c: Config<SUITE, READ>,
) -> Result<DistKeyGenerator<SUITE, READ>>
where
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
{
    if c.new_nodes.is_empty() && c.old_nodes.is_empty() {
        bail!("dkg: can't run with empty node list")
    }

    let mut is_resharing = false;
    if c.share.is_some() || c.public_coeffs.is_some() {
        is_resharing = true;
    }
    if is_resharing {
        if c.old_nodes.is_empty() {
            bail!("dkg: resharing config needs old nodes list");
        }
        if c.old_threshold == 0 {
            bail!("dkg: resharing case needs old threshold field");
        }
    }
    // canReceive is true by default since in the default DKG mode everyone
    // participates
    let mut can_receive = true;
    let pubb = c.suite.point().mul(&c.longterm, None);
    let (mut oidx, mut old_present) = find_pub(&c.old_nodes, &pubb);
    let (nidx, new_present) = find_pub(&c.new_nodes, &pubb);
    if !old_present && !new_present {
        bail!("dkg: public key not found in old list or new list");
    }

    let new_threshold = if c.threshold != 0 {
        c.threshold
    } else {
        vss::pedersen::vss::minimum_t(c.new_nodes.len())
    };

    let mut dealer = vss::pedersen::vss::Dealer::default();
    let mut can_issue = false;
    if c.share.is_some() {
        // resharing case
        let secret_coeff = c.share.clone().unwrap().share.v;
        dealer = vss::pedersen::vss::new_dealer(
            c.suite,
            c.longterm.clone(),
            secret_coeff,
            &c.new_nodes,
            new_threshold,
        )?;
        can_issue = true;
    } else if !is_resharing && new_present {
        // fresh DKG case
        let mut random_stream = Randstream::default();
        //if the user provided a reader, use it alone or combined with crypto/rand
        if c.reader.is_some() && !c.user_reader_only {
            let mut r_vec = Vec::new();
            let r = Box::new(c.reader.clone().unwrap()) as Box<dyn Read>;
            r_vec.push(r);
            let rng_core = Box::new(StdRng::from_entropy()) as Box<dyn RngCore>;
            r_vec.push(Box::new(rng_core) as Box<dyn Read>);
            random_stream = Randstream::new(r_vec); //, rand.Reader
        } else if c.reader.is_some() && c.user_reader_only {
            let mut r_vec = Vec::new();
            let r = Box::new(c.reader.clone().unwrap()) as Box<dyn Read>;
            r_vec.push(r);
            random_stream = Randstream::new(r_vec);
        }
        let secret_coeff = c.suite.scalar().pick(&mut random_stream);
        dealer = vss::pedersen::vss::new_dealer(
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
            bail!("dkg: can't receive new shares without the public polynomial")
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
        // oldThreshold is only useful in the context of a new share holder, to
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
    // return dkg, err
}

/// NewDistKeyGenerator returns a dist key generator ready to create a fresh
/// distributed key with the regular DKG protocol.
pub fn new_dist_key_generator<SUITE: Suite, READ: Read + Clone + 'static>(
    suite: SUITE,
    longterm: <SUITE::POINT as Point>::SCALAR,
    participants: &[SUITE::POINT],
    t: usize,
) -> Result<DistKeyGenerator<SUITE, READ>>
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
    /// Deals returns all the deals that must be broadcasted to all participants in
    /// the new list. The deal corresponding to this DKG is already added to this DKG
    /// and is ommitted from the returned map. To know which participant a deal
    /// belongs to, loop over the keys as indices in the list of new participants:
    ///
    /// for i,dd := range distDeals {
    ///    sendTo(participants[i],dd)
    /// }
    ///
    /// If this method cannot process its own Deal, that indicates a
    /// severe problem with the configuration or implementation and
    /// results in a panic.
    pub fn deals(&mut self) -> Result<HashMap<usize, Deal<SUITE::POINT>>> {
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
                if resp.is_err() {
                    panic!("dkg: cannot process own deal: ")
                } else if resp.unwrap().response.status != vss::pedersen::vss::STATUS_APPROVAL {
                    panic!("dkg: own deal gave a complaint")
                }
                continue;
            }
            dd.insert(i, distd);
        }
        Ok(dd)
    }

    /// ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
    /// returns a Response to broadcast to every other participant, including the old
    /// participants. It returns an error in case the deal has already been stored,
    /// or if the deal is incorrect (see vss.Verifier.ProcessEncryptedDeal).
    pub fn process_deal(&mut self, dd: &Deal<SUITE::POINT>) -> Result<Response> {
        if !self.new_present {
            bail!("dkg: unexpected deal for unlisted dealer in new list")
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
            bail!("dkg: dist deal out of bounds index")
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
                        .unsafe_set_response_dkg(idx as u32, vss::pedersen::vss::STATUS_COMPLAINT);
                }
                // indicate to VSS that this dkg's new status is complaint for this
                // deal
                self.verifiers
                    .get_mut(&dd.index)
                    .unwrap()
                    .unsafe_set_response_dkg(
                        self.nidx as u32,
                        vss::pedersen::vss::STATUS_COMPLAINT,
                    );
                resp.status = vss::pedersen::vss::STATUS_COMPLAINT;
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
            if !expected_pub_share.v.equal(&deal_commits.unwrap()[0]) {
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
                .unsafe_set_response_dkg(new_idx as u32, vss::pedersen::vss::STATUS_APPROVAL);
        }

        Ok(Response {
            index: dd.index,
            response: resp,
        })
    }

    /// ProcessResponse takes a response from every other peer.  If the response
    /// designates the deal of another participant than this dkg, this dkg stores it
    /// and returns nil with a possible error regarding the validity of the response.
    /// If the response designates a deal this dkg has issued, then the dkg will process
    /// the response, and returns a justification.
    pub fn process_response(&mut self, resp: &Response) -> Result<Option<Justification<SUITE>>> {
        if self.is_resharing && self.can_issue && !self.new_present {
            return self.process_resharing_response(resp);
        }

        if !self.verifiers.contains_key(&resp.index) {
            bail!("dkg: responses received for unknown dealer {}", resp.index)
        }
        let v = self.verifiers.get_mut(&resp.index).unwrap();
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
    ) -> Result<Option<Justification<SUITE>>> {
        let agg = match self.old_aggregators.contains_key(&resp.index) {
            true => self.old_aggregators.get_mut(&resp.index).unwrap(),
            false => {
                let mut agg = vss::pedersen::vss::Aggregator::<SUITE>::default();
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

        if resp.response.status == vss::pedersen::vss::STATUS_APPROVAL {
            return Ok(None);
        }

        let s_id = self.dealer.session_id();
        // status is complaint and it is about our deal
        let deal = self.dealer.plaintext_deal(resp.response.index as usize)?; // dkg: resharing response can't get deal. BUG - REPORT"

        let j = Justification {
            index: self.oidx as u32,
            justification: vss::pedersen::vss::Justification {
                session_id: s_id,
                index: resp.response.index, // good index because of signature check
                deal: deal.clone(),
                signature: Vec::new(),
            },
        };
        Ok(Some(j))
    }

    /// ProcessJustification takes a justification and validates it. It returns an
    /// error in case the justification is wrong.
    pub fn process_justification(&mut self, j: &Justification<SUITE>) -> Result<()> {
        if !self.verifiers.contains_key(&j.index) {
            bail!("dkg: Justification received but no deal for it")
        }
        let v = self.verifiers.get_mut(&j.index).unwrap();
        // TODO fix error management
        v.process_justification(&j.justification).map_err(|e| anyhow::Error::msg(""))
    }

    /// SetTimeout triggers the timeout on all verifiers, and thus makes sure
    /// all verifiers have either responded, or have a StatusComplaint response.
    pub fn set_timeout(&mut self) {
        self.timeout = true;
        for (_, v) in self.verifiers.iter_mut() {
            v.set_timeout()
        }
    }

    /// ThresholdCertified returns true if a THRESHOLD of deals are certified. To know the
    /// list of correct receiver, one can call d.QUAL()
    /// NOTE:
    /// This method should only be used after a certain timeout - mimicking the
    /// synchronous assumption of the Pedersen's protocol. One can call
    /// `Certified()` to check if the DKG is finished and stops it pre-emptively
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

    /// Certified returns true if *all* deals are certified. This method should
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

    /// QualifiedShares returns the set of shares holder index that are considered
    /// valid. In particular, it computes the list of common share holders that
    /// replied with an approval (or with a complaint later on justified) for each
    /// deal received. These indexes represent the new share holders with valid (or
    /// justified) shares from certified deals.  Detailled explanation:
    /// To compute this list, we consider the scenario where a share holder replied
    /// to one share but not the other, as invalid, as the library is not currently
    /// equipped to deal with that scenario.
    /// 1.  If there is a valid complaint non-justified for a deal, the deal is deemed
    /// invalid
    /// 2. if there are no response from a share holder, the share holder is
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
                        if resp.status == vss::pedersen::vss::STATUS_COMPLAINT {
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

    /// ExpectedDeals returns the number of deals that this node will
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

    /// QUAL returns the index in the list of participants that forms the QUALIFIED
    /// set, i.e. the list of Certified deals.
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
        F: FnMut(u32, &vss::pedersen::vss::Verifier<SUITE>) -> bool,
    {
        for (i, v) in self.verifiers.iter() {
            if v.deal_certified() && !f(*i, v) {
                break;
            }
        }
    }

    fn old_qual_iter<F>(&self, mut f: F)
    where
        F: FnMut(u32, &vss::pedersen::vss::Aggregator<SUITE>) -> bool,
    {
        for (i, v) in self.old_aggregators.iter() {
            if v.deal_certified() && !f(*i, v) {
                break;
            }
        }
    }

    /// DistKeyShare generates the distributed key relative to this receiver.
    /// It throws an error if something is wrong such as not enough deals received.
    /// The shared secret can be computed when all deals have been sent and
    /// basically consists of a public point and a share. The public point is the sum
    /// of all aggregated individual public commits of each individual secrets.
    /// The share is evaluated from the global Private Polynomial, basically SUM of
    /// fj(i) for a receiver i.
    pub fn dist_key_share(&self) -> Result<DistKeyShare<SUITE>> {
        if !self.threshold_certified() {
            bail!("dkg: distributed key not certified")
        }
        if !self.can_receive {
            bail!("dkg: should not expect to compute any dist. share")
        }

        if self.is_resharing {
            return self.resharing_key();
        }

        self.dkg_key()
    }

    fn dkg_key(&self) -> Result<DistKeyShare<SUITE>> {
        let mut sh = self.suite.scalar().zero();
        let mut pubb: Option<share::poly::PubPoly<SUITE>> = None;
        // TODO: fix this weird error management
        let mut error: Option<anyhow::Error> = None;
        self.qual_iter(|_i, v| {
            // share of dist. secret = sum of all share received.
            let (s, deal) = match v.deal() {
                Some(deal) => (deal.clone().sec_share.v, deal),
                None => {
                    error = Some(anyhow::Error::msg("dkg: deals not found"));
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
                // TODO fix this error management
                Some(pubb_val) => match pubb_val.add(&poly).map_err(|e| anyhow::Error::msg("")) {
                    Ok(res) => pubb = Some(res),
                    Err(e) => error = Some(e),
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

    fn resharing_key(&self) -> Result<DistKeyShare<SUITE>> {
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
                    error = Some(anyhow::Error::msg("dkg: deals not found"));
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
        // the new public polynomial must however have "newT" coefficients since it
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
            // len(d.c.OldNodes) i-th coefficients since they are the one generating one
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
            bail!("dkg: share do not correspond to public polynomial ><");
        }
        Ok(DistKeyShare {
            commits: final_coeffs,
            share: private_share,
            private_poly: pri_poly.coefficients(),
        })
    }

    // Verifiers returns the verifiers keeping state of each deals
    pub fn verifiers(&self) -> &HashMap<u32, vss::pedersen::vss::Verifier<SUITE>> {
        &self.verifiers
    }

    fn init_verifiers(&mut self, c: Config<SUITE, READ>) -> Result<()> {
        let mut already_taken = HashMap::new();
        let verifier_list = c.new_nodes;
        let dealer_list = c.old_nodes;
        let mut verifiers = HashMap::new();
        for (i, pubb) in dealer_list.iter().enumerate() {
            if already_taken.contains_key(&pubb.to_string()) {
                bail!("duplicate public key in NewNodes list")
            }
            already_taken.insert(pubb.to_string(), true);
            let mut ver =
                vss::pedersen::vss::new_verifier(&c.suite, &c.longterm, pubb, &verifier_list)?;
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
    /// Renew adds the new distributed key share g (with secret 0) to the distributed key share d.
    pub fn renew(&self, suite: SUITE, g: DistKeyShare<SUITE>) -> Result<DistKeyShare<SUITE>> {
        // Check G(0) = 0*G.
        if !g
            .public()
            .equal(&suite.point().base().mul(&suite.scalar().zero(), None))
        {
            bail!("wrong renewal function")
        }

        // Check whether they have the same index
        if self.share.i != g.share.i {
            bail!("not the same party")
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
        if p.equal(to_find) {
            return (i, true);
        }
    }
    (0, false)
}

pub fn checks_deal_certified<SUITE: Suite>(_i: u32, v: vss::pedersen::vss::Verifier<SUITE>) -> bool
where
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
{
    v.deal_certified()
}
