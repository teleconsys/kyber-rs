// Note: if you are looking for a complete scenario that shows DKG in action
// please have a look at examples/dkg_test.go

use std::{collections::HashMap, io::Read};

use crate::{
    group::{
        edwards25519::SuiteEd25519,
        edwards25519::{Point as EdPoint, Scalar as EdScalar},
        PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical,
    },
    share::{
        self,
        dkg::DKGError,
        vss::{self, suite::Suite},
    },
    Group, Point, Random, Scalar,
};
use lazy_static::lazy_static;
use rand::Rng;

use super::{
    dkg::{new_dist_key_generator, new_dist_key_handler, Config, DistKeyGenerator},
    structs::DistKeyShare,
};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake3_sha256_ed25519()
}

const DEFAULT_N: usize = 5;

lazy_static! {
    static ref DEFAULT_T: usize = vss::pedersen::vss::minimum_t(DEFAULT_N);
}

struct TestData<SUITE: Suite> {
    part_pubs: Vec<SUITE::POINT>,
    part_sec: Vec<<SUITE::POINT as Point>::SCALAR>,
    dkgs: Vec<DistKeyGenerator<SUITE, &'static [u8]>>,
}

fn generate(n: usize, t: usize) -> TestData<SuiteEd25519> {
    let mut part_pubs = Vec::with_capacity(n);
    let mut part_sec = Vec::with_capacity(n);
    for _ in 0..n {
        let (sec, pubb) = gen_pair();
        part_pubs.push(pubb);
        part_sec.push(sec);
    }
    let mut dkgs = Vec::with_capacity(n);
    (0..n).for_each(|i| {
        let dkg = new_dist_key_generator(suite(), part_sec[i].clone(), &part_pubs, t).unwrap();
        dkgs.push(dkg);
    });
    TestData {
        part_pubs,
        part_sec,
        dkgs,
    }
}

#[test]
fn test_dkg_new_dist_key_generator() {
    let test_data = generate(DEFAULT_N, *DEFAULT_T);
    let part_pubs = test_data.part_pubs;
    let part_sec = test_data.part_sec;

    let long = part_sec[0].clone();
    let dkg: DistKeyGenerator<SuiteEd25519, &'static [u8]> =
        new_dist_key_generator(suite(), long, &part_pubs, *DEFAULT_T).unwrap();
    assert!(dkg.can_issue);
    assert!(dkg.can_receive);
    assert!(dkg.new_present);
    // because we set old = new
    assert!(dkg.old_present);
    assert!(!dkg.is_resharing);

    let (sec, _) = gen_pair();
    // TODO: fix this check to get the specific error
    let dkg_res = new_dist_key_generator::<SuiteEd25519, &'static [u8]>(
        suite(),
        sec.clone(),
        &part_pubs,
        *DEFAULT_T,
    );
    assert!(dkg_res.is_err());

    let dkg_res =
        new_dist_key_generator::<SuiteEd25519, &'static [u8]>(suite(), sec, &[], *DEFAULT_T);
    if let Err(DKGError::EmptyNodeList) = dkg_res {
    } else {
        panic!("node list should be empty")
    }
}

#[test]
fn test_dkg_deal() {
    let mut dkgs = generate(DEFAULT_N, *DEFAULT_T).dkgs;
    let dkg = &mut dkgs[0];

    // TODO: fix this check to get the specific error
    let dks_res = dkg.dist_key_share();
    assert!(dks_res.is_err());

    let deals = dkg.deals().unwrap();
    assert_eq!(deals.len(), DEFAULT_N - 1);

    for i in 1..DEFAULT_N {
        assert!(deals.contains_key(&i));
        assert_eq!(deals.get(&i).unwrap().index, 0);
    }

    assert!(dkg.verifiers.contains_key(&(dkg.nidx as u32)));
}

#[test]
fn test_dkg_process_deal() {
    let mut dkgs = generate(DEFAULT_N, *DEFAULT_T).dkgs;
    let dkg = &mut dkgs[0];
    let mut deals = dkg.deals().unwrap();

    let rec = &mut dkgs[1];
    let deal = deals.get_mut(&1).unwrap();
    assert_eq!(deal.index, 0);
    assert_eq!(1, rec.nidx);

    // verifier don't find itself
    let good_p = rec.c.new_nodes.clone();
    rec.c.new_nodes = Vec::new();
    // TODO: fix this check to get the specific error
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    rec.c.new_nodes = good_p;

    // good deal
    let resp = rec.process_deal(deal).unwrap();
    assert_eq!(resp.response.status, vss::pedersen::vss::STATUS_APPROVAL);
    assert!(rec.verifiers.contains_key(&deal.index));
    assert_eq!(0, resp.index);

    // duplicate
    // TODO: fix this check to get the specific error
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());

    // wrong index
    let good_idx = deal.index;
    deal.index = (DEFAULT_N + 1) as u32;
    // TODO: fix this check to get the specific error
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    deal.index = good_idx;

    // wrong deal
    let good_sig = deal.deal.signature.clone();
    deal.deal.signature = random_bytes(deal.deal.signature.len());
    // TODO: fix this check to get the specific error
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    deal.deal.signature = good_sig;
}

#[test]
fn test_dkg_process_response() {
    // first peer generates wrong deal
    // second peer processes it and returns a complaint
    // first peer process the complaint

    let mut dkgs = generate(DEFAULT_N, *DEFAULT_T).dkgs;
    let idx_rec = 1;

    // give a wrong deal
    let good_secret = dkgs[0]
        .dealer
        .plaintext_deal(idx_rec)
        .unwrap()
        .sec_share
        .v
        .clone();
    dkgs[0].dealer.plaintext_deal(idx_rec).unwrap().sec_share.v = suite().scalar().zero();
    let dd = dkgs[0].deals().unwrap();
    let enc_d = dd.get(&idx_rec).unwrap();
    let mut resp = dkgs[idx_rec].process_deal(enc_d).unwrap();
    assert_eq!(resp.response.status, vss::pedersen::vss::STATUS_COMPLAINT);
    dkgs[0].dealer.plaintext_deal(idx_rec).unwrap().sec_share.v = good_secret;
    _ = dkgs[0].deals().unwrap(); //dd
                                  //enc_d = dd.get(&idx_rec).unwrap();

    // no verifier tied to Response
    assert!(dkgs[0].verifiers.contains_key(&0));
    let v = dkgs[0].verifiers.remove(&0).unwrap();
    // TODO: fix this check to get the specific error
    let res = dkgs[0].process_response(&resp);
    assert!(res.is_err());
    dkgs[0].verifiers.insert(0, v);

    // invalid response
    let good_sig = resp.response.signature.clone();
    resp.response.signature = random_bytes(good_sig.len());
    // TODO: fix this check to get the specific error
    let res = dkgs[0].process_response(&resp);
    assert!(res.is_err());
    resp.response.signature = good_sig;

    // valid complaint from our deal
    let j = dkgs[0].process_response(&resp).unwrap();
    assert!(j.is_some());

    // valid complaint from another deal from another peer
    // fake a wrong deal
    //deal20, err := dkg2.dealer.PlaintextDeal(0)
    //require.Nil(t, err)
    let good_rnd_2_1 = dkgs[2]
        .dealer
        .plaintext_deal(1)
        .unwrap()
        .sec_share
        .v
        .clone();
    dkgs[2].dealer.plaintext_deal(1).unwrap().sec_share.v = suite().scalar().zero();
    let mut deals_2 = dkgs[2].deals().unwrap();

    let mut resp_1_2 = dkgs[idx_rec]
        .process_deal(deals_2.get(&idx_rec).unwrap())
        .unwrap();
    assert_eq!(
        resp_1_2.response.status,
        vss::pedersen::vss::STATUS_COMPLAINT
    );

    dkgs[2].dealer.plaintext_deal(1).unwrap().sec_share.v = good_rnd_2_1;
    deals_2 = dkgs[2].deals().unwrap();

    // give it to the first peer
    // process dealer 2's deal
    dkgs[0].process_deal(deals_2.get(&0).unwrap()).unwrap(); //r

    // process response from peer 1
    let j = dkgs[0].process_response(&resp_1_2).unwrap();
    assert!(j.is_none());

    // Justification part:
    // give the complaint to the dealer
    let j = dkgs[2].process_response(&resp_1_2).unwrap().unwrap();

    // hack because all is local, and resp has been modified locally by dkg2's
    // dealer, the status has became "justified"
    resp_1_2.response.status = vss::pedersen::vss::STATUS_COMPLAINT;
    dkgs[0].process_justification(&j).unwrap();

    // remove verifiers
    let v = dkgs[0].verifiers.remove(&j.index).unwrap();
    // TODO: fix this check to get the specific error
    let res = dkgs[0].process_justification(&j);
    assert!(res.is_err());
    dkgs[0].verifiers.insert(j.index, v);
}

/// Test Resharing to a group with one mode node BUT only a threshold of dealers
/// are present during the resharing.
#[test]
fn test_dkg_resharing_threshold() {
    let n = 7;
    let old_t = vss::pedersen::vss::minimum_t(n);
    let test_data = generate(n, old_t);
    let publics = test_data.part_pubs;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let new_n = dkgs.len() + 1;
    let new_t = vss::pedersen::vss::minimum_t(new_n);
    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        shares.push(share.clone());
        sshares.push(Some(share.share));
    }

    let mut new_pubs = Vec::with_capacity(new_n);
    for dkg in dkgs.iter() {
        new_pubs.push(dkg.pubb.clone());
    }
    let (new_priv, new_pub) = gen_pair();
    new_pubs.push(new_pub);
    let mut new_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(new_n);
    for (i, _) in dkgs.iter().enumerate() {
        let c = Config {
            suite: suite(),
            longterm: dkgs[i].c.longterm.clone(),
            old_nodes: publics.clone(),
            new_nodes: new_pubs.clone(),
            share: Some(shares[i].clone()),
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
        };
        new_dkgs.push(new_dist_key_handler(c).unwrap());
    }
    new_dkgs.push(
        new_dist_key_handler(Config {
            suite: suite(),
            longterm: new_priv,
            old_nodes: publics,
            new_nodes: new_pubs,
            public_coeffs: Some(shares[0].commits.clone()),
            threshold: new_t,
            old_threshold: old_t,
            share: None,
            reader: None,
            user_reader_only: false,
        })
        .unwrap(),
    );

    let mut selected_dkgs = Vec::with_capacity(new_t);
    let mut selected = HashMap::new();
    // add the new node
    selected_dkgs.push(new_dkgs[dkgs.len()].clone());
    selected.insert(format!("{:x}", selected_dkgs[0].long), true);
    // select a subset of the new group
    while selected.len() < new_t + 1 {
        let idx = rand::thread_rng().gen_range(0..new_dkgs.len());
        let str = format!("{:x}", new_dkgs[idx].long);
        if selected.contains_key(&str) {
            continue;
        }
        selected.insert(str, true);
        selected_dkgs.push(new_dkgs[idx].clone());
    }

    let mut deals = Vec::with_capacity(new_n * new_n);
    for dkg in selected_dkgs.iter_mut() {
        if !dkg.old_present {
            continue;
        }
        let local_deals = dkg.deals().unwrap();
        deals.push(local_deals);
    }

    let mut resps = HashMap::new();
    for (i, local_deals) in deals.iter().enumerate() {
        resps.insert(i, Vec::new());
        for (j, d) in local_deals {
            for dkg in selected_dkgs.iter_mut() {
                if dkg.new_present && dkg.nidx == *j {
                    let resp = dkg.process_deal(d).unwrap();
                    assert_eq!(resp.response.status, vss::pedersen::vss::STATUS_APPROVAL);
                    resps.get_mut(&i).unwrap().push(resp);
                }
            }
        }
    }

    for (_, deal_responses) in resps {
        for resp in deal_responses {
            for dkg in selected_dkgs.iter_mut() {
                // Ignore messages from ourselves
                if resp.response.index == dkg.nidx as u32 {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap_or_else(|_| panic!("old dkg at (oidx {}, nidx {}) has received response from idx {} for dealer idx {}\n", dkg.oidx, dkg.nidx, resp.response.index, resp.index));
                assert!(j.is_none());
            }
        }
    }

    for dkg in selected_dkgs.iter_mut() {
        dkg.set_timeout();
    }

    let mut dkss = Vec::with_capacity(selected_dkgs.len());
    let mut new_shares = Vec::with_capacity(selected_dkgs.len());
    let mut all_qual_shares = Vec::with_capacity(selected_dkgs.len());
    for dkg in selected_dkgs.iter_mut() {
        if !dkg.new_present {
            continue;
        }
        assert!(!dkg.certified());
        assert!(dkg.threshold_certified());
        let dks = dkg.dist_key_share().unwrap();
        dkss.push(dks.clone());
        new_shares.push(Some(dks.share));
        let qual_shares = dkg.qualified_shares();
        all_qual_shares.push(qual_shares);
    }

    for (i, qual_shares) in all_qual_shares.iter().enumerate() {
        for dkg in selected_dkgs.iter() {
            if !selected_dkgs[i].new_present {
                continue;
            }
            assert!(qual_shares.contains(&dkg.nidx));
        }
    }

    // check
    // 1. shares are different between the two rounds
    // 2. shares reconstruct to the same secret
    // 3. public polynomial is different but for the first coefficient /public
    // key/

    for new_dks in dkss.iter() {
        for old_dks in shares.iter() {
            assert_ne!(new_dks.share.v, old_dks.share.v)
        }
    }
    //// 2.
    let old_secret = share::poly::recover_secret(suite(), &sshares, old_t, n).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_shares, new_t, new_n).unwrap();
    assert_eq!(old_secret, new_secret);
}

/// TestDKGThreshold tests the "threshold dkg" where only a subset of nodes succeed
/// at the DKG
#[test]
fn test_dkg_threshold() {
    let n = 7;
    // should succeed with only this number of nodes
    let new_total = vss::pedersen::vss::minimum_t(n);
    let dkgs = generate(n, new_total).dkgs;

    // only take a threshold of them
    let mut thr_dkgs = HashMap::new();
    let mut already_taken = HashMap::new();
    while thr_dkgs.len() < new_total {
        let idx = rand::thread_rng().gen_range(0..DEFAULT_N);
        if already_taken.contains_key(&idx) {
            continue;
        }
        already_taken.insert(idx, true);
        //thr_dkgs.insert(idx, dkgs[idx].clone());
        thr_dkgs.insert(idx, dkgs[idx].clone());
    }

    // full secret sharing exchange
    // 1. broadcast deals
    let mut all_deals = Vec::new();
    let mut resps = Vec::with_capacity(new_total * new_total);
    for (_, dkg) in thr_dkgs.iter_mut() {
        let deals = dkg.deals().unwrap();
        all_deals.push(deals);
    }
    for deals in all_deals {
        for (i, d) in deals {
            // give the deal anyway - simpler
            if !thr_dkgs.contains_key(&i) {
                continue;
            }
            let recipient = thr_dkgs.get_mut(&i).unwrap();
            let resp = recipient.process_deal(&d).unwrap();
            assert_eq!(vss::pedersen::vss::STATUS_APPROVAL, resp.response.status);
            resps.push(resp);
        }
    }

    // 2. Broadcast responses
    for resp in resps {
        for (_, dkg) in thr_dkgs.iter_mut() {
            if resp.response.index == dkg.nidx as u32 {
                // skip the responses this dkg sent out
                continue;
            }
            let j = dkg.process_response(&resp).unwrap();
            assert!(j.is_none());
        }
    }

    // 3. make sure nobody has a QUAL set
    for (_, dkg) in thr_dkgs.iter() {
        assert!(!dkg.certified());
        assert_eq!(0, dkg.qual().len());
        for (_, dkg2) in thr_dkgs.iter() {
            assert!(!dkg.is_in_qual(dkg2.nidx as u32));
        }
    }

    for (_, dkg) in thr_dkgs.iter_mut() {
        for (i, v) in dkg.verifiers.iter_mut() {
            let mut app = 0;
            let responses = v.responses();
            responses.iter().for_each(|(_, r)| {
                if r.status == vss::pedersen::vss::STATUS_APPROVAL {
                    app += 1;
                }
            });
            if already_taken.contains_key(&(*i as usize)) {
                assert_eq!(already_taken.len(), app);
            } else {
                assert_eq!(0, app);
            }
        }
        dkg.set_timeout()
    }

    for (_, dkg) in thr_dkgs.iter() {
        assert_eq!(new_total, dkg.qual().len());
        assert!(dkg.threshold_certified());
        assert!(!dkg.certified());
        let qual_shares = dkg.qualified_shares();
        for (_, dkg2) in thr_dkgs.iter() {
            assert!(qual_shares.contains(&dkg2.nidx));
        }
    }

    for (_, dkg) in thr_dkgs.iter_mut() {
        dkg.dist_key_share().unwrap();
    }

    for (_, dkg) in thr_dkgs.iter() {
        for (_, dkg2) in thr_dkgs.iter() {
            assert!(dkg.is_in_qual(dkg2.nidx as u32));
        }
    }
}

#[test]
fn test_dist_key_share() {
    let mut dkgs = generate(DEFAULT_N, *DEFAULT_T).dkgs;
    full_exchange(&mut dkgs, true);

    for dkg in dkgs.iter() {
        assert!(dkg.certified());
    }
    // verify integrity of shares etc
    let mut dkss = Vec::with_capacity(DEFAULT_N);
    let mut poly = None;
    for (_, dkg) in dkgs.iter_mut().enumerate() {
        let dks = dkg.dist_key_share().unwrap();
        assert!(!dks.private_poly.is_empty());
        dkss.push(dks.clone());
        assert_eq!(dkg.nidx, dks.share.i);

        let pri_poly = share::poly::coefficients_to_pri_poly(&suite(), &dks.private_poly);
        if poly.is_none() {
            poly = Some(pri_poly);
            continue;
        }
        poly = Some(poly.unwrap().add(&pri_poly).unwrap());
    }

    let mut shares = Vec::with_capacity(DEFAULT_N);
    for dks in dkss.iter() {
        assert!(
            check_dks(dks, &dkss[0]),
            "dist key share not equal {} vs {}",
            dks.share.i,
            0
        );
        shares.push(Some(dks.share.clone()));
    }

    let secret = share::poly::recover_secret(suite(), &shares, DEFAULT_N, DEFAULT_N).unwrap();

    let secret_coeffs = poly.unwrap().coefficients();
    assert_eq!(secret, secret_coeffs[0]);

    let commit_secret = suite().point().mul(&secret, None);
    assert_eq!(dkss[0].public(), commit_secret);
}

fn gen_pair() -> (EdScalar, EdPoint) {
    let suite = suite();
    let secret = suite.scalar().pick(&mut suite.random_stream());
    let public = suite.point().mul(&secret, None);
    (secret, public)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut buff = Vec::with_capacity(n);
    for _ in 0..n {
        buff.push(rng.gen());
    }
    buff
}

fn check_dks<SUITE: Suite>(dks1: &DistKeyShare<SUITE>, dks2: &DistKeyShare<SUITE>) -> bool {
    if dks1.commits.len() != dks2.commits.len() {
        return false;
    }
    for (i, p) in dks1.commits.iter().enumerate() {
        if !p.eq(&dks2.commits[i]) {
            return false;
        }
    }
    true
}

fn full_exchange<SUITE: Suite, READ: Read + Clone + 'static>(
    dkgs: &mut Vec<DistKeyGenerator<SUITE, READ>>,
    check_qual: bool,
) where
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    // full secret sharing exchange
    // 1. broadcast deals
    let n = dkgs.len();
    let mut all_deals = Vec::with_capacity(n);
    let mut resps = Vec::with_capacity(n * n);
    for dkg in dkgs.iter_mut() {
        let deals = dkg.deals().unwrap();
        all_deals.push(deals);
    }
    for deals in all_deals {
        for (i, d) in deals {
            let resp = dkgs[i].process_deal(&d).unwrap();
            assert_eq!(resp.response.status, vss::pedersen::vss::STATUS_APPROVAL);
            resps.push(resp);
        }
    }

    // 2. Broadcast responses
    for resp in resps {
        for dkg in dkgs.iter_mut() {
            // ignore all messages from ourself
            if resp.response.index == dkg.nidx as u32 {
                continue;
            }
            let j = dkg.process_response(&resp).unwrap();
            assert!(j.is_none())
        }
    }

    if check_qual {
        // 3. make sure everyone has the same QUAL set
        for dkg in dkgs.clone() {
            for dkg2 in dkgs.clone() {
                assert!(dkg.is_in_qual(dkg2.nidx as u32));
            }
        }
    }
}

/// Test resharing of a DKG to the same set of nodes
#[test]
fn test_dkg_resharing() {
    let old_t = vss::pedersen::vss::minimum_t(DEFAULT_N);
    let test_data = generate(DEFAULT_N, old_t);
    let publics = test_data.part_pubs;
    let secrets = test_data.part_sec;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        sshares.push(Some(share.share.clone()));
        shares.push(share);
    }
    // start resharing within the same group
    let mut new_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(dkgs.len());
    for (i, _) in dkgs.iter().enumerate() {
        let c = Config {
            suite: suite(),
            longterm: secrets[i].clone(),
            old_nodes: publics.clone(),
            new_nodes: publics.clone(),
            share: Some(shares[i].clone()),
            old_threshold: old_t,
            public_coeffs: None,
            threshold: 0,
            reader: None,
            user_reader_only: false,
        };
        new_dkgs.push(new_dist_key_handler(c).unwrap());
    }
    full_exchange(&mut new_dkgs, true);
    let mut new_shares = Vec::with_capacity(dkgs.len());
    let mut new_sshares = Vec::with_capacity(dkgs.len());
    for dkg in new_dkgs {
        let dks = dkg.dist_key_share().unwrap();
        new_sshares.push(Some(dks.share.clone()));
        new_shares.push(dks);
    }
    // check
    // 1. shares are different between the two rounds
    // 2. shares reconstruct to the same secret
    // 3. public polynomial is different but for the first coefficient /public
    // key/
    // 1.
    for i in 0..dkgs.len() {
        assert!(!shares[i].share.v.eq(&new_shares[i].share.v))
    }
    let thr = vss::pedersen::vss::minimum_t(DEFAULT_N);
    // 2.
    let old_secret = share::poly::recover_secret(suite(), &sshares, thr, DEFAULT_N).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_sshares, thr, DEFAULT_N).unwrap();
    assert_eq!(old_secret, new_secret);
}

/// Test resharing functionality with one node less
#[test]
fn test_dkg_resharing_remove_node() {
    let old_t = vss::pedersen::vss::minimum_t(DEFAULT_N);
    let test_data = generate(DEFAULT_N, old_t);
    let publics = test_data.part_pubs;
    let secrets = test_data.part_sec;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let new_n = publics.len() - 1;
    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        sshares.push(Some(share.share.clone()));
        shares.push(share);
    }

    // start resharing within the same group
    let mut new_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(dkgs.len());
    for (i, _) in dkgs.iter().enumerate() {
        let c = Config {
            suite: suite(),
            longterm: secrets[i].clone(),
            old_nodes: publics.clone(),
            new_nodes: publics[..new_n].to_vec(),
            share: Some(shares[i].clone()),
            old_threshold: old_t,
            public_coeffs: None,
            threshold: 0,
            reader: None,
            user_reader_only: false,
        };
        new_dkgs.push(new_dist_key_handler(c).unwrap());
    }
    full_exchange(&mut new_dkgs, false);
    let mut new_shares = Vec::with_capacity(dkgs.len());
    let mut new_sshares = Vec::with_capacity(dkgs.len() - 1);
    for dkg in new_dkgs[..new_n].iter() {
        let dks = dkg.dist_key_share().unwrap();
        new_sshares.push(Some(dks.share.clone()));
        new_shares.push(dks);
    }

    // check
    // 1. shares are different between the two rounds
    // 2. shares reconstruct to the same secret
    // 3. public polynomial is different but for the first coefficient /public
    // key/

    for i in 0..new_n {
        assert!(!shares[i].share.v.eq(&new_shares[i].share.v))
    }
    let thr = vss::pedersen::vss::minimum_t(DEFAULT_N);
    // 2.
    let old_secret = share::poly::recover_secret(suite(), &sshares[..new_n], thr, new_n).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_sshares, thr, new_n).unwrap();
    assert_eq!(old_secret, new_secret);
}

/// Test to reshare to a different set of nodes with only a threshold of the old
/// nodes present
#[test]
fn test_dkg_resharing_new_nodes_threshold() {
    let old_n = DEFAULT_N;
    let old_t = vss::pedersen::vss::minimum_t(old_n);
    let test_data = generate(old_n, old_t);
    let old_pubs = test_data.part_pubs;
    let old_privs = test_data.part_sec;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        sshares.push(Some(share.share.clone()));
        shares.push(share);
    }
    // start resharing to a different group
    let new_n = old_n + 3;
    let new_t = old_t + 2;
    let mut new_privs = Vec::with_capacity(new_n);
    let mut new_pubs = Vec::with_capacity(new_n);
    for _ in 0..new_n {
        let (new_priv, new_pub) = gen_pair();
        new_privs.push(new_priv);
        new_pubs.push(new_pub);
    }

    // creating the old dkgs and new dkgs
    let mut old_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(old_n);
    let mut new_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(new_n);
    for i in 0..old_n {
        let c = Config {
            suite: suite(),
            longterm: old_privs[i].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: Some(shares[i].clone()),
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
        };
        old_dkgs.push(new_dist_key_handler(c).unwrap());
        assert!(!old_dkgs[i].can_receive);
        assert!(old_dkgs[i].can_issue);
        assert!(old_dkgs[i].is_resharing);
        assert!(!old_dkgs[i].new_present);
        assert_eq!(old_dkgs[i].oidx, i);
    }

    for i in 0..new_n {
        let c = Config {
            suite: suite(),
            longterm: new_privs[i].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: None,
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: Some(shares[0].commits.clone()),
            reader: None,
            user_reader_only: false,
        };
        new_dkgs.push(new_dist_key_handler(c).unwrap());

        assert!(new_dkgs[i].can_receive);
        assert!(!new_dkgs[i].can_issue);
        assert!(new_dkgs[i].is_resharing);
        assert!(new_dkgs[i].new_present);
        assert_eq!(new_dkgs[i].nidx, i);
    }

    //alive = oldT - 1
    let alive = old_t;
    let mut old_selected = Vec::with_capacity(alive);
    let mut selected = HashMap::new();
    while selected.len() < alive {
        let i = rand::thread_rng().gen_range(0..old_dkgs.len());
        let str = format! {"{:x}", old_dkgs[i].pubb};
        if selected.contains_key(&str) {
            continue;
        }
        selected.insert(str, true);
        old_selected.push(old_dkgs[i].clone())
    }

    // 1. broadcast deals
    let mut deals = Vec::with_capacity(new_n * new_n);
    for dkg in old_selected.iter_mut() {
        let local_deals = dkg.deals().unwrap();
        deals.push(local_deals);
    }

    let mut resps = HashMap::new();
    for (i, local_deals) in deals.iter().enumerate() {
        resps.insert(i, vec![]);
        for (j, d) in local_deals {
            let dkg = &mut new_dkgs[(*j)];
            let resp = dkg.process_deal(d).unwrap();
            assert_eq!(vss::pedersen::vss::STATUS_APPROVAL, resp.response.status);
            resps.get_mut(&i).unwrap().push(resp);
        }
    }

    // 2. Broadcast responses
    for (_, deal_responses) in resps {
        for resp in deal_responses {
            // dispatch to old selected dkgs
            for dkg in old_selected.iter_mut() {
                // Ignore messages from ourselves
                if resp.response.index == dkg.nidx as u32 {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap_or_else(|_| panic!("old dkg at (oidx {}, nidx {}) has received response from idx {} for dealer idx {}\n", dkg.oidx, dkg.nidx, resp.response.index, resp.index));
                assert!(j.is_none());
            }
            // dispatch to the new dkgs
            for dkg in new_dkgs.iter_mut() {
                // Ignore messages from ourselves
                if resp.response.index == dkg.nidx as u32 {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap_or_else(|_| {
                    panic!(
                        "new dkg at nidx {} has received response from idx {} for dealer idx {}\n",
                        dkg.nidx, resp.response.index, resp.index
                    )
                });
                assert!(j.is_none());
            }
        }
    }

    for dkg in new_dkgs.iter() {
        for old_dkg in old_selected.iter() {
            let idx = old_dkg.oidx;
            assert!(
                dkg.verifiers.get(&(idx as u32)).unwrap().deal_certified(),
                "new dkg {} has not certified deal {} => {:?}",
                dkg.nidx,
                idx,
                dkg.verifiers.get(&(idx as u32)).unwrap().responses()
            );
        }
    }

    // 3. make sure everyone has the same QUAL set
    for dkg in new_dkgs.iter() {
        assert_eq!(alive, dkg.qual().len());
        for dkg2 in old_selected.iter() {
            assert!(
                dkg.is_in_qual(dkg2.oidx as u32),
                "new dkg {} has not in qual old dkg {} (qual = {:?})",
                dkg.nidx,
                dkg2.oidx,
                dkg.qual()
            )
        }
    }

    let mut new_shares = Vec::with_capacity(new_n);
    let mut new_sshares = Vec::with_capacity(new_n);
    for dkg in new_dkgs.iter() {
        let dks = dkg.dist_key_share().unwrap();
        new_sshares.push(Some(dks.share.clone()));
        new_shares.push(dks);
    }

    // check shares reconstruct to the same secret
    let old_secret = share::poly::recover_secret(suite(), &sshares, old_t, old_n).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_sshares, new_t, new_n).unwrap();
    assert_eq!(old_secret, new_secret);
}

/// Test resharing to a different set of nodes with two common.
#[test]
fn test_dkg_resharing_new_nodes() {
    let test_data = generate(DEFAULT_N, vss::pedersen::vss::minimum_t(DEFAULT_N));
    let old_pubs = test_data.part_pubs;
    let old_privs = test_data.part_sec;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        sshares.push(Some(share.share.clone()));
        shares.push(share);
    }

    // start resharing to a different group

    let old_n = DEFAULT_N;
    let old_t = shares[0].commits.len();
    let new_n = old_n + 1;
    let new_t = old_t + 1;
    let mut new_privs = Vec::with_capacity(new_n);
    let mut new_pubs = Vec::with_capacity(new_n);

    // new[0], new[1] = old[-1], old[-2]
    new_privs.push(old_privs[old_n - 1].clone());
    new_pubs.push(old_pubs[old_n - 1].clone());
    new_privs.push(old_privs[old_n - 2].clone());
    new_pubs.push(old_pubs[old_n - 2].clone());

    for _ in 2..new_n {
        let (new_priv, new_pub) = gen_pair();
        new_privs.push(new_priv);
        new_pubs.push(new_pub);
    }

    // creating the old dkgs

    let mut old_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(old_n);
    for i in 0..old_n {
        let c = Config {
            suite: suite(),
            longterm: old_privs[i].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: Some(shares[i].clone()),
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
        };
        old_dkgs.push(new_dist_key_handler(c).unwrap());

        // because the node's public key is already in newPubs
        if i >= old_n - 2 {
            assert!(old_dkgs[i].can_receive);
            assert!(old_dkgs[i].can_issue);
            assert!(old_dkgs[i].is_resharing);
            assert!(old_dkgs[i].new_present);
            assert_eq!(old_dkgs[i].oidx, i);
            assert_eq!(old_n - i - 1, old_dkgs[i].nidx);
            continue;
        }

        assert!(!old_dkgs[i].can_receive);
        assert!(old_dkgs[i].can_issue);
        assert!(old_dkgs[i].is_resharing);
        assert!(!old_dkgs[i].new_present);
        assert_eq!(old_dkgs[i].nidx, 0);
        assert_eq!(old_dkgs[i].oidx, i);
    }

    // creating the new dkg

    let mut new_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(new_n);

    new_dkgs.push(old_dkgs[old_n - 1].clone()); // the first one is the last old one
    new_dkgs.push(old_dkgs[old_n - 2].clone()); // the second one is the before-last old one

    for i in 2..new_n {
        let c = Config {
            suite: suite(),
            longterm: new_privs[i].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: None,
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: Some(shares[0].commits.clone()),
            reader: None,
            user_reader_only: false,
        };
        new_dkgs.push(new_dist_key_handler(c).unwrap());

        assert!(new_dkgs[i].can_receive);
        assert!(!new_dkgs[i].can_issue);
        assert!(new_dkgs[i].is_resharing);
        assert!(new_dkgs[i].new_present);
        assert_eq!(new_dkgs[i].nidx, i);
        // each old dkg act as a verifier
        assert_eq!(new_dkgs[i].verifiers().len(), old_n);
    }

    // full secret sharing exchange

    // 1. broadcast deals
    let mut deals = Vec::with_capacity(old_dkgs.len());

    for dkg in old_dkgs.iter_mut() {
        let local_deals = dkg.deals().unwrap();

        // each old DKG will sent a deal to each other dkg, including
        // themselves.
        assert_eq!(local_deals.len(), new_n);

        deals.push(local_deals);

        let exists = dkg.verifiers.contains_key(&(dkg.oidx as u32));
        if dkg.can_receive && dkg.nidx <= 1 {
            // staying nodes don't save their responses locally because they
            // will broadcast them for the old comities.
            assert!(exists);
            assert_eq!(
                dkg.verifiers
                    .get(&(dkg.oidx as u32))
                    .unwrap()
                    .responses()
                    .len(),
                0
            );
        } else {
            // no verifiers since these dkg are not in the new list
            assert!(!exists);
        }
    }

    // the index key indicates the dealer index for which the responses are for
    let mut resps = HashMap::new();
    for (i, local_deals) in deals.iter().enumerate() {
        resps.insert(i, vec![]);
        for (dest, d) in local_deals {
            let dkg = &mut new_dkgs[(*dest)];
            let resp = dkg.process_deal(d).unwrap();
            assert_eq!(vss::pedersen::vss::STATUS_APPROVAL, resp.response.status);
            resps.get_mut(&i).unwrap().push(resp);
        }
    }

    // all new dkgs should have the same length of verifiers map
    for dkg in new_dkgs.iter() {
        // one deal per old participants
        assert_eq!(dkg.verifiers.len(), old_n, "dkg nidx {} failing", dkg.nidx)
    }

    // 2. Broadcast responses
    for (_, deal_responses) in resps {
        for resp in deal_responses {
            // the two last ones will be processed while doing this step on the
            // newDkgs, since they are in the new set.
            for dkg in old_dkgs[..old_n - 2].iter_mut() {
                let j = dkg.process_response(&resp).unwrap_or_else(|_| panic!("old dkg at (oidx {}, nidx {}) has received response from idx {} for dealer idx {}\n", dkg.oidx, dkg.nidx, resp.response.index, resp.index));
                assert!(j.is_none());
            }
            // dispatch to the new dkgs
            for dkg in new_dkgs.iter_mut() {
                // Ignore messages from ourselves
                if resp.response.index == dkg.nidx as u32 {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap_or_else(|_| {
                    panic!(
                        "new dkg at nidx {} has received response from idx {} for dealer idx {}\n",
                        dkg.nidx, resp.response.index, resp.index
                    )
                });
                assert!(j.is_none());
            }
        }
    }

    for dkg in new_dkgs.iter() {
        for i in 0..old_n {
            assert!(
                dkg.verifiers.get(&(i as u32)).unwrap().deal_certified(),
                "new dkg {} has not certified deal {} => {:?}",
                dkg.nidx,
                i,
                dkg.verifiers.get(&(i as u32)).unwrap().responses()
            )
        }
    }

    // 3. make sure everyone has the same QUAL set
    for dkg in new_dkgs.iter() {
        for dkg2 in old_dkgs.iter() {
            assert!(
                dkg.is_in_qual(dkg2.oidx as u32),
                "new dkg {} has not in qual old dkg {} (qual = {:?})",
                dkg.nidx,
                dkg2.oidx,
                dkg.qual()
            )
        }
    }

    // make sure the new dkg members can certify
    for dkg in new_dkgs.iter() {
        assert!(dkg.certified(), "new dkg {} can't certify", dkg.nidx);
    }

    // make sure the old dkg members can certify
    for dkg in old_dkgs[..old_n - 2].iter() {
        assert!(dkg.certified(), "old dkg {} can't certify", dkg.oidx);
    }

    let mut new_shares = Vec::with_capacity(new_n);
    let mut new_sshares = Vec::with_capacity(new_n);
    for dkg in new_dkgs.iter() {
        let dks = dkg.dist_key_share().unwrap();
        new_sshares.push(Some(dks.share.clone()));
        new_shares.push(dks);
    }

    // check shares reconstruct to the same secret
    let old_secret = share::poly::recover_secret(suite(), &sshares, old_t, old_n).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_sshares, new_t, new_n).unwrap();
    assert_eq!(old_secret, new_secret);
}

#[test]
fn test_dkg_resharing_partial_new_nodes() {
    let test_data = generate(DEFAULT_N, vss::pedersen::vss::minimum_t(DEFAULT_N));
    let old_pubs = test_data.part_pubs;
    let old_privs = test_data.part_sec;
    let mut dkgs = test_data.dkgs;
    full_exchange(&mut dkgs, true);

    let mut shares = Vec::with_capacity(dkgs.len());
    let mut sshares = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        let share = dkg.dist_key_share().unwrap();
        sshares.push(Some(share.share.clone()));
        shares.push(share);
    }

    // start resharing to a different group
    let old_n = DEFAULT_N;
    let old_t = shares[0].commits.len();
    let new_n = old_n + 1;
    let new_t = old_t + 1;
    let total = old_n + 2;
    let new_offset = old_n - 1; // idx at which a new key is added to the group

    let mut new_privs = Vec::with_capacity(new_n);
    let mut new_pubs = Vec::with_capacity(new_n);
    for privv in old_privs[1..].iter() {
        new_privs.push(privv.clone());
    }
    for pubb in old_pubs[1..].iter() {
        new_pubs.push(pubb.clone());
    }

    // add two new nodes
    let (priv1, pub1) = gen_pair();
    let (priv2, pub2) = gen_pair();
    new_privs.push(priv1);
    new_privs.push(priv2);
    new_pubs.push(pub1);
    new_pubs.push(pub2);

    // creating all dkgs
    let mut total_dkgs: Vec<DistKeyGenerator<SuiteEd25519, &[u8]>> = Vec::with_capacity(total);
    for i in 0..old_n {
        let c = Config {
            suite: suite(),
            longterm: old_privs[i].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: Some(shares[i].clone()),
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
        };
        total_dkgs.push(new_dist_key_handler(c).unwrap());

        // because the node's public key is already in newPubs
        if i >= 1 {
            assert!(total_dkgs[i].can_receive);
            assert!(total_dkgs[i].can_issue);
            assert!(total_dkgs[i].is_resharing);
            assert!(total_dkgs[i].new_present);
            assert_eq!(total_dkgs[i].oidx, i);
            assert_eq!(i - 1, total_dkgs[i].nidx);
            continue;
        }

        assert!(!total_dkgs[i].can_receive);
        assert!(total_dkgs[i].can_issue);
        assert!(total_dkgs[i].is_resharing);
        assert!(!total_dkgs[i].new_present);
        assert_eq!(total_dkgs[i].oidx, i);
    }

    // the first one is the last old one
    for i in old_n..total {
        let new_idx = i - old_n + new_offset;
        let c = Config {
            suite: suite(),
            longterm: new_privs[new_idx].clone(),
            old_nodes: old_pubs.clone(),
            new_nodes: new_pubs.clone(),
            share: None,
            threshold: new_t,
            old_threshold: old_t,
            public_coeffs: Some(shares[0].commits.clone()),
            reader: None,
            user_reader_only: false,
        };
        total_dkgs.push(new_dist_key_handler(c).unwrap());
        let idx = total_dkgs.len() - 1;
        assert!(total_dkgs[idx].can_receive);
        assert!(!total_dkgs[idx].can_issue);
        assert!(total_dkgs[idx].is_resharing);
        assert!(total_dkgs[idx].new_present);
        assert_eq!(total_dkgs[idx].nidx, new_idx);
    }
    let new_dkgs = &mut total_dkgs.clone()[1..];
    let old_dkgs = &mut total_dkgs.clone()[..old_n];
    assert_eq!(old_n, old_dkgs.len());
    assert_eq!(new_n, new_dkgs.len());

    // full secret sharing exchange
    // 1. broadcast deals
    let mut deals = Vec::with_capacity(new_n * new_n);
    for dkg in old_dkgs.iter_mut() {
        let local_deals = dkg.deals().unwrap();
        deals.push(local_deals);
        let exists = dkg.verifiers.contains_key(&(dkg.oidx as u32));
        if dkg.can_receive && dkg.new_present {
            // staying nodes don't process their responses locally because they
            // broadcast them for the old comities to receive the responses.
            assert!(exists);
            let v = dkg.verifiers.get(&(dkg.oidx as u32)).unwrap();
            let len_responses = v.aggregator.clone().unwrap().responses().len();
            assert_eq!(len_responses, 0);
        } else {
            assert!(!exists);
        }
    }

    // the index key indicates the dealer index for which the responses are for
    let mut resps = HashMap::new();
    for (i, local_deals) in deals.iter().enumerate() {
        resps.insert(i, vec![]);
        for (j, d) in local_deals {
            let dkg = &mut new_dkgs[(*j)];
            let resp = dkg.process_deal(d).unwrap();
            assert_eq!(vss::pedersen::vss::STATUS_APPROVAL, resp.response.status);
            resps.get_mut(&i).unwrap().push(resp);
            if i == 0 {
                //fmt.Printf("dealer (oidx %d, nidx %d) processing deal to %d from %d\n", newDkgs[i].oidx, newDkgs[i].nidx, i, d.Index)
            }
        }
    }

    // all new dkgs should have the same length of verifiers map
    for dkg in new_dkgs.iter() {
        // one deal per old participants
        assert_eq!(old_n, dkg.verifiers.len(), "dkg nidx {} failing", dkg.nidx)
    }

    // 2. Broadcast responses
    for (_, deal_responses) in resps {
        for resp in deal_responses {
            // the other ones will be processed while doing this step on the
            // newDkgs, since they are in the new set.
            for dkg in old_dkgs[..1].iter_mut() {
                let j = dkg.process_response(&resp).unwrap_or_else(|_| panic!("old dkg at (oidx {}, nidx {}) has received response from idx {} for dealer idx {}\n", dkg.oidx, dkg.nidx, resp.response.index, resp.index));
                assert!(j.is_none());
            }
            // dispatch to the new dkgs
            for dkg in new_dkgs.iter_mut() {
                // Ignore messages from ourselves
                if resp.response.index == dkg.nidx as u32 {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap_or_else(|_| {
                    panic!(
                        "new dkg at nidx {} has received response from idx {} for dealer idx {}\n",
                        dkg.nidx, resp.response.index, resp.index
                    )
                });
                assert!(j.is_none());
            }
        }
    }

    for dkg in new_dkgs.iter() {
        for i in 0..old_n {
            assert!(
                dkg.verifiers.get(&(i as u32)).unwrap().deal_certified(),
                "new dkg {} has not certified deal {} => {:?}",
                dkg.nidx,
                i,
                dkg.verifiers.get(&(i as u32)).unwrap().responses()
            )
        }
    }

    // 3. make sure everyone has the same QUAL set
    for dkg in new_dkgs.iter() {
        for dkg2 in old_dkgs.iter() {
            assert!(
                dkg.is_in_qual(dkg2.oidx as u32),
                "new dkg {} has not in qual old dkg {} (qual = {:?})",
                dkg.nidx,
                dkg2.oidx,
                dkg.qual()
            )
        }
    }

    let mut new_shares = Vec::with_capacity(new_n);
    let mut new_sshares = Vec::with_capacity(new_n);
    for dkg in new_dkgs.iter() {
        let dks = dkg.dist_key_share().unwrap();
        new_sshares.push(Some(dks.share.clone()));
        new_shares.push(dks);
    }

    // check shares reconstruct to the same secret
    let old_secret = share::poly::recover_secret(suite(), &sshares, old_t, old_n).unwrap();
    let new_secret = share::poly::recover_secret(suite(), &new_sshares, new_t, new_n).unwrap();
    assert_eq!(old_secret, new_secret);
}

#[test]
fn test_reader_mixed_entropy() {
    let seed = "some stream to be used with crypto/rand";
    let test_data = generate(DEFAULT_N, *DEFAULT_T);
    let part_pubs = test_data.part_pubs;
    let part_sec = test_data.part_sec;
    let long = part_sec[0].clone();
    let r = seed.as_bytes();
    let c = Config {
        suite: suite(),
        longterm: long,
        new_nodes: part_pubs,
        threshold: *DEFAULT_T,
        reader: Some(r),
        old_nodes: vec![],
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        user_reader_only: false,
    };
    new_dist_key_handler(c).unwrap();
}

#[test]
fn test_user_only_flag_true_behavior() {
    let seed = "String to test reproducibility with";
    let test_data = generate(DEFAULT_N, *DEFAULT_T);
    let part_pubs = test_data.part_pubs;
    let part_sec = test_data.part_sec;
    let long = part_sec[0].clone();

    let r1 = seed.as_bytes();
    let c1 = Config {
        suite: suite(),
        longterm: long.clone(),
        new_nodes: part_pubs.clone(),
        threshold: *DEFAULT_T,
        reader: Some(r1),
        old_nodes: vec![],
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        user_reader_only: true,
    };
    let dkg1 = new_dist_key_handler(c1).unwrap();

    let r2 = seed.as_bytes();
    let c2 = Config {
        suite: suite(),
        longterm: long,
        new_nodes: part_pubs,
        threshold: *DEFAULT_T,
        reader: Some(r2),
        old_nodes: vec![],
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        user_reader_only: true,
    };
    let dkg2 = new_dist_key_handler(c2).unwrap();

    assert_eq!(
        dkg1.dealer.private_poly().secret(),
        dkg2.dealer.private_poly().secret()
    );
}

#[test]
fn test_user_only_flag_false_behavior() {
    let seed = "String to test reproducibility with";
    let test_data = generate(DEFAULT_N, *DEFAULT_T);
    let part_pubs = test_data.part_pubs;
    let part_sec = test_data.part_sec;
    let long = part_sec[0].clone();

    let r1 = seed.as_bytes();
    let c1 = Config {
        suite: suite(),
        longterm: long.clone(),
        new_nodes: part_pubs.clone(),
        threshold: *DEFAULT_T,
        reader: Some(r1),
        old_nodes: vec![],
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        user_reader_only: false,
    };
    let dkg1 = new_dist_key_handler(c1).unwrap();

    let r2 = seed.as_bytes();
    let c2 = Config {
        suite: suite(),
        longterm: long,
        new_nodes: part_pubs,
        threshold: *DEFAULT_T,
        reader: Some(r2),
        old_nodes: vec![],
        public_coeffs: None,
        share: None,
        old_threshold: 0,
        user_reader_only: false,
    };
    let dkg2 = new_dist_key_handler(c2).unwrap();

    assert_ne!(
        dkg1.dealer.private_poly().secret(),
        dkg2.dealer.private_poly().secret()
    );
}
