use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    group::edwards25519::{Point as EdPoint, Scalar as EdScalar, SuiteEd25519},
    share::{
        dkg::rabin::{DistKeyShare, ReconstructCommits, SecretCommits},
        poly::recover_secret,
        vss::{self, suite::Suite},
    },
    sign::schnorr,
    Group, Point, Random, Scalar,
};

use super::{new_dist_key_generator, DistKeyGenerator};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

struct TestData<SUITE: Suite> {
    suite: SUITE,
    nb_participants: usize,

    part_pubs: Vec<SUITE::POINT>,
    part_sec: Vec<<SUITE::POINT as Point>::SCALAR>,
}
const NB_PARTICIPANTS: usize = 7;

fn new_test_data() -> TestData<SuiteEd25519> {
    let mut part_pubs = Vec::with_capacity(NB_PARTICIPANTS);
    let mut part_sec = Vec::with_capacity(NB_PARTICIPANTS);
    for _ in 0..NB_PARTICIPANTS {
        let (sec, pubb) = gen_pair();
        part_pubs.push(pubb);
        part_sec.push(sec);
    }

    return TestData::<SuiteEd25519> {
        suite: suite(),
        nb_participants: NB_PARTICIPANTS,
        part_pubs,
        part_sec,
    };
}

fn dkg_gen<SUITE: Suite>(t: &TestData<SUITE>) -> Vec<DistKeyGenerator<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let mut dkgs = Vec::with_capacity(t.nb_participants);
    for i in 0..t.nb_participants {
        let dkg = new_dist_key_generator(
            t.suite,
            t.part_sec[i].clone(),
            &t.part_pubs,
            t.nb_participants / 2 + 1,
        )
        .unwrap();
        dkgs.push(dkg);
    }
    return dkgs;
}

#[test]
fn test_dkg_new_dist_key_generator() {
    let t = new_test_data();
    let long = t.part_sec[0].clone();
    let mut dkg =
        new_dist_key_generator(t.suite, long, &t.part_pubs, t.nb_participants / 2 + 1).unwrap();
    // quick testing here; easier.
    dkg.secret_commits().unwrap_err();

    let sec = gen_pair();
    let res = new_dist_key_generator(t.suite, sec.0, &t.part_pubs, t.nb_participants / 2 + 1);
    if res.is_ok() {
        panic!("this should fail")
    }
}

#[test]
fn test_dkg_deal() {
    let t = new_test_data();
    let mut dkgs = full_exchange(&t);
    let dkg = &mut dkgs[0];

    let res = dkg.dist_key_share();
    assert!(res.is_err());
    //assert.Nil(t, dks)

    let deals = dkg.deals().unwrap();
    assert_eq!(deals.len(), NB_PARTICIPANTS - 1);

    for (_, d) in deals {
        //assert.NotNil(t, deals[i])
        assert_eq!(0 as u32, d.index);
    }

    let own_index = dkg.index.clone();
    assert!(dkg.verifiers.contains_key(&own_index));
    assert!(dkg.verifiers.get(&own_index).is_some());
}

#[test]
fn test_dkg_process_deal() {
    let t = new_test_data();
    let mut dkgs = dkg_gen(&t);
    let dkg = &mut dkgs[0];
    let mut deals = dkg.deals().unwrap();

    let rec = &mut dkgs[1];
    let deal = deals.get_mut(&1).unwrap();
    assert_eq!(deal.index, 0);
    assert_eq!(1, rec.index);

    // verifier don't find itself
    let good_p = rec.participants.clone();
    rec.participants = Vec::new();
    let res = rec.process_deal(deal);
    assert!(res.is_err());
    rec.participants = good_p;

    // wrong index
    let good_idx = deal.index;
    deal.index = (NB_PARTICIPANTS + 1) as u32;
    let res = rec.process_deal(deal);
    assert!(res.is_err());
    deal.index = good_idx;

    // wrong deal
    let good_sig = deal.deal.signature.clone();
    deal.deal.signature = random_bytes(deal.deal.signature.len());
    let res = rec.process_deal(deal);
    assert!(res.is_err());
    deal.deal.signature = good_sig;

    // good deal
    let resp = rec.process_deal(deal).unwrap();
    assert!(resp.response.approved);
    assert!(rec.verifiers.contains_key(&deal.index));
    assert_eq!(0, resp.index);

    // duplicate
    let res = rec.process_deal(deal);
    assert!(res.is_err());
}

#[test]
fn test_dkg_process_response() {
    // first peer generates wrong deal
    // second peer processes it and returns a complaint
    // first peer process the complaint

    let t = new_test_data();
    let mut dkgs = dkg_gen(&t);
    let idx_rec = 1;
    //let deal = dkgs[0].dealer.PlaintextDeal(idx_rec).unwrap();

    // give a wrong deal
    let good_secret = dkgs[0]
        .dealer
        .plaintext_deal(idx_rec)
        .unwrap()
        .rnd_share
        .v
        .clone();
    dkgs[0].dealer.plaintext_deal(idx_rec).unwrap().rnd_share.v = t.suite.scalar().zero();
    let dd = dkgs[0].deals().unwrap();
    let enc_d = dd.get(&idx_rec).unwrap();
    let mut resp = dkgs[idx_rec].process_deal(enc_d).unwrap();
    assert!(!resp.response.approved);
    dkgs[0].dealer.plaintext_deal(idx_rec).unwrap().rnd_share.v = good_secret;
    _ = dkgs[0].deals().unwrap(); //dd
                                  //enc_d = dd.get(&idx_rec).unwrap();

    // no verifier tied to Response
    assert!(dkgs[0].verifiers.contains_key(&0));
    let v = dkgs[0].verifiers.remove(&0).unwrap();
    let res = dkgs[0].process_response(&resp);
    assert!(res.is_err());
    dkgs[0].verifiers.insert(0, v);

    // invalid response
    let good_sig = resp.response.signature.clone();
    resp.response.signature = random_bytes(good_sig.len());
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
        .rnd_share
        .v
        .clone();
    dkgs[2].dealer.plaintext_deal(1).unwrap().rnd_share.v = t.suite.scalar().zero();
    let mut deals_2 = dkgs[2].deals().unwrap();

    let mut resp_1_2 = dkgs[idx_rec]
        .process_deal(deals_2.get(&idx_rec).unwrap())
        .unwrap();
    assert!(!resp_1_2.response.approved);

    dkgs[2].dealer.plaintext_deal(1).unwrap().rnd_share.v = good_rnd_2_1;
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
    resp_1_2.response.approved = false;
    dkgs[0].process_justification(&j).unwrap();

    // remove verifiers
    let v = dkgs[0].verifiers.remove(&j.index).unwrap();
    let res = dkgs[0].process_justification(&j);
    assert!(res.is_err());
    dkgs[0].verifiers.insert(j.index, v);
}

#[test]
fn test_dkg_secret_commits() {
    let t = new_test_data();
    let mut dkgs = full_exchange(&t);

    let mut sc = dkgs[0].secret_commits().unwrap();
    let msg = sc.hash(&t.suite).unwrap();
    schnorr::verify(t.suite, &dkgs[0].pubb, &msg, &sc.clone().signature).unwrap();

    // wrong index
    let good_idx = sc.index;
    sc.index = (NB_PARTICIPANTS + 1) as u32;
    let res = dkgs[1].process_secret_commits(&sc);
    assert!(res.is_err());
    sc.index = good_idx;

    // not in qual: delete the verifier
    let good_v = dkgs[1].verifiers.remove(&0).unwrap();
    let res = dkgs[1].process_secret_commits(&sc);
    assert!(res.is_err());
    dkgs[1].verifiers.insert(0, good_v);

    // invalid sig
    let good_sig = sc.signature.clone();
    sc.signature = random_bytes(good_sig.clone().len());
    let res = dkgs[1].process_secret_commits(&sc);
    assert!(res.is_err());
    sc.signature = good_sig;

    // invalid session id
    let good_sid = sc.session_id;
    sc.session_id = random_bytes(good_sid.len());
    let res = dkgs[1].process_secret_commits(&sc);
    assert!(res.is_err());
    sc.session_id = good_sid;

    // wrong commitments
    let good_point = sc.commitments[0].clone();
    sc.commitments[0] = t.suite.point().null();
    let msg = sc.hash(&t.suite).unwrap();
    let sig = schnorr::sign(&t.suite, &dkgs[0].long, &msg).unwrap();
    let good_sig = sc.signature.clone();
    sc.signature = sig;
    let cc = dkgs[1].process_secret_commits(&sc).unwrap();
    assert!(cc.is_some());
    sc.commitments[0] = good_point;
    sc.signature = good_sig;

    // all fine
    let cc = dkgs[1].process_secret_commits(&sc).unwrap();
    assert!(cc.is_none());
}

#[test]
fn test_dkg_complaint_commits() {
    let t = new_test_data();
    let mut dkgs = full_exchange(&t);

    let mut scs = Vec::new();
    for dkg in dkgs.iter_mut() {
        let sc = dkg.secret_commits().unwrap();
        scs.push(sc);
    }

    for sc in scs.iter() {
        for dkg in dkgs.iter_mut() {
            let cc = dkg.process_secret_commits(sc).unwrap();
            assert!(cc.is_none());
        }
    }

    // change the sc for the second one
    let mut wrong_sc = SecretCommits {
        index: scs[0].index.clone(),
        session_id: scs[0].session_id.clone(),
        commitments: scs[0].commitments.clone(),
        signature: Vec::new(),
    };
    //goodScCommit := scs[0].Commitments[0]
    wrong_sc.commitments[0] = t.suite.point().null();
    let msg = wrong_sc.hash(&t.suite).unwrap();
    wrong_sc.signature = schnorr::sign(&t.suite, &dkgs[0].long, &msg).unwrap();

    let mut cc = dkgs[1].process_secret_commits(&wrong_sc).unwrap().unwrap();

    // ComplaintCommits: wrong index
    let good_index = cc.index;
    cc.index = NB_PARTICIPANTS as u32;
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());
    cc.index = good_index;

    // invalid signature
    let good_sig = cc.signature.clone();
    cc.signature = random_bytes(cc.signature.len());
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());
    cc.signature = good_sig;

    // no verifiers
    let v = dkgs[2].verifiers.remove(&0).unwrap();
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());
    dkgs[2].verifiers.insert(0, v);

    // deal does not verify
    let good_deal = cc.deal;
    cc.deal = vss::rabin::vss::Deal {
        session_id: good_deal.session_id.clone(),
        sec_share: good_deal.sec_share.clone(),
        rnd_share: good_deal.rnd_share.clone(),
        t: good_deal.t.clone(),
        commitments: good_deal.commitments.clone(),
    };
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());
    cc.deal = good_deal;

    //  no commitments
    let sc = dkgs[2].commitments.remove(&0).unwrap();
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());
    dkgs[2].commitments.insert(0, sc);

    // secret commits are passing the check
    let res = dkgs[2].process_complaint_commits(&cc);
    assert!(res.is_err());

    /*
        TODO find a way to be the malicious guys,i.e.
        make a deal which validates, but revealing the commitments coefficients makes
        the check fails.
        f is the secret polynomial
        g is the "random" one
        [f(i) + g(i)]*G == [F + G](i)
        but
        f(i)*G != F(i)

        goodV := cc.Deal.SecShare.V
        goodDSig := cc.Deal.Signature
        cc.Deal.SecShare.V = suite.Scalar().Zero()
        msg = msgDeal(cc.Deal)
        sig, _ := sign.Schnorr(suite, dkgs[cc.DealerIndex].long, msg)
        cc.Deal.Signature = sig
        msg = msgCommitComplaint(cc)
        sig, _ = sign.Schnorr(suite, dkgs[cc.Index].long, msg)
        goodCCSig := cc.Signature
        cc.Signature = sig
        rc, err = dkg2.ProcessComplaintCommits(cc)
        assert.Nil(t, err)
        assert.NotNil(t, rc)
        cc.Deal.SecShare.V = goodV
        cc.Deal.Signature = goodDSig
        cc.Signature = goodCCSig
    */
}

#[test]
fn test_dkg_reconstruct_commits() {
    let t = new_test_data();
    let mut dkgs = full_exchange(&t);

    let mut scs = Vec::new();
    for dkg in dkgs.iter_mut() {
        let sc = dkg.secret_commits().unwrap();
        scs.push(sc);
    }

    // give the secret commits to all dkgs but the second one
    for sc in scs.iter() {
        for dkg in dkgs[2..].iter_mut() {
            let cc = dkg.process_secret_commits(sc).unwrap();
            assert!(cc.is_none());
        }
    }

    // peer 1 wants to reconstruct coeffs from dealer 1
    let mut rc = ReconstructCommits {
        index: 1,
        dealer_index: 0,
        share: dkgs[1].verifiers.get(&0).unwrap().deal().unwrap().sec_share,
        session_id: dkgs[1]
            .verifiers
            .get(&0)
            .unwrap()
            .deal()
            .unwrap()
            .session_id,
        signature: Vec::new(),
    };
    let msg = rc.hash(&t.suite).unwrap();
    rc.signature = schnorr::sign(&t.suite, &dkgs[1].long, &msg).unwrap();

    // reconstructed already set
    dkgs[2].reconstructed.insert(0, true);
    dkgs[2].process_reconstruct_commits(&rc).unwrap();
    dkgs[2].reconstructed.remove(&0);

    // commitments not invalidated by any complaints
    assert!(dkgs[2].process_reconstruct_commits(&rc).is_err());
    dkgs[2].commitments.remove(&0);

    // invalid index
    let good_i = rc.index;
    rc.index = NB_PARTICIPANTS as u32;
    assert!(dkgs[2].process_reconstruct_commits(&rc).is_err());
    rc.index = good_i;

    // invalid sig
    let good_sig = rc.signature.clone();
    rc.signature = random_bytes(good_sig.clone().len());
    assert!(dkgs[2].process_reconstruct_commits(&rc).is_err());
    rc.signature = good_sig;

    // all fine
    dkgs[2].process_reconstruct_commits(&rc).unwrap();

    // packet already received
    let mut found = false;
    for p in dkgs[2].pending_reconstruct.get(&rc.dealer_index).unwrap() {
        if p.index == rc.index {
            found = true;
            break;
        }
    }
    assert!(found);
    assert!(!dkgs[2].finished());

    let mut rcs = Vec::new();
    // generate enough secret commits  to recover the secret
    for dkg in dkgs[2..].iter_mut() {
        let mut rc = ReconstructCommits {
            session_id: dkg.verifiers.get(&0).unwrap().deal().unwrap().session_id,
            index: dkg.index,
            dealer_index: 0,
            share: dkg.verifiers.get(&0).unwrap().deal().unwrap().sec_share,
            signature: Vec::new(),
        };
        let msg = rc.hash(&t.suite).unwrap();
        rc.signature = schnorr::sign(&t.suite, &dkg.long, &msg).unwrap();

        rcs.push(rc);
    }

    for rc in rcs.iter_mut() {
        if dkgs[2].reconstructed.contains_key(&0) {
            if *dkgs[2].reconstructed.get(&0).unwrap() {
                break;
            }
        }
        // invalid session ID
        let good_sid = rc.session_id.clone();
        rc.session_id = random_bytes(good_sid.len());
        assert!(dkgs[2].process_reconstruct_commits(&rc).is_err());
        rc.session_id = good_sid;

        dkgs[2].process_reconstruct_commits(&rc).unwrap();
    }
    assert!(dkgs[2].reconstructed.contains_key(&0));
    let com = dkgs[2].commitments.get(&0);
    assert!(com.is_some());
    assert_eq!(
        dkgs[0].dealer.secret_commit().unwrap().string(),
        com.unwrap().commit().string()
    );

    assert!(dkgs[2].finished());
}

#[test]
fn test_set_timeout() {
    let t = new_test_data();
    let mut dkgs = dkg_gen(&t);
    // full secret sharing exchange
    // 1. broadcast deals
    let mut all_deals = Vec::with_capacity(NB_PARTICIPANTS);
    let mut resps = Vec::with_capacity(NB_PARTICIPANTS * NB_PARTICIPANTS);
    for dkg in dkgs.iter_mut() {
        let deals = dkg.deals().unwrap();
        all_deals.push(deals);
    }

    for deals in all_deals {
        for (i, d) in deals {
            let resp = dkgs[i].process_deal(&d).unwrap();
            assert!(resp.response.approved);
            resps.push(resp);
        }
    }

    // 2. Broadcast responses
    for resp in resps {
        for dkg in dkgs.iter_mut() {
            if !dkg.verifiers.get(&resp.index).unwrap().enough_approvals() {
                // ignore messages about ourself
                if resp.response.index == dkg.index {
                    continue;
                }
                let j = dkg.process_response(&resp).unwrap();
                assert!(j.is_none());
            }
        }
    }

    // 3. make sure everyone has the same QUAL set
    let mut dkg_idxs = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter() {
        dkg_idxs.push(dkg.index.clone());
    }

    for dkg in dkgs.iter() {
        for idx in dkg_idxs.iter() {
            assert!(!dkg.is_in_qual(idx.clone()));
        }
    }

    for dkg in dkgs.iter_mut() {
        dkg.set_timeout();
    }

    for dkg in dkgs.iter() {
        for idx in dkg_idxs.iter() {
            assert!(dkg.is_in_qual(idx.clone()));
        }
    }
}

#[test]
fn test_dist_key_share() {
    let t = new_test_data();
    let mut dkgs = full_exchange(&t);
    let dkgs_len = dkgs.len();

    let mut scs = vec![];
    for (i, dkg) in dkgs[..dkgs_len - 1].iter_mut().enumerate() {
        let sc = dkg.secret_commits().unwrap();
        scs.push((i, sc));
    }
    for (i, dkg) in dkgs[..dkgs_len - 1].iter_mut().enumerate() {
        for sc in scs.iter() {
            if i == sc.0 {
                continue;
            }
            let cc = dkg.process_secret_commits(&sc.1).unwrap();
            assert!(cc.is_none());
        }
    }

    // check that we can't get the dist key share before exchanging commit.ents
    let sc: SecretCommits<SuiteEd25519>;
    // NOTE: need a block for the mut reference to dkgs
    {
        let last_dkg = &mut dkgs[dkgs_len - 1];
        let res = last_dkg.dist_key_share();
        assert!(res.is_err());

        for sc in scs.iter() {
            let cc = last_dkg.process_secret_commits(&sc.1).unwrap();
            assert!(cc.is_none());
        }

        sc = last_dkg.secret_commits().unwrap();
        //require.NotNil(t, sc)
    }

    for dkg in dkgs[..dkgs_len - 1].iter_mut() {
        let sc = dkg.process_secret_commits(&sc).unwrap();
        assert!(sc.is_none());

        assert_eq!(NB_PARTICIPANTS, dkg.qual().len());
        assert_eq!(NB_PARTICIPANTS, dkg.commitments.len());
    }

    // NOTE: need a block for the mut reference to dkgs
    {
        let last_dkg = &mut dkgs[dkgs_len - 1];
        // missing one commitment
        let last_commitment_0 = last_dkg.commitments.remove(&(0 as u32)).unwrap();
        let res = last_dkg.dist_key_share();
        assert!(res.is_err());
        last_dkg.commitments.insert(0 as u32, last_commitment_0);
    }

    // everyone should be finished
    for dkg in dkgs.iter_mut() {
        assert!(dkg.finished())
    }
    // verify integrity of shares etc
    let mut dkss = Vec::with_capacity(NB_PARTICIPANTS);
    for dkg in dkgs.iter_mut() {
        let dks = dkg.dist_key_share().unwrap();
        let index = dks.share.i;
        dkss.push(dks);
        assert_eq!(dkg.index, index as u32);
    }

    let mut shares = Vec::with_capacity(NB_PARTICIPANTS);
    for dks in dkss.iter() {
        assert!(
            check_dks(dks, &dkss[0]),
            "dist key share not equal {} vs {}",
            dks.share.i,
            0
        );
        shares.push(Some(dks.share.clone()));
    }

    let secret = recover_secret(t.suite, &shares, NB_PARTICIPANTS, NB_PARTICIPANTS).unwrap();

    let commit_secret = t.suite.point().mul(&secret, None);
    assert_eq!(dkss[0].public().string(), commit_secret.string())
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
    return buff;
}

fn check_dks<POINT: Point>(dks1: &DistKeyShare<POINT>, dks2: &DistKeyShare<POINT>) -> bool {
    if dks1.commits.len() != dks2.commits.len() {
        return false;
    }
    for (i, p) in dks1.commits.iter().enumerate() {
        if !p.equal(&dks2.commits[i]) {
            return false;
        }
    }
    return true;
}

fn full_exchange(t: &TestData<SuiteEd25519>) -> Vec<DistKeyGenerator<SuiteEd25519>> {
    let mut dkgs = dkg_gen(t);
    // full secret sharing exchange
    // 1. broadcast deals
    let mut all_deals = Vec::with_capacity(NB_PARTICIPANTS);
    let mut resps = Vec::with_capacity(NB_PARTICIPANTS * NB_PARTICIPANTS);
    for dkg in dkgs.iter_mut() {
        let deals = dkg.deals().unwrap();
        all_deals.push(deals);
    }
    for deals in all_deals {
        for (i, d) in deals {
            let resp = dkgs[i].process_deal(&d).unwrap();
            assert!(resp.response.approved);
            resps.push(resp);
        }
    }

    // 2. Broadcast responses
    for resp in resps {
        for dkg in dkgs.iter_mut() {
            // ignore all messages from ourself
            if resp.response.index == dkg.index {
                continue;
            }
            let j = dkg.process_response(&resp).unwrap();
            assert!(j.is_none())
        }
    }
    // 3. make sure everyone has the same QUAL set
    for dkg in &dkgs {
        for dkg2 in &dkgs {
            assert!(dkg.is_in_qual(dkg2.index));
        }
    }

    return dkgs;
}
