use bincode::de;
use core::panic;
use rand::{Rng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::encoding::BinaryMarshaler;
use crate::share::vss::rabin::dh;
use crate::share::vss::rabin::vss::Response;
use crate::sign::schnorr;
use crate::{group::edwards25519::SuiteEd25519, Group, Point, Random, Scalar};
use crate::{random, Suite};

use super::dh::{context, dhExchange};
use super::vss::{
    findPub, minimum_t, sessionID, Dealer, NewDealer, NewVerifier, RecoverSecret, Verifier,
};

// lazy_static! {
//     static ref SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
// }

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

#[derive(Clone)]
struct TestData<SUITE: Suite> {
    suite: SUITE,
    nb_verifiers: usize,
    vss_threshold: usize,

    verifiers_pub: Vec<SUITE::POINT>,
    verifiers_sec: Vec<<SUITE::POINT as Point>::SCALAR>,

    dealer_pub: SUITE::POINT,
    dealer_sec: <SUITE::POINT as Point>::SCALAR,

    secret: <SUITE::POINT as Point>::SCALAR,
}
const NB_VERIFIERS: usize = 7;

fn new_test_data(
    vss_threshold: usize,
    verifiers_pub: Vec<<SuiteEd25519 as Group>::POINT>,
    verifiers_sec: Vec<<<SuiteEd25519 as Group>::POINT as Point>::SCALAR>,
    dealer_pub: <SuiteEd25519 as Group>::POINT,
    dealer_sec: <<SuiteEd25519 as Group>::POINT as Point>::SCALAR,
    secret: <<SuiteEd25519 as Group>::POINT as Point>::SCALAR,
) -> TestData<SuiteEd25519> {
    TestData {
        suite: SuiteEd25519::new_blake_sha256ed25519(),
        nb_verifiers: NB_VERIFIERS,
        vss_threshold,
        verifiers_pub,
        verifiers_sec,
        dealer_pub,
        dealer_sec,
        secret,
    }
}

fn default_test_data() -> TestData<SuiteEd25519> {
    let (verifiers_sec, verifiers_pub) = genCommits(NB_VERIFIERS);
    let (dealer_sec, dealer_pub) = genPair();
    let (secret, _) = genPair();
    let vss_threshold = minimum_t(NB_VERIFIERS);
    TestData {
        suite: suite(),
        nb_verifiers: NB_VERIFIERS,
        vss_threshold,
        verifiers_pub,
        verifiers_sec,
        dealer_pub,
        dealer_sec,
        secret,
    }
}

#[test]
fn test_vss_whole() {
    let test_data = default_test_data();

    let (mut dealer, mut verifiers) = genAll(&test_data);

    // 1. dispatch deal
    let mut resps = vec![];
    let enc_deals = dealer.encrypted_deals().unwrap();
    for (i, d) in enc_deals.iter().enumerate() {
        let resp = verifiers[i].process_encrypted_deal(d).unwrap();
        resps.push(resp);
    }

    // 2. dispatch responses
    for resp in resps {
        for (i, v) in verifiers.iter_mut().enumerate() {
            if resp.index == i as u32 {
                continue;
            }
            assert!(v.process_response(&resp).is_ok());
        }
        // 2.1. check dealer (no justification here)
        let justification_response = dealer.process_response(&resp);
        assert!(justification_response.is_ok());
        assert!(justification_response.unwrap().is_none());
    }

    // 3. check certified
    for v in &verifiers {
        assert!(v.deal_certified());
    }

    // 4. collect deals
    let mut deals = Vec::with_capacity(test_data.nb_verifiers);
    for v in verifiers {
        deals.push(v.deal().unwrap());
    }

    // 5. recover
    let sec = RecoverSecret(
        test_data.suite,
        deals,
        test_data.nb_verifiers,
        minimum_t(test_data.nb_verifiers),
    )
    .unwrap();

    assert_eq!(dealer.secret.to_string(), sec.to_string());
}

#[test]
fn TestVSSDealerNew() {
    let test_data = default_test_data();
    let goodT = minimum_t(test_data.nb_verifiers);
    NewDealer(
        test_data.suite,
        test_data.dealer_sec.clone(),
        test_data.secret.clone(),
        &test_data.verifiers_pub,
        goodT,
    )
    .unwrap();

    for badT in [0i32, 1, -4] {
        assert!(
            NewDealer(
                test_data.suite,
                test_data.dealer_sec.clone(),
                test_data.secret.clone(),
                &test_data.verifiers_pub,
                badT as usize,
            )
            .is_err(),
            "threshold {} should result in error",
            badT
        );
    }
}

#[test]
fn TestVSSVerifierNew() {
    let test_data = default_test_data();
    let rand_idx = rand::thread_rng().gen::<usize>() % test_data.verifiers_pub.len();
    let v = NewVerifier(
        test_data.suite,
        test_data.verifiers_sec[rand_idx].clone(),
        test_data.dealer_pub.clone(),
        test_data.verifiers_pub.clone(),
    )
    .unwrap();
    assert_eq!(rand_idx, v.index);

    let wrong_key = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    assert!(NewVerifier(
        test_data.suite.clone(),
        wrong_key,
        test_data.dealer_pub.clone(),
        test_data.verifiers_pub
    )
    .is_err());
}

#[test]
fn TestVSSShare() {
    let test_data = default_test_data();
    let (dealer, mut verifiers) = genAll(&test_data);
    let ver = &mut verifiers[0];
    let deal = dealer.EncryptedDeal(0).unwrap();

    let resp = ver.process_encrypted_deal(&deal).unwrap();
    assert!(resp.approved);

    let aggr = ver.aggregator.as_mut().unwrap();

    for i in 1..aggr.t - 1 {
        ver.aggregator.as_mut().unwrap().responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Response::default()
            },
        );
    }

    ver.SetTimeout();

    // not enough approvals
    assert!(ver.deal().is_none());
    let aggr = ver.aggregator.as_mut().unwrap();
    let idx = aggr.t;
    aggr.responses.insert(
        idx as u32,
        Response {
            approved: true,
            ..Response::default()
        },
    );
    // deal not certified
    aggr.bad_dealer = true;
    assert!(ver.deal().is_none());
    let aggr = ver.aggregator.as_mut().unwrap();
    aggr.bad_dealer = false;

    assert!(ver.deal().is_some());
}

#[test]
fn TestVSSAggregatorEnoughApprovals() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;
    // just below
    for i in 0..aggr.t - 1 {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }

    dealer.set_timeout();
    let aggr = &mut dealer.aggregator;

    // assert.False(t, aggr.EnoughApprovals())
    assert!(!aggr.enough_approvals());
    assert!(dealer.secret_commit().is_none());
    let aggr = &mut dealer.aggregator;

    aggr.responses.insert(
        aggr.t as u32,
        Response {
            approved: true,
            ..Default::default()
        },
    );
    assert!(aggr.enough_approvals());

    // for i := aggr.t + 1; i < nbVerifiers; i++ {
    for i in aggr.t + 1..NB_VERIFIERS {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }
    assert!(aggr.enough_approvals());
    assert_eq!(
        test_data.suite.point().mul(&test_data.clone().secret, None),
        dealer.secret_commit().unwrap()
    );
}

#[test]
fn TestVSSAggregatorDealCertified() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }

    dealer.set_timeout();

    let aggr = &mut dealer.aggregator;
    assert!(aggr.deal_certified());
    assert_eq!(
        test_data.suite.point().mul(&test_data.secret, None),
        dealer.secret_commit().unwrap()
    );
    // bad dealer response
    let aggr = &mut dealer.aggregator;
    aggr.bad_dealer = true;
    assert!(!aggr.deal_certified());
    assert!(dealer.secret_commit().is_none());

    let aggr = &mut dealer.aggregator;
    // inconsistent state on purpose
    // too much complaints
    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: false,
                ..Default::default()
            },
        );
    }
    assert!(!aggr.deal_certified());
}

#[test]
fn TestVSSVerifierDecryptDeal() {
    let test_data = default_test_data();
    let (dealer, verifiers) = genAll(&test_data);
    let v = &verifiers[0];
    let d = &dealer.deals[0];

    // all fine
    let mut encD = dealer.EncryptedDeal(0).unwrap();
    let decD = v.decryptDeal(&encD).unwrap();
    let b1 = d.marshal_binary().unwrap();
    let b2 = decD.marshal_binary().unwrap();
    assert_eq!(b1, b2);

    // wrong dh key
    let goodDh = encD.dhkey;
    encD.dhkey = test_data.suite.point();
    let decD = v.decryptDeal(&encD);
    assert!(decD.is_err());
    encD.dhkey = goodDh;

    // wrong signature
    let goodSig = encD.signature;
    encD.signature = randomBytes(32);
    let decD = v.decryptDeal(&encD);
    assert!(decD.is_err());
    encD.signature = goodSig;

    // wrong ciphertext
    let goodCipher = encD.cipher;
    encD.cipher = randomBytes(goodCipher.len());
    let decD = v.decryptDeal(&encD);
    assert!(decD.is_err());
    encD.cipher = goodCipher;
}

#[test]
fn TestVSSVerifierReceiveDeal() {
    let test_data = default_test_data();
    let (mut dealer, mut verifiers) = genAll(&test_data);

    let mut encD = dealer.EncryptedDeal(0).unwrap();

    let v = &mut verifiers[0];

    // correct deal
    let resp = v.process_encrypted_deal(&encD).unwrap();
    assert!(resp.approved);
    assert_eq!(v.index, resp.index as usize);
    assert_eq!(dealer.sid, resp.session_id);
    schnorr::Verify(
        test_data.suite,
        &v.pubb,
        &resp.hash(test_data.suite).unwrap(),
        &resp.signature,
    )
    .unwrap();
    assert_eq!(v.responses[&((v.index) as u32)], resp);

    // wrong encryption
    let goodSig = encD.signature;
    encD.signature = randomBytes(32);
    let resp = v.process_encrypted_deal(&encD);
    assert!(resp.is_err());
    encD.signature = goodSig;

    let d = &mut dealer.deals[0];

    // wrong index
    let goodIdx = d.sec_share.i;
    d.sec_share.i = (goodIdx - 1) % NB_VERIFIERS;
    let encD = dealer.EncryptedDeal(0).unwrap();
    let resp = v.process_encrypted_deal(&encD);
    assert!(resp.is_err());

    let d = &mut dealer.deals[0];
    d.sec_share.i = goodIdx;

    // wrong commitments
    let goodCommit = d.commitments[0].clone();
    d.commitments[0] = test_data
        .suite
        .point()
        .pick(&mut test_data.suite.random_stream());
    let encD = dealer.EncryptedDeal(0).unwrap();
    let resp = v.process_encrypted_deal(&encD);
    assert!(resp.is_err());

    let d = &mut dealer.deals[0];
    d.commitments[0] = goodCommit.clone();

    // already seen twice
    let resp = v.process_encrypted_deal(&encD);
    assert!(resp.is_err());
    let mut v_aggr = v.aggregator.clone().unwrap();
    v_aggr.deal = None;

    // approval already existing from same origin, should never happen right ?
    v_aggr.responses.insert(
        (v.index) as u32,
        Response {
            approved: true,
            ..Default::default()
        },
    );
    d.commitments[0] = test_data
        .suite
        .point()
        .pick(&mut test_data.suite.random_stream());
    v.aggregator = Some(v_aggr.clone());
    let resp = v.process_encrypted_deal(&encD);
    assert!(resp.is_err());
    d.commitments[0] = goodCommit.clone();

    // valid complaint
    v_aggr.deal = None;
    v_aggr.responses.remove(&(v.index as u32));
    d.rnd_share.v = test_data.suite.scalar().set_bytes(&randomBytes(32));
    v.aggregator = Some(v_aggr.clone());
    let resp = v.process_encrypted_deal(&encD).unwrap();
    assert!(!resp.approved);
}

#[test]
fn TestVSSAggregatorVerifyJustification() {
    let test_data = default_test_data();
    let (mut dealer, mut verifiers) = genAll(&test_data);
    let v = &mut verifiers[0];
    let d = &mut dealer.deals[0];

    let wrongV = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    let goodV = d.sec_share.v.clone();
    d.sec_share.v = wrongV.clone();
    let encD = dealer.EncryptedDeal(0).unwrap();
    let mut resp = v.process_encrypted_deal(&encD).unwrap();
    assert!(!resp.approved);
    assert_eq!(v.responses[&(v.index as u32)], resp);

    // in tests, pointers point to the same underlying share..
    let d = &mut dealer.deals[0];
    d.sec_share.v = goodV;

    let mut j = dealer.process_response(&resp).unwrap().unwrap();

    // invalid deal justified
    let goodV = j.deal.sec_share.v;
    j.deal.sec_share.v = wrongV;
    let result = v.process_justification(&j);
    assert!(result.is_err());
    match &v.aggregator {
        Some(a) => assert!(a.bad_dealer),
        None => panic!("missing aggregtor"),
    }

    j.deal.sec_share.v = goodV;
    match &mut v.aggregator {
        Some(a) => a.bad_dealer = false,
        None => panic!("missing aggregator"),
    }

    // valid complaint
    assert!(v.process_justification(&j).is_ok());

    // invalid complaint
    resp.session_id = randomBytes(resp.session_id.len());
    let badJ = dealer.process_response(&resp);
    assert!(badJ.is_err());
    resp.session_id = dealer.sid.clone();

    // no complaints for this justification before
    match &mut v.aggregator {
        Some(a) => {
            a.responses.remove(&(v.index as u32));
        }
        None => panic!("missing aggregator"),
    }
    assert!(v.process_justification(&j).is_err());
    match &mut v.aggregator {
        Some(a) => {
            a.responses.insert(v.index as u32, resp);
        }
        None => panic!("missing aggregator"),
    }
}

#[test]
fn TestVSSAggregatorVerifyResponseDuplicate() {
    let test_data = default_test_data();
    let (dealer, mut verifiers) = genAll(&test_data);
    let encD1 = dealer.EncryptedDeal(0).unwrap();
    let encD2 = dealer.EncryptedDeal(1).unwrap();

    let resp1 = verifiers[0].process_encrypted_deal(&encD1).unwrap();
    assert!(resp1.approved);

    let resp2 = verifiers[1].process_encrypted_deal(&encD2).unwrap();
    assert!(resp2.approved);

    verifiers[0].process_response(&resp2).unwrap();

    match &verifiers[0].aggregator {
        Some(a) => {
            let r = &a.responses[&(verifiers[1].index as u32)];
            assert_eq!(&resp2, r);
        }
        None => panic!("missing aggregator"),
    }

    let result = verifiers[0].process_response(&resp2);
    assert!(result.is_err());

    let v1_idx = verifiers[1].index as u32;
    match &mut verifiers[0].aggregator {
        Some(a) => {
            a.responses.remove(&v1_idx);
            a.responses.insert(
                v1_idx,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }
        None => panic!("missing aggregator"),
    }
    let result = verifiers[0].process_response(&resp2);
    assert!(result.is_err());
}

#[test]
fn TestVSSAggregatorVerifyResponse() {
    let test_data = default_test_data();
    let (mut dealer, mut verifiers) = genAll(&test_data);
    let v = &mut verifiers[0];
    let deal = &mut dealer.deals[0];
    //goodSec := deal.SecShare.V
    let (wrongSec, _) = genPair();
    deal.sec_share.v = wrongSec;
    let encD = dealer.EncryptedDeal(0).unwrap();
    // valid complaint
    let mut resp = v.process_encrypted_deal(&encD).unwrap();
    assert!(!resp.approved);
    assert!(v.aggregator.is_some());
    assert_eq!(resp.session_id, dealer.sid);

    let aggr = &mut v.aggregator.as_mut().unwrap();
    let r = &aggr.responses[&(v.index as u32)];
    assert!(!r.approved);

    // wrong index
    resp.index = test_data.verifiers_pub.len() as u32;
    let sig = schnorr::Sign(
        &test_data.suite,
        &v.longterm,
        &resp.hash(test_data.suite).unwrap(),
    )
    .unwrap();
    resp.signature = sig;
    assert!(aggr.verify_response(&resp).is_err());
    resp.index = 0;

    // wrong signature
    let goodSig = resp.signature;
    resp.signature = randomBytes(goodSig.len());
    assert!(aggr.verify_response(&resp).is_err());
    resp.signature = goodSig;

    // wrongID
    let wrongID = randomBytes(resp.session_id.len());
    let goodID = resp.session_id;
    resp.session_id = wrongID;
    assert!(aggr.verify_response(&resp).is_err());
    resp.session_id = goodID;
}

#[test]
fn TestVSSAggregatorVerifyDeal() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;
    let deals = &mut dealer.deals;

    // OK
    let deal = &mut deals[0];
    aggr.verify_deal(deal, true).unwrap();
    assert!(aggr.deal.is_some());

    // already received deal
    assert!(aggr.verify_deal(deal, true).is_err());

    // wrong T
    let wrongT = 1u32;
    let goodT = deal.t;
    deal.t = wrongT as usize;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.t = goodT;

    // wrong SessionID
    let goodSid = deal.session_id.clone();
    deal.session_id = vec![0u8; 32];
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.session_id = goodSid;

    // index different in one share
    let goodI = deal.rnd_share.i;
    deal.rnd_share.i = goodI + 1;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.rnd_share.i = goodI;

    // index not in bounds
    deal.sec_share.i = usize::MAX;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.sec_share.i = test_data.verifiers_pub.len();
    assert!(aggr.verify_deal(deal, false).is_err());

    // shares invalid in respect to the commitments
    let (wrongSec, _) = genPair();
    deal.sec_share.v = wrongSec;
    assert!(aggr.verify_deal(deal, false).is_err());
}

#[test]
fn TestVSSAggregatorAddComplaint() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;

    let idx = 1u32;
    let c = Response {
        index: idx,
        approved: false,
        ..Default::default()
    };
    // ok
    assert!(aggr.add_response(c.clone()).is_ok());
    assert_eq!(aggr.responses[&idx], c);

    // response already there
    assert!(aggr.add_response(c).is_err());
    aggr.responses.remove(&idx);
}

#[test]
fn TestVSSAggregatorCleanVerifiers() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }

    assert!(aggr.enough_approvals());
    assert!(!aggr.deal_certified());

    aggr.cleanVerifiers();

    assert!(aggr.deal_certified());
}

#[test]
fn TestVSSDealerSetTimeout() {
    let test_data = default_test_data();
    let mut dealer = genDealer(&test_data);
    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }

    assert!(aggr.enough_approvals());
    assert!(!aggr.deal_certified());

    dealer.set_timeout();

    let aggr = &mut dealer.aggregator;
    assert!(aggr.deal_certified());
}

#[test]
fn TestVSSVerifierSetTimeout() {
    let test_data = default_test_data();
    let (dealer, mut verifiers) = genAll(&test_data);
    let ver = &mut verifiers[0];

    let encD = dealer.EncryptedDeal(0).unwrap();

    let _resp = ver.process_encrypted_deal(&encD).unwrap();

    let aggr = &mut ver.aggregator.as_mut().unwrap();

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                approved: true,
                ..Default::default()
            },
        );
    }

    assert!(aggr.enough_approvals());
    assert!(!aggr.deal_certified());

    ver.SetTimeout();

    let aggr = &mut ver.aggregator.as_mut().unwrap();
    assert!(aggr.deal_certified());
}

#[test]
fn TestVSSSessionID() {
    let test_data = default_test_data();
    let mut dealer = NewDealer(
        test_data.suite.clone(),
        test_data.dealer_sec.clone(),
        test_data.secret.clone(),
        &test_data.verifiers_pub,
        test_data.vss_threshold.clone(),
    )
    .unwrap();
    let commitments = &dealer.deals[0].commitments;
    let sid = sessionID(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();

    let sid2 = sessionID(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();
    assert_eq!(sid, sid2);

    let wrongDealerPub = test_data
        .suite
        .point()
        .add(&test_data.dealer_pub, &test_data.dealer_pub);

    let sid3 = sessionID(
        &test_data.suite,
        &wrongDealerPub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();
    assert_ne!(sid3, sid2);
}

#[test]
fn TestVSSFindPub() {
    let test_data = default_test_data();
    let p = findPub(&test_data.verifiers_pub, 0).unwrap();
    assert_eq!(test_data.verifiers_pub[0], p);

    let p_option = findPub(&test_data.verifiers_pub, test_data.verifiers_pub.len());
    assert!(p_option.is_none());
}

#[test]
fn TestVSSDHExchange() {
    let test_data = default_test_data();
    let pubb = test_data.suite.point().base();
    let privv = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    let point = dhExchange(test_data.suite, privv.clone(), pubb.clone());
    assert_eq!(pubb.mul(&privv, None).string(), point.string());
}

#[test]
fn TestVSSContext() {
    let test_data = default_test_data();
    let c = context(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
    );
    assert_eq!(c.len(), dh::KEY_SIZE);
}

use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::edwards25519::Point as EdPoint;
fn genPair() -> (EdScalar, EdPoint) {
    let suite = suite();
    // let mut s1 = SUITE.scalar();
    // let mut rs1 = SUITE.RandomStream();
    // let secret = s1.pick(&mut rs1);
    // let mut p1 = SUITE.point();
    // let _public = p1.mul(secret, None);
    // (*secret, p1)
    let secret = suite.scalar().pick(&mut suite.random_stream());
    let public = suite.point().mul(&secret, None);
    (secret, public)
}

fn genCommits(n: usize) -> (Vec<EdScalar>, Vec<EdPoint>) {
    let mut secrets = vec![];
    let mut publics = vec![];
    for _ in 0..n {
        let (s, p) = genPair();
        secrets.push(s);
        publics.push(p);
    }
    (secrets, publics)
}

fn genDealer<SUITE: Suite>(test_data: &TestData<SUITE>) -> Dealer<SUITE>
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let test_data = test_data.clone();
    let d = NewDealer(
        test_data.suite,
        test_data.dealer_sec,
        test_data.secret,
        &test_data.verifiers_pub,
        test_data.vss_threshold,
    )
    .unwrap();
    d
}

fn genAll<SUITE: Suite>(test_data: &TestData<SUITE>) -> (Dealer<SUITE>, Vec<Verifier<SUITE>>)
where
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
    SUITE::POINT: Serialize + DeserializeOwned,
{
    let dealer = genDealer(&test_data);
    let mut verifiers = vec![];
    for i in 0..NB_VERIFIERS {
        let v = NewVerifier(
            test_data.suite.clone(),
            test_data.verifiers_sec[i].clone(),
            test_data.dealer_pub.clone(),
            test_data.verifiers_pub.clone(),
        )
        .unwrap();
        verifiers.push(v);
    }
    (dealer, verifiers)
}

fn randomBytes(n: usize) -> Vec<u8> {
    let mut buff = vec![0; n];
    for v in &mut buff {
        *v = rand::random();
    }
    return buff;
}
