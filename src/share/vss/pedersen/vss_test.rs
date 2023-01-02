use digest::DynDigest;
use rand::Rng;

use crate::{
    dh::Dh,
    encoding::BinaryMarshaler,
    group::{
        edwards25519::{Point as EdPoint, Scalar as EdScalar, SuiteEd25519},
        HashFactory,
    },
    share::vss::{
        pedersen::vss::{self, recover_secret, Response, STATUS_APPROVAL, STATUS_COMPLAINT},
        pedersen::vss::{find_pub, session_id},
        suite::Suite,
    },
    sign::schnorr,
    Group, Point, Random, Scalar,
};

use super::vss::{minimum_t, new_dealer, new_verifier, Dealer, Verifier};

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

fn new_test_data() -> TestData<SuiteEd25519> {
    let (verifiers_sec, verifiers_pub) = gen_commits(NB_VERIFIERS);
    let (dealer_sec, dealer_pub) = gen_pair();
    let (secret, _) = gen_pair();
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
    let test_data = new_test_data();

    let (mut dealer, mut verifiers) = gen_all(&test_data);

    // 1. dispatch deal
    let mut resps = vec![];
    let enc_deals = dealer.encrypted_deals().unwrap();
    for (i, d) in enc_deals.iter().enumerate() {
        let resp = verifiers[i].process_encrypted_deal(d).unwrap();
        resps.push(resp);
    }

    // 2. dispatch responses
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
    // 5. recover
    let sec = recover_secret(
        test_data.suite,
        deals,
        test_data.nb_verifiers,
        minimum_t(test_data.nb_verifiers),
    )
    .unwrap();
    assert_eq!(dealer.secret.to_string(), sec.to_string());

    let pri_poly = dealer.private_poly();
    let pri_coeffs = pri_poly.coefficients();
    assert_eq!(test_data.secret.string(), pri_coeffs[0].string())
}

#[test]
fn test_vss_dealer_new() {
    let test_data = new_test_data();
    let good_t = minimum_t(test_data.nb_verifiers);
    new_dealer(
        test_data.suite,
        test_data.dealer_sec.clone(),
        test_data.secret.clone(),
        &test_data.verifiers_pub,
        good_t,
    )
    .unwrap();

    for bad_t in [0i32, 1, -4] {
        assert!(
            new_dealer(
                test_data.suite,
                test_data.dealer_sec.clone(),
                test_data.secret.clone(),
                &test_data.verifiers_pub,
                bad_t as usize,
            )
            .is_err(),
            "threshold {} should result in error",
            bad_t
        );
    }
}

#[test]
fn test_vss_verifier_new() {
    let test_data = new_test_data();
    let rand_idx = rand::thread_rng().gen::<usize>() % test_data.verifiers_pub.len();
    let v = new_verifier(
        &test_data.suite,
        &test_data.verifiers_sec[rand_idx],
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
    )
    .unwrap();
    assert_eq!(rand_idx, v.index);

    let wrong_key = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    assert!(new_verifier(
        &test_data.suite,
        &wrong_key,
        &test_data.dealer_pub,
        &test_data.verifiers_pub
    )
    .is_err());
}

#[test]
fn test_vss_share() {
    let test_data = new_test_data();
    let (dealer, mut verifiers) = gen_all(&test_data);
    let ver = &mut verifiers[0];
    let deal = dealer.encrypted_deal(0).unwrap();

    let resp = ver.process_encrypted_deal(&deal).unwrap();
    assert_eq!(resp.status, STATUS_APPROVAL);

    let aggr = ver.aggregator.as_mut().unwrap();

    for i in 1..aggr.t - 1 {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Response::default()
            },
        );
    }

    // not enough approvals
    assert!(ver.deal().is_none());
    let aggr = ver.aggregator.as_mut().unwrap();
    aggr.responses.insert(
        aggr.t as u32,
        Response {
            status: STATUS_APPROVAL,
            ..Response::default()
        },
    );

    ver.set_timeout();

    // deal not certified
    let aggr = ver.aggregator.as_mut().unwrap();
    aggr.bad_dealer = true;
    assert!(ver.deal().is_none());
    let aggr = ver.aggregator.as_mut().unwrap();
    aggr.bad_dealer = false;

    assert!(ver.deal().is_some());
}

#[test]
fn test_vss_aggregator_deal_certified() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Default::default()
            },
        );
    }

    // Mark remaining verifiers as timed-out
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

    // reset dealer status
    let aggr = &mut dealer.aggregator;
    aggr.bad_dealer = false;

    // inconsistent state on purpose
    // too much complaints
    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_COMPLAINT,
                ..Default::default()
            },
        );
    }
    assert!(!aggr.deal_certified());
}

#[test]
fn test_vss_verifier_decrypt_deal() {
    let test_data = new_test_data();
    let (dealer, verifiers) = gen_all(&test_data);
    let v = &verifiers[0];
    let d = &dealer.deals[0];

    // all fine
    let mut enc_d = dealer.encrypted_deal(0).unwrap();
    let dec_d = v.decrypt_deal(&enc_d).unwrap();
    let b1 = d.marshal_binary().unwrap();
    let b2 = dec_d.marshal_binary().unwrap();
    assert_eq!(b1, b2);

    // wrong dh key
    let good_dh = enc_d.dhkey;
    enc_d.dhkey = test_data.suite.point();
    let dec_d = v.decrypt_deal(&enc_d);
    assert!(dec_d.is_err());
    enc_d.dhkey = good_dh;

    // wrong signature
    let good_sig = enc_d.signature;
    enc_d.signature = random_bytes(32);
    let dec_d = v.decrypt_deal(&enc_d);
    assert!(dec_d.is_err());
    enc_d.signature = good_sig;

    // wrong ciphertext
    let good_cipher = enc_d.cipher;
    enc_d.cipher = random_bytes(good_cipher.len());
    let dec_d = v.decrypt_deal(&enc_d);
    assert!(dec_d.is_err());
    enc_d.cipher = good_cipher;
}

#[test]
fn test_vss_verifier_receive_deal() {
    let test_data = new_test_data();
    let (mut dealer, mut verifiers) = gen_all(&test_data);

    let mut enc_d = dealer.encrypted_deal(0).unwrap();

    let v = &mut verifiers[0];

    // correct deal
    let resp = v.process_encrypted_deal(&enc_d).unwrap();
    assert_eq!(resp.status, STATUS_APPROVAL);
    assert_eq!(v.index, resp.index as usize);
    assert_eq!(dealer.sid, resp.session_id);
    schnorr::verify(
        test_data.suite,
        &v.pubb,
        &resp.hash(&test_data.suite).unwrap(),
        &resp.signature,
    )
    .unwrap();
    assert_eq!(v.responses[&((v.index) as u32)], resp);

    // wrong encryption
    let good_sig = enc_d.signature;
    enc_d.signature = random_bytes(32);
    let resp = v.process_encrypted_deal(&enc_d);
    assert!(resp.is_err());
    enc_d.signature = good_sig;

    let d = &mut dealer.deals[0];

    // wrong index
    let good_idx = d.sec_share.i;
    d.sec_share.i = (good_idx - 1) % NB_VERIFIERS;
    let enc_d = dealer.encrypted_deal(0).unwrap();
    let resp = v.process_encrypted_deal(&enc_d);
    assert!(resp.is_err());

    let d = &mut dealer.deals[0];
    d.sec_share.i = good_idx;

    // wrong commitments
    let good_commit = d.commitments[0].clone();
    d.commitments[0] = test_data
        .suite
        .point()
        .pick(&mut test_data.suite.random_stream());
    let enc_d = dealer.encrypted_deal(0).unwrap();
    let resp = v.process_encrypted_deal(&enc_d);
    assert!(resp.is_err());

    let d = &mut dealer.deals[0];
    d.commitments[0] = good_commit.clone();

    // already seen twice
    let resp = v.process_encrypted_deal(&enc_d);
    assert!(resp.is_err());
    let mut v_aggr = v.aggregator.clone().unwrap();
    v_aggr.deal = None;

    // approval already existing from same origin, should never happen right ?
    v_aggr.responses.insert(
        (v.index) as u32,
        Response {
            status: STATUS_APPROVAL,
            ..Default::default()
        },
    );
    d.commitments[0] = test_data
        .suite
        .point()
        .pick(&mut test_data.suite.random_stream());
    v.aggregator = Some(v_aggr.clone());
    let resp = v.process_encrypted_deal(&enc_d);
    assert!(resp.is_err());
    d.commitments[0] = good_commit;

    // valid complaint
    v_aggr.deal = None;
    v_aggr.responses.remove(&(v.index as u32));
    v.aggregator = Some(v_aggr.clone());
    let resp = v.process_encrypted_deal(&enc_d).unwrap();
    assert_eq!(resp.status, STATUS_COMPLAINT);
}

#[test]
fn test_vss_aggregator_verify_justification() {
    let test_data = new_test_data();
    let (mut dealer, mut verifiers) = gen_all(&test_data);
    let v = &mut verifiers[0];
    let d = &mut dealer.deals[0];

    let wrong_v = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    let good_v = d.sec_share.v.clone();
    d.sec_share.v = wrong_v.clone();
    let enc_d = dealer.encrypted_deal(0).unwrap();
    let mut resp = v.process_encrypted_deal(&enc_d).unwrap();
    assert_eq!(resp.status, STATUS_COMPLAINT);
    assert_eq!(v.responses[&(v.index as u32)], resp);

    // in tests, pointers point to the same underlying share..
    let d = &mut dealer.deals[0];
    d.sec_share.v = good_v;

    let mut j = dealer.process_response(&resp).unwrap().unwrap();

    // invalid deal justified
    let good_v = j.deal.sec_share.v;
    j.deal.sec_share.v = wrong_v;
    let result = v.process_justification(&j);
    assert!(result.is_err());
    match &v.aggregator {
        Some(a) => assert!(a.bad_dealer),
        None => panic!("missing aggregator"),
    }

    j.deal.sec_share.v = good_v;
    match &mut v.aggregator {
        Some(a) => a.bad_dealer = false,
        None => panic!("missing aggregator"),
    }

    // valid complaint
    assert!(v.process_justification(&j).is_ok());

    // invalid complaint
    resp.session_id = random_bytes(resp.session_id.len());
    let bad_j = dealer.process_response(&resp);
    assert!(bad_j.is_err());
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
fn test_vss_aggregator_verify_response_duplicate() {
    let test_data = new_test_data();
    let (dealer, mut verifiers) = gen_all(&test_data);
    let enc_d1 = dealer.encrypted_deal(0).unwrap();
    let enc_d2 = dealer.encrypted_deal(1).unwrap();

    let resp1 = verifiers[0].process_encrypted_deal(&enc_d1).unwrap();
    assert_eq!(resp1.status, STATUS_APPROVAL);

    let resp2 = verifiers[1].process_encrypted_deal(&enc_d2).unwrap();
    assert_eq!(resp2.status, STATUS_APPROVAL);

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
                    status: STATUS_APPROVAL,
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
fn test_vss_aggregator_verify_response() {
    let test_data = new_test_data();
    let (mut dealer, mut verifiers) = gen_all(&test_data);
    let v = &mut verifiers[0];
    let deal = &mut dealer.deals[0];
    //goodSec := deal.SecShare.V
    let (wrong_sec, _) = gen_pair();
    deal.sec_share.v = wrong_sec;
    let enc_d = dealer.encrypted_deal(0).unwrap();
    // valid complaint
    let mut resp = v.process_encrypted_deal(&enc_d).unwrap();
    assert_eq!(resp.status, STATUS_COMPLAINT);
    assert!(v.aggregator.is_some());
    assert_eq!(resp.session_id, dealer.sid);

    let aggr = &mut v.aggregator.as_mut().unwrap();
    let r = &aggr.responses[&(v.index as u32)];
    assert_eq!(r.status, STATUS_COMPLAINT);

    // wrong index
    resp.index = test_data.verifiers_pub.len() as u32;
    let sig = schnorr::sign(
        &test_data.suite,
        &v.longterm,
        &resp.hash(&test_data.suite).unwrap(),
    )
    .unwrap();
    resp.signature = sig;
    assert!(aggr.verify_response(&resp).is_err());
    resp.index = 0;

    // wrong signature
    let good_sig = resp.signature;
    resp.signature = random_bytes(good_sig.len());
    assert!(aggr.verify_response(&resp).is_err());
    resp.signature = good_sig;

    // wrongID
    let wrong_id = random_bytes(resp.session_id.len());
    let good_id = resp.session_id;
    resp.session_id = wrong_id;
    assert!(aggr.verify_response(&resp).is_err());
    resp.session_id = good_id;
}

#[test]
fn test_vss_aggregator_all_responses() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Default::default()
            },
        );
    }
    assert!(!aggr.deal_certified());

    for i in aggr.t..test_data.nb_verifiers {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Default::default()
            },
        );
    }

    assert!(aggr.deal_certified());
    assert_eq!(
        test_data.suite.point().mul(&test_data.secret, None),
        dealer.secret_commit().unwrap()
    )
}

#[test]
fn test_vss_dealer_timeout() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);

    let aggr = &mut dealer.aggregator;

    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Default::default()
            },
        );
    }
    assert!(!aggr.deal_certified());

    // Tell dealer to consider other verifiers timed-out
    dealer.set_timeout();

    // Deal should be certified
    let aggr = &mut dealer.aggregator;
    assert!(aggr.deal_certified());
    assert!(dealer.secret_commit().is_some());
}

#[test]
fn test_vss_verifier_timeout() {
    let test_data = new_test_data();
    let (dealer, mut verifiers) = gen_all(&test_data);
    let v = &mut verifiers[0];

    let enc_deal = dealer.encrypted_deal(0).unwrap();

    // Make verifier create it's Aggregator by processing EncDeal
    _ = v.process_encrypted_deal(&enc_deal).unwrap();

    let aggr = v.aggregator.as_mut().unwrap();

    // Add t responses
    for i in 0..aggr.t {
        aggr.responses.insert(
            i as u32,
            Response {
                status: STATUS_APPROVAL,
                ..Default::default()
            },
        );
    }
    assert!(!aggr.deal_certified());

    // Trigger time out, thus adding StatusComplaint to all
    // remaining verifiers
    v.set_timeout();

    // Deal must be certified now
    let aggr = v.aggregator.as_mut().unwrap();
    assert!(aggr.deal_certified());
    assert!(v.deal().is_some());
}

#[test]
fn test_vss_aggregator_verify_deal() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
    let aggr = &mut dealer.aggregator;
    let deals = &mut dealer.deals;

    // OK
    let deal = &mut deals[0];
    aggr.verify_deal(deal, true).unwrap();
    assert!(aggr.deal.is_some());

    // already received deal
    assert!(aggr.verify_deal(deal, true).is_err());

    // wrong T
    let wrong_t = 1u32;
    let good_t = deal.t;
    deal.t = wrong_t as usize;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.t = good_t;

    // wrong SessionID
    let good_sid = deal.session_id.clone();
    deal.session_id = vec![0u8; 32];
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.session_id = good_sid;

    // index different in one share
    let good_i = deal.sec_share.i;
    deal.sec_share.i = good_i + 1;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.sec_share.i = good_i;

    // index not in bounds
    deal.sec_share.i = usize::MAX;
    assert!(aggr.verify_deal(deal, false).is_err());
    deal.sec_share.i = test_data.verifiers_pub.len();
    assert!(aggr.verify_deal(deal, false).is_err());

    // shares invalid in respect to the commitments
    let (wrong_sec, _): (EdScalar, EdPoint) = gen_pair();
    deal.sec_share.v = wrong_sec;
    assert!(aggr.verify_deal(deal, false).is_err());
}

#[test]
fn test_vss_aggregator_add_complaint() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
    let aggr = &mut dealer.aggregator;

    let idx = 1u32;
    let c = Response {
        index: idx,
        status: STATUS_COMPLAINT,
        ..Default::default()
    };
    // ok
    assert!(aggr.add_response(&c).is_ok());
    assert_eq!(aggr.responses[&idx], c);

    // response already there
    assert!(aggr.add_response(&c).is_err());
    aggr.responses.remove(&idx);
}

#[test]
fn test_vss_session_id() {
    let test_data = new_test_data();
    let dealer = new_dealer(
        test_data.suite,
        test_data.dealer_sec.clone(),
        test_data.secret.clone(),
        &test_data.verifiers_pub,
        test_data.vss_threshold,
    )
    .unwrap();
    let commitments = &dealer.deals[0].commitments;
    let sid = session_id(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();

    let sid2 = session_id(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();
    assert_eq!(sid, sid2);

    let wrong_dealer_pub = test_data
        .suite
        .point()
        .add(&test_data.dealer_pub, &test_data.dealer_pub);

    let sid3 = session_id(
        &test_data.suite,
        &wrong_dealer_pub,
        &test_data.verifiers_pub,
        commitments,
        dealer.t,
    )
    .unwrap();
    assert_ne!(sid3, sid2);
}

#[test]
fn test_vss_find_pub() {
    let test_data = new_test_data();
    let p = find_pub(&test_data.verifiers_pub, 0).unwrap();
    assert_eq!(test_data.verifiers_pub[0], p);

    let p_option = find_pub(&test_data.verifiers_pub, test_data.verifiers_pub.len());
    assert!(p_option.is_none());
}

#[test]
fn test_vss_dhexchange() {
    let test_data = new_test_data();
    let pubb = test_data.suite.point().base();
    let privv = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    let point = SuiteEd25519::dh_exchange(test_data.suite, privv.clone(), pubb.clone());
    assert_eq!(pubb.mul(&privv, None).string(), point.string());
}

#[test]
fn test_vss_context() {
    let test_data = new_test_data();
    let c = vss::context(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
    );
    assert_eq!(c.len(), test_data.suite.hash().output_size());
}

fn gen_pair() -> (EdScalar, EdPoint) {
    let suite = suite();
    let secret = suite.scalar().pick(&mut suite.random_stream());
    let public = suite.point().mul(&secret, None);
    (secret, public)
}

fn gen_commits(n: usize) -> (Vec<EdScalar>, Vec<EdPoint>) {
    let mut secrets = vec![];
    let mut publics = vec![];
    for _ in 0..n {
        let (s, p) = gen_pair();
        secrets.push(s);
        publics.push(p);
    }
    (secrets, publics)
}

fn gen_dealer<SUITE: Suite>(test_data: &TestData<SUITE>) -> Dealer<SUITE> {
    let test_data = test_data.clone();
    new_dealer(
        test_data.suite,
        test_data.dealer_sec,
        test_data.secret,
        &test_data.verifiers_pub,
        test_data.vss_threshold,
    )
    .unwrap()
}

fn gen_all<SUITE: Suite>(test_data: &TestData<SUITE>) -> (Dealer<SUITE>, Vec<Verifier<SUITE>>) {
    let dealer = gen_dealer(test_data);
    let mut verifiers = vec![];
    for i in 0..NB_VERIFIERS {
        let v = new_verifier(
            &test_data.suite,
            &test_data.verifiers_sec[i],
            &test_data.dealer_pub,
            &test_data.verifiers_pub,
        )
        .unwrap();
        verifiers.push(v);
    }
    (dealer, verifiers)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buff = vec![0; n];
    for v in &mut buff {
        *v = rand::random();
    }
    buff
}
