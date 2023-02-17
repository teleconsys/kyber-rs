use rand::Rng;
use vss::KEY_SIZE;

use crate::{
    dh::{Dh, DhError},
    encoding::BinaryMarshaler,
    group::edwards25519::{Point as EdPoint, Scalar as EdScalar, SuiteEd25519},
    share::vss::{
        rabin::vss::{self, find_pub, new_verifier, recover_secret, session_id, Response},
        suite::Suite, VSSError,
    },
    sign::{schnorr, error::SignatureError},
    Group, Point, Random, Scalar,
};

use super::vss::{minimum_t, new_dealer, Dealer, Verifier};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake3_sha256_ed25519()
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
    let sec = recover_secret(
        test_data.suite,
        deals,
        test_data.nb_verifiers,
        minimum_t(test_data.nb_verifiers),
    )
    .unwrap();

    assert_eq!(dealer.secret.to_string(), sec.to_string());
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
        if let Err(VSSError::InvalidThreshold(_)) = new_dealer(
            test_data.suite,
            test_data.dealer_sec.clone(),
            test_data.secret.clone(),
            &test_data.verifiers_pub,
            bad_t as usize,
        ) {
        } else {
            panic!("threshold {bad_t} should result in error");
        }
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
    if let Err(VSSError::PublicKeyNotFound) = new_verifier(
        &test_data.suite,
        &wrong_key,
        &test_data.dealer_pub,
        &test_data.verifiers_pub
    ) {
    } else {
        panic!("public key {wrong_key:?} should not be valid");
    }
}

#[test]
fn test_vss_share() {
    let test_data = new_test_data();
    let (dealer, mut verifiers) = gen_all(&test_data);
    let ver = &mut verifiers[0];
    let deal = dealer.encrypted_deal(0).unwrap();

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

    ver.set_timeout();

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
fn test_vss_aggregator_enough_approvals() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
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
        test_data.suite.point().mul(&test_data.secret, None),
        dealer.secret_commit().unwrap()
    );
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
    // TODO: fix this check
    let good_dh = enc_d.dhkey;
    enc_d.dhkey = test_data.suite.point();
    if let Err(VSSError::SignatureError(SignatureError::InvalidSignature(_))) = v.decrypt_deal(&enc_d) {
    } else {
        panic!("dh key should be invalid")
    };
    enc_d.dhkey = good_dh;

    // wrong signature
    // TODO: fix this check
    let good_sig = enc_d.signature;
    enc_d.signature = random_bytes(32);
    if v.decrypt_deal(&enc_d).is_err() {
    } else {
        panic!("signature should be wrong")
    };
    enc_d.signature = good_sig;

    // wrong ciphertext
    let good_cipher = enc_d.cipher;
    enc_d.cipher = random_bytes(good_cipher.len());
    if let Err(VSSError::DhError(DhError::DecryptionFailed(_))) = v.decrypt_deal(&enc_d) {
    } else {
        panic!("decryption should fail")
    };
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
    assert!(resp.approved);
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
    // TODO: fix this check
    let good_sig = enc_d.signature;
    enc_d.signature = random_bytes(32);
    if v.process_encrypted_deal(&enc_d).is_err() {
    } else {
        panic!("encryption should be invalid")
    };
    enc_d.signature = good_sig;

    let d = &mut dealer.deals[0];

    // wrong index
    let good_idx = d.sec_share.i;
    d.sec_share.i = (good_idx - 1) % NB_VERIFIERS;
    let enc_d = dealer.encrypted_deal(0).unwrap();
    if let Err(VSSError::DealWrongIndex) = v.process_encrypted_deal(&enc_d) {
    } else {
        panic!("deal's index should be wrong")
    };

    let d = &mut dealer.deals[0];
    d.sec_share.i = good_idx;

    // wrong commitments
    // TODO: fix this check
    let good_commit = d.commitments[0].clone();
    d.commitments[0] = test_data
        .suite
        .point()
        .pick(&mut test_data.suite.random_stream());
    let enc_d = dealer.encrypted_deal(0).unwrap();
    if v.process_encrypted_deal(&enc_d).is_err() {
    } else {
        panic!("commitments should be wrong")
    };

    let d = &mut dealer.deals[0];
    d.commitments[0] = good_commit.clone();

    // already seen twice
    if let Err(VSSError::DealAlreadyProcessed) = v.process_encrypted_deal(&enc_d) {
    } else {
        panic!("signature length should be invalid")
    };
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
    if let Err(VSSError::ResponseAlreadyExisting) = v.process_encrypted_deal(&enc_d) {
    } else {
        panic!("response should already exitst")
    };
    d.commitments[0] = good_commit;

    // valid complaint
    v_aggr.deal = None;
    v_aggr.responses.remove(&(v.index as u32));
    d.rnd_share.v = test_data.suite.scalar().set_bytes(&random_bytes(32));
    v.aggregator = Some(v_aggr.clone());
    let resp = v.process_encrypted_deal(&enc_d).unwrap();
    assert!(!resp.approved);
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
    assert!(!resp.approved);
    assert_eq!(v.responses[&(v.index as u32)], resp);

    // in tests, pointers point to the same underlying share..
    let d = &mut dealer.deals[0];
    d.sec_share.v = good_v;

    let mut j = dealer.process_response(&resp).unwrap().unwrap();

    // invalid deal justified
    let good_v = j.deal.sec_share.v;
    j.deal.sec_share.v = wrong_v;
    if let Err(VSSError::DealDoesNotVerify) = v.process_justification(&j) {
        assert!(v.clone().aggregator.unwrap().bad_dealer)
    } else {
        panic!("justified deal should be invalid")
    };

    j.deal.sec_share.v = good_v;
    match &mut v.aggregator {
        Some(a) => a.bad_dealer = false,
        None => panic!("missing aggregator"),
    }

    // valid complaint
    assert!(v.process_justification(&j).is_ok());

    // invalid complaint
    resp.session_id = random_bytes(resp.session_id.len());
    if let Err(VSSError::ResponseInconsistentSessionId) = dealer.process_response(&resp) {
    } else {
        panic!("complaint should be invalid")
    };
    resp.session_id = dealer.sid.clone();

    // no complaints for this justification before
    match &mut v.aggregator {
        Some(a) => {
            a.responses.remove(&(v.index as u32));
        }
        None => panic!("missing aggregator"),
    }
    if let Err(VSSError::JustificationNoComplaints) = v.process_justification(&j) {
    } else {
        panic!("justification should not have complaints")
    };
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
    assert!(resp1.approved);

    let resp2 = verifiers[1].process_encrypted_deal(&enc_d2).unwrap();
    assert!(resp2.approved);

    verifiers[0].process_response(&resp2).unwrap();

    match &verifiers[0].aggregator {
        Some(a) => {
            let r = &a.responses[&(verifiers[1].index as u32)];
            assert_eq!(&resp2, r);
        }
        None => panic!("missing aggregator"),
    }

    if let Err(VSSError::ResponseAlreadyExisting) = verifiers[0].process_response(&resp2) {
    } else {
        panic!("should be already existing")
    };

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
    if let Err(VSSError::ResponseAlreadyExisting) = verifiers[0].process_response(&resp2) {
    } else {
        panic!("should be already existing")
    };
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
    assert!(!resp.approved);
    assert!(v.aggregator.is_some());
    assert_eq!(resp.session_id, dealer.sid);

    let aggr = &mut v.aggregator.as_mut().unwrap();
    let r = &aggr.responses[&(v.index as u32)];
    assert!(!r.approved);

    // wrong index
    resp.index = test_data.verifiers_pub.len() as u32;
    let sig = schnorr::sign(
        &test_data.suite,
        &v.longterm,
        &resp.hash(&test_data.suite).unwrap(),
    )
    .unwrap();
    resp.signature = sig;
    if let Err(VSSError::ResponseIndexOutOfBounds) = aggr.verify_response(&resp) {
    } else {
        panic!("should be wrong index")
    };
    resp.index = 0;

    // wrong signature
    let good_sig = resp.signature;
    resp.signature = random_bytes(good_sig.len());
    if let Err(VSSError::SignatureError(_)) = aggr.verify_response(&resp) {
    } else {
        panic!("signature should not be valid")
    };
    resp.signature = good_sig;

    // wrongID
    let wrong_id = random_bytes(resp.session_id.len());
    let good_id = resp.session_id;
    resp.session_id = wrong_id;
    if let Err(VSSError::ResponseInconsistentSessionId) = aggr.verify_response(&resp) {
    } else {
        panic!("id should be wrong")
    };
    resp.session_id = good_id;
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
    if let Err(VSSError::DealAlreadyProcessed) = aggr.verify_deal(deal, true) {
    } else {
        panic!("deal should be already processed")
    };

    // wrong T
    let wrong_t = 1u32;
    let good_t = deal.t;
    deal.t = wrong_t as usize;
    if let Err(VSSError::DealInvalidThreshold) = aggr.verify_deal(deal, false) {
    } else {
        panic!("threshold should be invalid")
    };
    deal.t = good_t;

    // wrong SessionID
    let good_sid = deal.session_id.clone();
    deal.session_id = vec![0u8; 32];
    if let Err(VSSError::DealInvalidSessionId) = aggr.verify_deal(deal, false) {
    } else {
        panic!("session id should be invalid")
    };
    deal.session_id = good_sid;

    // index different in one share
    let good_i = deal.rnd_share.i;
    deal.rnd_share.i = good_i + 1;
    if let Err(VSSError::DealInconsistentIndex) = aggr.verify_deal(deal, false) {
    } else {
        panic!("session id should be invalid")
    };
    deal.rnd_share.i = good_i;

    // index not in bounds
    //TODO: fix this check
    deal.sec_share.i = usize::MAX;
    if aggr.verify_deal(deal, false).is_err() {
    } else {
        panic!("index should not be in bounds")
    };
    deal.sec_share.i = test_data.verifiers_pub.len();
    if aggr.verify_deal(deal, false).is_err() {
    } else {
        panic!("index should not be in bounds")
    };

    // shares invalid in respect to the commitments
    //TODO: fix this check
    let (wrong_sec, _): (EdScalar, EdPoint) = gen_pair();
    deal.sec_share.v = wrong_sec;
    if aggr.verify_deal(deal, false).is_err() {
    } else {
        panic!("shares should be invalid")
    };
}

#[test]
fn test_vss_aggregator_add_complaint() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
    let aggr = &mut dealer.aggregator;

    let idx = 1u32;
    let c = Response {
        index: idx,
        approved: false,
        ..Default::default()
    };
    // ok
    assert!(aggr.add_response(&c).is_ok());
    assert_eq!(aggr.responses[&idx], c);

    // response already there
    if let Err(VSSError::ResponseAlreadyExisting) = aggr.add_response(&c) {
    } else {
        panic!("response should already be there")
    };
    aggr.responses.remove(&idx);
}

#[test]
fn test_vss_aggregator_clean_verifiers() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
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

    aggr.clean_verifiers();

    assert!(aggr.deal_certified());
}

#[test]
fn test_vss_dealer_set_timeout() {
    let test_data = new_test_data();
    let mut dealer = gen_dealer(&test_data);
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
fn test_vss_verifier_set_timeout() {
    let test_data = new_test_data();
    let (dealer, mut verifiers) = gen_all(&test_data);
    let ver = &mut verifiers[0];

    let enc_d = dealer.encrypted_deal(0).unwrap();

    let _resp = ver.process_encrypted_deal(&enc_d).unwrap();

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

    ver.set_timeout();

    let aggr = &mut ver.aggregator.as_mut().unwrap();
    assert!(aggr.deal_certified());
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
    assert_eq!(pubb.mul(&privv, None).to_string(), point.to_string());
}

#[test]
fn test_vss_context() {
    let test_data = new_test_data();
    let c = vss::context(
        &test_data.suite,
        &test_data.dealer_pub,
        &test_data.verifiers_pub,
    );
    assert_eq!(c.len(), KEY_SIZE);
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
