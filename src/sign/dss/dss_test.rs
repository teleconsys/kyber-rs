use core::panic;

use rand::Rng;

use crate::{
    group::{
        edwards25519::SuiteEd25519, PointCanCheckCanonicalAndSmallOrder, ScalarCanCheckCanonical,
    },
    share::dkg,
    sign::{dss::DSSError, eddsa, schnorr},
    Group, Point, Random, Scalar,
};

use super::{new_dss, verify, DistKeyShare, Suite, DSS};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake3_sha256_ed25519()
}

struct TestData<SUITE: Suite, DKS: DistKeyShare<SUITE>> {
    suite: SUITE,
    nb_participants: usize,

    part_pubs: Vec<SUITE::POINT>,
    part_sec: Vec<<SUITE::POINT as Point>::SCALAR>,

    longterms: Vec<DKS>,
    randoms: Vec<DKS>,
}
const NB_PARTICIPANTS: usize = 7;

fn new_test_data() -> TestData<SuiteEd25519, dkg::rabin::DistKeyShare<SuiteEd25519>> {
    let mut part_pubs = Vec::with_capacity(NB_PARTICIPANTS);
    let mut part_sec = Vec::with_capacity(NB_PARTICIPANTS);
    for _ in 0..NB_PARTICIPANTS {
        let (sec, pubb) = gen_pair();
        part_pubs.push(pubb);
        part_sec.push(sec);
    }
    let longterms = gen_dist_secret(&part_sec, &part_pubs, suite());
    let randoms = gen_dist_secret(&part_sec, &part_pubs, suite());

    TestData::<SuiteEd25519, dkg::rabin::DistKeyShare<SuiteEd25519>> {
        suite: suite(),
        nb_participants: NB_PARTICIPANTS,
        part_pubs,
        part_sec,
        longterms,
        randoms,
    }
}

#[test]
fn test_dss_new() {
    let t = new_test_data();
    new_dss(
        t.suite,
        &t.part_sec[0],
        &t.part_pubs,
        &t.longterms[0],
        &t.randoms[0],
        "hello".as_bytes(),
        4,
    )
    .unwrap();

    let res = new_dss(
        t.suite,
        &t.suite.scalar().zero(),
        &t.part_pubs,
        &t.longterms[0],
        &t.randoms[0],
        "hello".as_bytes(),
        4,
    );
    assert!(res.is_err());
}

#[test]
#[allow(unused_assignments)]
fn test_dss_partial_sigs() {
    let t = new_test_data();
    let mut dss0 = get_dss(&t, 0);
    let mut dss1 = get_dss(&t, 1);
    let mut ps0 = dss0.partial_sig().unwrap();
    assert_eq!(dss0.partials.len(), 1);
    // second time should not affect list
    ps0 = dss0.partial_sig().unwrap();
    assert_eq!(dss0.partials.len(), 1);

    // wrong index
    let good_i = ps0.partial.i;
    ps0.partial.i = 100;
    assert!(dss1.process_partial_sig(ps0.clone()).is_err());
    ps0.partial.i = good_i;

    // wrong Signature
    let good_sig = ps0.signature.clone();
    ps0.signature = random_bytes(ps0.signature.len());
    assert!(dss1.process_partial_sig(ps0.clone()).is_err());
    ps0.signature = good_sig.clone();

    // invalid partial sig
    let good_v = ps0.partial.v;
    ps0.partial.v = t.suite.scalar().zero();
    ps0.signature = schnorr::sign(&t.suite, &dss0.secret, &ps0.hash(t.suite).unwrap()).unwrap();
    if let Err(DSSError::InvalidPartialSignature) = dss1.process_partial_sig(ps0.clone()) {
    } else {
        panic!("partial signature should be invalid")
    };

    ps0.partial.v = good_v;
    ps0.signature = good_sig;

    // fine
    dss1.process_partial_sig(ps0.clone()).unwrap();

    // already received
    dss1.process_partial_sig(ps0).unwrap_err();

    // if not enough partial signatures, can't generate signature
    if let Err(DSSError::NotEnoughPartials) = dss1.signature() {
    } else {
        panic!("should not have enough partial signatures")
    };

    // enough partial sigs ?
    for i in 2..t.nb_participants {
        let mut dss = get_dss(&t, i);
        let ps = dss.partial_sig().unwrap();
        dss1.process_partial_sig(ps).unwrap()
    }
    assert!(dss1.enough_partial_sig())
}

#[test]
fn test_dss_signature() {
    let t = new_test_data();
    let mut dsss = Vec::with_capacity(t.nb_participants);
    let mut pss = Vec::with_capacity(t.nb_participants);
    for i in 0..t.nb_participants {
        dsss.push(get_dss(&t, i));
        let ps = dsss[i].partial_sig().unwrap();
        pss.push(ps);
    }
    for (i, dss) in dsss.iter_mut().enumerate() {
        for (j, ps) in pss.iter().enumerate() {
            if i == j {
                continue;
            }
            assert!(dss.process_partial_sig(ps.clone()).is_ok());
        }
    }
    // issue and verify signature
    let dss0 = &mut dsss[0];
    let buff = dss0.signature().unwrap();
    assert!(!buff.is_empty());
    eddsa::verify(&t.longterms[0].public(), &dss0.msg, &buff).unwrap();
    verify(&t.longterms[0].public(), &dss0.msg, &buff).unwrap();
}

fn get_dss<SUITE: Suite, DKS: DistKeyShare<SUITE>>(
    t: &TestData<SUITE, DKS>,
    i: usize,
) -> DSS<SUITE, DKS> {
    let dss: DSS<SUITE, DKS> = new_dss(
        t.suite.clone(),
        &t.part_sec[i],
        &t.part_pubs,
        &t.longterms[i],
        &t.randoms[i],
        "hello".as_bytes(),
        t.nb_participants / 2 + 1,
    )
    .unwrap();
    dss
}

fn gen_dist_secret<SUITE: crate::share::vss::suite::Suite>(
    part_sec: &[<SUITE::POINT as Point>::SCALAR],
    part_pubs: &[SUITE::POINT],
    suite: SUITE,
) -> Vec<dkg::rabin::DistKeyShare<SUITE>>
where
    <SUITE::POINT as Point>::SCALAR: ScalarCanCheckCanonical,
    SUITE::POINT: PointCanCheckCanonicalAndSmallOrder,
{
    let mut dkgs = Vec::with_capacity(NB_PARTICIPANTS);
    (0..NB_PARTICIPANTS).for_each(|i| {
        let dkg = dkg::rabin::new_dist_key_generator::<SUITE>(
            &suite,
            &part_sec[i],
            part_pubs,
            NB_PARTICIPANTS / 2 + 1,
        )
        .unwrap();
        dkgs.push(dkg);
    });
    // full secret sharing exchange
    // 1. broadcast deals
    let mut all_deals = Vec::new();
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
        for (h, dkg) in dkgs.iter_mut().enumerate() {
            // ignore all messages from ourself
            if resp.response.index == h as u32 {
                continue;
            }
            let j = dkg.process_response(&resp).unwrap();
            assert!(j.is_none(), "wrong process_response");
        }
    }
    // 4. Broadcast secret commitment
    let mut all_scs = Vec::new();
    for (i, dkg) in dkgs.iter_mut().enumerate() {
        let scs = dkg.secret_commits().expect("wrong secret_commits");
        all_scs.push((i, scs));
    }
    for scs in all_scs {
        for (i, dkg) in dkgs.iter_mut().enumerate() {
            if i == scs.0 {
                continue;
            }
            let cc = dkg.process_secret_commits(&scs.1).unwrap();
            assert!(cc.is_none(), "wrong process_secret_commits");
        }
    }

    // 5. reveal shares
    let mut dkss = Vec::with_capacity(dkgs.len());
    for dkg in dkgs.iter_mut() {
        let dks = dkg.dist_key_share().unwrap();
        dkss.push(dks);
    }
    dkss
}

use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::edwards25519::Point as EdPoint;
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
