use rand::{Rng, RngCore};

use crate::random;
use crate::share::vss::rabin::vss::Response;
use crate::{group::edwards25519::SuiteEd25519, Group, Point, Random, Scalar};

use super::vss::{minimum_t, Dealer, NewDealer, NewVerifier, RecoverSecret, Verifier};

// lazy_static! {
//     static ref SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
// }

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

struct TestData<POINT, SCALAR>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
{
    suite: SuiteEd25519,
    nb_verifiers: usize,
    vss_threshold: usize,

    verifiers_pub: Vec<POINT>,
    verifiers_sec: Vec<SCALAR>,

    dealer_pub: POINT,
    dealer_sec: SCALAR,

    secret: SCALAR,
}
const NB_VERIFIERS: usize = 7;

fn new_test_data<POINT, SCALAR>(
    vss_threshold: usize,
    verifiers_pub: Vec<POINT>,
    verifiers_sec: Vec<SCALAR>,
    dealer_pub: POINT,
    dealer_sec: SCALAR,
    secret: SCALAR,
) -> TestData<POINT, SCALAR>
where
    POINT: Point<SCALAR>,
    SCALAR: Scalar,
{
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

fn default_test_data() -> TestData<EdPoint, EdScalar> {
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

    let (dealer, mut verifiers) = genAll();

    // 1. dispatch deal
    let mut resps = Vec::with_capacity(test_data.nb_verifiers); //make([]*Response, nbVerifiers)
    let enc_deals = dealer.encrypted_deals().unwrap();
    for (i, d) in enc_deals.iter().enumerate() {
        let resp = verifiers[i].process_encrypted_deal(d).unwrap();
        resps[i] = resp;
    }

    // 2. dispatch responses
    for resp in resps {
        for (i, v) in verifiers.iter().enumerate() {
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
    for (i, v) in verifiers.iter().enumerate() {
        deals[i] = v.deal().unwrap();
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
        test_data.verifiers_pub.clone(),
        goodT,
    )
    .unwrap();

    for badT in [0i32, 1, -4] {
        assert!(
            NewDealer(
                test_data.suite,
                test_data.dealer_sec.clone(),
                test_data.secret.clone(),
                test_data.verifiers_pub.clone(),
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
        test_data.dealer_pub,
        test_data.verifiers_pub.clone(),
    )
    .unwrap();
    assert_eq!(rand_idx, v.index);

    let wrong_key = test_data
        .suite
        .scalar()
        .pick(&mut test_data.suite.random_stream());
    assert!(NewVerifier(
        test_data.suite,
        wrong_key,
        test_data.dealer_pub,
        test_data.verifiers_pub
    )
    .is_err());
}

#[test]
fn TestVSSShare() {
    let (dealer, mut verifiers) = genAll();
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

// func TestVSSAggregatorEnoughApprovals(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator
// 	// just below
// 	for i := 0; i < aggr.t-1; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	dealer.SetTimeout()

// 	assert.False(t, aggr.EnoughApprovals())
// 	assert.Nil(t, dealer.SecretCommit())

// 	aggr.responses[uint32(aggr.t)] = &Response{Approved: true}
// 	assert.True(t, aggr.EnoughApprovals())

// 	for i := aggr.t + 1; i < nbVerifiers; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}
// 	assert.True(t, aggr.EnoughApprovals())
// 	assert.Equal(t, suite.Point().Mul(secret, nil), dealer.SecretCommit())
// }

// func TestVSSAggregatorDealCertified(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator

// 	for i := 0; i < aggr.t; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	dealer.SetTimeout()

// 	assert.True(t, aggr.DealCertified())
// 	assert.Equal(t, suite.Point().Mul(secret, nil), dealer.SecretCommit())
// 	// bad dealer response
// 	aggr.badDealer = true
// 	assert.False(t, aggr.DealCertified())
// 	assert.Nil(t, dealer.SecretCommit())
// 	// inconsistent state on purpose
// 	// too much complaints
// 	for i := 0; i < aggr.t; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: false}
// 	}
// 	assert.False(t, aggr.DealCertified())
// }

// func TestVSSVerifierDecryptDeal(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	v := verifiers[0]
// 	d := dealer.deals[0]

// 	// all fine
// 	encD, err := dealer.EncryptedDeal(0)
// 	require.Nil(t, err)
// 	decD, err := v.decryptDeal(encD)
// 	require.Nil(t, err)
// 	b1, _ := protobuf.Encode(d)
// 	b2, _ := protobuf.Encode(decD)
// 	assert.Equal(t, b1, b2)

// 	// wrong dh key
// 	goodDh := encD.DHKey
// 	encD.DHKey = suite.Point()
// 	decD, err = v.decryptDeal(encD)
// 	assert.Error(t, err)
// 	assert.Nil(t, decD)
// 	encD.DHKey = goodDh

// 	// wrong signature
// 	goodSig := encD.Signature
// 	encD.Signature = randomBytes(32)
// 	decD, err = v.decryptDeal(encD)
// 	assert.Error(t, err)
// 	assert.Nil(t, decD)
// 	encD.Signature = goodSig

// 	// wrong ciphertext
// 	goodCipher := encD.Cipher
// 	encD.Cipher = randomBytes(len(goodCipher))
// 	decD, err = v.decryptDeal(encD)
// 	assert.Error(t, err)
// 	assert.Nil(t, decD)
// 	encD.Cipher = goodCipher
// }

// func TestVSSVerifierReceiveDeal(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	v := verifiers[0]
// 	d := dealer.deals[0]

// 	encD, err := dealer.EncryptedDeal(0)
// 	require.Nil(t, err)

// 	// correct deal
// 	resp, err := v.ProcessEncryptedDeal(encD)
// 	require.NotNil(t, resp)
// 	assert.Equal(t, true, resp.Approved)
// 	assert.Nil(t, err)
// 	assert.Equal(t, v.index, int(resp.Index))
// 	assert.Equal(t, dealer.sid, resp.SessionID)
// 	assert.Nil(t, schnorr.Verify(suite, v.pub, resp.Hash(suite), resp.Signature))
// 	assert.Equal(t, v.responses[uint32(v.index)], resp)

// 	// wrong encryption
// 	goodSig := encD.Signature
// 	encD.Signature = randomBytes(32)
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	encD.Signature = goodSig

// 	// wrong index
// 	goodIdx := d.SecShare.I
// 	d.SecShare.I = (goodIdx - 1) % nbVerifiers
// 	encD, _ = dealer.EncryptedDeal(0)
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.Error(t, err)
// 	assert.Nil(t, resp)
// 	d.SecShare.I = goodIdx

// 	// wrong commitments
// 	goodCommit := d.Commitments[0]
// 	d.Commitments[0] = suite.Point().Pick(suite.RandomStream())
// 	encD, _ = dealer.EncryptedDeal(0)
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.Error(t, err)
// 	assert.Nil(t, resp)
// 	d.Commitments[0] = goodCommit

// 	// already seen twice
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	v.aggregator.deal = nil

// 	// approval already existing from same origin, should never happen right ?
// 	v.aggregator.responses[uint32(v.index)] = &Response{Approved: true}
// 	d.Commitments[0] = suite.Point().Pick(suite.RandomStream())
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	d.Commitments[0] = goodCommit

// 	// valid complaint
// 	v.aggregator.deal = nil
// 	delete(v.aggregator.responses, uint32(v.index))
// 	d.RndShare.V = suite.Scalar().SetBytes(randomBytes(32))
// 	resp, err = v.ProcessEncryptedDeal(encD)
// 	assert.NotNil(t, resp)
// 	assert.Equal(t, false, resp.Approved)
// 	assert.Nil(t, err)
// }

// func TestVSSAggregatorVerifyJustification(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	v := verifiers[0]
// 	d := dealer.deals[0]

// 	wrongV := suite.Scalar().Pick(suite.RandomStream())
// 	goodV := d.SecShare.V
// 	d.SecShare.V = wrongV
// 	encD, _ := dealer.EncryptedDeal(0)
// 	resp, err := v.ProcessEncryptedDeal(encD)
// 	assert.NotNil(t, resp)
// 	assert.Equal(t, false, resp.Approved)
// 	assert.Nil(t, err)
// 	assert.Equal(t, v.responses[uint32(v.index)], resp)
// 	// in tests, pointers point to the same underlying share..
// 	d.SecShare.V = goodV

// 	j, err := dealer.ProcessResponse(resp)

// 	// invalid deal justified
// 	goodV = j.Deal.SecShare.V
// 	j.Deal.SecShare.V = wrongV
// 	err = v.ProcessJustification(j)
// 	assert.Error(t, err)
// 	assert.True(t, v.aggregator.badDealer)
// 	j.Deal.SecShare.V = goodV
// 	v.aggregator.badDealer = false

// 	// valid complaint
// 	assert.Nil(t, v.ProcessJustification(j))

// 	// invalid complaint
// 	resp.SessionID = randomBytes(len(resp.SessionID))
// 	badJ, err := dealer.ProcessResponse(resp)
// 	assert.Nil(t, badJ)
// 	assert.Error(t, err)
// 	resp.SessionID = dealer.sid

// 	// no complaints for this justification before
// 	delete(v.aggregator.responses, uint32(v.index))
// 	assert.Error(t, v.ProcessJustification(j))
// 	v.aggregator.responses[uint32(v.index)] = resp

// }

// func TestVSSAggregatorVerifyResponseDuplicate(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	v1 := verifiers[0]
// 	v2 := verifiers[1]
// 	//d1 := dealer.deals[0]
// 	//d2 := dealer.deals[1]
// 	encD1, _ := dealer.EncryptedDeal(0)
// 	encD2, _ := dealer.EncryptedDeal(1)

// 	resp1, err := v1.ProcessEncryptedDeal(encD1)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, resp1)
// 	assert.Equal(t, true, resp1.Approved)

// 	resp2, err := v2.ProcessEncryptedDeal(encD2)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, resp2)
// 	assert.Equal(t, true, resp2.Approved)

// 	err = v1.ProcessResponse(resp2)
// 	assert.Nil(t, err)
// 	r, ok := v1.aggregator.responses[uint32(v2.index)]
// 	assert.True(t, ok)
// 	assert.Equal(t, resp2, r)

// 	err = v1.ProcessResponse(resp2)
// 	assert.Error(t, err)

// 	delete(v1.aggregator.responses, uint32(v2.index))
// 	v1.aggregator.responses[uint32(v2.index)] = &Response{Approved: true}
// 	err = v1.ProcessResponse(resp2)
// 	assert.Error(t, err)
// }

// func TestVSSAggregatorVerifyResponse(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	v := verifiers[0]
// 	deal := dealer.deals[0]
// 	//goodSec := deal.SecShare.V
// 	wrongSec, _ := genPair()
// 	deal.SecShare.V = wrongSec
// 	encD, _ := dealer.EncryptedDeal(0)
// 	// valid complaint
// 	resp, err := v.ProcessEncryptedDeal(encD)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, resp)
// 	assert.Equal(t, false, resp.Approved)
// 	assert.NotNil(t, v.aggregator)
// 	assert.Equal(t, resp.SessionID, dealer.sid)

// 	aggr := v.aggregator
// 	r, ok := aggr.responses[uint32(v.index)]
// 	assert.True(t, ok)
// 	assert.Equal(t, false, r.Approved)

// 	// wrong index
// 	resp.Index = uint32(len(verifiersPub))
// 	sig, err := schnorr.Sign(suite, v.longterm, resp.Hash(suite))
// 	resp.Signature = sig
// 	assert.Error(t, aggr.verifyResponse(resp))
// 	resp.Index = 0

// 	// wrong signature
// 	goodSig := resp.Signature
// 	resp.Signature = randomBytes(len(goodSig))
// 	assert.Error(t, aggr.verifyResponse(resp))
// 	resp.Signature = goodSig

// 	// wrongID
// 	wrongID := randomBytes(len(resp.SessionID))
// 	goodID := resp.SessionID
// 	resp.SessionID = wrongID
// 	assert.Error(t, aggr.verifyResponse(resp))
// 	resp.SessionID = goodID
// }

// func TestVSSAggregatorVerifyDeal(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator
// 	deals := dealer.deals

// 	// OK
// 	deal := deals[0]
// 	err := aggr.VerifyDeal(deal, true)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, aggr.deal)

// 	// already received deal
// 	err = aggr.VerifyDeal(deal, true)
// 	assert.Error(t, err)

// 	// wrong T
// 	wrongT := uint32(1)
// 	goodT := deal.T
// 	deal.T = wrongT
// 	assert.Error(t, aggr.VerifyDeal(deal, false))
// 	deal.T = goodT

// 	// wrong SessionID
// 	goodSid := deal.SessionID
// 	deal.SessionID = make([]byte, 32)
// 	assert.Error(t, aggr.VerifyDeal(deal, false))
// 	deal.SessionID = goodSid

// 	// index different in one share
// 	goodI := deal.RndShare.I
// 	deal.RndShare.I = goodI + 1
// 	assert.Error(t, aggr.VerifyDeal(deal, false))
// 	deal.RndShare.I = goodI

// 	// index not in bounds
// 	deal.SecShare.I = -1
// 	assert.Error(t, aggr.VerifyDeal(deal, false))
// 	deal.SecShare.I = len(verifiersPub)
// 	assert.Error(t, aggr.VerifyDeal(deal, false))

// 	// shares invalid in respect to the commitments
// 	wrongSec, _ := genPair()
// 	deal.SecShare.V = wrongSec
// 	assert.Error(t, aggr.VerifyDeal(deal, false))
// }

// func TestVSSAggregatorAddComplaint(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator

// 	var idx uint32 = 1
// 	c := &Response{
// 		Index:    idx,
// 		Approved: false,
// 	}
// 	// ok
// 	assert.Nil(t, aggr.addResponse(c))
// 	assert.Equal(t, aggr.responses[idx], c)

// 	// response already there
// 	assert.Error(t, aggr.addResponse(c))
// 	delete(aggr.responses, idx)

// }

// func TestVSSAggregatorCleanVerifiers(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator

// 	for i := 0; i < aggr.t; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	assert.True(t, aggr.EnoughApprovals())
// 	assert.False(t, aggr.DealCertified())

// 	aggr.cleanVerifiers()

// 	assert.True(t, aggr.DealCertified())
// }

// func TestVSSDealerSetTimeout(t *testing.T) {
// 	dealer := genDealer()
// 	aggr := dealer.aggregator

// 	for i := 0; i < aggr.t; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	assert.True(t, aggr.EnoughApprovals())
// 	assert.False(t, aggr.DealCertified())

// 	dealer.SetTimeout()

// 	assert.True(t, aggr.DealCertified())
// }

// func TestVSSVerifierSetTimeout(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	ver := verifiers[0]

// 	encD, err := dealer.EncryptedDeal(0)

// 	require.Nil(t, err)

// 	resp, err := ver.ProcessEncryptedDeal(encD)

// 	require.Nil(t, err)
// 	require.NotNil(t, resp)

// 	aggr := ver.aggregator

// 	for i := 0; i < aggr.t; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	assert.True(t, aggr.EnoughApprovals())
// 	assert.False(t, aggr.DealCertified())

// 	ver.SetTimeout()

// 	assert.True(t, aggr.DealCertified())
// }

// func TestVSSSessionID(t *testing.T) {
// 	dealer, _ := NewDealer(suite, dealerSec, secret, verifiersPub, vssThreshold)
// 	commitments := dealer.deals[0].Commitments
// 	sid, err := sessionID(suite, dealerPub, verifiersPub, commitments, dealer.t)
// 	assert.NoError(t, err)

// 	sid2, err2 := sessionID(suite, dealerPub, verifiersPub, commitments, dealer.t)
// 	assert.NoError(t, err2)
// 	assert.Equal(t, sid, sid2)

// 	wrongDealerPub := suite.Point().Add(dealerPub, dealerPub)

// 	sid3, err3 := sessionID(suite, wrongDealerPub, verifiersPub, commitments, dealer.t)
// 	assert.NoError(t, err3)
// 	assert.NotEqual(t, sid3, sid2)
// }

// func TestVSSFindPub(t *testing.T) {
// 	p, ok := findPub(verifiersPub, 0)
// 	assert.True(t, ok)
// 	assert.Equal(t, verifiersPub[0], p)

// 	p, ok = findPub(verifiersPub, uint32(len(verifiersPub)))
// 	assert.False(t, ok)
// 	assert.Nil(t, p)
// }

// func TestVSSDHExchange(t *testing.T) {
// 	pub := suite.Point().Base()
// 	priv := suite.Scalar().Pick(suite.RandomStream())
// 	point := dhExchange(suite, priv, pub)
// 	assert.Equal(t, pub.Mul(priv, nil).String(), point.String())
// }

// func TestVSSContext(t *testing.T) {
// 	c := context(suite, dealerPub, verifiersPub)
// 	assert.Len(t, c, keySize)
// }

use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::edwards25519::Point as EdPoint;
fn genPair() -> (EdScalar, EdPoint) {
    let SUITE = suite();
    // let mut s1 = SUITE.scalar();
    // let mut rs1 = SUITE.RandomStream();
    // let secret = s1.pick(&mut rs1);
    // let mut p1 = SUITE.point();
    // let _public = p1.mul(secret, None);
    // (*secret, p1)
    let secret = SUITE.scalar().pick(&mut SUITE.random_stream());
    let public = SUITE.point().mul(&secret, None);
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

fn genDealer() -> Dealer<EdScalar, SuiteEd25519, EdPoint> {
    let test_data = default_test_data();
    let d = NewDealer(
        test_data.suite,
        test_data.dealer_sec,
        test_data.secret,
        test_data.verifiers_pub,
        test_data.vss_threshold,
    )
    .unwrap();
    d
}

fn genAll() -> (
    Dealer<EdScalar, SuiteEd25519, EdPoint>,
    Vec<Verifier<EdScalar, EdPoint, SuiteEd25519>>,
) {
    let test_data = default_test_data();
    let dealer = genDealer();
    let mut verifiers = vec![];
    for i in 0..NB_VERIFIERS {
        let v = NewVerifier(
            test_data.suite,
            test_data.verifiers_sec[i].clone(),
            test_data.dealer_pub,
            test_data.verifiers_pub.clone(),
        )
        .unwrap();
        verifiers.push(v);
    }
    (dealer, verifiers)
}

// func randomBytes(n int) []byte {
// 	var buff = make([]byte, n)
// 	_, err := rand.Read(buff)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return buff
// }
