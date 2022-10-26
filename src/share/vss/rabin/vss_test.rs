use crypto::signature::Verifier;
use lazy_static::lazy_static;

use crate::{group::edwards25519::SuiteEd25519, Group, Point, Random, Scalar};

use super::vss::{Dealer, NewDealer, Suite};

// lazy_static! {
//     static ref SUITE: SuiteEd25519 = SuiteEd25519::new_blake_sha256ed25519();
// }

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

struct TestData<POINT, SCALAR>
where
    SCALAR: Scalar,
    POINT: Point,
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
    POINT: Point,
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

fn default_test_data() {
    let (verifiersSec, verifiersPub) = genCommits(NB_VERIFIERS);
    // let dealerSec, dealerPub = genPair();
    // let secret, _ = genPair();
    // let vssThreshold = MinimumT(nbVerifiers);
}

// func init() {
// 	verifiersSec, verifiersPub = genCommits(nbVerifiers)
// 	dealerSec, dealerPub = genPair()
// 	secret, _ = genPair()
// 	vssThreshold = MinimumT(nbVerifiers)
// }

// #[test]
// fn TestVSSWhole() {
// 	dealer, verifiers := genAll()

// 	// 1. dispatch deal
// 	resps := make([]*Response, nbVerifiers)
// 	encDeals, err := dealer.EncryptedDeals()
// 	require.Nil(t, err)
// 	for i, d := range encDeals {
// 		resp, err := verifiers[i].ProcessEncryptedDeal(d)
// 		require.Nil(t, err)
// 		resps[i] = resp
// 	}

// 	// 2. dispatch responses
// 	for _, resp := range resps {
// 		for i, v := range verifiers {
// 			if resp.Index == uint32(i) {
// 				continue
// 			}
// 			require.Nil(t, v.ProcessResponse(resp))
// 		}
// 		// 2.1. check dealer (no justification here)
// 		j, err := dealer.ProcessResponse(resp)
// 		require.Nil(t, err)
// 		require.Nil(t, j)
// 	}

// 	// 3. check certified
// 	for _, v := range verifiers {
// 		require.True(t, v.DealCertified())
// 	}

// 	// 4. collect deals
// 	deals := make([]*Deal, nbVerifiers)
// 	for i, v := range verifiers {
// 		deals[i] = v.Deal()
// 	}

// 	// 5. recover
// 	sec, err := RecoverSecret(suite, deals, nbVerifiers, MinimumT(nbVerifiers))
// 	assert.Nil(t, err)
// 	require.NotNil(t, sec)
// 	assert.Equal(t, dealer.secret.String(), sec.String())
// }

// func TestVSSDealerNew(t *testing.T) {
// 	goodT := MinimumT(nbVerifiers)
// 	_, err := NewDealer(suite, dealerSec, secret, verifiersPub, goodT)
// 	assert.NoError(t, err)

// 	for _, badT := range []int{0, 1, -4} {
// 		_, err = NewDealer(suite, dealerSec, secret, verifiersPub, badT)
// 		assert.Error(t, err)
// 	}
// }

// func TestVSSVerifierNew(t *testing.T) {
// 	randIdx := rand.Int() % len(verifiersPub)
// 	v, err := NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub)
// 	assert.NoError(t, err)
// 	assert.Equal(t, randIdx, v.index)

// 	wrongKey := suite.Scalar().Pick(suite.RandomStream())
// 	_, err = NewVerifier(suite, wrongKey, dealerPub, verifiersPub)
// 	assert.Error(t, err)
// }

// func TestVSSShare(t *testing.T) {
// 	dealer, verifiers := genAll()
// 	ver := verifiers[0]
// 	deal, err := dealer.EncryptedDeal(0)
// 	require.Nil(t, err)

// 	resp, err := ver.ProcessEncryptedDeal(deal)
// 	require.NotNil(t, resp)
// 	require.Equal(t, true, resp.Approved)
// 	require.Nil(t, err)

// 	aggr := ver.aggregator

// 	for i := 1; i < aggr.t-1; i++ {
// 		aggr.responses[uint32(i)] = &Response{Approved: true}
// 	}

// 	ver.SetTimeout()

// 	// not enough approvals
// 	assert.Nil(t, ver.Deal())
// 	aggr.responses[uint32(aggr.t)] = &Response{Approved: true}
// 	// deal not certified
// 	aggr.badDealer = true
// 	assert.Nil(t, ver.Deal())
// 	aggr.badDealer = false

// 	assert.NotNil(t, ver.Deal())

// }

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
    let mut s1 = SUITE.scalar();
    let mut rs1 = SUITE.RandomStream();
    let secret = s1.pick(&mut rs1);
    let mut p1 = SUITE.point();
    let _public = p1.mul(secret, None);
    (*secret, p1)
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

// fn genDealer() -> *Dealer {
//     let test_data = default_test_data();
//     NewDealer(suite, longterm, secret, verifiers, t);
// 	d, _ := NewDealer(suite, dealerSec, secret, verifiersPub, vssThreshold)
// 	return d
// }

// fn genAll() -> (Dealer, Vec<Verifier>) {
// 	dealer := genDealer()
// 	// var verifiers = make([]*Verifier, nbVerifiers)
// 	// for i := 0; i < nbVerifiers; i++ {
// 	// 	v, _ := NewVerifier(suite, verifiersSec[i], dealerPub, verifiersPub)
// 	// 	verifiers[i] = v
// 	// }
// 	// return dealer, verifiers
// }

// func randomBytes(n int) []byte {
// 	var buff = make([]byte, n)
// 	_, err := rand.Read(buff)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return buff
// }
