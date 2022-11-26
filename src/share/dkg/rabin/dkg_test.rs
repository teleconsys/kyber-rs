use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};

use crate::group::{ScalarCanCheckCanonical, PointCanCheckCanonicalAndSmallOrder};
use crate::share::dkg::rabin::dkg::SecretCommits;
use crate::share::poly::recover_secret;
use crate::{Group, Random};
use crate::{group::edwards25519::SuiteEd25519, Suite, Point, Scalar};

use super::dkg::{DistKeyGenerator, new_dist_key_generator, DistKeyShare};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

struct TestData<SUITE: Suite> 
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned + ScalarCanCheckCanonical,
    SUITE::POINT: Serialize + DeserializeOwned + PointCanCheckCanonicalAndSmallOrder
{
    suite: SUITE,
    nb_participants: usize,

    part_pubs: Vec<SUITE::POINT>,
    part_sec: Vec<<SUITE::POINT as Point>::SCALAR>,

    //dkgs: Vec<DistKeyGenerator<SUITE>>,
}
const NB_PARTICIPANTS: usize = 7;


fn new_test_data<SUITE: Suite>() -> TestData<SuiteEd25519>
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned + ScalarCanCheckCanonical,
    SUITE::POINT: Serialize + DeserializeOwned + PointCanCheckCanonicalAndSmallOrder
{
	let mut part_pubs = Vec::with_capacity(NB_PARTICIPANTS);
    let mut part_sec = Vec::with_capacity(NB_PARTICIPANTS);
	for _ in 0..NB_PARTICIPANTS {
		let (sec, pubb) = genPair();
		part_pubs.push(pubb);
		part_sec.push(sec);
	}

    return TestData::<SuiteEd25519> { suite: suite(), nb_participants: NB_PARTICIPANTS, part_pubs, part_sec }
}

fn dkgGen<SUITE: Suite>(t: &TestData<SUITE>) -> Vec<DistKeyGenerator<SUITE>> 
where
    <SUITE::POINT as Point>::SCALAR: Scalar + Serialize + DeserializeOwned + ScalarCanCheckCanonical,
    SUITE::POINT: Serialize + DeserializeOwned + PointCanCheckCanonicalAndSmallOrder{
	let mut dkgs = Vec::with_capacity(t.nb_participants);
	for i in 0..t.nb_participants{
		let dkg= new_dist_key_generator(t.suite, t.part_sec[i].clone(), t.part_pubs.clone(), t.nb_participants/2+1).unwrap();
		dkgs.push(dkg);
	}
	return dkgs
}

#[test]
fn TestDKGNewDistKeyGenerator() {
    let t = new_test_data::<SuiteEd25519>();
	let long = t.part_sec[0].clone();
	let mut dkg = new_dist_key_generator(t.suite, long, t.part_pubs.clone(), t.nb_participants/2+1).unwrap();
	// quick testing here; easier.
	dkg.secret_commits().unwrap_err();

	let sec = genPair();
	let res = new_dist_key_generator(t.suite, sec.0, t.part_pubs, t.nb_participants/2+1);
    if res.is_ok() {
        panic!("this should fail")
    }


}

// func TestDKGDeal(t *testing.T) {
// 	dkg := dkgs[0]

// 	dks, err := dkg.DistKeyShare()
// 	assert.Error(t, err)
// 	assert.Nil(t, dks)

// 	deals, err := dkg.Deals()
// 	require.Nil(t, err)
// 	assert.Len(t, deals, nbParticipants-1)

// 	for i := range deals {
// 		assert.NotNil(t, deals[i])
// 		assert.Equal(t, uint32(0), deals[i].Index)
// 	}

// 	v, ok := dkg.verifiers[dkg.index]
// 	assert.True(t, ok)
// 	assert.NotNil(t, v)
// }

// func TestDKGProcessDeal(t *testing.T) {
// 	dkgs = dkgGen()
// 	dkg := dkgs[0]
// 	deals, err := dkg.Deals()
// 	require.Nil(t, err)

// 	rec := dkgs[1]
// 	deal := deals[1]
// 	assert.Equal(t, int(deal.Index), 0)
// 	assert.Equal(t, uint32(1), rec.index)

// 	// verifier don't find itself
// 	goodP := rec.participants
// 	rec.participants = make([]kyber.Point, 0)
// 	resp, err := rec.ProcessDeal(deal)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	rec.participants = goodP

// 	// wrong index
// 	goodIdx := deal.Index
// 	deal.Index = uint32(nbParticipants + 1)
// 	resp, err = rec.ProcessDeal(deal)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	deal.Index = goodIdx

// 	// wrong deal
// 	goodSig := deal.Deal.Signature
// 	deal.Deal.Signature = randomBytes(len(deal.Deal.Signature))
// 	resp, err = rec.ProcessDeal(deal)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)
// 	deal.Deal.Signature = goodSig

// 	// good deal
// 	resp, err = rec.ProcessDeal(deal)
// 	assert.NotNil(t, resp)
// 	assert.Equal(t, true, resp.Response.Approved)
// 	assert.Nil(t, err)
// 	_, ok := rec.verifiers[deal.Index]
// 	require.True(t, ok)
// 	assert.Equal(t, uint32(0), resp.Index)

// 	// duplicate
// 	resp, err = rec.ProcessDeal(deal)
// 	assert.Nil(t, resp)
// 	assert.Error(t, err)

// }

// func TestDKGProcessResponse(t *testing.T) {
// 	// first peer generates wrong deal
// 	// second peer processes it and returns a complaint
// 	// first peer process the complaint

// 	dkgs = dkgGen()
// 	dkg := dkgs[0]
// 	idxRec := 1
// 	rec := dkgs[idxRec]
// 	deal, err := dkg.dealer.PlaintextDeal(idxRec)
// 	require.Nil(t, err)

// 	// give a wrong deal
// 	goodSecret := deal.RndShare.V
// 	deal.RndShare.V = suite.Scalar().Zero()
// 	dd, err := dkg.Deals()
// 	encD := dd[idxRec]
// 	require.Nil(t, err)
// 	resp, err := rec.ProcessDeal(encD)
// 	assert.Nil(t, err)
// 	require.NotNil(t, resp)
// 	assert.Equal(t, false, resp.Response.Approved)
// 	deal.RndShare.V = goodSecret
// 	dd, _ = dkg.Deals()
// 	encD = dd[idxRec]

// 	// no verifier tied to Response
// 	v, ok := dkg.verifiers[0]
// 	require.NotNil(t, v)
// 	require.True(t, ok)
// 	require.NotNil(t, v)
// 	delete(dkg.verifiers, 0)
// 	j, err := dkg.ProcessResponse(resp)
// 	assert.Nil(t, j)
// 	assert.NotNil(t, err)
// 	dkg.verifiers[0] = v

// 	// invalid response
// 	goodSig := resp.Response.Signature
// 	resp.Response.Signature = randomBytes(len(goodSig))
// 	j, err = dkg.ProcessResponse(resp)
// 	assert.Nil(t, j)
// 	assert.Error(t, err)
// 	resp.Response.Signature = goodSig

// 	// valid complaint from our deal
// 	j, err = dkg.ProcessResponse(resp)
// 	assert.NotNil(t, j)
// 	assert.Nil(t, err)

// 	// valid complaint from another deal from another peer
// 	dkg2 := dkgs[2]
// 	require.Nil(t, err)
// 	// fake a wrong deal
// 	//deal20, err := dkg2.dealer.PlaintextDeal(0)
// 	//require.Nil(t, err)
// 	deal21, err := dkg2.dealer.PlaintextDeal(1)
// 	require.Nil(t, err)
// 	goodRnd21 := deal21.RndShare.V
// 	deal21.RndShare.V = suite.Scalar().Zero()
// 	deals2, err := dkg2.Deals()
// 	require.Nil(t, err)

// 	resp12, err := rec.ProcessDeal(deals2[idxRec])
// 	assert.NotNil(t, resp)
// 	assert.Equal(t, false, resp12.Response.Approved)

// 	deal21.RndShare.V = goodRnd21
// 	deals2, err = dkg2.Deals()
// 	require.Nil(t, err)

// 	// give it to the first peer
// 	// process dealer 2's deal
// 	r, err := dkg.ProcessDeal(deals2[0])
// 	assert.Nil(t, err)
// 	assert.NotNil(t, r)

// 	// process response from peer 1
// 	j, err = dkg.ProcessResponse(resp12)
// 	assert.Nil(t, j)
// 	assert.Nil(t, err)

// 	// Justification part:
// 	// give the complaint to the dealer
// 	j, err = dkg2.ProcessResponse(resp12)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, j)

// 	// hack because all is local, and resp has been modified locally by dkg2's
// 	// dealer, the status has became "justified"
// 	resp12.Response.Approved = false
// 	err = dkg.ProcessJustification(j)
// 	assert.Nil(t, err)

// 	// remove verifiers
// 	v = dkg.verifiers[j.Index]
// 	delete(dkg.verifiers, j.Index)
// 	err = dkg.ProcessJustification(j)
// 	assert.Error(t, err)
// 	dkg.verifiers[j.Index] = v

// }

// func TestDKGSecretCommits(t *testing.T) {
// 	fullExchange(t)

// 	dkg := dkgs[0]

// 	sc, err := dkg.SecretCommits()
// 	assert.Nil(t, err)
// 	msg := sc.Hash(suite)
// 	assert.Nil(t, schnorr.Verify(suite, dkg.pub, msg, sc.Signature))

// 	dkg2 := dkgs[1]
// 	// wrong index
// 	goodIdx := sc.Index
// 	sc.Index = uint32(nbParticipants + 1)
// 	cc, err := dkg2.ProcessSecretCommits(sc)
// 	assert.Nil(t, cc)
// 	assert.Error(t, err)
// 	sc.Index = goodIdx

// 	// not in qual: delete the verifier
// 	goodV := dkg2.verifiers[uint32(0)]
// 	delete(dkg2.verifiers, uint32(0))
// 	cc, err = dkg2.ProcessSecretCommits(sc)
// 	assert.Nil(t, cc)
// 	assert.Error(t, err)
// 	dkg2.verifiers[uint32(0)] = goodV

// 	// invalid sig
// 	goodSig := sc.Signature
// 	sc.Signature = randomBytes(len(goodSig))
// 	cc, err = dkg2.ProcessSecretCommits(sc)
// 	assert.Nil(t, cc)
// 	assert.Error(t, err)
// 	sc.Signature = goodSig
// 	// invalid session id
// 	goodSid := sc.SessionID
// 	sc.SessionID = randomBytes(len(goodSid))
// 	cc, err = dkg2.ProcessSecretCommits(sc)
// 	assert.Nil(t, cc)
// 	assert.Error(t, err)
// 	sc.SessionID = goodSid

// 	// wrong commitments
// 	goodPoint := sc.Commitments[0]
// 	sc.Commitments[0] = suite.Point().Null()
// 	msg = sc.Hash(suite)
// 	sig, err := schnorr.Sign(suite, dkg.long, msg)
// 	require.Nil(t, err)
// 	goodSig = sc.Signature
// 	sc.Signature = sig
// 	cc, err = dkg2.ProcessSecretCommits(sc)
// 	assert.NotNil(t, cc)
// 	assert.Nil(t, err)
// 	sc.Commitments[0] = goodPoint
// 	sc.Signature = goodSig

// 	// all fine
// 	cc, err = dkg2.ProcessSecretCommits(sc)
// 	assert.Nil(t, cc)
// 	assert.Nil(t, err)
// }

// func TestDKGComplaintCommits(t *testing.T) {
// 	fullExchange(t)

// 	var scs []*SecretCommits
// 	for _, dkg := range dkgs {
// 		sc, err := dkg.SecretCommits()
// 		require.Nil(t, err)
// 		scs = append(scs, sc)
// 	}

// 	for _, sc := range scs {
// 		for _, dkg := range dkgs {
// 			cc, err := dkg.ProcessSecretCommits(sc)
// 			assert.Nil(t, err)
// 			assert.Nil(t, cc)
// 		}
// 	}

// 	// change the sc for the second one
// 	wrongSc := &SecretCommits{}
// 	wrongSc.Index = scs[0].Index
// 	wrongSc.SessionID = scs[0].SessionID
// 	wrongSc.Commitments = make([]kyber.Point, len(scs[0].Commitments))
// 	copy(wrongSc.Commitments, scs[0].Commitments)
// 	//goodScCommit := scs[0].Commitments[0]
// 	wrongSc.Commitments[0] = suite.Point().Null()
// 	msg := wrongSc.Hash(suite)
// 	wrongSc.Signature, _ = schnorr.Sign(suite, dkgs[0].long, msg)

// 	dkg := dkgs[1]
// 	cc, err := dkg.ProcessSecretCommits(wrongSc)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, cc)

// 	dkg2 := dkgs[2]
// 	// ComplaintCommits: wrong index
// 	goodIndex := cc.Index
// 	cc.Index = uint32(nbParticipants)
// 	rc, err := dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)
// 	cc.Index = goodIndex

// 	// invalid signature
// 	goodSig := cc.Signature
// 	cc.Signature = randomBytes(len(cc.Signature))
// 	rc, err = dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)
// 	cc.Signature = goodSig

// 	// no verifiers
// 	v := dkg2.verifiers[uint32(0)]
// 	delete(dkg2.verifiers, uint32(0))
// 	rc, err = dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)
// 	dkg2.verifiers[uint32(0)] = v

// 	// deal does not verify
// 	goodDeal := cc.Deal
// 	cc.Deal = &vss.Deal{
// 		SessionID:   goodDeal.SessionID,
// 		SecShare:    goodDeal.SecShare,
// 		RndShare:    goodDeal.RndShare,
// 		T:           goodDeal.T,
// 		Commitments: goodDeal.Commitments,
// 	}
// 	rc, err = dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)
// 	cc.Deal = goodDeal

// 	//  no commitments
// 	sc := dkg2.commitments[uint32(0)]
// 	delete(dkg2.commitments, uint32(0))
// 	rc, err = dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)
// 	dkg2.commitments[uint32(0)] = sc

// 	// secret commits are passing the check
// 	rc, err = dkg2.ProcessComplaintCommits(cc)
// 	assert.Nil(t, rc)
// 	assert.Error(t, err)

// 	/*
// 		TODO find a way to be the malicious guys,i.e.
// 		make a deal which validates, but revealing the commitments coefficients makes
// 		the check fails.
// 		f is the secret polynomial
// 		g is the "random" one
// 		[f(i) + g(i)]*G == [F + G](i)
// 		but
// 		f(i)*G != F(i)

// 		goodV := cc.Deal.SecShare.V
// 		goodDSig := cc.Deal.Signature
// 		cc.Deal.SecShare.V = suite.Scalar().Zero()
// 		msg = msgDeal(cc.Deal)
// 		sig, _ := sign.Schnorr(suite, dkgs[cc.DealerIndex].long, msg)
// 		cc.Deal.Signature = sig
// 		msg = msgCommitComplaint(cc)
// 		sig, _ = sign.Schnorr(suite, dkgs[cc.Index].long, msg)
// 		goodCCSig := cc.Signature
// 		cc.Signature = sig
// 		rc, err = dkg2.ProcessComplaintCommits(cc)
// 		assert.Nil(t, err)
// 		assert.NotNil(t, rc)
// 		cc.Deal.SecShare.V = goodV
// 		cc.Deal.Signature = goodDSig
// 		cc.Signature = goodCCSig
// 	*/

// }

// func TestDKGReconstructCommits(t *testing.T) {
// 	fullExchange(t)

// 	var scs []*SecretCommits
// 	for _, dkg := range dkgs {
// 		sc, err := dkg.SecretCommits()
// 		require.Nil(t, err)
// 		scs = append(scs, sc)
// 	}

// 	// give the secret commits to all dkgs but the second one
// 	for _, sc := range scs {
// 		for _, dkg := range dkgs[2:] {
// 			cc, err := dkg.ProcessSecretCommits(sc)
// 			assert.Nil(t, err)
// 			assert.Nil(t, cc)
// 		}
// 	}

// 	// peer 1 wants to reconstruct coeffs from dealer 1
// 	rc := &ReconstructCommits{
// 		Index:       1,
// 		DealerIndex: 0,
// 		Share:       dkgs[uint32(1)].verifiers[uint32(0)].Deal().SecShare,
// 		SessionID:   dkgs[uint32(1)].verifiers[uint32(0)].Deal().SessionID,
// 	}
// 	msg := rc.Hash(suite)
// 	rc.Signature, _ = schnorr.Sign(suite, dkgs[1].long, msg)

// 	dkg2 := dkgs[2]
// 	// reconstructed already set
// 	dkg2.reconstructed[0] = true
// 	assert.Nil(t, dkg2.ProcessReconstructCommits(rc))
// 	delete(dkg2.reconstructed, uint32(0))

// 	// commitments not invalidated by any complaints
// 	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
// 	delete(dkg2.commitments, uint32(0))

// 	// invalid index
// 	goodI := rc.Index
// 	rc.Index = uint32(nbParticipants)
// 	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
// 	rc.Index = goodI

// 	// invalid sig
// 	goodSig := rc.Signature
// 	rc.Signature = randomBytes(len(goodSig))
// 	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
// 	rc.Signature = goodSig

// 	// all fine
// 	assert.Nil(t, dkg2.ProcessReconstructCommits(rc))

// 	// packet already received
// 	var found bool
// 	for _, p := range dkg2.pendingReconstruct[rc.DealerIndex] {
// 		if p.Index == rc.Index {
// 			found = true
// 			break
// 		}
// 	}
// 	assert.True(t, found)
// 	assert.False(t, dkg2.Finished())
// 	// generate enough secret commits  to recover the secret
// 	for _, dkg := range dkgs[2:] {
// 		rc = &ReconstructCommits{
// 			SessionID:   dkg.verifiers[uint32(0)].Deal().SessionID,
// 			Index:       dkg.index,
// 			DealerIndex: 0,
// 			Share:       dkg.verifiers[uint32(0)].Deal().SecShare,
// 		}
// 		msg := rc.Hash(suite)
// 		rc.Signature, _ = schnorr.Sign(suite, dkg.long, msg)

// 		if dkg2.reconstructed[uint32(0)] {
// 			break
// 		}
// 		// invalid session ID
// 		goodSID := rc.SessionID
// 		rc.SessionID = randomBytes(len(goodSID))
// 		require.Error(t, dkg2.ProcessReconstructCommits(rc))
// 		rc.SessionID = goodSID

// 		_ = dkg2.ProcessReconstructCommits(rc)
// 	}
// 	assert.True(t, dkg2.reconstructed[uint32(0)])
// 	com := dkg2.commitments[uint32(0)]
// 	assert.NotNil(t, com)
// 	assert.Equal(t, dkgs[0].dealer.SecretCommit().String(), com.Commit().String())

// 	assert.True(t, dkg2.Finished())
// }

// func TestSetTimeout(t *testing.T) {
// 	dkgs = dkgGen()
// 	// full secret sharing exchange
// 	// 1. broadcast deals
// 	resps := make([]*Response, 0, nbParticipants*nbParticipants)
// 	for _, dkg := range dkgs {
// 		deals, err := dkg.Deals()
// 		require.Nil(t, err)
// 		for i, d := range deals {
// 			resp, err := dkgs[i].ProcessDeal(d)
// 			require.Nil(t, err)
// 			require.True(t, resp.Response.Approved)
// 			resps = append(resps, resp)
// 		}
// 	}

// 	// 2. Broadcast responses
// 	for _, resp := range resps {
// 		for _, dkg := range dkgs {
// 			if !dkg.verifiers[resp.Index].EnoughApprovals() {
// 				// ignore messages about ourself
// 				if resp.Response.Index == dkg.index {
// 					continue
// 				}
// 				j, err := dkg.ProcessResponse(resp)
// 				require.Nil(t, err)
// 				require.Nil(t, j)
// 			}
// 		}
// 	}

// 	// 3. make sure everyone has the same QUAL set
// 	for _, dkg := range dkgs {
// 		for _, dkg2 := range dkgs {
// 			require.False(t, dkg.isInQUAL(dkg2.index))
// 		}
// 	}

// 	for _, dkg := range dkgs {
// 		dkg.SetTimeout()
// 	}

// 	for _, dkg := range dkgs {
// 		for _, dkg2 := range dkgs {
// 			require.True(t, dkg.isInQUAL(dkg2.index))
// 		}
// 	}

// }

#[test]
fn TestDistKeyShare() {
	let t = new_test_data::<SuiteEd25519>();
	let mut dkgs =  full_exchange(&t);
	let dkgs_len = dkgs.len();

	let mut scs = vec![];
	for (i, dkg) in dkgs[..dkgs_len-1].iter_mut().enumerate() {
		let sc = dkg.secret_commits().unwrap();
		scs.push((i, sc));
	};
	for (i, dkg) in dkgs[..dkgs_len-1].iter_mut().enumerate() {
		for sc in scs.iter() { 
		if i == sc.0 {
			continue
		}
		let cc = dkg.process_secret_commits(&sc.1).unwrap();
		assert!(cc.is_none());
		}
	}

	// check that we can't get the dist key share before exchanging commit.ents
	let sc: SecretCommits<SuiteEd25519>;
	// NOTE: need a block for the mut reference to dkgs
	{
	let last_dkg = &mut dkgs[dkgs_len-1];
	let res = last_dkg.dist_key_share();
	assert!(res.is_err());

	for sc in scs.iter() {
		let cc = last_dkg.process_secret_commits(&sc.1).unwrap();
		assert!(cc.is_none());
	}

	sc = last_dkg.secret_commits().unwrap();
	//require.NotNil(t, sc)
	}

	for dkg in dkgs[..dkgs_len-1].iter_mut() {
		let sc = dkg.process_secret_commits(&sc).unwrap();
		assert!(sc.is_none());

		assert_eq!(NB_PARTICIPANTS, dkg.qual().len());
		assert_eq!(NB_PARTICIPANTS, dkg.commitments.len());
	}

	// NOTE: need a block for the mut reference to dkgs
	{
	let last_dkg = &mut dkgs[dkgs_len-1];
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
		assert!(check_dks(dks, &dkss[0]), "dist key share not equal {} vs {}", dks.share.i, 0);
		shares.push(Some(dks.share.clone())); 
	}

	let secret = recover_secret(t.suite, &shares, NB_PARTICIPANTS, NB_PARTICIPANTS).unwrap();

	let commit_secret = t.suite.point().mul(&secret, None);
	assert_eq!(dkss[0].public().string(), commit_secret.string())
}



use crate::group::edwards25519::scalar::Scalar as EdScalar;
use crate::group::edwards25519::Point as EdPoint;
fn genPair() -> (EdScalar, EdPoint) {
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
	return buff
}

fn check_dks<POINT: Point>(dks1: &DistKeyShare<POINT>, dks2: &DistKeyShare<POINT>) -> bool {
	if dks1.commits.len() != dks2.commits.len() {
		return false
	}
	for (i, p) in dks1.commits.iter().enumerate() {
		if !p.equal(&dks2.commits[i]) {
			return false
		}
	}
	return true
}

fn full_exchange(t: &TestData<SuiteEd25519>) -> Vec<DistKeyGenerator<SuiteEd25519>>{
	let mut dkgs = dkgGen(t);
	// full secret sharing exchange
	// 1. broadcast deals
    let mut all_deals = Vec::with_capacity(NB_PARTICIPANTS);
	let mut resps = Vec::with_capacity(NB_PARTICIPANTS*NB_PARTICIPANTS);
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
				continue
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

	return dkgs
}
