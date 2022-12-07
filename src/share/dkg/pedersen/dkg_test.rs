// Note: if you are looking for a complete scenario that shows DKG in action
// please have a look at examples/dkg_test.go

use std::{io::Read, collections::HashMap};

use crate::{group::{edwards25519::SuiteEd25519, edwards25519::{Point as EdPoint, Scalar as EdScalar}, ScalarCanCheckCanonical, PointCanCheckCanonicalAndSmallOrder}, share::{vss, self}, Suite, Point, Group, Scalar, Random};
use lazy_static::lazy_static;
use rand::Rng;
use serde::{Serialize, de::DeserializeOwned, Deserialize};

use super::dkg::{DistKeyGenerator, new_dist_key_generator, Config, new_dist_key_handler};

fn suite() -> SuiteEd25519 {
    SuiteEd25519::new_blake_sha256ed25519()
}

const DEFAULT_N: usize = 5;

lazy_static!{
    static ref DEFAULT_T: usize = vss::pedersen::vss::minimum_t(DEFAULT_N);
}

fn generate(n: usize, t: usize) -> (Vec<EdPoint>, Vec<EdScalar>, Vec<DistKeyGenerator<SuiteEd25519, &'static [u8]>>) 
{
	let mut part_pubs = Vec::with_capacity(n);
    let mut part_sec = Vec::with_capacity(n);
    for _ in 0..n {
        let (sec, pubb) = gen_pair();
        part_pubs.push(pubb);
        part_sec.push(sec);
    }
	let mut dkgs = Vec::with_capacity(n);
	for i in 0..n {
		let dkg = new_dist_key_generator(suite(), part_sec[i].clone(), &part_pubs, t).unwrap();
		dkgs.push(dkg);
	}
	return (part_pubs, part_sec, dkgs)
}

#[test]
fn test_dkg_new_dist_key_generator() {
	let (part_pubs, part_sec, _) = generate(DEFAULT_N, *DEFAULT_T);

	let long = part_sec[0].clone();
	let dkg: DistKeyGenerator<SuiteEd25519, &'static [u8]> = new_dist_key_generator(suite(), long, &part_pubs, *DEFAULT_T).unwrap();
	assert!(dkg.can_issue);
    assert!(dkg.can_receive);
    assert!(dkg.new_present);
	// because we set old = new
	assert!(dkg.old_present);
    assert!(!dkg.is_resharing);

	let (sec, _) = gen_pair();
	let dkg_res = new_dist_key_generator::<SuiteEd25519, &'static [u8]>(suite(), sec.clone(), &part_pubs, *DEFAULT_T);
	assert!(dkg_res.is_err());

    let dkg_res = new_dist_key_generator::<SuiteEd25519, &'static [u8]>(suite(), sec, &vec![], *DEFAULT_T);
	assert_eq!(dkg_res.err().unwrap().to_string(), "dkg: can't run with empty node list");
}

#[test]
fn test_dkg_deal() {
	let (_, _, mut dkgs) = generate(DEFAULT_N, *DEFAULT_T);
	let dkg = &mut dkgs[0];

	let dks_res = dkg.dist_key_share();
    assert!(dks_res.is_err());

	let deals = dkg.deals().unwrap();
	assert_eq!(deals.len(), DEFAULT_N-1);

	for i in 1..DEFAULT_N {
        assert!(deals.contains_key(&i));
        assert_eq!(deals.get(&i).unwrap().index, 0);
	}

    assert!(dkg.verifiers.contains_key(&(dkg.nidx as u32)));
}

#[test]
fn test_dkg_process_deal() {
	let (_, _, mut dkgs) = generate(DEFAULT_N, *DEFAULT_T);
	let dkg = &mut dkgs[0];
    let mut deals = dkg.deals().unwrap();

    let rec = &mut dkgs[1];
    let deal = deals.get_mut(&1).unwrap();
    assert_eq!(deal.index, 0);
    assert_eq!(1, rec.nidx);

    // verifier don't find itself
    let good_p = rec.c.new_nodes.clone();
    rec.c.new_nodes = Vec::new();
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    rec.c.new_nodes = good_p;

    // good deal
    let resp = rec.process_deal(deal).unwrap();
    assert_eq!(resp.response.status, vss::pedersen::vss::STATUS_APPROVAL);
    assert!(rec.verifiers.contains_key(&deal.index));
    assert_eq!(0, resp.index);
	
    // duplicate
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());

    // wrong index
    let good_idx = deal.index;
    deal.index = (DEFAULT_N + 1) as u32;
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    deal.index = good_idx;

    // wrong deal
    let good_sig = deal.deal.signature.clone();
    deal.deal.signature = random_bytes(deal.deal.signature.len());
    let resp_res = rec.process_deal(deal);
    assert!(resp_res.is_err());
    deal.deal.signature = good_sig;
}

#[test]
fn test_dkg_process_response() {
    // first peer generates wrong deal
    // second peer processes it and returns a complaint
    // first peer process the complaint

	let (_, _, mut dkgs) = generate(DEFAULT_N, *DEFAULT_T);
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
        .sec_share
        .v
        .clone();
    dkgs[2].dealer.plaintext_deal(1).unwrap().sec_share.v = suite().scalar().zero();
    let mut deals_2 = dkgs[2].deals().unwrap();

    let mut resp_1_2 = dkgs[idx_rec]
        .process_deal(deals_2.get(&idx_rec).unwrap())
        .unwrap();
    assert_eq!(resp_1_2.response.status, vss::pedersen::vss::STATUS_COMPLAINT);

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
    let (publics, _, mut dkgs) = generate(n, old_t);
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
		let c = Config{
			suite:        suite(),
			longterm:     dkgs[i].c.longterm.clone(),
			old_nodes:     publics.clone(),
			new_nodes:     new_pubs.clone(),
			share:        Some(shares[i].clone()),
			threshold:    new_t,
			old_threshold: old_t,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
		};
		new_dkgs.push(new_dist_key_handler(c).unwrap());
	}
    new_dkgs.push(new_dist_key_handler(Config{
        suite:        suite(),
		longterm:     new_priv,
		old_nodes:     publics,
		new_nodes:     new_pubs,
		public_coeffs: Some(shares[0].commits.clone()),
		threshold:    new_t,
		old_threshold: old_t,
        share: None,
        reader: None,
        user_reader_only: false
    }).unwrap());

	let mut selected_dkgs = Vec::with_capacity(new_t);
	let mut selected = HashMap::new();
	// add the new node
	selected_dkgs.push(new_dkgs[dkgs.len()].clone());
	selected.insert(selected_dkgs[0].long.to_string(), true);
	// select a subset of the new group
	while selected.len() < new_t+1 {
		let idx = rand::thread_rng().gen_range(0..new_dkgs.len());
		let str = new_dkgs[idx].long.to_string();
		if selected.contains_key(&str) {
			continue
		}
		selected.insert(str, true);
        selected_dkgs.push(new_dkgs[idx].clone());
	}

	let mut deals = Vec::with_capacity(new_n * new_n);
	for dkg in selected_dkgs.iter_mut() {
		if !dkg.old_present {
			continue
		}
		let local_deals = dkg.deals().unwrap();
		deals.push(local_deals);
	}

	let mut resps = HashMap::new();
	for (i, local_deals) in deals.iter().enumerate() {
        resps.insert(i, Vec::new());
		for (j, d) in local_deals {
			for dkg in selected_dkgs.iter_mut() {
				if dkg.new_present && dkg.nidx == j.clone() {
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
					continue
				}
				let j = dkg.process_response(&resp).expect(&format!("old dkg at (oidx {}, nidx {}) has received response from idx {} for dealer idx {}\n", dkg.oidx, dkg.nidx, resp.response.index, resp.index));
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
			continue
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
                continue
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
			assert_ne!(new_dks.share.v.to_string(), old_dks.share.v.to_string())
		}
	}
	//// 2.
	let old_secret = share::poly::recover_secret(suite(), &sshares, old_t, n).unwrap();
	let new_secret = share::poly::recover_secret(suite(), &new_shares, new_t, new_n).unwrap();
    assert_eq!(old_secret.to_string(), new_secret.to_string());

}

// // TestDKGThreshold tests the "threshold dkg" where only a subset of nodes succeed
// // at the DKG
// func TestDKGThreshold(t *testing.T) {
// 	n := 7
// 	// should succeed with only this number of nodes
// 	newTotal := vss.MinimumT(n)

// 	dkgs := make([]*DistKeyGenerator, n)
// 	privates := make([]kyber.Scalar, n)
// 	publics := make([]kyber.Point, n)
// 	for i := 0; i < n; i++ {
// 		priv, pub := genPair()
// 		privates[i] = priv
// 		publics[i] = pub
// 	}

// 	for i := 0; i < n; i++ {
// 		dkg, err := NewDistKeyGenerator(suite, privates[i], publics, newTotal)
// 		if err != nil {
// 			panic(err)
// 		}
// 		dkgs[i] = dkg
// 	}

// 	// only take a threshold of them
// 	thrDKGs := make(map[uint32]*DistKeyGenerator)
// 	alreadyTaken := make(map[int]bool)
// 	for len(thrDKGs) < newTotal {
// 		idx := mathRand.Intn(defaultN)
// 		if alreadyTaken[idx] {
// 			continue
// 		}
// 		alreadyTaken[idx] = true
// 		dkg := dkgs[idx]
// 		thrDKGs[uint32(dkg.nidx)] = dkg
// 	}

// 	// full secret sharing exchange
// 	// 1. broadcast deals
// 	resps := make([]*Response, 0, newTotal*newTotal)
// 	for _, dkg := range thrDKGs {
// 		deals, err := dkg.Deals()
// 		require.Nil(t, err)
// 		for i, d := range deals {
// 			// give the deal anyway - simpler
// 			recipient, exists := thrDKGs[uint32(i)]
// 			if !exists {
// 				// one of the "offline" dkg
// 				continue
// 			}
// 			resp, err := recipient.ProcessDeal(d)
// 			require.Nil(t, err)
// 			require.Equal(t, vss.StatusApproval, resp.Response.Status)
// 			resps = append(resps, resp)
// 		}
// 	}

// 	// 2. Broadcast responses
// 	for _, resp := range resps {
// 		for _, dkg := range thrDKGs {
// 			if resp.Response.Index == uint32(dkg.nidx) {
// 				// skip the responses this dkg sent out
// 				continue
// 			}
// 			j, err := dkg.ProcessResponse(resp)
// 			require.Nil(t, err)
// 			require.Nil(t, j)
// 		}
// 	}

// 	// 3. make sure nobody has a QUAL set
// 	for _, dkg := range thrDKGs {
// 		require.False(t, dkg.Certified())
// 		require.Equal(t, 0, len(dkg.QUAL()))
// 		for _, dkg2 := range thrDKGs {
// 			require.False(t, dkg.isInQUAL(uint32(dkg2.nidx)))
// 		}
// 	}

// 	for _, dkg := range thrDKGs {
// 		for i, v := range dkg.verifiers {
// 			var app int
// 			for _, r := range v.Responses() {
// 				if r.Status == vss.StatusApproval {
// 					app++
// 				}
// 			}
// 			if alreadyTaken[int(i)] {
// 				require.Equal(t, len(alreadyTaken), app)
// 			} else {
// 				require.Equal(t, 0, app)
// 			}
// 		}
// 		dkg.SetTimeout()
// 	}

// 	for _, dkg := range thrDKGs {
// 		require.Equal(t, newTotal, len(dkg.QUAL()))
// 		require.True(t, dkg.ThresholdCertified())
// 		require.False(t, dkg.Certified())
// 		qualShares := dkg.QualifiedShares()
// 		for _, dkg2 := range thrDKGs {
// 			require.Contains(t, qualShares, dkg2.nidx)
// 		}
// 		_, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		for _, dkg2 := range thrDKGs {
// 			require.True(t, dkg.isInQUAL(uint32(dkg2.nidx)))
// 		}
// 	}

// }

// func TestDistKeyShare(t *testing.T) {
// 	_, _, dkgs := generate(defaultN, defaultT)
// 	fullExchange(t, dkgs, true)

// 	for _, dkg := range dkgs {
// 		require.True(t, dkg.Certified())
// 	}
// 	// verify integrity of shares etc
// 	dkss := make([]*DistKeyShare, defaultN)
// 	var poly *share.PriPoly
// 	for i, dkg := range dkgs {
// 		dks, err := dkg.DistKeyShare()
// 		require.Nil(t, err)
// 		require.NotNil(t, dks)
// 		require.NotNil(t, dks.PrivatePoly)
// 		dkss[i] = dks
// 		require.Equal(t, dkg.nidx, dks.Share.I)

// 		pripoly := share.CoefficientsToPriPoly(suite, dks.PrivatePoly)
// 		if poly == nil {
// 			poly = pripoly
// 			continue
// 		}
// 		poly, err = poly.Add(pripoly)
// 		require.NoError(t, err)
// 	}

// 	shares := make([]*share.PriShare, defaultN)
// 	for i, dks := range dkss {
// 		require.True(t, checkDks(dks, dkss[0]), "dist key share not equal %d vs %d", dks.Share.I, 0)
// 		shares[i] = dks.Share
// 	}

// 	secret, err := share.RecoverSecret(suite, shares, defaultN, defaultN)
// 	require.Nil(t, err)

// 	secretCoeffs := poly.Coefficients()
// 	require.Equal(t, secret.String(), secretCoeffs[0].String())

// 	commitSecret := suite.Point().Mul(secret, nil)
// 	require.Equal(t, dkss[0].Public().String(), commitSecret.String())
// }

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

// func checkDks(dks1, dks2 *DistKeyShare) bool {
// 	if len(dks1.Commits) != len(dks2.Commits) {
// 		return false
// 	}
// 	for i, p := range dks1.Commits {
// 		if !p.Equal(dks2.Commits[i]) {
// 			return false
// 		}
// 	}
// 	return true
// }

fn full_exchange<SUITE: Suite, READ: Read + Clone +'static>(dkgs: &mut Vec<DistKeyGenerator<SUITE, READ>>, check_qual: bool) 
where 
<SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned + ScalarCanCheckCanonical,
SUITE::POINT: Serialize + DeserializeOwned + PointCanCheckCanonicalAndSmallOrder
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

// // Test resharing of a DKG to the same set of nodes
// func TestDKGResharing(t *testing.T) {
// 	oldT := vss.MinimumT(defaultN)
// 	publics, secrets, dkgs := generate(defaultN, oldT)
// 	fullExchange(t, dkgs, true)

// 	shares := make([]*DistKeyShare, len(dkgs))
// 	sshares := make([]*share.PriShare, len(dkgs))
// 	for i, dkg := range dkgs {
// 		share, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		shares[i] = share
// 		sshares[i] = shares[i].Share
// 	}
// 	// start resharing within the same group
// 	newDkgs := make([]*DistKeyGenerator, len(dkgs))
// 	var err error
// 	for i := range dkgs {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     secrets[i],
// 			OldNodes:     publics,
// 			NewNodes:     publics,
// 			Share:        shares[i],
// 			OldThreshold: oldT,
// 		}
// 		newDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 	}
// 	fullExchange(t, newDkgs, true)
// 	newShares := make([]*DistKeyShare, len(dkgs))
// 	newSShares := make([]*share.PriShare, len(dkgs))
// 	for i := range newDkgs {
// 		dks, err := newDkgs[i].DistKeyShare()
// 		require.NoError(t, err)
// 		newShares[i] = dks
// 		newSShares[i] = newShares[i].Share
// 	}
// 	// check
// 	// 1. shares are different between the two rounds
// 	// 2. shares reconstruct to the same secret
// 	// 3. public polynomial is different but for the first coefficient /public
// 	// key/
// 	// 1.
// 	for i := 0; i < len(dkgs); i++ {
// 		require.False(t, shares[i].Share.V.Equal(newShares[i].Share.V))
// 	}
// 	thr := vss.MinimumT(defaultN)
// 	// 2.
// 	oldSecret, err := share.RecoverSecret(suite, sshares, thr, defaultN)
// 	require.NoError(t, err)
// 	newSecret, err := share.RecoverSecret(suite, newSShares, thr, defaultN)
// 	require.NoError(t, err)
// 	require.Equal(t, oldSecret.String(), newSecret.String())
// }

// // Test resharing functionality with one node less
// func TestDKGResharingRemoveNode(t *testing.T) {
// 	oldT := vss.MinimumT(defaultN)
// 	publics, secrets, dkgs := generate(defaultN, oldT)
// 	fullExchange(t, dkgs, true)

// 	newN := len(publics) - 1
// 	shares := make([]*DistKeyShare, len(dkgs))
// 	sshares := make([]*share.PriShare, len(dkgs))
// 	for i, dkg := range dkgs {
// 		share, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		shares[i] = share
// 		sshares[i] = shares[i].Share
// 	}

// 	// start resharing within the same group
// 	newDkgs := make([]*DistKeyGenerator, len(dkgs))
// 	var err error
// 	for i := range dkgs {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     secrets[i],
// 			OldNodes:     publics,
// 			NewNodes:     publics[:newN],
// 			Share:        shares[i],
// 			OldThreshold: oldT,
// 		}
// 		newDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 	}

// 	fullExchange(t, newDkgs, false)
// 	newShares := make([]*DistKeyShare, len(dkgs))
// 	newSShares := make([]*share.PriShare, len(dkgs)-1)
// 	for i := range newDkgs[:newN] {
// 		dks, err := newDkgs[i].DistKeyShare()
// 		require.NoError(t, err)
// 		newShares[i] = dks
// 		newSShares[i] = newShares[i].Share
// 	}

// 	// check
// 	// 1. shares are different between the two rounds
// 	// 2. shares reconstruct to the same secret
// 	// 3. public polynomial is different but for the first coefficient /public
// 	// key/

// 	// 1.
// 	for i := 0; i < newN; i++ {
// 		require.False(t, shares[i].Share.V.Equal(newShares[i].Share.V))
// 	}
// 	thr := vss.MinimumT(defaultN)
// 	// 2.
// 	oldSecret, err := share.RecoverSecret(suite, sshares[:newN], thr, newN)
// 	require.NoError(t, err)
// 	newSecret, err := share.RecoverSecret(suite, newSShares, thr, newN)
// 	require.NoError(t, err)
// 	require.Equal(t, oldSecret.String(), newSecret.String())
// }

// // Test to reshare to a different set of nodes with only a threshold of the old
// // nodes present
// func TestDKGResharingNewNodesThreshold(t *testing.T) {
// 	oldN := defaultN
// 	oldT := vss.MinimumT(oldN)
// 	oldPubs, oldPrivs, dkgs := generate(oldN, oldT)
// 	fullExchange(t, dkgs, true)

// 	shares := make([]*DistKeyShare, len(dkgs))
// 	sshares := make([]*share.PriShare, len(dkgs))
// 	for i, dkg := range dkgs {
// 		share, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		shares[i] = share
// 		sshares[i] = shares[i].Share
// 	}
// 	// start resharing to a different group
// 	newN := oldN + 3
// 	newT := oldT + 2
// 	newPrivs := make([]kyber.Scalar, newN)
// 	newPubs := make([]kyber.Point, newN)
// 	for i := 0; i < newN; i++ {
// 		newPrivs[i], newPubs[i] = genPair()
// 	}

// 	// creating the old dkgs and new dkgs
// 	oldDkgs := make([]*DistKeyGenerator, oldN)
// 	newDkgs := make([]*DistKeyGenerator, newN)
// 	var err error
// 	for i := 0; i < oldN; i++ {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     oldPrivs[i],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			Share:        shares[i],
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}
// 		oldDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 		require.False(t, oldDkgs[i].canReceive)
// 		require.True(t, oldDkgs[i].canIssue)
// 		require.True(t, oldDkgs[i].isResharing)
// 		require.False(t, oldDkgs[i].newPresent)
// 		require.Equal(t, oldDkgs[i].oidx, i)
// 	}

// 	for i := 0; i < newN; i++ {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     newPrivs[i],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			PublicCoeffs: shares[0].Commits,
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}
// 		newDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 		require.True(t, newDkgs[i].canReceive)
// 		require.False(t, newDkgs[i].canIssue)
// 		require.True(t, newDkgs[i].isResharing)
// 		require.True(t, newDkgs[i].newPresent)
// 		require.Equal(t, newDkgs[i].nidx, i)
// 	}

// 	//alive := oldT - 1
// 	alive := oldT
// 	oldSelected := make([]*DistKeyGenerator, 0, alive)
// 	selected := make(map[string]bool)
// 	for len(selected) < alive {
// 		i := mathRand.Intn(len(oldDkgs))
// 		str := oldDkgs[i].pub.String()
// 		if _, exists := selected[str]; exists {
// 			continue
// 		}
// 		selected[str] = true
// 		oldSelected = append(oldSelected, oldDkgs[i])
// 	}

// 	// 1. broadcast deals
// 	deals := make([]map[int]*Deal, 0, newN*newN)
// 	for _, dkg := range oldSelected {
// 		localDeals, err := dkg.Deals()
// 		require.Nil(t, err)
// 		deals = append(deals, localDeals)
// 	}

// 	resps := make(map[int][]*Response)
// 	for i, localDeals := range deals {
// 		for j, d := range localDeals {
// 			dkg := newDkgs[j]
// 			resp, err := dkg.ProcessDeal(d)
// 			require.Nil(t, err)
// 			require.Equal(t, vss.StatusApproval, resp.Response.Status)
// 			resps[i] = append(resps[i], resp)
// 		}
// 	}

// 	// 2. Broadcast responses
// 	for _, dealResponses := range resps {
// 		for _, resp := range dealResponses {
// 			// dispatch to old selected dkgs
// 			for _, dkg := range oldSelected {
// 				// Ignore messages from ourselves
// 				if resp.Response.Index == uint32(dkg.nidx) {
// 					continue
// 				}
// 				j, err := dkg.ProcessResponse(resp)
// 				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.oidx, dkg.nidx, resp.Index)
// 				if err != nil {
// 					fmt.Printf("old dkg at (oidx %d, nidx %d) has received response from idx %d for dealer idx %d\n", dkg.oidx, dkg.nidx, resp.Response.Index, resp.Index)
// 				}
// 				require.Nil(t, err)
// 				require.Nil(t, j)
// 			}
// 			// dispatch to the new dkgs
// 			for _, dkg := range newDkgs {
// 				// Ignore messages from ourselves
// 				if resp.Response.Index == uint32(dkg.nidx) {
// 					continue
// 				}
// 				j, err := dkg.ProcessResponse(resp)
// 				//fmt.Printf("new dkg %d process responses from new dkg %d about deal %d\n", dkg.nidx, dkg.nidx, resp.Index)
// 				if err != nil {
// 					fmt.Printf("new dkg at nidx %d has received response from idx %d for deal %d\n", dkg.nidx, resp.Response.Index, resp.Index)
// 				}
// 				require.Nil(t, err)
// 				require.Nil(t, j)
// 			}

// 		}
// 	}

// 	for _, dkg := range newDkgs {
// 		for _, oldDkg := range oldSelected {
// 			idx := oldDkg.oidx
// 			require.True(t, dkg.verifiers[uint32(idx)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.nidx, idx, dkg.verifiers[uint32(idx)].Responses())
// 		}
// 	}

// 	// 3. make sure everyone has the same QUAL set
// 	for _, dkg := range newDkgs {
// 		require.Equal(t, alive, len(dkg.QUAL()))
// 		for _, dkg2 := range oldSelected {
// 			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.nidx, dkg2.oidx, dkg.QUAL())
// 		}
// 	}

// 	newShares := make([]*DistKeyShare, newN)
// 	newSShares := make([]*share.PriShare, newN)
// 	for i := range newDkgs {
// 		dks, err := newDkgs[i].DistKeyShare()
// 		require.NoError(t, err)
// 		newShares[i] = dks
// 		newSShares[i] = newShares[i].Share
// 	}
// 	// check shares reconstruct to the same secret
// 	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
// 	require.NoError(t, err)
// 	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
// 	require.NoError(t, err)
// 	require.Equal(t, oldSecret.String(), newSecret.String())

// }

// // Test resharing to a different set of nodes with two common.
// func TestDKGResharingNewNodes(t *testing.T) {
// 	oldPubs, oldPrivs, dkgs := generate(defaultN, vss.MinimumT(defaultN))
// 	fullExchange(t, dkgs, true)

// 	shares := make([]*DistKeyShare, len(dkgs))
// 	sshares := make([]*share.PriShare, len(dkgs))

// 	for i, dkg := range dkgs {
// 		share, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		shares[i] = share
// 		sshares[i] = shares[i].Share
// 	}

// 	// start resharing to a different group

// 	oldN := defaultN
// 	oldT := len(shares[0].Commits)
// 	newN := oldN + 1
// 	newT := oldT + 1
// 	newPrivs := make([]kyber.Scalar, newN)
// 	newPubs := make([]kyber.Point, newN)

// 	// new[0], new[1] = old[-1], old[-2]
// 	newPrivs[0] = oldPrivs[oldN-1]
// 	newPubs[0] = oldPubs[oldN-1]
// 	newPrivs[1] = oldPrivs[oldN-2]
// 	newPubs[1] = oldPubs[oldN-2]

// 	for i := 2; i < newN; i++ {
// 		newPrivs[i], newPubs[i] = genPair()
// 	}

// 	// creating the old dkgs

// 	oldDkgs := make([]*DistKeyGenerator, oldN)
// 	var err error
// 	for i := 0; i < oldN; i++ {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     oldPrivs[i],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			Share:        shares[i],
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}

// 		oldDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)

// 		// because the node's public key is already in newPubs
// 		if i >= oldN-2 {
// 			require.True(t, oldDkgs[i].canReceive)
// 			require.True(t, oldDkgs[i].canIssue)
// 			require.True(t, oldDkgs[i].isResharing)
// 			require.True(t, oldDkgs[i].newPresent)
// 			require.Equal(t, oldDkgs[i].oidx, i)
// 			require.Equal(t, oldN-i-1, oldDkgs[i].nidx)
// 			continue
// 		}

// 		require.False(t, oldDkgs[i].canReceive)
// 		require.True(t, oldDkgs[i].canIssue)
// 		require.True(t, oldDkgs[i].isResharing)
// 		require.False(t, oldDkgs[i].newPresent)
// 		require.Equal(t, 0, oldDkgs[i].nidx) // default for nidx
// 		require.Equal(t, oldDkgs[i].oidx, i)
// 	}

// 	// creating the new dkg

// 	newDkgs := make([]*DistKeyGenerator, newN)

// 	newDkgs[0] = oldDkgs[oldN-1] // the first one is the last old one
// 	newDkgs[1] = oldDkgs[oldN-2] // the second one is the before-last old one

// 	for i := 2; i < newN; i++ {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     newPrivs[i],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			PublicCoeffs: shares[0].Commits,
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}

// 		newDkgs[i], err = NewDistKeyHandler(c)

// 		require.NoError(t, err)
// 		require.True(t, newDkgs[i].canReceive)
// 		require.False(t, newDkgs[i].canIssue)
// 		require.True(t, newDkgs[i].isResharing)
// 		require.True(t, newDkgs[i].newPresent)
// 		require.Equal(t, newDkgs[i].nidx, i)
// 		// each old dkg act as a verifier
// 		require.Len(t, newDkgs[i].Verifiers(), oldN)
// 	}

// 	// full secret sharing exchange

// 	// 1. broadcast deals
// 	deals := make([]map[int]*Deal, len(oldDkgs))

// 	for i, dkg := range oldDkgs {
// 		localDeals, err := dkg.Deals()
// 		require.NoError(t, err)

// 		// each old DKG will sent a deal to each other dkg, including
// 		// themselves.
// 		require.Len(t, localDeals, newN)

// 		deals[i] = localDeals

// 		v, exists := dkg.verifiers[uint32(dkg.oidx)]
// 		if dkg.canReceive && dkg.nidx <= 1 {
// 			// staying nodes don't save their responses locally because they
// 			// will broadcast them for the old comities.
// 			require.Len(t, v.Responses(), 0)
// 			require.True(t, exists)
// 		} else {
// 			// no verifiers since these dkg are not in in the new list
// 			require.False(t, exists)
// 		}
// 	}

// 	// the index key indicates the dealer index for which the responses are for
// 	resps := make(map[int][]*Response)

// 	for i, localDeals := range deals {
// 		for dest, d := range localDeals {
// 			dkg := newDkgs[dest]
// 			resp, err := dkg.ProcessDeal(d)
// 			require.NoError(t, err)
// 			require.Equal(t, vss.StatusApproval, resp.Response.Status)
// 			resps[i] = append(resps[i], resp)
// 		}
// 	}

// 	// all new dkgs should have the same length of verifiers map
// 	for _, dkg := range newDkgs {
// 		// one deal per old participants
// 		require.Len(t, dkg.verifiers, oldN, "dkg nidx %d failing", dkg.nidx)
// 	}

// 	// 2. Broadcast responses
// 	for _, dealResponses := range resps {
// 		for _, resp := range dealResponses {
// 			// the two last ones will be processed while doing this step on the
// 			// newDkgs, since they are in the new set.
// 			for _, dkg := range oldDkgs[:oldN-2] {
// 				j, err := dkg.ProcessResponse(resp)
// 				require.NoError(t, err, "old dkg at (oidx %d, nidx %d) has received response from idx %d for dealer idx %d\n", dkg.oidx, dkg.nidx, resp.Response.Index, resp.Index)
// 				require.Nil(t, j)
// 			}

// 			for _, dkg := range newDkgs {
// 				// Ignore messages from ourselves
// 				if resp.Response.Index == uint32(dkg.nidx) {
// 					continue
// 				}
// 				j, err := dkg.ProcessResponse(resp)
// 				require.NoError(t, err, "new dkg at nidx %d has received response from idx %d for deal %d\n", dkg.nidx, resp.Response.Index, resp.Index)
// 				require.Nil(t, j)
// 			}

// 		}
// 	}

// 	for _, dkg := range newDkgs {
// 		for i := 0; i < oldN; i++ {
// 			require.True(t, dkg.verifiers[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.nidx, i, dkg.verifiers[uint32(i)].Responses())
// 		}
// 	}

// 	// 3. make sure everyone has the same QUAL set
// 	for _, dkg := range newDkgs {
// 		for _, dkg2 := range oldDkgs {
// 			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.nidx, dkg2.oidx, dkg.QUAL())
// 		}
// 	}

// 	// make sure the new dkg members can certify
// 	for _, dkg := range newDkgs {
// 		require.True(t, dkg.Certified(), "new dkg %d can't certify", dkg.nidx)
// 	}

// 	// make sure the old dkg members can certify
// 	for _, dkg := range oldDkgs {
// 		require.True(t, dkg.Certified(), "old dkg %d can't certify", dkg.oidx)
// 	}

// 	newShares := make([]*DistKeyShare, newN)
// 	newSShares := make([]*share.PriShare, newN)
// 	for i := range newDkgs {
// 		dks, err := newDkgs[i].DistKeyShare()
// 		require.NoError(t, err)
// 		newShares[i] = dks
// 		newSShares[i] = newShares[i].Share
// 	}

// 	// check shares reconstruct to the same secret
// 	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
// 	require.NoError(t, err)
// 	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
// 	require.NoError(t, err)
// 	require.Equal(t, oldSecret.String(), newSecret.String())
// }

// func TestDKGResharingPartialNewNodes(t *testing.T) {
// 	oldPubs, oldPrivs, dkgs := generate(defaultN, vss.MinimumT(defaultN))
// 	fullExchange(t, dkgs, true)

// 	shares := make([]*DistKeyShare, len(dkgs))
// 	sshares := make([]*share.PriShare, len(dkgs))
// 	for i, dkg := range dkgs {
// 		share, err := dkg.DistKeyShare()
// 		require.NoError(t, err)
// 		shares[i] = share
// 		sshares[i] = shares[i].Share
// 	}
// 	// start resharing to a different group
// 	oldN := defaultN
// 	oldT := len(shares[0].Commits)
// 	newN := oldN + 1
// 	newT := oldT + 1
// 	total := oldN + 2
// 	newOffset := oldN - 1 // idx at which a new key is added to the group

// 	newPrivs := make([]kyber.Scalar, 0, newN)
// 	newPubs := make([]kyber.Point, 0, newN)
// 	for _, priv := range oldPrivs[1:] {
// 		newPrivs = append(newPrivs, priv)
// 	}
// 	for _, pub := range oldPubs[1:] {
// 		newPubs = append(newPubs, pub)
// 	}
// 	// add two new nodes
// 	priv1, pub1 := genPair()
// 	priv2, pub2 := genPair()
// 	newPrivs = append(newPrivs, []kyber.Scalar{priv1, priv2}...)
// 	newPubs = append(newPubs, []kyber.Point{pub1, pub2}...)

// 	// creating all dkgs
// 	totalDkgs := make([]*DistKeyGenerator, total)
// 	var err error
// 	for i := 0; i < oldN; i++ {
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     oldPrivs[i],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			Share:        shares[i],
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}
// 		totalDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 		if i >= 1 {
// 			require.True(t, totalDkgs[i].canReceive)
// 			require.True(t, totalDkgs[i].canIssue)
// 			require.True(t, totalDkgs[i].isResharing)
// 			require.True(t, totalDkgs[i].newPresent)
// 			require.Equal(t, totalDkgs[i].oidx, i)
// 			require.Equal(t, i-1, totalDkgs[i].nidx)
// 			continue
// 		}
// 		require.False(t, totalDkgs[i].canReceive)
// 		require.True(t, totalDkgs[i].canIssue)
// 		require.True(t, totalDkgs[i].isResharing)
// 		require.False(t, totalDkgs[i].newPresent)
// 		require.Equal(t, totalDkgs[i].oidx, i)
// 	}

// 	// the first one is the last old one
// 	for i := oldN; i < total; i++ {
// 		newIdx := i - oldN + newOffset
// 		c := &Config{
// 			Suite:        suite,
// 			Longterm:     newPrivs[newIdx],
// 			OldNodes:     oldPubs,
// 			NewNodes:     newPubs,
// 			PublicCoeffs: shares[0].Commits,
// 			Threshold:    newT,
// 			OldThreshold: oldT,
// 		}
// 		totalDkgs[i], err = NewDistKeyHandler(c)
// 		require.NoError(t, err)
// 		require.True(t, totalDkgs[i].canReceive)
// 		require.False(t, totalDkgs[i].canIssue)
// 		require.True(t, totalDkgs[i].isResharing)
// 		require.True(t, totalDkgs[i].newPresent)
// 		require.Equal(t, totalDkgs[i].nidx, newIdx)
// 	}
// 	newDkgs := totalDkgs[1:]
// 	oldDkgs := totalDkgs[:oldN]
// 	require.Equal(t, oldN, len(oldDkgs))
// 	require.Equal(t, newN, len(newDkgs))

// 	// full secret sharing exchange
// 	// 1. broadcast deals
// 	deals := make([]map[int]*Deal, 0, newN*newN)
// 	for _, dkg := range oldDkgs {
// 		localDeals, err := dkg.Deals()
// 		require.Nil(t, err)
// 		deals = append(deals, localDeals)
// 		v, exists := dkg.verifiers[uint32(dkg.oidx)]
// 		if dkg.canReceive && dkg.newPresent {
// 			// staying nodes don't process their responses locally because they
// 			// broadcast them for the old comities to receive the responses.
// 			lenResponses := len(v.Aggregator.Responses())
// 			require.True(t, exists)
// 			require.Equal(t, 0, lenResponses)
// 		} else {
// 			require.False(t, exists)
// 		}
// 	}

// 	// the index key indicates the dealer index for which the responses are for
// 	resps := make(map[int][]*Response)
// 	for i, localDeals := range deals {
// 		for j, d := range localDeals {
// 			dkg := newDkgs[j]
// 			resp, err := dkg.ProcessDeal(d)
// 			require.Nil(t, err)
// 			require.Equal(t, vss.StatusApproval, resp.Response.Status)
// 			resps[i] = append(resps[i], resp)
// 			if i == 0 {
// 				//fmt.Printf("dealer (oidx %d, nidx %d) processing deal to %d from %d\n", newDkgs[i].oidx, newDkgs[i].nidx, i, d.Index)
// 			}
// 		}
// 	}

// 	// all new dkgs should have the same length of verifiers map
// 	for _, dkg := range newDkgs {
// 		// one deal per old participants
// 		require.Equal(t, oldN, len(dkg.verifiers), "dkg nidx %d failing", dkg.nidx)
// 	}

// 	// 2. Broadcast responses
// 	for _, dealResponses := range resps {
// 		for _, resp := range dealResponses {
// 			for _, dkg := range totalDkgs {
// 				// Ignore messages from ourselves
// 				if dkg.canReceive && resp.Response.Index == uint32(dkg.nidx) {
// 					continue
// 				}
// 				j, err := dkg.ProcessResponse(resp)
// 				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.oidx, dkg.nidx, resp.Index)
// 				if err != nil {
// 					fmt.Printf("old dkg at (oidx %d, nidx %d) has received response from idx %d for dealer idx %d\n", dkg.oidx, dkg.nidx, resp.Response.Index, resp.Index)
// 				}
// 				require.Nil(t, err)
// 				require.Nil(t, j)
// 			}
// 		}
// 	}
// 	for _, dkg := range newDkgs {
// 		for i := 0; i < oldN; i++ {
// 			require.True(t, dkg.verifiers[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.nidx, i, dkg.verifiers[uint32(i)].Responses())
// 		}
// 	}

// 	// 3. make sure everyone has the same QUAL set
// 	for _, dkg := range newDkgs {
// 		for _, dkg2 := range oldDkgs {
// 			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.nidx, dkg2.oidx, dkg.QUAL())
// 		}
// 	}

// 	newShares := make([]*DistKeyShare, newN)
// 	newSShares := make([]*share.PriShare, newN)
// 	for i := range newDkgs {
// 		dks, err := newDkgs[i].DistKeyShare()
// 		require.NoError(t, err)
// 		newShares[i] = dks
// 		newSShares[i] = newShares[i].Share
// 	}
// 	// check shares reconstruct to the same secret
// 	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
// 	require.NoError(t, err)
// 	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
// 	require.NoError(t, err)
// 	require.Equal(t, oldSecret.String(), newSecret.String())
// }

// func TestReaderMixedEntropy(t *testing.T) {
// 	seed := "some stream to be used with crypto/rand"
// 	partPubs, partSec, _ := generate(defaultN, defaultT)
// 	long := partSec[0]
// 	r := strings.NewReader(seed)
// 	c := &Config{
// 		Suite:     suite,
// 		Longterm:  long,
// 		NewNodes:  partPubs,
// 		Threshold: defaultT,
// 		Reader:    r,
// 	}
// 	dkg, err := NewDistKeyHandler(c)
// 	require.Nil(t, err)
// 	require.NotNil(t, dkg.dealer)
// }

// func TestUserOnlyFlagTrueBehavior(t *testing.T) {
// 	seed := "String to test reproducibility with"
// 	partPubs, partSec, _ := generate(defaultN, defaultT)
// 	long := partSec[0]

// 	r1 := strings.NewReader(seed)
// 	c1 := &Config{
// 		Suite:          suite,
// 		Longterm:       long,
// 		NewNodes:       partPubs,
// 		Threshold:      defaultT,
// 		Reader:         r1,
// 		UserReaderOnly: true,
// 	}
// 	dkg1, err := NewDistKeyHandler(c1)
// 	require.Nil(t, err)
// 	require.NotNil(t, dkg1.dealer)

// 	r2 := strings.NewReader(seed)
// 	c2 := &Config{
// 		Suite:          suite,
// 		Longterm:       long,
// 		NewNodes:       partPubs,
// 		Threshold:      defaultT,
// 		Reader:         r2,
// 		UserReaderOnly: true,
// 	}
// 	dkg2, err := NewDistKeyHandler(c2)
// 	require.Nil(t, err)
// 	require.NotNil(t, dkg2.dealer)

// 	require.True(t, dkg1.dealer.PrivatePoly().Secret().Equal(dkg2.dealer.PrivatePoly().Secret()))
// }

// func TestUserOnlyFlagFalseBehavior(t *testing.T) {
// 	seed := "String to test reproducibility with"
// 	partPubs, partSec, _ := generate(defaultN, defaultT)
// 	long := partSec[0]

// 	r1 := strings.NewReader(seed)
// 	c1 := &Config{
// 		Suite:          suite,
// 		Longterm:       long,
// 		NewNodes:       partPubs,
// 		Threshold:      defaultT,
// 		Reader:         r1,
// 		UserReaderOnly: false,
// 	}
// 	dkg1, err := NewDistKeyHandler(c1)
// 	require.Nil(t, err)
// 	require.NotNil(t, dkg1.dealer)

// 	r2 := strings.NewReader(seed)
// 	c2 := &Config{
// 		Suite:          suite,
// 		Longterm:       long,
// 		NewNodes:       partPubs,
// 		Threshold:      defaultT,
// 		Reader:         r2,
// 		UserReaderOnly: false,
// 	}
// 	dkg2, err := NewDistKeyHandler(c2)
// 	require.Nil(t, err)
// 	require.NotNil(t, dkg2.dealer)

// 	require.False(t, dkg1.dealer.PrivatePoly().Secret().Equal(dkg2.dealer.PrivatePoly().Secret()))
// }
