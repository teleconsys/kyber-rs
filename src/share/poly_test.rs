
use std::ops::Add;

use crate::{group::edwards25519::{self, SuiteEd25519}, share::poly::{PriShare, RecoverPubPoly, CoefficientsToPriPoly}, Random, Point, Group, Scalar};

use super::poly::{recover_secret, NewPriPoly, RecoverCommit, RecoverPriPoly, PubPoly, PubShare};

#[test]
fn TestSecretRecovery() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = NewPriPoly(g, t, None, g.random_stream());
    let shares = poly.Shares(n);

    let recovered = recover_secret(g, &shares, t, n).unwrap();

    assert_eq!(
        recovered,
        poly.Secret(),
        "recovered secret does not match initial value"
    );
}

/// tests the recovery of a secret when one of the share has an index
/// higher than the given `n`. This is a valid scenario that can happen during
/// a DKG-resharing:
/// 1. we add a new node n6 to an already-established group of 5 nodes.
/// 2. DKG runs without the first node in the group, i.e. without n1
/// 3. The list of qualified shares are [n2 ... n6] so the new resulting group
///    has 5 members (no need to keep the 1st node around).
/// 4. When n6 wants to reconstruct, it will give its index given during the
/// resharing, i.e. 6 (or 5 in 0-based indexing) whereas n = 5.
/// See TestPublicRecoveryOutIndex for testing with the commitment.
#[test]
fn TestSecretRecoveryOutIndex() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = NewPriPoly(g, t, None, g.random_stream());
    let shares = poly.Shares(n);

    let selected = &shares[n - t..];
    assert_eq!(selected.len(), t);
    let newN = t + 1;

    let recovered = recover_secret(g, selected, t, newN).unwrap();

    assert_eq!(
        recovered,
        poly.Secret(),
        "recovered secret does not match initial value"
    );
}

#[test]
fn TestSecretRecoveryDelete() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = NewPriPoly(g, t, None, g.random_stream());
    let mut shares = poly.Shares(n);

    // Corrupt a few shares
    shares[2] = None;
    shares[5] = None;
    shares[7] = None;
    shares[8] = None;

    let recovered = recover_secret(g, &shares, t, n).unwrap();

    assert_eq!(
        recovered,
        poly.Secret(),
        "recovered secret does not match initial value",
    );
}

#[test]
fn TestSecretRecoveryDeleteFail() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let poly = NewPriPoly(g, t, None, g.random_stream());
	let mut shares = poly.Shares(n);

	// Corrupt one more share than acceptable
	shares[1] = None;
	shares[2] = None;
	shares[5] = None;
	shares[7] = None;
	shares[8] = None;

	recover_secret(g, &shares, t, n).expect_err("recovered secret unexpectably");
}

#[test]
fn TestSecretPolyEqual() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
    let n = 10;
    let t = n/2 + 1;

    let p1 = NewPriPoly(g, t, None, g.random_stream());
    let p2 = NewPriPoly(g, t, None, g.random_stream());
    let p3 = NewPriPoly(g, t, None, g.random_stream());

    let p12 = p1.Add(&p2).unwrap();
    let p13 = p1.Add(&p3).unwrap();

    let p123 = p12.Add(&p3).unwrap();
    let p132 = p13.Add(&p2).unwrap();

    assert!(p123.Equal(&p132).unwrap(), "private polynomials not equal");
}

#[test]
fn TestPublicCheck() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let priPoly = NewPriPoly(g, t, None, g.random_stream());
	let priShares = priPoly.Shares(n);
	let pubPoly = priPoly.Commit(None);

	for (i, share) in priShares.iter().enumerate() {
		assert!(pubPoly.Check(&share.as_ref().unwrap()), "{}", format!("private share {} not valid with respect to the public commitment polynomial", i))
	}
}

#[test]
fn TestPublicRecovery() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let priPoly = NewPriPoly(g, t, None, g.random_stream());
	let pubPoly = priPoly.Commit(None);
	let pubShares = pubPoly.Shares(n);

	let recovered = RecoverCommit(g, pubShares.as_slice(), t, n).unwrap();

	assert_eq!(recovered, pubPoly.Commit());

    let polyRecovered = RecoverPubPoly(g, &pubShares, t, n).unwrap();

    assert!(pubPoly.Equal(&polyRecovered).unwrap());
}

#[test]
fn TestPublicRecoveryOutIndex() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let priPoly = NewPriPoly(g, t, None, g.random_stream());
	let pubPoly = priPoly.Commit(None);
	let pubShares = pubPoly.Shares(n);

	let selected = &pubShares[n-t..];
    assert_eq!(selected.len(), t);

	let newN = t + 1;

	let recovered = RecoverCommit(g, selected, t, newN).unwrap();

    assert_eq!(recovered, pubPoly.Commit());

	let polyRecovered= RecoverPubPoly(g, &pubShares, t, n).unwrap();

    assert!(pubPoly.Equal(&polyRecovered).unwrap());
}

#[test]
fn TestPublicRecoveryDelete() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let priPoly = NewPriPoly(g, t, None, g.random_stream());
	let pubPoly = priPoly.Commit(None);
	let mut shares = pubPoly.Shares(n);

	// Corrupt aNone;w shares
	shares[2] = None;
	shares[5] = None;
	shares[7] = None;
	shares[8] = None;

	let recovered = RecoverCommit(g, &shares, t, n).unwrap();

    assert_eq!(recovered, pubPoly.Commit(), "recovered commit does not match initial value");
}

#[test]
fn TestPublicRecoveryDeleteFail() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let priPoly = NewPriPoly(g, t, None, g.random_stream());
	let pubPoly = priPoly.Commit(None);
	let mut shares = pubPoly.Shares(n);

	// Corrupt one more share than acceptable
	shares[1] = None;
	shares[2] = None;
	shares[5] = None;
	shares[7] = None;
	shares[8] = None;

	RecoverCommit(g, &shares, t, n).expect_err("recovered commit unexpectably");
}

#[test]
fn TestPrivateAdd() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let p = NewPriPoly(g, t, None, g.random_stream());
	let q = NewPriPoly(g, t, None, g.random_stream());

	let r = p.Add(&q).unwrap();

	let ps = p.Secret();
	let qs = q.Secret();
    let rs = ps + qs;

    assert_eq!(rs, r.Secret(), "addition of secret sharing polynomials failed");
}

#[test]
fn TestPublicAdd() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let G = g.point().pick(&mut g.random_stream());
	let H = g.point().pick(&mut g.random_stream());

	let p = NewPriPoly(g, t, None, g.random_stream());
	let q = NewPriPoly(g, t, None, g.random_stream());

	let P = p.Commit(Some(&G));
	let Q = q.Commit(Some(&H));

	let R = P.Add(&Q).unwrap();

	let shares = R.Shares(n);
	let recovered = RecoverCommit(g, &shares, t, n).unwrap();

	let x = P.Commit();
	let y = Q.Commit();
	let z = g.point().add(&x, &y);

    assert_eq!(recovered, z, "addition of public commitment polynomials failed");

}

#[test]
fn TestPublicPolyEqual() {
    let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	let G = g.point().pick(&mut g.random_stream());

	let p1 = NewPriPoly(g, t, None, g.random_stream());
	let p2 = NewPriPoly(g, t, None, g.random_stream());
	let p3 = NewPriPoly(g, t, None, g.random_stream());

	let P1 = p1.Commit(Some(&G));
	let P2 = p2.Commit(Some(&G));
	let P3 = p3.Commit(Some(&G));

	let P12 = P1.Add(&P2).unwrap();
	let P13 = P1.Add(&P3).unwrap();

	let P123 = P12.Add(&P3).unwrap();
	let P132 = P13.Add(&P2).unwrap();

    assert!(P123.Equal(&P132).unwrap(), "public polynomials not equal");
}

#[test]
fn TestPriPolyMul() {
	let suite = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;
	let a = NewPriPoly(suite, t, None, suite.random_stream());
	let b = NewPriPoly(suite, t, None, suite.random_stream());

	let c = a.Mul(&b);
	assert_eq!(a.coeffs.len() + b.coeffs.len() - 1, c.coeffs.len());
	let nul = suite.scalar().zero();
	for c in c.coeffs.clone() {
        assert_ne!(nul.to_string(), c.to_string());
	}

	let a0 = a.coeffs[0].clone();
	let b0 = b.coeffs[0].clone();
	let mut mul = b0 * a0;
	let c0 = c.coeffs[0].clone();

	assert_eq!(c0.to_string(), mul.to_string());

	let at = a.coeffs[a.coeffs.len() - 1].clone();
	let bt = b.coeffs[b.coeffs.len() - 1].clone();
	mul = at * bt;
	let ct = c.coeffs[c.coeffs.len() - 1].clone();
    assert_eq!(ct.to_string(), mul.to_string());
}

#[test]
fn TestRecoverPriPoly() {
	let suite = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;
	let a = NewPriPoly(suite, t, None, suite.random_stream());

	let shares = a.Shares(n);
	let mut reverses = shares.clone();
    reverses.reverse();

	let recovered = RecoverPriPoly(&suite, &shares, t, n).unwrap();

	let reverseRecovered = RecoverPriPoly(&suite, &reverses, t, n).unwrap();

	for i in 0..t {
        assert_eq!(recovered.Eval(i).v.to_string(), a.Eval(i).v.to_string());
        assert_eq!(reverseRecovered.Eval(i).v.to_string(), a.Eval(i).v.to_string());
	}
}

#[test]
fn TestPriPolyCoefficients() {
	let suite = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;
	let a = NewPriPoly(suite, t, None, suite.random_stream());

	let coeffs = a.Coefficients();
	assert_eq!(coeffs.len(), t);

	let b = CoefficientsToPriPoly(&suite, coeffs);
    assert_eq!(a.coeffs, b.coeffs);

}

#[test]
fn TestRefreshDKG() {
	let g = edwards25519::SuiteEd25519::new_blake_sha256ed25519();
	let n = 10;
	let t = n/2 + 1;

	// Run an n-fold Pedersen VSS (= DKG)
	let mut priPolys = Vec::with_capacity(n);
	let mut priShares = Vec::with_capacity(n);
	let mut pubPolys = Vec::with_capacity(n);
	let mut pubShares = Vec::with_capacity(n);
	for i in 0..n {
		priPolys.push(NewPriPoly(g, t, None, g.random_stream()));
		priShares.push(priPolys[i].Shares(n));
		pubPolys.push(priPolys[i].Commit(None));
		pubShares.push(pubPolys[i].Shares(n));
	}

	// Verify VSS shares
	for i in 0..n {
		for j in 0..n {
			let sij = priShares[i][j].clone().unwrap();
			// s_ij * G
            let mut sijG = g.point().base();
			sijG = sijG.mul(&sij.v, None);
            assert_eq!(sijG, pubShares[i][j].as_ref().unwrap().v);
		}
	}

	// Create private DKG shares
	let mut dkgShares = Vec::with_capacity(n);
	for i in 0..n {
		let mut acc = g.scalar().zero();
		for j in 0..n { // assuming all participants are in the qualified set
			acc = acc + priShares[j][i].clone().unwrap().v;
		}
		dkgShares.push(PriShare{i, v: acc});
	}

	// Create public DKG commitments (= verification vector)
	let mut dkgCommits = Vec::with_capacity(t);
	for k in 0..t {
		let mut acc = g.point().null();
		for i in 0..n { // assuming all participants are in the qualified set
			let (_, coeff) = pubPolys[i].Info();
            let acc_clone = acc.clone();
			acc = acc.add(&acc_clone, &coeff[k]);
		}
		dkgCommits.push(acc);
	}

	// Check that the private DKG shares verify against the public DKG commits
	let dkgPubPoly = PubPoly::new(&g, None, dkgCommits.clone());
	for i in 0..n {
		assert!(dkgPubPoly.Check(&dkgShares[i]));
	}

	// Start verifiable resharing process
	let mut subPriPolys = Vec::with_capacity(n);
	let mut subPriShares = Vec::with_capacity(n);
	let mut subPubPolys = Vec::with_capacity(n);
	let mut subPubShares = Vec::with_capacity(n);

	// Create subshares and subpolys
	for i in 0..n {
		subPriPolys.push(NewPriPoly(g, t, Some(dkgShares[i].clone().v), g.random_stream()));
		subPriShares.push(subPriPolys[i].Shares(n));
		subPubPolys.push(subPriPolys[i].Commit(None));
		subPubShares.push(subPubPolys[i].Shares(n));

        assert_eq!(g.point().mul(&subPriShares[i][0].clone().unwrap().v, None), subPubShares[i][0].as_ref().unwrap().v)
	}

	// Handout shares to new nodes column-wise and verify them
	let mut newDKGShares = Vec::with_capacity(n);
	for i in 0..n {
		let mut tmpPriShares = Vec::with_capacity(n); // column-wise reshuffled sub-shares
		let mut tmpPubShares = Vec::with_capacity(n); // public commitments to old DKG private shares
		for j in 0..n {
			// Check 1: Verify that the received individual private subshares s_ji
			// is correct by evaluating the public commitment vector
			tmpPriShares.push(Some(PriShare{i: j, v: subPriShares[j][i].clone().unwrap().v}));  // Shares that participant i gets from j
            assert!(g.point().mul(&tmpPriShares[j].clone().unwrap().v, None).equal(&subPubPolys[j].Eval(i).v));

			// Check 2: Verify that the received sub public shares are
			// commitments to the original secret
			tmpPubShares.push(Some(dkgPubPoly.Eval(j)));
            assert!(tmpPubShares[j].as_ref().unwrap().v.equal(&subPubPolys[j].Commit()));
		}
		// Check 3: Verify that the received public shares interpolate to the
		// original DKG public key
		let com = RecoverCommit(g, &tmpPubShares, t, n).unwrap();
		assert!(dkgCommits[0].equal(&com));

		// Compute the refreshed private DKG share of node i
		let s = recover_secret(g, &tmpPriShares, t, n).unwrap();
		newDKGShares.push(Some(PriShare{i, v: s}));
	}

	// Refresh the DKG commitments (= verification vector)
	let mut newDKGCommits = Vec::with_capacity(t);
	for i in 0..t {
		let mut pubShares = Vec::with_capacity(n);
		for j in 0..n {
			let (_, c) = subPubPolys[j].Info();
			pubShares.push(Some(PubShare{i: j, v: c[i].clone()}));
		}
		let com = RecoverCommit(g, &pubShares, t, n).unwrap();
		newDKGCommits.push(com);
	}

	// Check that the old and new DKG public keys are the same
	assert!(dkgCommits[0].equal(&newDKGCommits[0]));

	// Check that the old and new DKG private shares are different
	for i in 0..n {
        assert_ne!(dkgShares[i].v, newDKGShares[i].clone().unwrap().v);
	}

	// Check that the refreshed private DKG shares verify against the refreshed public DKG commits
	let q = PubPoly::new(&g, None, newDKGCommits);
	for i in 0..n {
		assert!(q.Check(&newDKGShares[i].clone().unwrap()));
	}

	// Recover the private polynomial
	let refreshedPriPoly = RecoverPriPoly(&g, &newDKGShares, t, n).unwrap();

	// Check that the secret and the corresponding (old) public commit match
	assert!(g.point().mul(&refreshedPriPoly.Secret(), None).equal(&dkgCommits[0]));
}
