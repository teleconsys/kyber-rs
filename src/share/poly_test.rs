use crate::{
    group::edwards25519,
    share::poly::{coefficients_to_pri_poly, recover_pub_poly, PriShare},
    Group, Point, Random, Scalar,
};

use super::poly::{
    new_pri_poly, recover_commit, recover_pri_poly, recover_secret, PubPoly, PubShare,
};

#[test]
fn test_secret_recovery() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = new_pri_poly(g, t, None, g.random_stream());
    let shares = poly.shares(n);

    let recovered = recover_secret(g, &shares, t, n).unwrap();

    assert_eq!(
        recovered,
        poly.secret(),
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
fn test_secret_recovery_out_index() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = new_pri_poly(g, t, None, g.random_stream());
    let shares = poly.shares(n);

    let selected = &shares[n - t..];
    assert_eq!(selected.len(), t);
    let new_n = t + 1;

    let recovered = recover_secret(g, selected, t, new_n).unwrap();

    assert_eq!(
        recovered,
        poly.secret(),
        "recovered secret does not match initial value"
    );
}

#[test]
fn test_secret_recovery_delete() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let poly = new_pri_poly(g, t, None, g.random_stream());
    let mut shares = poly.shares(n);

    // Corrupt a few shares
    shares[2] = None;
    shares[5] = None;
    shares[7] = None;
    shares[8] = None;

    let recovered = recover_secret(g, &shares, t, n).unwrap();

    assert_eq!(
        recovered,
        poly.secret(),
        "recovered secret does not match initial value",
    );
}

#[test]
fn test_secret_recovery_delete_fail() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let poly = new_pri_poly(g, t, None, g.random_stream());
    let mut shares = poly.shares(n);

    // Corrupt one more share than acceptable
    shares[1] = None;
    shares[2] = None;
    shares[5] = None;
    shares[7] = None;
    shares[8] = None;

    recover_secret(g, &shares, t, n).expect_err("recovered secret unexpectably");
}

#[test]
fn test_secret_poly_equal() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let p1 = new_pri_poly(g, t, None, g.random_stream());
    let p2 = new_pri_poly(g, t, None, g.random_stream());
    let p3 = new_pri_poly(g, t, None, g.random_stream());

    let p12 = p1.add(&p2).unwrap();
    let p13 = p1.add(&p3).unwrap();

    let p123 = p12.add(&p3).unwrap();
    let p132 = p13.add(&p2).unwrap();

    assert!(p123.equal(&p132).unwrap(), "private polynomials not equal");
}

#[test]
fn test_public_check() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let pri_poly = new_pri_poly(g, t, None, g.random_stream());
    let pri_shares = pri_poly.shares(n);
    let pub_poly = pri_poly.commit(None);

    for (i, share) in pri_shares.iter().enumerate() {
        assert!(
            pub_poly.check(share.as_ref().unwrap()),
            "{}",
            format!("private share {i} not valid with respect to the public commitment polynomial")
        )
    }
}

#[test]
fn test_public_recovery() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let pri_poly = new_pri_poly(g, t, None, g.random_stream());
    let pub_poly = pri_poly.commit(None);
    let pub_shares = pub_poly.shares(n);

    let recovered = recover_commit(g, pub_shares.as_slice(), t, n).unwrap();

    assert_eq!(recovered, pub_poly.commit());

    let poly_recovered = recover_pub_poly(g, &pub_shares, t, n).unwrap();

    assert!(pub_poly.equal(&poly_recovered).unwrap());
}

#[test]
fn test_public_recovery_out_index() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let pri_poly = new_pri_poly(g, t, None, g.random_stream());
    let pub_poly = pri_poly.commit(None);
    let pub_shares = pub_poly.shares(n);

    let selected = &pub_shares[n - t..];
    assert_eq!(selected.len(), t);

    let new_n = t + 1;

    let recovered = recover_commit(g, selected, t, new_n).unwrap();

    assert_eq!(recovered, pub_poly.commit());

    let poly_recovered = recover_pub_poly(g, &pub_shares, t, n).unwrap();

    assert!(pub_poly.equal(&poly_recovered).unwrap());
}

#[test]
fn test_public_recovery_delete() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let pri_poly = new_pri_poly(g, t, None, g.random_stream());
    let pub_poly = pri_poly.commit(None);
    let mut shares = pub_poly.shares(n);

    // Corrupt aNone;w shares
    shares[2] = None;
    shares[5] = None;
    shares[7] = None;
    shares[8] = None;

    let recovered = recover_commit(g, &shares, t, n).unwrap();

    assert_eq!(
        recovered,
        pub_poly.commit(),
        "recovered commit does not match initial value"
    );
}

#[test]
fn test_public_recovery_delete_fail() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let pri_poly = new_pri_poly(g, t, None, g.random_stream());
    let pub_poly = pri_poly.commit(None);
    let mut shares = pub_poly.shares(n);

    // Corrupt one more share than acceptable
    shares[1] = None;
    shares[2] = None;
    shares[5] = None;
    shares[7] = None;
    shares[8] = None;

    recover_commit(g, &shares, t, n).expect_err("recovered commit unexpectably");
}

#[test]
fn test_private_add() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let p = new_pri_poly(g, t, None, g.random_stream());
    let q = new_pri_poly(g, t, None, g.random_stream());

    let r = p.add(&q).unwrap();

    let ps = p.secret();
    let qs = q.secret();
    let rs = ps + qs;

    assert_eq!(
        rs,
        r.secret(),
        "addition of secret sharing polynomials failed"
    );
}

#[test]
fn test_public_add() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let g_caps = g.point().pick(&mut g.random_stream());
    let h = g.point().pick(&mut g.random_stream());

    let p = new_pri_poly(g, t, None, g.random_stream());
    let q = new_pri_poly(g, t, None, g.random_stream());

    let p_caps = p.commit(Some(&g_caps));
    let q_caps = q.commit(Some(&h));

    let r = p_caps.add(&q_caps).unwrap();

    let shares = r.shares(n);
    let recovered = recover_commit(g, &shares, t, n).unwrap();

    let x = p_caps.commit();
    let y = q_caps.commit();
    let z = g.point().add(&x, &y);

    assert_eq!(
        recovered, z,
        "addition of public commitment polynomials failed"
    );
}

#[test]
fn test_public_poly_equal() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    let g_caps = g.point().pick(&mut g.random_stream());

    let p1 = new_pri_poly(g, t, None, g.random_stream());
    let p2 = new_pri_poly(g, t, None, g.random_stream());
    let p3 = new_pri_poly(g, t, None, g.random_stream());

    let p_caps1 = p1.commit(Some(&g_caps));
    let p_caps2 = p2.commit(Some(&g_caps));
    let p_caps3 = p3.commit(Some(&g_caps));

    let p12 = p_caps1.add(&p_caps2).unwrap();
    let p13 = p_caps1.add(&p_caps3).unwrap();

    let p123 = p12.add(&p_caps3).unwrap();
    let p132 = p13.add(&p_caps2).unwrap();

    assert!(p123.equal(&p132).unwrap(), "public polynomials not equal");
}

#[test]
fn test_pri_poly_mul() {
    let suite = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let a = new_pri_poly(suite, t, None, suite.random_stream());
    let b = new_pri_poly(suite, t, None, suite.random_stream());

    let c = a.mul(&b);
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
fn test_recover_pri_poly() {
    let suite = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let a = new_pri_poly(suite, t, None, suite.random_stream());

    let shares = a.shares(n);
    let mut reverses = shares.clone();
    reverses.reverse();

    let recovered = recover_pri_poly(&suite, &shares, t, n).unwrap();

    let reverse_recovered = recover_pri_poly(&suite, &reverses, t, n).unwrap();

    for i in 0..t {
        assert_eq!(recovered.eval(i).v.to_string(), a.eval(i).v.to_string());
        assert_eq!(
            reverse_recovered.eval(i).v.to_string(),
            a.eval(i).v.to_string()
        );
    }
}

#[test]
fn test_pri_poly_coefficients() {
    let suite = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;
    let a = new_pri_poly(suite, t, None, suite.random_stream());

    let coeffs = a.coefficients();
    assert_eq!(coeffs.len(), t);

    let b = coefficients_to_pri_poly(&suite, &coeffs);
    assert_eq!(a.coeffs, b.coeffs);
}

#[test]
fn test_refresh_dkg() {
    let g = edwards25519::SuiteEd25519::new_blake3_sha256_ed25519();
    let n = 10;
    let t = n / 2 + 1;

    // Run an n-fold Pedersen VSS (= DKG)
    let mut pri_polys = Vec::with_capacity(n);
    let mut pri_shares = Vec::with_capacity(n);
    let mut pub_polys = Vec::with_capacity(n);
    let mut pub_shares = Vec::with_capacity(n);
    for i in 0..n {
        pri_polys.push(new_pri_poly(g, t, None, g.random_stream()));
        pri_shares.push(pri_polys[i].shares(n));
        pub_polys.push(pri_polys[i].commit(None));
        pub_shares.push(pub_polys[i].shares(n));
    }

    // Verify VSS shares
    for i in 0..n {
        for j in 0..n {
            let sij = pri_shares[i][j].clone().unwrap();
            // s_ij * G
            let mut sij_g = g.point().base();
            sij_g = sij_g.mul(&sij.v, None);
            assert_eq!(sij_g, pub_shares[i][j].as_ref().unwrap().v);
        }
    }

    // Create private DKG shares
    let mut dkg_shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut acc = g.scalar().zero();
        (0..n).for_each(|j| {
            // assuming all participants are in the qualified set
            acc = acc.clone() + pri_shares[j][i].clone().unwrap().v;
        });
        dkg_shares.push(PriShare { i, v: acc });
    }

    // Create public DKG commitments (= verification vector)
    let mut dkg_commits = Vec::with_capacity(t);
    for k in 0..t {
        let mut acc = g.point().null();
        (0..n).for_each(|i| {
            // assuming all participants are in the qualified set
            let (_, coeff) = pub_polys[i].info();
            let acc_clone = acc.clone();
            acc = acc.clone().add(&acc_clone, &coeff[k]);
        });
        dkg_commits.push(acc);
    }

    // Check that the private DKG shares verify against the public DKG commits
    let dkg_pub_poly = PubPoly::new(&g, None, &dkg_commits);
    (0..n).for_each(|i| {
        assert!(dkg_pub_poly.check(&dkg_shares[i]));
    });

    // Start verifiable resharing process
    let mut sub_pri_polys = Vec::with_capacity(n);
    let mut sub_pri_shares = Vec::with_capacity(n);
    let mut sub_pub_polys = Vec::with_capacity(n);
    let mut sub_pub_shares = Vec::with_capacity(n);

    // Create subshares and subpolys
    for i in 0..n {
        sub_pri_polys.push(new_pri_poly(
            g,
            t,
            Some(dkg_shares[i].clone().v),
            g.random_stream(),
        ));
        sub_pri_shares.push(sub_pri_polys[i].shares(n));
        sub_pub_polys.push(sub_pri_polys[i].commit(None));
        sub_pub_shares.push(sub_pub_polys[i].shares(n));

        assert_eq!(
            g.point()
                .mul(&sub_pri_shares[i][0].clone().unwrap().v, None),
            sub_pub_shares[i][0].as_ref().unwrap().v
        )
    }

    // Handout shares to new nodes column-wise and verify them
    let mut new_dkg_shares = Vec::with_capacity(n);
    for i in 0..n {
        let mut tmp_pri_shares = Vec::with_capacity(n); // column-wise reshuffled sub-shares
        let mut tmp_pub_shares = Vec::with_capacity(n); // public commitments to old DKG private shares
        for j in 0..n {
            // Check 1: Verify that the received individual private subshares s_ji
            // is correct by evaluating the public commitment vector
            tmp_pri_shares.push(Some(PriShare {
                i: j,
                v: sub_pri_shares[j][i].clone().unwrap().v,
            })); // Shares that participant i gets from j
            assert!(g
                .point()
                .mul(&tmp_pri_shares[j].clone().unwrap().v, None)
                .equal(&sub_pub_polys[j].eval(i).v));

            // Check 2: Verify that the received sub public shares are
            // commitments to the original secret
            tmp_pub_shares.push(Some(dkg_pub_poly.eval(j)));
            assert!(tmp_pub_shares[j]
                .as_ref()
                .unwrap()
                .v
                .equal(&sub_pub_polys[j].commit()));
        }
        // Check 3: Verify that the received public shares interpolate to the
        // original DKG public key
        let com = recover_commit(g, &tmp_pub_shares, t, n).unwrap();
        assert!(dkg_commits[0].equal(&com));

        // Compute the refreshed private DKG share of node i
        let s = recover_secret(g, &tmp_pri_shares, t, n).unwrap();
        new_dkg_shares.push(Some(PriShare { i, v: s }));
    }

    // Refresh the DKG commitments (= verification vector)
    let mut new_dkg_commits = Vec::with_capacity(t);
    for i in 0..t {
        let mut pub_shares = Vec::with_capacity(n);
        (0..n).for_each(|j| {
            let (_, c) = sub_pub_polys[j].info();
            pub_shares.push(Some(PubShare {
                i: j,
                v: c[i].clone(),
            }));
        });
        let com = recover_commit(g, &pub_shares, t, n).unwrap();
        new_dkg_commits.push(com);
    }

    // Check that the old and new DKG public keys are the same
    assert!(dkg_commits[0].equal(&new_dkg_commits[0]));

    // Check that the old and new DKG private shares are different
    for i in 0..n {
        assert_ne!(dkg_shares[i].v, new_dkg_shares[i].clone().unwrap().v);
    }

    // Check that the refreshed private DKG shares verify against the refreshed public DKG commits
    let q = PubPoly::new(&g, None, &new_dkg_commits);
    (0..n).for_each(|i| {
        assert!(q.check(&new_dkg_shares[i].clone().unwrap()));
    });

    // Recover the private polynomial
    let refreshed_pri_poly = recover_pri_poly(&g, &new_dkg_shares, t, n).unwrap();

    // Check that the secret and the corresponding (old) public commit match
    assert!(g
        .point()
        .mul(&refreshed_pri_poly.secret(), None)
        .equal(&dkg_commits[0]));
}
