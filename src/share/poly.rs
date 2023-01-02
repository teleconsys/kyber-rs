// Package share implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows you to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.
// Both schemes of this package are core building blocks for more advanced
// secret sharing techniques.

use anyhow::bail;
use anyhow::Ok;
use anyhow::Result;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use digest::Digest;
use serde::Deserialize;
use serde::Serialize;

use std::collections::HashMap;
use std::vec;

use crate::encoding::BinaryMarshaler;

use crate::group::HashFactory;
use crate::{cipher::Stream, Group, Point, Scalar};

// Some error definitions
const ERROR_GROUPS: &str = "non-matching groups";
const ERROR_COEFFS: &str = "different number of coefficients";

/// PriShare represents a private share.
#[derive(Clone, Serialize, Deserialize)]
pub struct PriShare<SCALAR> {
    /// Index of the private share
    pub i: usize,
    /// Value of the private share
    pub v: SCALAR,
}

impl<SCALAR: Scalar> Default for PriShare<SCALAR> {
    fn default() -> Self {
        Self {
            i: Default::default(),
            v: Default::default(),
        }
    }
}

impl<SCALAR: Scalar> PriShare<SCALAR> {
    /// Hash returns the hash representation of this share
    pub fn hash<HASHFACTORY: HashFactory>(&self, s: HASHFACTORY) -> Result<Vec<u8>> {
        let mut h = s.hash();
        self.v.marshal_to(&mut h)?;
        h.write_u32::<LittleEndian>(self.i as u32)?;
        Ok(h.finalize().to_vec())
    }

    pub fn string(&self) -> String {
        format!("{{{}:{}}}", self.i, self.v.to_string())
    }
}

/// PriPoly represents a secret sharing polynomial.
#[derive(Clone)]
pub struct PriPoly<GROUP: Group> {
    /// Cryptographic group
    g: GROUP,
    /// Coefficients of the polynomial
    pub coeffs: Vec<<GROUP::POINT as Point>::SCALAR>,
}

impl<GROUP: Group> Default for PriPoly<GROUP> {
    fn default() -> Self {
        Self {
            g: Default::default(),
            coeffs: Default::default(),
        }
    }
}

/// NewPriPoly creates a new secret sharing polynomial using the provided
/// cryptographic group, the secret sharing threshold t, and the secret to be
/// shared s. If s is nil, a new s is chosen using the provided randomness
/// stream rand.
pub fn new_pri_poly<GROUP: Group, STREAM>(
    group: GROUP,
    t: usize,
    s: Option<<GROUP::POINT as Point>::SCALAR>,
    mut rand: STREAM,
) -> PriPoly<GROUP>
where
    STREAM: Stream,
{
    let mut coeffs: Vec<<GROUP::POINT as Point>::SCALAR> = vec![];
    coeffs.push(match s {
        Some(v) => v,
        None => group.scalar().pick(&mut rand),
    });
    for _ in 1..t {
        coeffs.push(group.scalar().pick(&mut rand));
    }
    PriPoly { g: group, coeffs }
}

/// CoefficientsToPriPoly returns a PriPoly based on the given coefficients
pub fn coefficients_to_pri_poly<GROUP: Group>(
    g: &GROUP,
    coeffs: &[<GROUP::POINT as Point>::SCALAR],
) -> PriPoly<GROUP> {
    PriPoly {
        g: g.clone(),
        coeffs: coeffs.to_vec(),
    }
}

impl<GROUP: Group> PriPoly<GROUP> {
    /// Threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
    pub fn secret(&self) -> <GROUP::POINT as Point>::SCALAR {
        self.coeffs[0].clone()
    }

    /// Eval computes the private share v = p(i).
    pub fn eval(&self, i: usize) -> PriShare<<GROUP::POINT as Point>::SCALAR> {
        let xi = self.g.scalar().set_int64(1 + i as i64);
        let mut v = self.g.scalar().zero();
        for j in (0..self.threshold()).rev() {
            v = v * xi.clone();
            v = v + self.coeffs[j].clone();
        }
        PriShare { i, v }
    }

    /// Shares creates a list of n private shares p(1),...,p(n).
    pub fn shares(&self, n: usize) -> Vec<Option<PriShare<<GROUP::POINT as Point>::SCALAR>>> {
        let mut shares = Vec::with_capacity(n);
        for i in 0..n {
            shares.push(Some(self.eval(i)));
        }
        shares
    }

    /// Add computes the component-wise sum of the polynomials p and q and returns it
    /// as a new polynomial.
    pub fn add(&self, q: &PriPoly<GROUP>) -> Result<PriPoly<GROUP>> {
        if self.g.string() != q.g.string() {
            return Err(anyhow::Error::msg("errorGroups"));
        }
        if self.threshold() != q.threshold() {
            return Err(anyhow::Error::msg("errorCoeffs"));
        }
        let mut coeffs = Vec::with_capacity(self.threshold());
        //coeffs := make([]kyber.Scalar, p.Threshold())
        for i in 0..self.threshold() {
            coeffs.push(self.coeffs[i].clone() + q.coeffs[i].clone());
        }
        Ok(PriPoly {
            g: self.g.clone(),
            coeffs,
        })
    }

    /// Equal checks equality of two secret sharing polynomials p and q. If p and q are trivially
    /// unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
    /// returns in variable time. Otherwise it runs in constant time regardless of whether it
    /// eventually returns true or false.
    pub fn equal(&self, q: &PriPoly<GROUP>) -> Result<bool> {
        if self.g.string() != q.g.string() {
            return Ok(false);
        }
        if self.coeffs.len() != q.coeffs.len() {
            return Ok(false);
        }
        let mut b = true;
        for i in 0..self.threshold() {
            let pb = self.coeffs[i].marshal_binary()?;
            let qb = q.coeffs[i].marshal_binary()?;
            b &= pb.eq(&qb);
            //b &= subtle.ConstantTimeCompare(pb, qb)
        }
        Ok(b)
    }

    /// Commit creates a public commitment polynomial for the given base point b or
    /// the standard base if b == nil.
    pub fn commit(&self, b: Option<&GROUP::POINT>) -> PubPoly<GROUP> {
        let mut commits = vec![];
        for i in 0..self.threshold() {
            commits.push(self.g.point().mul(&self.coeffs[i], b));
        }

        PubPoly {
            g: self.g.clone(),
            b: b.cloned(),
            commits,
        }
    }

    /// Mul multiples p and q together. The result is a polynomial of the sum of
    /// the two degrees of p and q. NOTE: it does not check for null coefficients
    /// after the multiplication, so the degree of the polynomial is "always" as
    /// described above. This is only for use in secret sharing schemes. It is not
    /// a general polynomial multiplication routine.
    pub fn mul(&self, q: &Self) -> Self {
        let d1 = self.coeffs.len() - 1;
        let d2 = q.coeffs.len() - 1;
        let new_degree = d1 + d2;
        let mut coeffs = Vec::with_capacity(new_degree + 1);
        for _ in 0..new_degree + 1 {
            coeffs.push(self.g.scalar().zero());
        }
        for (i, cp) in self.coeffs.iter().enumerate() {
            for (j, cq) in q.coeffs.iter().enumerate() {
                let mut tmp = cp.clone();
                tmp = tmp * cq.clone();
                coeffs[i + j] = coeffs[i + j].clone() + tmp;
            }
        }
        PriPoly {
            g: self.g.clone(),
            coeffs,
        }
    }

    /// Coefficients return the list of coefficients representing p. This
    /// information is generally PRIVATE and should not be revealed to a third party
    /// lightly.
    pub fn coefficients(&self) -> Vec<<GROUP::POINT as Point>::SCALAR> {
        self.coeffs.clone()
    }
}

/// RecoverSecret reconstructs the shared secret p(0) from a list of private
/// shares using Lagrange interpolation.
pub fn recover_secret<GROUP: Group>(
    g: GROUP,
    shares: &[Option<PriShare<<GROUP::POINT as Point>::SCALAR>>],
    t: usize,
    n: usize,
) -> Result<<GROUP::POINT as Point>::SCALAR> {
    let (x, y) = xy_scalar(&g, shares, t, n);
    if x.len() < t {
        bail!("share: not enough shares to recover secret");
    }

    let mut acc = g.scalar().zero();
    let mut num = g.scalar();
    let mut den = g.scalar();
    let mut tmp = g.scalar();

    for (i, xi) in x.iter() {
        let yi = &y[i];
        num = num.set(yi);
        den = den.one();
        for (j, xj) in x.iter() {
            if i == j {
                continue;
            }
            num = num * xj.clone();
            tmp = tmp.sub(xj, xi);
            den = den * tmp.clone();
        }
        let num_clone = num.clone();
        num = num.div(&num_clone, &den);
        acc = acc + num.clone();
    }

    Ok(acc)
}

/// xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
/// is the list of x_i and the second map is the list of y_i, both indexed in
/// their respective map at index i.
fn xy_scalar<GROUP: Group>(
    g: &GROUP,
    shares: &[Option<PriShare<<GROUP::POINT as Point>::SCALAR>>],
    t: usize,
    n: usize,
) -> (
    HashMap<usize, <GROUP::POINT as Point>::SCALAR>,
    HashMap<usize, <GROUP::POINT as Point>::SCALAR>,
) {
    // we are sorting first the shares since the shares may be unrelated for
    // some applications. In this case, all participants needs to interpolate on
    // the exact same order shares.
    let mut sorted = Vec::with_capacity(n);
    shares.iter().for_each(|share| {
        if let Some(share) = share {
            sorted.push(share);
        }
    });
    sorted.sort_by(|i, j| i.i.cmp(&j.i));

    let mut x = HashMap::new();
    let mut y = HashMap::new();
    for s in sorted {
        let idx = s.i;
        x.insert(idx, g.scalar().set_int64((idx + 1) as i64));
        y.insert(idx, s.v.clone());
        if x.len() == t {
            break;
        }
    }
    (x, y)
}

fn minus_const<GROUP: Group>(g: &GROUP, c: <GROUP::POINT as Point>::SCALAR) -> PriPoly<GROUP> {
    let neg = g.scalar().neg(&c);
    PriPoly {
        g: g.clone(),
        coeffs: vec![neg, g.scalar().one()],
    }
}

/// RecoverPriPoly takes a list of shares and the parameters t and n to
/// reconstruct the secret polynomial completely, i.e., all private
/// coefficients.  It is up to the caller to make sure that there are enough
/// shares to correctly re-construct the polynomial. There must be at least t
/// shares.
pub fn recover_pri_poly<GROUP: Group>(
    g: &GROUP,
    shares: &[Option<PriShare<<GROUP::POINT as Point>::SCALAR>>],
    t: usize,
    n: usize,
) -> Result<PriPoly<GROUP>> {
    let (x, y) = xy_scalar(g, shares, t, n);
    if x.len() != t {
        bail!("share: not enough shares to recover private polynomial");
    }

    let mut acc_poly = PriPoly {
        g: g.clone(),
        coeffs: vec![],
    };
    //den := g.Scalar()
    // Notations follow the Wikipedia article on Lagrange interpolation
    // https://en.wikipedia.org/wiki/Lagrange_polynomial
    for j in x.keys() {
        let mut basis = lagrange_basis(g, *j, x.clone());
        for (i, _) in basis.coeffs.clone().iter().enumerate() {
            basis.coeffs[i] = basis.coeffs[i].clone() * y[j].clone();
        }

        if acc_poly.coeffs.is_empty() {
            acc_poly = basis;
            continue;
        }

        acc_poly = acc_poly.add(&basis)?;
    }

    Ok(acc_poly)
}

impl<GROUP: Group> PriPoly<GROUP> {
    fn string(&self) -> String {
        let mut strs = Vec::with_capacity(self.coeffs.len());
        for c in self.coeffs.clone() {
            strs.push(c.to_string());
        }
        "[ ".to_string() + &strs.join(", ") + " ]"
    }
}

// PubShare represents a public share.
pub struct PubShare<POINT: Point> {
    /// Index of the public share
    pub i: usize,
    /// Value of the public share
    pub v: POINT,
}

impl<POINT: Point> PubShare<POINT> {
    /// Hash returns the hash representation of this share
    fn hash<HASHFACTORY: HashFactory>(&self, s: HASHFACTORY) -> Result<Vec<u8>> {
        let mut h = s.hash();
        self.v.marshal_to(&mut h)?;
        h.write_u32::<LittleEndian>(self.i as u32)?;
        Ok(h.finalize().to_vec())
    }
}

/// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
#[derive(Clone)]
pub struct PubPoly<GROUP: Group> {
    /// Cryptographic group
    g: GROUP,
    /// Base point, nil for standard base
    b: Option<GROUP::POINT>,
    /// Commitments to coefficients of the secret sharing polynomial
    commits: Vec<GROUP::POINT>,
}

impl<GROUP: Group> Default for PubPoly<GROUP> {
    fn default() -> Self {
        Self {
            g: Default::default(),
            b: Default::default(),
            commits: Default::default(),
        }
    }
}

impl<GROUP: Group> PubPoly<GROUP> {
    /// NewPubPoly creates a new public commitment polynomial.
    pub fn new(g: &GROUP, b: Option<GROUP::POINT>, commits: &[GROUP::POINT]) -> PubPoly<GROUP> {
        PubPoly {
            g: g.clone(),
            b,
            commits: commits.to_vec(),
        }
    }
}

impl<GROUP: Group> PubPoly<GROUP> {
    /// Info returns the base point and the commitments to the polynomial coefficients.
    pub fn info(&self) -> (Option<GROUP::POINT>, Vec<GROUP::POINT>) {
        (self.b.clone(), self.commits.clone())
    }

    /// threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    /// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    pub fn commit(&self) -> GROUP::POINT {
        self.commits[0].clone()
    }

    /// Eval computes the public share v = p(i).
    pub fn eval(&self, i: usize) -> PubShare<GROUP::POINT> {
        // x-coordinate of this share
        let xi = self.g.scalar().set_int64(1 + (i as i64));
        let mut v = self.g.point();
        v = v.null();
        for j in (0..=(self.threshold() - 1)).rev() {
            let v_clone = v.clone();
            v = v.mul(&xi, Some(&v_clone));
            let v_clone = v.clone();
            v = v.add(&v_clone, &self.commits[j]);
        }
        PubShare { i, v }
    }

    /// Shares creates a list of n public commitment shares p(1),...,p(n).
    pub fn shares(&self, n: usize) -> Vec<Option<PubShare<GROUP::POINT>>> {
        let mut shares = Vec::with_capacity(n);
        for i in 0..n {
            shares.push(Some(self.eval(i)));
        }
        shares
    }

    /// Add computes the component-wise sum of the polynomials p and q and returns it
    /// as a new polynomial. NOTE: If the base points p.b and q.b are different then the
    /// base point of the resulting PubPoly cannot be computed without knowing the
    /// discrete logarithm between p.b and q.b. In this particular case, we are using
    /// p.b as a default value which of course does not correspond to the correct
    /// base point and thus should not be used in further computations.
    pub fn add(&self, q: &Self) -> Result<Self> {
        if self.g.string() != q.g.string() {
            bail!(ERROR_GROUPS);
        }

        if self.threshold() != q.threshold() {
            bail!(ERROR_COEFFS);
        }

        let mut commits = vec![];
        for i in 0..self.threshold() {
            commits.push(self.g.point().add(&self.commits[i], &q.commits[i]));
        }

        Ok(PubPoly {
            g: self.g.clone(),
            b: self.b.clone(),
            commits,
        })
    }

    /// Equal checks equality of two public commitment polynomials p and q. If p and
    /// q are trivially unequal (e.g., due to mismatching cryptographic groups),
    /// this routine returns in variable time. Otherwise it runs in constant time
    /// regardless of whether it eventually returns true or false.
    pub fn equal(&self, q: &PubPoly<GROUP>) -> Result<bool> {
        if self.g.string() != q.g.string() {
            return Ok(false);
        }
        let mut b = true;
        for i in 0..self.threshold() {
            let pb = self.commits[i].marshal_binary()?;
            let qb = q.commits[i].marshal_binary()?;
            b &= pb.eq(&qb);
            //b &= subtle.ConstantTimeCompare(pb, qb)
        }
        Ok(b)
    }

    /// Check a private share against a public commitment polynomial.
    pub fn check(&self, s: &PriShare<<GROUP::POINT as Point>::SCALAR>) -> bool {
        let pv = self.eval(s.i);
        let ps = self.g.point().mul(&s.v, self.b.as_ref());
        pv.v.equal(&ps)
    }
}

// type byIndexPub []*PubShare

// func (s byIndexPub) Len() int           { return len(s) }
// func (s byIndexPub) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byIndexPub) Less(i, j int) bool { return s[i].I < s[j].I }

/// xyCommits is the public version of xScalars.
pub fn xy_commit<GROUP: Group>(
    g: &GROUP,
    shares: &[Option<PubShare<GROUP::POINT>>],
    t: usize,
    n: usize,
) -> (
    HashMap<usize, <GROUP::POINT as Point>::SCALAR>,
    HashMap<usize, GROUP::POINT>,
) {
    // we are sorting first the shares since the shares may be unrelated for
    // some applications. In this case, all participants needs to interpolate on
    // the exact same order shares.
    let mut sorted = Vec::with_capacity(n);
    shares.iter().for_each(|share| {
        if let Some(share) = share {
            sorted.push(share);
        }
    });
    sorted.sort_by(|i, j| i.i.cmp(&j.i));

    let mut x = HashMap::new();
    let mut y = HashMap::new();
    for s in sorted {
        let idx = s.i;
        x.insert(idx, g.scalar().set_int64((idx + 1) as i64));
        y.insert(idx, s.v.clone());
        if x.len() == t {
            break;
        }
    }
    (x, y)
}

/// RecoverCommit reconstructs the secret commitment p(0) from a list of public
/// shares using Lagrange interpolation.
pub fn recover_commit<GROUP: Group>(
    g: GROUP,
    shares: &[Option<PubShare<GROUP::POINT>>],
    t: usize,
    n: usize,
) -> Result<GROUP::POINT> {
    let (x, y) = xy_commit(&g, shares, t, n);

    if x.len() < t {
        bail!("share: not enough good public shares to reconstruct secret commitment")
    }

    let mut num = g.scalar();
    let mut den = g.scalar();
    let mut tmp = g.scalar();
    let mut acc = g.point().null();
    let mut tmp_caps = g.point();

    for (i, xi) in x.iter() {
        num = num.one();
        den = den.one();
        for (j, xj) in x.iter() {
            if i == j {
                continue;
            }
            num = num * xj.clone();
            tmp = tmp.sub(xj, xi);
            den = den * tmp.clone();
        }
        let num_clone = num.clone();
        num = num.div(&num_clone, &den);
        tmp_caps = tmp_caps.mul(&num, Some(&y[i]));
        let acc_clone = acc.clone();
        acc = acc.add(&acc_clone, &tmp_caps);
    }

    Ok(acc)
}

/// RecoverPubPoly reconstructs the full public polynomial from a set of public
/// shares using Lagrange interpolation.
pub fn recover_pub_poly<GROUP: Group>(
    g: GROUP,
    shares: &[Option<PubShare<GROUP::POINT>>],
    t: usize,
    n: usize,
) -> Result<PubPoly<GROUP>> {
    let (x, y) = xy_commit(&g, shares, t, n);
    if x.len() < t {
        bail!("share: not enough good public shares to reconstruct secret commitment");
    }

    let mut acc_poly = PubPoly::new(&g, None, &[]);

    for (j, _) in x.iter().enumerate() {
        let basis = lagrange_basis(&g, j, x.clone());

        // compute the L_j * y_j polynomial in point space
        let tmp = basis.commit(Some(&y[&j]));
        if acc_poly.commits.is_empty() {
            acc_poly = tmp;
            continue;
        }

        // add all L_j * y_j together
        acc_poly = acc_poly.add(&tmp)?;
    }

    Ok(acc_poly)
}

/// lagrangeBasis returns a PriPoly containing the Lagrange coefficients for the
/// i-th position. xs is a mapping between the indices and the values that the
/// interpolation is using, computed with xyScalar().
fn lagrange_basis<GROUP: Group>(
    g: &GROUP,
    i: usize,
    xs: HashMap<usize, <GROUP::POINT as Point>::SCALAR>,
) -> PriPoly<GROUP> {
    let mut basis = PriPoly {
        g: g.clone(),
        coeffs: vec![g.clone().scalar().one()],
    };
    // compute lagrange basis l_j
    let mut den = g.scalar().one();
    let mut acc = g.scalar().one();
    for (m, xm) in xs.iter() {
        if &i == m {
            continue;
        }
        basis = basis.mul(&minus_const(g, xm.clone()));
        den = den.sub(&xs[&i], xm); // den = xi - xm
        let den_clone = den.clone();
        den = den.inv(&den_clone); // den = 1 / den
        acc = acc * den.clone(); // acc = acc * den
    }

    // multiply all coefficients by the denominator
    for (i, _) in basis.coeffs.clone().iter().enumerate() {
        basis.coeffs[i] = basis.coeffs[i].clone() * acc.clone();
    }
    basis
}
