// Package share implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows you to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.
// Both schemes of this package are core building blocks for more advanced
// secret sharing techniques.

use anyhow::Ok;
use anyhow::bail;
use anyhow::Result;
use lazy_static::__Deref;
use serde::Deserialize;
use serde::Serialize;

// Some error definitions
const ERROR_GROUPS: &str = "non-matching groups";
const ERROR_COEFFS: &str = "different number of coefficients";

/// PriShare represents a private share.
#[derive(Clone, Serialize, Deserialize)]
pub struct PriShare<SCALAR: Scalar> {
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

// // Hash returns the hash representation of this share
// func (p *PriShare) Hash(s kyber.HashFactory) []byte {
// 	h := s.Hash()
// 	_, _ = p.V.MarshalTo(h)
// 	_ = binary.Write(h, binary.LittleEndian, p.I)
// 	return h.Sum(nil)
// }

// func (p *PriShare) String() string {
// 	return fmt.Sprintf("{%d:%s}", p.I, p.V)
// }

/// PriPoly represents a secret sharing polynomial.
pub struct PriPoly<GROUP: Group> {
    /// Cryptographic group
    g: GROUP,
    /// Coefficients of the polynomial
    coeffs: Vec<<GROUP::POINT as Point>::SCALAR>,
}

use std::cmp;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::DerefMut;
use std::ops::Mul;
use std::vec;

use crate::encoding::BinaryMarshaler;
use crate::{cipher::Stream, Group, Point, Scalar};

/// NewPriPoly creates a new secret sharing polynomial using the provided
/// cryptographic group, the secret sharing threshold t, and the secret to be
/// shared s. If s is nil, a new s is chosen using the provided randomness
/// stream rand.
pub fn NewPriPoly<GROUP: Group, STREAM>(
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
    PriPoly {
        g: group,
        coeffs: coeffs,
    }
}

// // CoefficientsToPriPoly returns a PriPoly based on the given coefficients
// func CoefficientsToPriPoly(g kyber.Group, coeffs []kyber.Scalar) *PriPoly {
// 	return &PriPoly{g: g, coeffs: coeffs}
// }

impl<GROUP: Group> PriPoly<GROUP> {
    /// Threshold returns the secret sharing threshold.
    pub fn Threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
    pub fn Secret(&self) -> <GROUP::POINT as Point>::SCALAR {
        self.coeffs[0].clone()
    }

    /// Eval computes the private share v = p(i).
    pub fn Eval(&self, i: usize) -> PriShare<<GROUP::POINT as Point>::SCALAR> {
        let xi = self.g.scalar().set_int64(1 + i as i64);
        let mut v = self.g.scalar().zero();
        for j in (0..self.Threshold()).rev() {
            v = v * xi.clone();
            v = v + self.coeffs[j].clone();
        }
        PriShare { i, v }
    }

    /// Shares creates a list of n private shares p(1),...,p(n).
    pub fn Shares(&self, n: usize) -> Vec<Option<PriShare<<GROUP::POINT as Point>::SCALAR>>> {
        let mut shares = Vec::with_capacity(n);
        for i in 0..n {
            shares.push(Some(self.Eval(i)));
        }
        shares
    }

    /// Add computes the component-wise sum of the polynomials p and q and returns it
    /// as a new polynomial.
    pub fn Add(&self, q: &PriPoly<GROUP>) -> Result<PriPoly<GROUP>> {
    	if self.g.string() != q.g.string() {
    		return Err(anyhow::Error::msg("errorGroups"))
    	}
    	if self.Threshold() != q.Threshold() {
            return Err(anyhow::Error::msg("errorCoeffs"))
    	}
        let mut coeffs = Vec::with_capacity(self.Threshold());
    	//coeffs := make([]kyber.Scalar, p.Threshold())
    	for i in 0..self.Threshold() {
            coeffs.push(self.coeffs[i].clone() + q.coeffs[i].clone());
    	}
        Ok(PriPoly{g: self.g.clone(), coeffs})
    }

    /// Equal checks equality of two secret sharing polynomials p and q. If p and q are trivially
    /// unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
    /// returns in variable time. Otherwise it runs in constant time regardless of whether it
    /// eventually returns true or false.
    pub fn Equal(&self, q: &PriPoly<GROUP>) -> Result<bool> {
    	if self.g.string() != q.g.string() {
    		return Ok(false)
    	}
    	if self.coeffs.len() != q.coeffs.len() {
    		return Ok(false)
    	}
    	let mut b = true;
    	for i in 0..self.Threshold() {
    		let pb = self.coeffs[i].marshal_binary()?;
    		let qb = q.coeffs[i].marshal_binary()?;
    		b &= pb.eq(&qb);
            //b &= subtle.ConstantTimeCompare(pb, qb)
    	}
    	Ok(b)
    }

    /// Commit creates a public commitment polynomial for the given base point b or
    /// the standard base if b == nil.
    pub fn Commit(&self, b: Option<&GROUP::POINT>) -> PubPoly<GROUP> {
        let mut commits = vec![];
        for i in 0..self.Threshold() {
            commits.push(self.g.point().mul(&self.coeffs[i], b));
        }

        PubPoly {
            g: self.g.clone(),
            b: b.map(|p| p.clone()),
            commits,
        }
    }

    // // Mul multiples p and q together. The result is a polynomial of the sum of
    // // the two degrees of p and q. NOTE: it does not check for null coefficients
    // // after the multiplication, so the degree of the polynomial is "always" as
    // // described above. This is only for use in secret sharing schemes. It is not
    // // a general polynomial multiplication routine.
    // func (p *PriPoly) Mul(q *PriPoly) *PriPoly {
    // 	d1 := len(p.coeffs) - 1
    // 	d2 := len(q.coeffs) - 1
    // 	newDegree := d1 + d2
    // 	coeffs := make([]kyber.Scalar, newDegree+1)
    // 	for i := range coeffs {
    // 		coeffs[i] = p.g.Scalar().Zero()
    // 	}
    // 	for i := range p.coeffs {
    // 		for j := range q.coeffs {
    // 			tmp := p.g.Scalar().Mul(p.coeffs[i], q.coeffs[j])
    // 			coeffs[i+j] = tmp.Add(coeffs[i+j], tmp)
    // 		}
    // 	}
    // 	return &PriPoly{p.g, coeffs}
    // }

    // // Coefficients return the list of coefficients representing p. This
    // // information is generally PRIVATE and should not be revealed to a third party
    // // lightly.
    // func (p *PriPoly) Coefficients() []kyber.Scalar {
    // 	return p.coeffs
    // }
}

/// RecoverSecret reconstructs the shared secret p(0) from a list of private
/// shares using Lagrange interpolation.
pub fn recover_secret<GROUP: Group>(
    g: GROUP,
    shares: &[Option<PriShare<<GROUP::POINT as Point>::SCALAR>>],
    t: usize,
    n: usize,
) -> Result<<GROUP::POINT as Point>::SCALAR> {
    let (x, y) = xy_scalar(&g, &shares, t, n);
    if x.len() < t {
        bail!("share: not enough shares to recover secret");
    }

    let mut acc = g.scalar().zero();
    let mut num = g.scalar();
    let mut den = g.scalar();
    let mut tmp = g.scalar();

    for (i, xi) in x.iter() {
        let yi = &y[&i];
        num = num.set(&yi);
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

// type byIndexScalar []*PriShare

// func (s byIndexScalar) Len() int           { return len(s) }
// func (s byIndexScalar) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byIndexScalar) Less(i, j int) bool { return s[i].I < s[j].I }

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
    for share in shares.clone() {
        if let Some(share) = share {
            sorted.push(share);
        }
    }
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

// func minusConst(g kyber.Group, c kyber.Scalar) *PriPoly {
// 	neg := g.Scalar().Neg(c)
// 	return &PriPoly{
// 		g:      g,
// 		coeffs: []kyber.Scalar{neg, g.Scalar().One()},
// 	}
// }

// // RecoverPriPoly takes a list of shares and the parameters t and n to
// // reconstruct the secret polynomial completely, i.e., all private
// // coefficients.  It is up to the caller to make sure that there are enough
// // shares to correctly re-construct the polynomial. There must be at least t
// // shares.
// func RecoverPriPoly(g kyber.Group, shares []*PriShare, t, n int) (*PriPoly, error) {
// 	x, y := xyScalar(g, shares, t, n)
// 	if len(x) != t {
// 		return nil, errors.New("share: not enough shares to recover private polynomial")
// 	}

// 	var accPoly *PriPoly
// 	var err error
// 	//den := g.Scalar()
// 	// Notations follow the Wikipedia article on Lagrange interpolation
// 	// https://en.wikipedia.org/wiki/Lagrange_polynomial
// 	for j := range x {
// 		basis := lagrangeBasis(g, j, x)
// 		for i := range basis.coeffs {
// 			basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], y[j])
// 		}

// 		if accPoly == nil {
// 			accPoly = basis
// 			continue
// 		}

// 		// add all L_j * y_j together
// 		accPoly, err = accPoly.Add(basis)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	return accPoly, nil
// }

// func (p *PriPoly) String() string {
// 	var strs = make([]string, len(p.coeffs))
// 	for i, c := range p.coeffs {
// 		strs[i] = c.String()
// 	}
// 	return "[ " + strings.Join(strs, ", ") + " ]"
// }

// PubShare represents a public share.
pub struct PubShare<POINT: Point> {
    /// Index of the public share
    pub i: usize,
    /// Value of the public share
    pub v: POINT,
}

// // Hash returns the hash representation of this share.
// func (p *PubShare) Hash(s kyber.HashFactory) []byte {
// 	h := s.Hash()
// 	_, _ = p.V.MarshalTo(h)
// 	_ = binary.Write(h, binary.LittleEndian, p.I)
// 	return h.Sum(nil)
// }

/// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
pub struct PubPoly<GROUP>
where
    GROUP: Group,
{
    /// Cryptographic group
    g: GROUP,
    /// Base point, nil for standard base
    b: Option<GROUP::POINT>,
    /// Commitments to coefficients of the secret sharing polynomial
    commits: Vec<GROUP::POINT>,
}

impl<GROUP: Group> PubPoly<GROUP> {
    /// NewPubPoly creates a new public commitment polynomial.
    pub fn new(g: GROUP, b: Option<GROUP::POINT>, commits: Vec<GROUP::POINT>) -> PubPoly<GROUP> {
        return PubPoly { g, b, commits };
    }
}

impl<GROUP: Group> PubPoly<GROUP> {
    /// Info returns the base point and the commitments to the polynomial coefficients.
    pub fn Info(&self) -> (GROUP::POINT, Vec<GROUP::POINT>) {
        (self.b.as_ref().unwrap().clone(), self.commits.clone())
    }

    /// threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    /// Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    pub fn Commit(&self) -> GROUP::POINT {
    	return self.commits[0].clone()
    }

    /// Eval computes the public share v = p(i).
    pub fn Eval(&self, i: usize) -> PubShare<GROUP::POINT> {
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
        return PubShare { i, v };
    }

    /// Shares creates a list of n public commitment shares p(1),...,p(n).
    pub fn Shares(&self, n: usize) -> Vec<Option<PubShare<GROUP::POINT>>> {
    	let mut shares = Vec::with_capacity(n);
    	for i in 0..n {
    		shares.push(Some(self.Eval(i)));
    	}
    	return shares
    }

    /// Add computes the component-wise sum of the polynomials p and q and returns it
    /// as a new polynomial. NOTE: If the base points p.b and q.b are different then the
    /// base point of the resulting PubPoly cannot be computed without knowing the
    /// discrete logarithm between p.b and q.b. In this particular case, we are using
    /// p.b as a default value which of course does not correspond to the correct
    /// base point and thus should not be used in further computations.
    pub fn Add(self, q: &Self) -> Result<Self> {
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
            g: self.g,
            b: self.b,
            commits,
        })
    }

    /// Equal checks equality of two public commitment polynomials p and q. If p and
    /// q are trivially unequal (e.g., due to mismatching cryptographic groups),
    /// this routine returns in variable time. Otherwise it runs in constant time
    /// regardless of whether it eventually returns true or false.
    pub fn Equal(&self, q: &PubPoly<GROUP>) -> Result<bool> {
    	if self.g.string() != q.g.string() {
    		return Ok(false)
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
    pub fn Check(&self, s: &PriShare<<GROUP::POINT as Point>::SCALAR>) -> bool {
    	let pv = self.Eval(s.i);
    	let ps = self.g.point().mul(&s.v, self.b.as_ref());
    	return pv.v.equal(&ps)
    }
}

// type byIndexPub []*PubShare

// func (s byIndexPub) Len() int           { return len(s) }
// func (s byIndexPub) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byIndexPub) Less(i, j int) bool { return s[i].I < s[j].I }

/// xyCommits is the public version of xScalars.
pub fn xyCommit<GROUP: Group>(g: &GROUP, shares: &[Option<PubShare<GROUP::POINT>>], t: usize, n: usize) -> (
HashMap<usize, <GROUP::POINT as Point>::SCALAR>,
HashMap<usize, GROUP::POINT>,
) {
	// we are sorting first the shares since the shares may be unrelated for
	// some applications. In this case, all participants needs to interpolate on
	// the exact same order shares.
    let mut sorted = Vec::with_capacity(n);
    for share in shares.clone() {
        if let Some(share) = share {
            sorted.push(share);
        }
    }
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
pub fn RecoverCommit<GROUP: Group>(g: GROUP, shares: &[Option<PubShare<GROUP::POINT>>], t: usize, n: usize) -> Result<GROUP::POINT> {
	let (x, y) = xyCommit(&g, shares, t, n);

    if x.len() < t {
        bail!("share: not enough good public shares to reconstruct secret commitment")
    }

	let mut num = g.scalar();
	let mut den = g.scalar();
	let mut tmp = g.scalar();
	let mut Acc = g.point().null();
	let mut Tmp = g.point();

	for (i, xi) in x.iter().enumerate() {
		num = num.one();
		den = den.one();
		for (j, xj) in x.iter().enumerate() {
			if i == j {
				continue
			}
			num = num * xj.1.clone();
            tmp = tmp.sub(&xj.1,&xi.1);
			den = den.mul(tmp.clone());
		}
        let num_clone = num.clone();
        num = num.div(&num_clone, &den);
		Tmp = Tmp.mul(&num, Some(&y[&i]));
        let acc_clone = Acc.clone();
		Acc = Acc.add(&acc_clone, &Tmp);
	}

	Ok(Acc)
}

/// RecoverPubPoly reconstructs the full public polynomial from a set of public
/// shares using Lagrange interpolation.
pub fn RecoverPubPoly<GROUP: Group>(g: GROUP, shares: &[Option<PubShare<GROUP::POINT>>], t: usize, n: usize) -> Result<PubPoly<GROUP>> {
    todo!();
	// x, y := xyCommit(g, shares, t, n)
	// if len(x) < t {
	// 	return nil, errors.New("share: not enough good public shares to reconstruct secret commitment")
	// }

	// var accPoly *PubPoly
	// var err error

	// for j := range x {
	// 	basis := lagrangeBasis(g, j, x)

	// 	// compute the L_j * y_j polynomial in point space
	// 	tmp := basis.Commit(y[j])
	// 	if accPoly == nil {
	// 		accPoly = tmp
	// 		continue
	// 	}

	// 	// add all L_j * y_j together
	// 	accPoly, err = accPoly.Add(tmp)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	// return accPoly, nil

}

// // lagrangeBasis returns a PriPoly containing the Lagrange coefficients for the
// // i-th position. xs is a mapping between the indices and the values that the
// // interpolation is using, computed with xyScalar().
// func lagrangeBasis(g kyber.Group, i int, xs map[int]kyber.Scalar) *PriPoly {
// 	var basis = &PriPoly{
// 		g:      g,
// 		coeffs: []kyber.Scalar{g.Scalar().One()},
// 	}
// 	// compute lagrange basis l_j
// 	den := g.Scalar().One()
// 	var acc = g.Scalar().One()
// 	for m, xm := range xs {
// 		if i == m {
// 			continue
// 		}
// 		basis = basis.Mul(minusConst(g, xm))
// 		den.Sub(xs[i], xm) // den = xi - xm
// 		den.Inv(den)       // den = 1 / den
// 		acc.Mul(acc, den)  // acc = acc * den
// 	}

// 	// multiply all coefficients by the denominator
// 	for i := range basis.coeffs {
// 		basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], acc)
// 	}
// 	return basis
// }
