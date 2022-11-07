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
use anyhow::Result;

// Some error definitions
const ERROR_GROUPS: &str = "non-matching groups";
const ERROR_COEFFS: &str = "different number of coefficients";

/// PriShare represents a private share.
pub struct PriShare<SCALAR>
where
    SCALAR: Scalar,
{
    /// Index of the private share
    pub i: usize,
    /// Value of the private share
    pub v: SCALAR,
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
pub struct PriPoly<SCALAR, POINT, GROUP>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    _phantom: PhantomData<POINT>,
    /// Cryptographic group
    g: GROUP,
    /// Coefficients of the polynomial
    coeffs: Vec<SCALAR>,
}

use std::marker::PhantomData;

use crate::{cipher::Stream, Group, Point, Scalar};

/// NewPriPoly creates a new secret sharing polynomial using the provided
/// cryptographic group, the secret sharing threshold t, and the secret to be
/// shared s. If s is nil, a new s is chosen using the provided randomness
/// stream rand.
pub fn NewPriPoly<SCALAR, POINT, GROUP, STREAM>(
    group: GROUP,
    t: usize,
    s: Option<SCALAR>,
    mut rand: STREAM,
) -> PriPoly<SCALAR, POINT, GROUP>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
    STREAM: Stream,
{
    let mut coeffs: Vec<SCALAR> = vec![];
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
        _phantom: PhantomData,
    }
}

// // CoefficientsToPriPoly returns a PriPoly based on the given coefficients
// func CoefficientsToPriPoly(g kyber.Group, coeffs []kyber.Scalar) *PriPoly {
// 	return &PriPoly{g: g, coeffs: coeffs}
// }

impl<SCALAR, POINT, GROUP> PriPoly<SCALAR, POINT, GROUP>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    /// Threshold returns the secret sharing threshold.
    pub fn Threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
    pub fn Secret(&self) -> SCALAR {
        // return p.coeffs[0]
        todo!()
    }

    /// Eval computes the private share v = p(i).
    pub fn Eval(&self, i: usize) -> PriShare<SCALAR> {
        let xi = self.g.scalar().set_int64(1 + i as i64);
        let mut v = self.g.scalar().zero();
        for j in (0..self.Threshold()).rev() {
            v = v * xi.clone();
            v = v + self.coeffs[j].clone();
        }
        PriShare { i, v }
    }

    // // Shares creates a list of n private shares p(1),...,p(n).
    // func (p *PriPoly) Shares(n int) []*PriShare {
    // 	shares := make([]*PriShare, n)
    // 	for i := range shares {
    // 		shares[i] = p.Eval(i)
    // 	}
    // 	return shares
    // }

    // // Add computes the component-wise sum of the polynomials p and q and returns it
    // // as a new polynomial.
    // func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
    // 	if p.g.String() != q.g.String() {
    // 		return nil, errorGroups
    // 	}
    // 	if p.Threshold() != q.Threshold() {
    // 		return nil, errorCoeffs
    // 	}
    // 	coeffs := make([]kyber.Scalar, p.Threshold())
    // 	for i := range coeffs {
    // 		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
    // 	}
    // 	return &PriPoly{p.g, coeffs}, nil
    // }

    // // Equal checks equality of two secret sharing polynomials p and q. If p and q are trivially
    // // unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
    // // returns in variable time. Otherwise it runs in constant time regardless of whether it
    // // eventually returns true or false.
    // func (p *PriPoly) Equal(q *PriPoly) bool {
    // 	if p.g.String() != q.g.String() {
    // 		return false
    // 	}
    // 	if len(p.coeffs) != len(q.coeffs) {
    // 		return false
    // 	}
    // 	b := 1
    // 	for i := 0; i < p.Threshold(); i++ {
    // 		pb, _ := p.coeffs[i].MarshalBinary()
    // 		qb, _ := q.coeffs[i].MarshalBinary()
    // 		b &= subtle.ConstantTimeCompare(pb, qb)
    // 	}
    // 	return b == 1
    // }

    /// Commit creates a public commitment polynomial for the given base point b or
    /// the standard base if b == nil.
    pub fn Commit(&self, b: POINT) -> PubPoly<SCALAR, POINT, GROUP> {
        let mut commits = vec![];
        for i in 0..self.Threshold() {
            commits.push(self.g.point().mul(&self.coeffs[i], Some(&b)));
        }

        PubPoly {
            g: self.g.clone(),
            b,
            commits,
            _phantom: PhantomData,
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

// // RecoverSecret reconstructs the shared secret p(0) from a list of private
// // shares using Lagrange interpolation.
// func RecoverSecret(g kyber.Group, shares []*PriShare, t, n int) (kyber.Scalar, error) {
// 	x, y := xyScalar(g, shares, t, n)
// 	if len(x) < t {
// 		return nil, errors.New("share: not enough shares to recover secret")
// 	}

// 	acc := g.Scalar().Zero()
// 	num := g.Scalar()
// 	den := g.Scalar()
// 	tmp := g.Scalar()

// 	for i, xi := range x {
// 		yi := y[i]
// 		num.Set(yi)
// 		den.One()
// 		for j, xj := range x {
// 			if i == j {
// 				continue
// 			}
// 			num.Mul(num, xj)
// 			den.Mul(den, tmp.Sub(xj, xi))
// 		}
// 		acc.Add(acc, num.Div(num, den))
// 	}

// 	return acc, nil
// }

// type byIndexScalar []*PriShare

// func (s byIndexScalar) Len() int           { return len(s) }
// func (s byIndexScalar) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byIndexScalar) Less(i, j int) bool { return s[i].I < s[j].I }

// // xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
// // is the list of x_i and the second map is the list of y_i, both indexed in
// // their respective map at index i.
// func xyScalar(g kyber.Group, shares []*PriShare, t, n int) (map[int]kyber.Scalar, map[int]kyber.Scalar) {
// 	// we are sorting first the shares since the shares may be unrelated for
// 	// some applications. In this case, all participants needs to interpolate on
// 	// the exact same order shares.
// 	sorted := make([]*PriShare, 0, n)
// 	for _, share := range shares {
// 		if share != nil {
// 			sorted = append(sorted, share)
// 		}
// 	}
// 	sort.Sort(byIndexScalar(sorted))

// 	x := make(map[int]kyber.Scalar)
// 	y := make(map[int]kyber.Scalar)
// 	for _, s := range sorted {
// 		if s == nil || s.V == nil || s.I < 0 {
// 			continue
// 		}
// 		idx := s.I
// 		x[idx] = g.Scalar().SetInt64(int64(idx + 1))
// 		y[idx] = s.V
// 		if len(x) == t {
// 			break
// 		}
// 	}
// 	return x, y
// }

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

// // PubShare represents a public share.
// type PubShare struct {
// 	I int         // Index of the public share
// 	V kyber.Point // Value of the public share
// }

// // Hash returns the hash representation of this share.
// func (p *PubShare) Hash(s kyber.HashFactory) []byte {
// 	h := s.Hash()
// 	_, _ = p.V.MarshalTo(h)
// 	_ = binary.Write(h, binary.LittleEndian, p.I)
// 	return h.Sum(nil)
// }

/// PubPoly represents a public commitment polynomial to a secret sharing polynomial.
pub struct PubPoly<SCALAR, POINT, GROUP>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    _phantom: PhantomData<SCALAR>,
    /// Cryptographic group
    g: GROUP,
    /// Base point, nil for standard base
    b: POINT,
    /// Commitments to coefficients of the secret sharing polynomial
    commits: Vec<POINT>,
}

impl<SCALAR, POINT, GROUP> PubPoly<SCALAR, POINT, GROUP>
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    GROUP: Group<SCALAR, POINT>,
{
    /// Info returns the base point and the commitments to the polynomial coefficients.
    pub fn Info(&self) -> (POINT, Vec<POINT>) {
        (self.b.clone(), self.commits.clone())
    }

    /// threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> usize {
        self.commits.len()
    }

    // // Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    // func (p *PubPoly) Commit() kyber.Point {
    // 	return p.commits[0]
    // }

    // // Eval computes the public share v = p(i).
    // func (p *PubPoly) Eval(i int) *PubShare {
    // 	xi := p.g.Scalar().SetInt64(1 + int64(i)) // x-coordinate of this share
    // 	v := p.g.Point().Null()
    // 	for j := p.Threshold() - 1; j >= 0; j-- {
    // 		v.Mul(xi, v)
    // 		v.Add(v, p.commits[j])
    // 	}
    // 	return &PubShare{i, v}
    // }

    // // Shares creates a list of n public commitment shares p(1),...,p(n).
    // func (p *PubPoly) Shares(n int) []*PubShare {
    // 	shares := make([]*PubShare, n)
    // 	for i := range shares {
    // 		shares[i] = p.Eval(i)
    // 	}
    // 	return shares
    // }

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
            _phantom: PhantomData,
        })
    }

    // // Equal checks equality of two public commitment polynomials p and q. If p and
    // // q are trivially unequal (e.g., due to mismatching cryptographic groups),
    // // this routine returns in variable time. Otherwise it runs in constant time
    // // regardless of whether it eventually returns true or false.
    // func (p *PubPoly) Equal(q *PubPoly) bool {
    // 	if p.g.String() != q.g.String() {
    // 		return false
    // 	}
    // 	b := 1
    // 	for i := 0; i < p.Threshold(); i++ {
    // 		pb, _ := p.commits[i].MarshalBinary()
    // 		qb, _ := q.commits[i].MarshalBinary()
    // 		b &= subtle.ConstantTimeCompare(pb, qb)
    // 	}
    // 	return b == 1
    // }

    // // Check a private share against a public commitment polynomial.
    // func (p *PubPoly) Check(s *PriShare) bool {
    // 	pv := p.Eval(s.I)
    // 	ps := p.g.Point().Mul(s.V, p.b)
    // 	return pv.V.Equal(ps)
    // }
}

// // NewPubPoly creates a new public commitment polynomial.
// func NewPubPoly(g kyber.Group, b kyber.Point, commits []kyber.Point) *PubPoly {
// 	return &PubPoly{g, b, commits}
// }

// type byIndexPub []*PubShare

// func (s byIndexPub) Len() int           { return len(s) }
// func (s byIndexPub) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
// func (s byIndexPub) Less(i, j int) bool { return s[i].I < s[j].I }

// // xyCommits is the public version of xScalars.
// func xyCommit(g kyber.Group, shares []*PubShare, t, n int) (map[int]kyber.Scalar, map[int]kyber.Point) {
// 	// we are sorting first the shares since the shares may be unrelated for
// 	// some applications. In this case, all participants needs to interpolate on
// 	// the exact same order shares.
// 	sorted := make([]*PubShare, 0, n)
// 	for _, share := range shares {
// 		if share != nil {
// 			sorted = append(sorted, share)
// 		}
// 	}
// 	sort.Sort(byIndexPub(sorted))

// 	x := make(map[int]kyber.Scalar)
// 	y := make(map[int]kyber.Point)

// 	for _, s := range sorted {
// 		if s == nil || s.V == nil || s.I < 0 {
// 			continue
// 		}
// 		idx := s.I
// 		x[idx] = g.Scalar().SetInt64(int64(idx + 1))
// 		y[idx] = s.V
// 		if len(x) == t {
// 			break
// 		}
// 	}
// 	return x, y
// }

// // RecoverCommit reconstructs the secret commitment p(0) from a list of public
// // shares using Lagrange interpolation.
// func RecoverCommit(g kyber.Group, shares []*PubShare, t, n int) (kyber.Point, error) {
// 	x, y := xyCommit(g, shares, t, n)
// 	if len(x) < t {
// 		return nil, errors.New("share: not enough good public shares to reconstruct secret commitment")
// 	}

// 	num := g.Scalar()
// 	den := g.Scalar()
// 	tmp := g.Scalar()
// 	Acc := g.Point().Null()
// 	Tmp := g.Point()

// 	for i, xi := range x {
// 		num.One()
// 		den.One()
// 		for j, xj := range x {
// 			if i == j {
// 				continue
// 			}
// 			num.Mul(num, xj)
// 			den.Mul(den, tmp.Sub(xj, xi))
// 		}
// 		Tmp.Mul(num.Div(num, den), y[i])
// 		Acc.Add(Acc, Tmp)
// 	}

// 	return Acc, nil
// }

// // RecoverPubPoly reconstructs the full public polynomial from a set of public
// // shares using Lagrange interpolation.
// func RecoverPubPoly(g kyber.Group, shares []*PubShare, t, n int) (*PubPoly, error) {
// 	x, y := xyCommit(g, shares, t, n)
// 	if len(x) < t {
// 		return nil, errors.New("share: not enough good public shares to reconstruct secret commitment")
// 	}

// 	var accPoly *PubPoly
// 	var err error

// 	for j := range x {
// 		basis := lagrangeBasis(g, j, x)

// 		// compute the L_j * y_j polynomial in point space
// 		tmp := basis.Commit(y[j])
// 		if accPoly == nil {
// 			accPoly = tmp
// 			continue
// 		}

// 		// add all L_j * y_j together
// 		accPoly, err = accPoly.Add(tmp)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	return accPoly, nil

// }

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