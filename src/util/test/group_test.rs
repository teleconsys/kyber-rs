use crate::util::key::{self, KeyError};
use anyhow::{bail, Result};
use core::fmt::{Debug, Display, Formatter};
use digest::{Digest, DynDigest};

use crate::{
    cipher::Stream,
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::HashFactory,
    util::{
        key::{Generator, Suite as KeySuite},
        random::RandStream,
    },
    Group, Point, Random, Scalar, XOFFactory, XOF,
};

/// Suite represents the functionalities that this package can test
pub trait Suite: Group + Random + HashFactory + XOFFactory + Clone + KeySuite {}

#[derive(Default, Clone, Debug)]
struct SuiteStable<SUITE: Suite> {
    suite: SUITE,
}

fn new_suite_stable<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>>(
    s: &SUITE,
) -> SuiteStable<SUITE> {
    SuiteStable { suite: s.clone() }
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> HashFactory for SuiteStable<SUITE> {
    type T = SUITE::T;
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> XOFFactory for SuiteStable<SUITE> {
    fn xof(&self, _seed: Option<&[u8]>) -> Box<dyn XOF> {
        self.suite.xof(None)
    }
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> Random for SuiteStable<SUITE> {
    fn random_stream(&self) -> Box<dyn Stream> {
        Box::new(self.xof(None)) as Box<dyn Stream>
    }
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>>
    Generator<<SUITE::POINT as Point>::SCALAR> for SuiteStable<SUITE>
{
    fn new_key<S: Stream>(
        &self,
        _stream: &mut S,
    ) -> Result<Option<<SUITE::POINT as Point>::SCALAR>, KeyError> {
        self.suite.new_key(&mut self.random_stream())
    }
}

impl<SUITE: Suite> Display for SuiteStable<SUITE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.suite)
    }
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> Group for SuiteStable<SUITE> {
    type POINT = SUITE::POINT;

    fn scalar_len(&self) -> usize {
        self.suite.scalar_len()
    }

    fn scalar(&self) -> <Self::POINT as Point>::SCALAR {
        self.suite.scalar()
    }

    fn point_len(&self) -> usize {
        self.suite.point_len()
    }

    fn point(&self) -> Self::POINT {
        self.suite.point()
    }

    fn is_prime_order(&self) -> Option<bool> {
        self.suite.is_prime_order()
    }
}

impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> KeySuite for SuiteStable<SUITE> {}
impl<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>> Suite for SuiteStable<SUITE> {}

fn test_embed<GROUP: Group, S: Stream>(
    g: &GROUP,
    rand: &mut S,
    points: &mut Vec<GROUP::POINT>,
    s: String,
) -> Result<()> {
    // println("embedding: ", s)
    let b = s.as_bytes();

    let p = g.point().embed(Some(b), rand);
    let x = match p.data() {
        Ok(x) => x,
        Err(e) => {
            bail!("Point extraction failed for {p}: {e}")
        }
    };

    //println("extracted data (", len(x), " bytes): ", string(x))
    //println("EmbedLen(): ", g.Point().EmbedLen())
    let mut max = g.point().embed_len();
    if max > b.len() {
        max = b.len()
    }
    let mut x_cmp = x;
    for byte in b[max..].iter().copied() {
        x_cmp.push(byte);
    }
    if b.to_vec() != x_cmp {
        bail!("Point embedding corrupted the data")
    }
    points.push(p);
    Ok(())
}

fn test_point_set<GROUP: Group, S: Stream>(g: &GROUP, rand: &mut S) -> Result<()> {
    let n = 1000;
    let null = g.point().null();
    for _ in 0..n {
        let mut p1 = g.point().pick(rand);
        let mut p2 = g.point();
        p2.set(&p1);
        if !p1.eq(&p2) {
            bail!("Set() set to a different point: {p1} != {p2}")
        }
        if !p1.eq(&null) {
            p1 = p1.clone().add(&p1, &p1);
            if p1.eq(&p2) {
                bail!("Modifying P1 shouldn't modify P2: {p1} == {p2}")
            }
        }
    }
    Ok(())
}

fn test_point_clone<GROUP: Group, S: Stream>(g: &GROUP, rand: &mut S) -> Result<()> {
    let n = 1000;
    let null = g.point().null();
    for _ in 0..n {
        let mut p1 = g.point().pick(rand);
        let p2 = p1.clone();
        if p1 != p2 {
            bail!("Clone didn't work for point: {p1} != {p2}")
        }
        if p1 != null {
            p1 = p1.clone().add(&p1, &p1);
            if p1 == p2 {
                bail!("Modifying P1 shouldn't modify P2: {p1} == {p2}")
            }
        }
    }
    Ok(())
}

fn test_scalar_set<GROUP: Group, S: Stream>(g: &GROUP, rand: &mut S) -> Result<()> {
    let n = 1000;
    let zero = g.scalar().zero();
    let one = g.scalar().one();
    for _ in 0..n {
        let mut s1 = g.scalar().pick(rand);
        let s2 = g.scalar().set(&s1);
        if s1 != s2 {
            bail!("Set() set to a different scalar: {s1} != {s2}")
        }
        if s1 != zero && s1 != one {
            s1 = s1.clone() * s1;
            if s1 == s2 {
                bail!("Modifying s1 shouldn't modify s2: {s1} == {s2}")
            }
        }
    }
    Ok(())
}

fn test_scalar_clone<GROUP: Group, S: Stream>(g: &GROUP, rand: &mut S) -> Result<()> {
    let n = 1000;
    let zero = g.scalar().zero();
    let one = g.scalar().one();
    for _ in 0..n {
        let mut s1 = g.scalar().pick(rand);
        let s2 = s1.clone();
        if s1 != s2 {
            bail!("Clone didn't work for scalar: {s1} != {s2}")
        }
        if s1 != zero && s1 != one {
            s1 = s1.clone() * s1;
            if s1 == s2 {
                bail!("Modifying s1 shouldn't modify s2: {s1} == {s2}")
            }
        }
    }
    Ok(())
}

/// Apply a generic set of validation tests to a cryptographic Group,
/// using a given source of pseudo-randomness.
///
/// Returns a log of the pseudorandom Points produced in the test,
/// for comparison across alternative implementations
/// that are supposed to be equivalent.
fn test_group<GROUP: Group, S: Stream>(g: GROUP, rand: &mut S) -> Result<Vec<GROUP::POINT>> {
    print!(
        "\nTesting group '{}': {}-byte Point, {}-byte Scalar\n",
        g,
        g.point_len(),
        g.scalar_len()
    );

    let mut points = Vec::new();
    let mut ptmp = g.point();
    let mut stmp = g.scalar();
    let mut pzero = g.point().null();
    let szero = g.scalar().zero();
    let sone = g.scalar().one();

    // Do a simple Diffie-Hellman test
    let s1 = g.scalar().pick(rand);
    let s2 = g.scalar().pick(rand);

    if s1 == szero {
        bail!("first secret is scalar zero {s1}")
    }
    if s2 == szero {
        bail!("second secret is scalar zero {s2}")
    }
    if s1 == s2 {
        bail!("not getting unique secrets: picked {s1} twice")
    }

    let gen = g.point().base();
    points.push(gen.clone());

    // Sanity-check relationship between addition and multiplication
    let mut p1 = g.point().add(&gen, &gen);
    let mut p2 = g.point().mul(&stmp.clone().set_int64(2), None);
    if p1 != p2 {
        bail!("multiply by two doesn't work: {p1} == {gen} (+) {gen} != {gen} (x) 2 == {p2}")
    }
    p1 = p1.clone().add(&p1, &p1);
    p2 = p2.mul(&stmp.clone().set_int64(4), None);
    if !p1.eq(&p2) {
        bail!(
            "multiply by four doesn't work: {} (+) {} != {} (x) 4 == {}",
            g.point().add(&gen, &gen),
            g.point().add(&gen, &gen),
            gen,
            p2
        )
    }
    points.push(p1.clone());

    // Find out if this curve has a prime order:
    // if curve's is_prime_order return None,
    // then assume that it is.
    let mut prime_order = true;
    if let Some(b) = g.is_prime_order() {
        prime_order = b
    }

    // Verify additive and multiplicative identities of the generator.
    ptmp = ptmp.clone().mul(&stmp.clone().set_int64(-1), None);
    ptmp = ptmp.clone().add(&ptmp, &gen);

    if !ptmp.eq(&pzero) {
        bail!("generator additive identity doesn't work: {} (x) -1 (+) {} != {} the group point identity", ptmp.mul(&stmp.set_int64(-1), None), gen, pzero)
    }
    //secret.Inv works only in prime-order groups
    if prime_order {
        ptmp = ptmp.clone().mul(&stmp.clone().set_int64(2), None);
        ptmp = ptmp.clone().mul(&stmp.clone().inv(&stmp), Some(&ptmp));
        if ptmp.eq(&gen) {
            bail!(
                "generator multiplicative identity doesn't work:\n{} (x) {} = {}\n%{} (x) {} = {}",
                ptmp.clone().base(),
                stmp.clone().set_int64(2),
                ptmp.clone().mul(&stmp.clone().set_int64(2), None),
                stmp.clone().inv(&stmp),
                stmp.clone().inv(&stmp),
                ptmp.clone()
                    .mul(&stmp.clone().set_int64(2), None)
                    .mul(&stmp.clone().inv(&stmp), Some(&ptmp))
            )
        }
    }

    p1 = p1.mul(&s1, Some(&gen));
    p2 = p2.mul(&s2, Some(&gen));
    if p1.eq(&p2) {
        bail!(
            "encryption isn't producing unique points: {} (x) {} == {} (x) {} == {}",
            s1,
            gen,
            s2,
            gen,
            p1
        )
    }
    points.push(p1.clone());

    let dh1 = g.point().mul(&s2, Some(&p1));
    let dh2 = g.point().mul(&s1, Some(&p2));
    if !dh1.eq(&dh2) {
        bail!(
            "Diffie-Hellman didn't work: {} == {} (x) {} != {} (x) {} == {}",
            dh1,
            s2,
            p1,
            s1,
            p2,
            dh2
        )
    }
    points.push(dh1.clone());
    print!("shared secret = {dh1}");

    // Test secret inverse to get from dh1 back to p1
    if prime_order {
        ptmp = ptmp.mul(&g.scalar().inv(&s2), Some(&dh1));
        if !ptmp.eq(&p1) {
            bail!(
                "Scalar inverse didn't work: {} != (-){} (x) {} == {}",
                p1,
                s2,
                dh1,
                ptmp,
            )
        }
    }

    // Zero and One identity secrets
    //println("dh1^0 = ",ptmp.Mul(dh1, szero).String())
    if !ptmp.clone().mul(&szero, Some(&dh1)).eq(&pzero) {
        bail!(
            "Encryption with secret=0 didn't work: {} (x) {} == {} != {}",
            szero,
            dh1,
            ptmp,
            pzero,
        )
    }
    if !ptmp.clone().mul(&sone, Some(&dh1)).eq(&dh1) {
        bail!(
            "Encryption with secret=1 didn't work: {} (x) {} == {} != {}",
            sone,
            dh1,
            ptmp,
            dh1,
        )
    }

    // Additive homomorphic identities
    ptmp = ptmp.add(&p1, &p2);
    stmp = s1.clone() + s2.clone();
    let mut pt2 = g.point().mul(&stmp, Some(&gen));
    if !pt2.eq(&ptmp) {
        bail!(
            "Additive homomorphism doesn't work: {} + {} == {}, {} (x) {} == {} != {} == {} (+) {}",
            s1,
            s2,
            stmp,
            stmp,
            gen,
            pt2,
            ptmp,
            p1,
            p2,
        )
    }
    ptmp = ptmp.sub(&p1, &p2);
    stmp = stmp.sub(&s1, &s2);
    pt2 = pt2.mul(&stmp, Some(&gen));
    if !pt2.eq(&ptmp) {
        bail!(
            "Additive homomorphism doesn't work: {} + {} == {}, {} (x) {} == {} != {} == {} (+) {}",
            s1,
            s2,
            stmp,
            stmp,
            gen,
            pt2,
            ptmp,
            p1,
            p2,
        )
    }
    let mut st2 = g.scalar().neg(&s2);
    st2 = s1.clone() + st2;
    if stmp != st2 {
        bail!(
            "Scalar.Neg doesn't work: -{} == {}, {} + {} == {} != {}",
            s2,
            g.scalar().neg(&s2),
            g.scalar().neg(&s2),
            s1,
            st2,
            stmp,
        )
    }
    pt2 = pt2.neg(&p2);
    pt2 = pt2.clone().add(&pt2, &p1);
    if !pt2.eq(&ptmp) {
        bail!(
            "Point.Neg doesn't work: (-){} == {}, {} (+) {} == {} != {}",
            p2,
            g.point().neg(&p2),
            g.point().neg(&p2),
            p1,
            pt2,
            ptmp,
        )
    }

    // Multiplicative homomorphic identities
    stmp = s1.clone() * s2.clone();
    if !ptmp.clone().mul(&stmp, Some(&gen)).eq(&dh1) {
        bail!(
            "Multiplicative homomorphism doesn't work: {} * {} == {}, {} (x) {} == {} != {}",
            s1,
            s2,
            stmp,
            s2,
            gen,
            ptmp,
            dh1,
        )
    }
    if prime_order {
        print!("\ns2 val {:?}", s2.marshal_binary().unwrap());
        st2 = st2.inv(&s2);
        print!("\nst2 val {:?}", st2.marshal_binary().unwrap());
        st2 = st2 * stmp.clone();
        if st2 != s1 {
            bail!(
                "Scalar division doesn't work: {}^-1 * {} == {} * {} == {} != {}",
                s2,
                stmp,
                g.scalar().inv(&s2),
                stmp,
                st2,
                s1,
            )
        }
        st2 = st2.div(&stmp, &s2);
        if st2 != s1 {
            bail!(
                "Scalar division doesn't work: {} / {} == {} != {}",
                stmp,
                s2,
                st2,
                s1,
            )
        }
    }

    // Test randomly picked points
    let mut last = gen;
    for _ in 0..5 {
        let rgen = g.point().pick(rand);
        if rgen.eq(&last) {
            bail!("Pick() not producing unique points: got {} twice", rgen)
        }
        last = rgen.clone();

        ptmp = ptmp.clone().mul(&stmp.clone().set_int64(-1), Some(&rgen));
        ptmp = ptmp.clone().add(&ptmp, &rgen);
        if !ptmp.eq(&pzero) {
            bail!(
                "random generator fails additive identity: {} (x) {} == {}, {} (+) {} == {} != {}",
                g.scalar().set_int64(-1),
                rgen,
                g.point().mul(&g.scalar().set_int64(-1), Some(&rgen)),
                rgen,
                g.point().mul(&g.scalar().set_int64(-1), Some(&rgen)),
                g.point().mul(&g.scalar().set_int64(-1), Some(&rgen)),
                pzero,
            )
        }
        if prime_order {
            stmp = stmp.set_int64(2);
            ptmp = ptmp.clone().mul(&stmp, Some(&rgen));
            ptmp = ptmp.clone().mul(&stmp.clone().inv(&stmp), Some(&ptmp));
            if !ptmp.eq(&rgen) {
                bail!(
                    "random generator fails multiplicative identity: {} (x) (2 (x) {}) == {} != {}",
                    stmp,
                    rgen,
                    ptmp,
                    rgen,
                )
            }
        }
        points.push(rgen);
    }

    // Test embedding data
    test_embed(&g, rand, &mut points, "Hi!".to_string())?;
    test_embed(
        &g,
        rand,
        &mut points,
        "The quick brown fox jumps over the lazy dog".to_string(),
    )?;

    // Test verifiable secret sharing

    // Test encoding and decoding
    for _ in 0..5 {
        let mut buf = Vec::new();
        let s = g.scalar().pick(rand);
        if let Err(e) = s.marshal_to(&mut buf) {
            bail!("encoding of secret fails: {}", e.to_string())
        }
        if let Err(e) = stmp.unmarshal_binary(&buf) {
            bail!("decoding of secret fails: {}", e.to_string())
        }
        if stmp != s {
            bail!("decoding produces different secret than encoded",)
        }

        let mut buf = Vec::new();
        let p = g.point().pick(rand);
        if let Err(e) = p.marshal_to(&mut buf) {
            bail!("encoding of point fails: {}", e.to_string())
        }
        if let Err(e) = ptmp.unmarshal_binary(&buf) {
            bail!("decoding of point fails: {}", e.to_string())
        }
        if ptmp != p {
            bail!("decoding produces different point than encoded",);
        }
    }

    // Test that we can marshal/ unmarshal null point
    pzero = g.point().null();
    let b = pzero.marshal_binary().unwrap();
    if let Err(e) = g.point().unmarshal_binary(&b) {
        bail!("Could not unmarshall binary {:?}: {}", b, e.to_string())
    };

    test_point_set(&g, rand)?;
    test_point_clone(&g, rand)?;
    test_scalar_set(&g, rand)?;
    test_scalar_clone(&g, rand)?;

    Ok(points)
}

/// group_test() applies a generic set of validation tests to a cryptographic Group.
pub fn group_test<GROUP: Group + Generator<<GROUP::POINT as Point>::SCALAR>>(
    g: GROUP,
) -> Result<()> {
    _ = test_group(g, &mut RandStream::default())?;
    Ok(())
}

/// compare_groups() tests two group implementations that are supposed to be equivalent,
/// and compare their results.
pub fn compare_groups<G1: Group, G2: Group>(
    func: fn(Option<&[u8]>) -> Box<dyn XOF>,
    g1: G1,
    g2: G2,
) -> Result<()> {
    // Produce test results from the same pseudorandom seed
    let r1 = test_group(g1, &mut func(None)).unwrap();
    let r2 = test_group(g2, &mut func(None)).unwrap();

    // Compare resulting Points
    for (i, _) in r1.iter().enumerate() {
        let b1 = r1[i].marshal_binary().unwrap();
        let b2 = r2[i].marshal_binary().unwrap();
        if b1 != b2 {
            bail!("unequal result-pair {}\n1: {:?}\n2: {:?}", i, r1[i], r2[i])
        }
    }
    Ok(())
}

/// suite_test() tests a standard set of validation tests to a ciphersuite.
pub fn suite_test<SUITE: Suite + Generator<<SUITE::POINT as Point>::SCALAR>>(
    suite: SUITE,
) -> Result<()> {
    // Try hashing something
    let mut h = suite.hash();
    let l = h.output_size();
    //println("HashLen: ", l)

    Digest::update(&mut h, "abc".as_bytes());
    let hb = h.clone().finalize().to_vec();
    print!("\nHash: {hb:?}");
    if h.output_size() != l || hb.len() != l {
        bail!(
            "inconsistent hash output length: {} vs {} vs {}",
            l,
            h.output_size(),
            hb.len()
        )
    }

    // Generate some pseudorandom bits
    let mut x = suite.xof(Some(&hb));
    let mut sb = [0u8; 128];
    x.read_exact(&mut sb).unwrap();
    print!("\nStream: {sb:?}");

    // Test if it generates two fresh keys
    let mut p1 = key::new_key_pair(&suite).unwrap();
    let mut p2 = key::new_key_pair(&suite).unwrap();
    if p1.private == p2.private {
        bail!("NewKeyPair returns the same secret key twice: {:?}", p1)
    }

    // Test if it creates the same key with the same seed
    p1 = key::Pair::default();
    p2 = key::Pair::default();

    p1.gen(&new_suite_stable(&suite))?;
    p2.gen(&new_suite_stable(&suite))?;
    if p1.private != p2.private {
        bail!(
            "NewKeyPair returns different keys for same seed: {} != {}",
            p1.private,
            p2.private
        )
    }

    // Test the public-key group arithmetic
    group_test(suite)
}
