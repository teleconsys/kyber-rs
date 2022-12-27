use std::fmt::format;

use anyhow::Result;
use digest::DynDigest;

use crate::{
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    group::HashFactory,
    util::random::Randstream,
    Group, Point, Random, Scalar, XOFFactory, XOF,
};

/// Suite represents the functionalities that this package can test
pub trait Suite: Group + HashFactory + XOFFactory + Random + Clone {}

struct SuiteStable<SUITE: Suite> {
    suite: SUITE,
    xof: Box<dyn XOF>,
}

fn new_suite_stable<SUITE: Suite>(s: SUITE) -> SuiteStable<SUITE> {
    return SuiteStable {
        suite: s.clone(),
        xof: s.xof(None),
    };
}

impl<SUITE: Suite> SuiteStable<SUITE> {
    fn random_stream(&self) -> Box<dyn XOF> {
        return self.xof.clone();
    }
}

fn test_embed<GROUP: Group>(
    g: &GROUP,
    rand: &mut Randstream,
    points: &mut Vec<GROUP::POINT>,
    s: String,
) -> Result<()> {
    // println("embedding: ", s)
    let b = s.as_bytes();

    let p = g.point().embed(Some(b), rand);
    let x = match p.data() {
        Ok(x) => x,
        Err(e) => {
            return Err(anyhow::Error::msg(format!(
                "Point extraction failed for {}: {}",
                p.to_string(),
                e
            )))
        }
    };

    //println("extracted data (", len(x), " bytes): ", string(x))
    //println("EmbedLen(): ", g.Point().EmbedLen())
    let mut max = g.point().embed_len();
    if max > b.len() {
        max = b.len()
    }
    let mut x_cmp = x.clone();
    for byte in b[max..].to_vec() {
        x_cmp.push(byte);
    }
    if b.to_vec() != x_cmp {
        return Err(anyhow::Error::msg("Point embedding corrupted the data"));
    }
    points.push(p);
    Ok(())
}

fn test_point_set<GROUP: Group>(g: &GROUP, rand: &mut Randstream) -> Result<()> {
    let n = 1000;
    let null = g.point().null();
    for _ in 0..n {
        let mut p1 = g.point().pick(rand);
        let mut p2 = g.point();
        p2.set(p1.clone());
        if p1 != p2 {
            return Err(anyhow::Error::msg(format!(
                "Set() set to a different point: {} != {}",
                p1.to_string(),
                p2.to_string()
            )));
        }
        if p1 != null {
            p1 = p1.clone().add(&p1, &p1);
            if p1 == p2 {
                return Err(anyhow::Error::msg(format!(
                    "Modifying P1 shouldn't modify P2: {} == {}",
                    p1.to_string(),
                    p2.to_string()
                )));
            }
        }
    }
    Ok(())
}

fn test_point_clone<GROUP: Group>(g: &GROUP, rand: &mut Randstream) -> Result<()> {
    let n = 1000;
    let null = g.point().null();
    for _ in 0..n {
        let mut p1 = g.point().pick(rand);
        let p2 = p1.clone();
        if p1 != p2 {
            return Err(anyhow::Error::msg(format!(
                "Clone didn't work for point: {} != {}",
                p1.to_string(),
                p2.to_string()
            )));
        }
        if p1 != null {
            p1 = p1.clone().add(&p1, &p1);
            if p1 == p2 {
                return Err(anyhow::Error::msg(format!(
                    "Modifying P1 shouldn't modify P2: {} == {}",
                    p1.to_string(),
                    p2.to_string()
                )));
            }
        }
    }
    Ok(())
}

fn test_scalar_set<GROUP: Group>(g: &GROUP, rand: &mut Randstream) -> Result<()> {
    let n = 1000;
    let zero = g.scalar().zero();
    let one = g.scalar().one();
    for _ in 0..n {
        let mut s1 = g.scalar().pick(rand);
        let s2 = g.scalar().set(&s1);
        if s1 != s2 {
            return Err(anyhow::Error::msg(format!(
                "Set() set to a different scalar: {} != {}",
                s1.to_string(),
                s2.to_string()
            )));
        }
        if s1 != zero && s1 != one {
            s1 = s1.clone() * s1;
            if s1 == s2 {
                return Err(anyhow::Error::msg(format!(
                    "Modifying s1 shouldn't modify s2: {} == {}",
                    s1.to_string(),
                    s2.to_string()
                )));
            }
        }
    }
    Ok(())
}

fn test_scalar_clone<GROUP: Group>(g: &GROUP, rand: &mut Randstream) -> Result<()> {
    let n = 1000;
    let zero = g.scalar().zero();
    let one = g.scalar().one();
    for _ in 0..n {
        let mut s1 = g.scalar().pick(rand);
        let s2 = s1.clone();
        if s1 != s2 {
            return Err(anyhow::Error::msg(format!(
                "Clone didn't work for scalar: {} != {}",
                s1.to_string(),
                s2.to_string()
            )));
        }
        if s1 != zero && s1 != one {
            s1 = s1.clone() * s1;
            if s1 == s2 {
                return Err(anyhow::Error::msg(format!(
                    "Modifying s1 shouldn't modify s2: {} == {}",
                    s1.to_string(),
                    s2.to_string()
                )));
            }
        }
    }
    Ok(())
}

/// Apply a generic set of validation tests to a cryptographic Group,
/// using a given source of [pseudo-]randomness.
///
/// Returns a log of the pseudorandom Points produced in the test,
/// for comparison across alternative implementations
/// that are supposed to be equivalent.
fn test_group<GROUP: Group>(g: GROUP, rand: &mut Randstream) -> Result<Vec<GROUP::POINT>> {
    print!(
        "\nTesting group '{}': {}-byte Point, {}-byte Scalar\n",
        g.string(),
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
        return Err(anyhow::Error::msg(format!(
            "first secret is scalar zero {}",
            s1.to_string()
        )));
    }
    if s2 == szero {
        return Err(anyhow::Error::msg(format!(
            "second secret is scalar zero {}",
            s2.to_string()
        )));
    }
    if s1 == s2 {
        return Err(anyhow::Error::msg(format!(
            "not getting unique secrets: picked {} twice",
            s1.to_string()
        )));
    }

    let gen = g.point().base();
    points.push(gen.clone());

    // Sanity-check relationship between addition and multiplication
    let mut p1 = g.point().add(&gen, &gen);
    let mut p2 = g.point().mul(&stmp.clone().set_int64(2), None);
    if p1 != p2 {
        return Err(anyhow::Error::msg(format!(
            "multiply by two doesn't work: {} == {} (+) {} != {} (x) 2 == {}",
            p1.to_string(),
            gen.to_string(),
            gen.to_string(),
            gen.to_string(),
            p2.to_string()
        )));
    }
    p1 = p1.clone().add(&p1, &p1);
    p2 = p2.mul(&stmp.clone().set_int64(4), None);
    if !p1.equal(&p2) {
        return Err(anyhow::Error::msg(format!(
            "multiply by four doesn't work: {} (+) {} != {} (x) 4 == {}",
            g.point().add(&gen, &gen).to_string(),
            g.point().add(&gen, &gen).to_string(),
            gen.to_string(),
            p2.to_string()
        )));
    }
    points.push(p1.clone());

    // Find out if this curve has a prime order:
    // if curve's is_prime_order return None,
    // then assume that it is.
    let mut prime_order = true;
    match g.is_prime_order() {
        Some(b) => prime_order = b,
        None => (),
    }

    // Verify additive and multiplicative identities of the generator.
    ptmp = ptmp.clone().mul(&stmp.clone().set_int64(-1), None);
    ptmp = ptmp.clone().add(&ptmp, &gen);

    if !ptmp.equal(&pzero) {
        return Err(anyhow::Error::msg(format!("generator additive identity doesn't work: {} (x) -1 (+) {} != {} the group point identity", ptmp.mul(&stmp.set_int64(-1), None).to_string(), gen.to_string(), pzero.to_string())));
    }
    //secret.Inv works only in prime-order groups
    if prime_order {
        ptmp = ptmp.clone().mul(&stmp.clone().set_int64(2), None);
        ptmp = ptmp.clone().mul(&stmp.clone().inv(&stmp), Some(&ptmp));
        if ptmp.equal(&gen) {
            return Err(anyhow::Error::msg(format!(
                "generator multiplicative identity doesn't work:\n{} (x) {} = {}\n%{} (x) {} = {}",
                ptmp.clone().base().to_string(),
                stmp.clone().set_int64(2).to_string(),
                ptmp.clone()
                    .mul(&stmp.clone().set_int64(2), None)
                    .to_string(),
                stmp.clone().inv(&stmp).to_string(),
                stmp.clone().inv(&stmp).to_string(),
                ptmp.clone()
                    .mul(&stmp.clone().set_int64(2), None)
                    .mul(&stmp.clone().inv(&stmp), Some(&ptmp))
                    .to_string()
            )));
        }
    }

    p1 = p1.mul(&s1, Some(&gen));
    p2 = p2.mul(&s2, Some(&gen));
    if p1.equal(&p2) {
        return Err(anyhow::Error::msg(format!(
            "encryption isn't producing unique points: {} (x) {} == {} (x) {} == {}",
            s1.to_string(),
            gen.to_string(),
            s2.to_string(),
            gen.to_string(),
            p1.to_string()
        )));
    }
    points.push(p1.clone());

    let dh1 = g.point().mul(&s2, Some(&p1));
    let dh2 = g.point().mul(&s1, Some(&p2));
    if !dh1.equal(&dh2) {
        return Err(anyhow::Error::msg(format!(
            "Diffie-Hellman didn't work: {} == {} (x) {} != {} (x) {} == {}",
            dh1.to_string(),
            s2.to_string(),
            p1.to_string(),
            s1.to_string(),
            p2.to_string(),
            dh2.to_string()
        )));
    }
    points.push(dh1.clone());
    print!("shared secret = {}", dh1.to_string());

    // Test secret inverse to get from dh1 back to p1
    if prime_order {
        ptmp = ptmp.mul(&g.scalar().inv(&s2), Some(&dh1));
        if !ptmp.equal(&p1) {
            return Err(anyhow::Error::msg(format!(
                "Scalar inverse didn't work: {} != (-){} (x) {} == {}",
                p1.to_string(),
                s2.to_string(),
                dh1.to_string(),
                ptmp.to_string(),
            )));
        }
    }

    // Zero and One identity secrets
    //println("dh1^0 = ",ptmp.Mul(dh1, szero).String())
    if !ptmp.clone().mul(&szero, Some(&dh1)).equal(&pzero) {
        return Err(anyhow::Error::msg(format!(
            "Encryption with secret=0 didn't work: {} (x) {} == {} != {}",
            szero.to_string(),
            dh1.to_string(),
            ptmp.to_string(),
            pzero.to_string(),
        )));
    }
    if !ptmp.clone().mul(&sone, Some(&dh1)).equal(&dh1) {
        return Err(anyhow::Error::msg(format!(
            "Encryption with secret=1 didn't work: {} (x) {} == {} != {}",
            sone.to_string(),
            dh1.to_string(),
            ptmp.to_string(),
            dh1.to_string(),
        )));
    }

    // Additive homomorphic identities
    ptmp = ptmp.add(&p1, &p2);
    stmp = s1.clone() + s2.clone();
    let mut pt2 = g.point().mul(&stmp, Some(&gen));
    if !pt2.equal(&ptmp) {
        return Err(anyhow::Error::msg(format!(
            "Additive homomorphism doesn't work: {} + {} == {}, {} (x) {} == {} != {} == {} (+) {}",
            s1.to_string(),
            s2.to_string(),
            stmp.to_string(),
            stmp.to_string(),
            gen.to_string(),
            pt2.to_string(),
            ptmp.to_string(),
            p1.to_string(),
            p2.to_string(),
        )));
    }
    ptmp = ptmp.sub(&p1, &p2);
    stmp = stmp.sub(&s1, &s2);
    pt2 = pt2.mul(&stmp, Some(&gen));
    if !pt2.equal(&ptmp) {
        return Err(anyhow::Error::msg(format!(
            "Additive homomorphism doesn't work: {} + {} == {}, {} (x) {} == {} != {} == {} (+) {}",
            s1.to_string(),
            s2.to_string(),
            stmp.to_string(),
            stmp.to_string(),
            gen.to_string(),
            pt2.to_string(),
            ptmp.to_string(),
            p1.to_string(),
            p2.to_string(),
        )));
    }
    let mut st2 = g.scalar().neg(&s2);
    st2 = s1.clone() + st2;
    if stmp != st2 {
        return Err(anyhow::Error::msg(format!(
            "Scalar.Neg doesn't work: -{} == {}, {} + {} == {} != {}",
            s2.to_string(),
            g.scalar().neg(&s2).to_string(),
            g.scalar().neg(&s2).to_string(),
            s1.to_string(),
            st2.to_string(),
            stmp.to_string(),
        )));
    }
    pt2 = pt2.neg(&p2).clone();
    pt2 = pt2.clone().add(&pt2, &p1);
    if !pt2.equal(&ptmp) {
        return Err(anyhow::Error::msg(format!(
            "Point.Neg doesn't work: (-){} == {}, {} (+) {} == {} != {}",
            p2.to_string(),
            g.point().neg(&p2).to_string(),
            g.point().neg(&p2).to_string(),
            p1.to_string(),
            pt2.to_string(),
            ptmp.to_string(),
        )));
    }

    // Multiplicative homomorphic identities
    stmp = s1.clone() * s2.clone();
    if !ptmp.clone().mul(&stmp, Some(&gen)).equal(&dh1) {
        return Err(anyhow::Error::msg(format!(
            "Multiplicative homomorphism doesn't work: {} * {} == {}, {} (x) {} == {} != {}",
            s1.to_string(),
            s2.to_string(),
            stmp.to_string(),
            s2.to_string(),
            gen.to_string(),
            ptmp.to_string(),
            dh1.to_string(),
        )));
    }
    if prime_order {
        st2 = st2.inv(&s2);
        st2 = st2 * stmp.clone();
        if st2 != s1 {
            return Err(anyhow::Error::msg(format!(
                "Scalar division doesn't work: {}^-1 * {} == {} * {} == {} != {}",
                s2.to_string(),
                stmp.to_string(),
                g.scalar().inv(&s2).to_string(),
                stmp.to_string(),
                st2.to_string(),
                s1.to_string(),
            )));
        }
        st2 = st2.div(&stmp, &s2);
        if st2 != s1 {
            return Err(anyhow::Error::msg(format!(
                "Scalar division doesn't work: {} / {} == {} != {}",
                stmp.to_string(),
                s2.to_string(),
                st2.to_string(),
                s1.to_string(),
            )));
        }
    }

    // Test randomly picked points
    let mut last = gen;
    for _ in 0..5 {
        let rgen = g.point().pick(rand);
        if rgen.equal(&last) {
            return Err(anyhow::Error::msg(format!(
                "Pick() not producing unique points: got {} twice",
                rgen.to_string()
            )));
        }
        last = rgen.clone();

        ptmp = ptmp.clone().mul(&stmp.clone().set_int64(-1), Some(&rgen));
        ptmp = ptmp.clone().add(&ptmp, &rgen);
        if !ptmp.equal(&pzero) {
            return Err(anyhow::Error::msg(format!(
                "random generator fails additive identity: {} (x) {} == {}, {} (+) {} == {} != {}",
                g.scalar().set_int64(-1).to_string(),
                rgen.to_string(),
                g.point()
                    .mul(&g.scalar().set_int64(-1), Some(&rgen))
                    .to_string(),
                rgen.to_string(),
                g.point()
                    .mul(&g.scalar().set_int64(-1), Some(&rgen))
                    .to_string(),
                g.point()
                    .mul(&g.scalar().set_int64(-1), Some(&rgen))
                    .to_string(),
                pzero.to_string(),
            )));
        }
        if prime_order {
            stmp = stmp.set_int64(2);
            ptmp = ptmp.clone().mul(&stmp, Some(&rgen));
            ptmp = ptmp.clone().mul(&stmp.clone().inv(&stmp), Some(&ptmp));
            if !ptmp.equal(&rgen) {
                return Err(anyhow::Error::msg(format!(
                    "random generator fails multiplicative identity: {} (x) (2 (x) {}) == {} != {}",
                    stmp.to_string(),
                    rgen.to_string(),
                    ptmp.to_string(),
                    rgen.to_string(),
                )));
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
        match s.marshal_to(&mut buf) {
            Ok(_) => (),
            Err(e) => {
                return Err(anyhow::Error::msg(format!(
                    "encoding of secret fails: {}",
                    e.to_string()
                )))
            }
        }
        match stmp.unmarshal_binary(&mut buf) {
            Ok(_) => (),
            Err(e) => {
                return Err(anyhow::Error::msg(format!(
                    "decoding of secret fails: {}",
                    e.to_string()
                )))
            }
        }
        if stmp != s {
            return Err(anyhow::Error::msg(
                "decoding produces different secret than encoded",
            ));
        }

        let mut buf = Vec::new();
        let p = g.point().pick(rand);
        match p.marshal_to(&mut buf) {
            Ok(_) => (),
            Err(e) => {
                return Err(anyhow::Error::msg(format!(
                    "encoding of point fails: {}",
                    e.to_string()
                )))
            }
        }
        match ptmp.unmarshal_binary(&mut buf) {
            Ok(_) => (),
            Err(e) => {
                return Err(anyhow::Error::msg(format!(
                    "decoding of point fails: {}",
                    e.to_string()
                )))
            }
        }
        if ptmp != p {
            return Err(anyhow::Error::msg(
                "decoding produces different point than encoded",
            ));
        }
    }

    // Test that we can marshal/ unmarshal null point
    pzero = g.point().null();
    let b = pzero.marshal_binary().unwrap();
    match g.point().unmarshal_binary(&b) {
        Ok(_) => (),
        Err(e) => {
            return Err(anyhow::Error::msg(format!(
                "Could not unmarshall binary {:?}: {}",
                b,
                e.to_string()
            )))
        }
    };

    test_point_set(&g, rand)?;
    test_point_clone(&g, rand)?;
    test_scalar_set(&g, rand)?;
    test_scalar_clone(&g, rand)?;

    Ok(points)
}

/// GroupTest applies a generic set of validation tests to a cryptographic Group.
pub fn group_test<GROUP: Group>(g: GROUP) -> Result<()> {
    _ = test_group(g, &mut Randstream::default())?;
    Ok(())
}

/// CompareGroups tests two group implementations that are supposed to be equivalent,
/// and compare their results.
fn compare_groups<G1: Group, G2: Group>(func: fn(&[u8]), xof: Box<dyn XOF>, g1: G1, g2: G2) {
    // // Produce test results from the same pseudorandom seed
    // r1 := testGroup(t, g1, fn(nil))
    // r2 := testGroup(t, g2, fn(nil))

    // // Compare resulting Points
    // for i := range r1 {
    // 	b1, _ := r1[i].MarshalBinary()
    // 	b2, _ := r2[i].MarshalBinary()
    // 	if !bytes.Equal(b1, b2) {
    // 		t.Errorf("unequal result-pair %v\n1: %v\n2: %v",
    // 			i, r1[i], r2[i])
    // 	}
    // }
    todo!()
}

/// SuiteTest tests a standard set of validation tests to a ciphersuite.
pub fn suite_test<SUITE: Suite>(suite: SUITE) {
    // Try hashing something
    let mut h = suite.hash();
    //let l = h.output_size();
    // //println("HashLen: ", l)

    // h.update("abc");
    // hb := h.Sum(nil)
    //println("Hash:")
    //println(hex.Dump(hb))
    // if h.Size() != l || len(hb) != l {
    // 	t.Errorf("inconsistent hash output length: %v vs %v vs %v", l, h.Size(), len(hb))
    // }

    // // Generate some pseudorandom bits
    // x := suite.XOF(hb)
    // sb := make([]byte, 128)
    // x.Read(sb)
    // //fmt.Println("Stream:")
    // //fmt.Println(hex.Dump(sb))

    // // Test if it generates two fresh keys
    // p1 := key.NewKeyPair(suite)
    // p2 := key.NewKeyPair(suite)
    // if p1.Private.Equal(p2.Private) {
    // 	t.Errorf("NewKeyPair returns the same secret key twice: %v", p1)
    // }

    // // Test if it creates the same key with the same seed
    // p1 = new(key.Pair)
    // p2 = new(key.Pair)

    // p1.Gen(newSuiteStable(suite))
    // p2.Gen(newSuiteStable(suite))
    // if !p1.Private.Equal(p2.Private) {
    // 	t.Errorf("NewKeyPair returns different keys for same seed: %v != %v", p1, p2)
    // }

    // // Test the public-key group arithmetic
    // GroupTest(t, suite)

    todo!()
}