/*
This example illustrates how to use the dkg/pedersen API to generate a public
key and its corresponding private key that is shared among nodes. It shows the
different phases that each node must perform in order to construct the private
shares that will form the final private key. The example uses 3 nodes and shows
the "happy" path where each node does its job correctly.
*/
use crate::{
    examples::enc_test::el_gamal_decrypt,
    group::edwards25519::SuiteEd25519,
    share::{
        self,
        dkg::{
            self,
            pedersen::{
                new_dist_key_handler,
                structs::{Deal, Response},
                Config,
            },
        },
        vss::suite::Suite,
    },
    sign::dss::DistKeyShare,
    Group, Point, Random, Scalar,
};

use super::enc_test::el_gamal_encrypt;

struct Node<SUITE: Suite> {
    dkg: dkg::pedersen::DistKeyGenerator<SUITE, &'static [u8]>,
    _pub_key: SUITE::POINT,
    priv_key: <SUITE::POINT as Point>::SCALAR,
    deals: Vec<Deal<SUITE::POINT>>,
    resps: Vec<Response>,
    secret_share: share::poly::PriShare<<SUITE::POINT as Point>::SCALAR>,
    distributed_public_key: SUITE::POINT,
}

#[test]
fn test_example_dkg() {
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();

    // DKG scales exponentially, the following command prints the duration [ns]
    // of this test case with an increasing number of nodes. The resulting plot
    // should illustrate an exponential growth.
    //
    // for (( i=1; i<30; i++ )); do
    //   start=`gdate +%s%N`
    //   NUM_NODES=$i go test -run Test_Example_DKG >/dev/null
    //   duration=$(( `gdate +%s%N` - start ))
    //   echo $duration
    // done
    //

    // var nStr = os.Getenv("NUM_NODES")
    // if nStr == "" {
    // 	default number of node for this test
    // 	nStr = "7"
    // }

    // n, err := strconv.Atoi(nStr)
    // require.NoError(t, err)

    let n = 7;

    let mut nodes = Vec::with_capacity(n);
    let mut pub_keys = Vec::with_capacity(n);

    // 1. Init the nodes
    for _ in 0..n {
        let priv_key = suite.scalar().pick(&mut suite.random_stream());
        let pub_key = suite.point().mul(&priv_key, None);
        pub_keys.push(pub_key.clone());
        nodes.push(Node::<SuiteEd25519> {
            _pub_key: pub_key,
            priv_key,
            deals: Vec::new(),
            resps: Vec::new(),
            secret_share: Default::default(),
            dkg: Default::default(),
            distributed_public_key: Default::default(),
        });
    }

    // 2. Create the DKGs on each node
    for node in nodes.iter_mut() {
        let dkg = dkg::pedersen::new_dist_key_generator(suite, node.priv_key.clone(), &pub_keys, n)
            .unwrap();
        node.dkg = dkg;
    }

    // 3. Each node sends its Deals to the other nodes
    let mut all_deals = Vec::new();
    for node in nodes.iter_mut() {
        let deals = node.dkg.deals().unwrap();
        all_deals.push(deals);
    }
    for deals in all_deals {
        for (i, deal) in deals {
            nodes[i].deals.push(deal);
        }
    }

    // 4. Process the Deals on each node and send the responses to the other
    // nodes
    let mut all_resps = Vec::new();
    for (i, node) in nodes.iter_mut().enumerate() {
        for deal in node.deals.clone() {
            let resp = node.dkg.process_deal(&deal).unwrap();
            all_resps.push((i, resp));
        }
    }
    for (i, node) in nodes.iter_mut().enumerate() {
        for (j, resp) in all_resps.clone() {
            if i == j {
                continue;
            }
            node.resps.push(resp);
        }
    }

    let mut all_justifications = Vec::new();
    // 5. Process the responses on each node
    for node in nodes.iter_mut() {
        for resp in node.resps.clone() {
            let justification = node.dkg.process_response(&resp).unwrap();
            all_justifications.push(justification);
        }
    }
    for (_, node) in nodes.iter_mut().enumerate() {
        for j in all_justifications.clone() {
            if j.is_none() {
                continue;
            }
            let justification = j.unwrap();
            assert!(
                node.dkg.process_justification(&justification).is_ok(),
                "dealer misbehaved"
            )
        }
    }

    // 6. Check and print the qualified shares
    for node in nodes.iter() {
        assert!(node.dkg.certified());
        assert_eq!(n, node.dkg.qualified_shares().len());
        assert_eq!(n, node.dkg.qual().len());
        println!("qualified shares: {:?}", node.dkg.qualified_shares());
        println!("QUAL: {:?}", node.dkg.qual());
    }

    // 7. Get the secret shares and public key
    let mut shares = Vec::with_capacity(n);
    let mut public_key = Default::default();
    for node in nodes.iter_mut() {
        let distr_key = node.dkg.dist_key_share().unwrap();
        shares.push(Some(distr_key.pri_share()));
        public_key = distr_key.public();
        node.secret_share = distr_key.pri_share();
        node.distributed_public_key = public_key.clone();
        println!("new distributed public key {:?}", public_key);
    }

    // 8. Variant A - Encrypt a secret with the public key and decrypt it with
    // the reconstructed shared secret key. Reconstructing the shared secret key
    // in not something we should do as it gives the power to decrypt any
    // further messages encrypted with the shared public key. For this we show
    // in variant B how to make nodes send back partial decryptions instead of
    // their shares. In variant C the nodes return partial decrpytions that are
    // encrypted under a provided public key.
    let message = "Hello world".as_bytes();
    let secret_key = share::poly::recover_secret(suite, &shares, n, n).unwrap();
    let (k, c, remainder) = el_gamal_encrypt(suite, &public_key, message);
    assert_eq!(remainder.len(), 0);
    let decrypted_message = el_gamal_decrypt(suite, &secret_key, k.clone(), c.clone()).unwrap();
    assert_eq!(message.to_vec(), decrypted_message);

    // 8. Variant B - Each node provide only a partial decryption by sending its
    // public share. We then reconstruct the public commitment with those public
    // shares.
    let mut partials = Vec::with_capacity(n);
    let mut pub_shares = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let s = suite.point().mul(&node.secret_share.v, Some(&k));
        partials.push(suite.point().sub(&c.clone(), &s).clone());
        pub_shares.push(Some(share::poly::PubShare {
            i,
            v: partials[i].clone(),
        }));
    }

    // Reconstruct the public commitment, which contains the decrypted message
    let res = share::poly::recover_commit(suite, &pub_shares, n, n).unwrap();
    let decrypted_message = res.data().unwrap();
    assert_eq!(message.to_vec(), decrypted_message);

    // 8 Variant C - Nodes return a partial decryption under the encryption from
    // the client's provided public key. This is useful in case the decryption
    // happens in public. In that case the decrypted message is never released
    // in clear, but the message is revealed re-encrypted under the provided
    // public key.
    //
    // Here is the crypto that happens in 3 phases:
    //
    // (1) Message encryption:
    //
    // r: random point
    // A: dkg public key
    // G: curve's generator
    // M: message to encrypt
    // (C, U): encrypted message
    //
    // C = rA + M
    // U = rG
    //
    // (2) Node's partial decryption
    //
    // V: node's public re-encrypted share
    // o: node's private share
    // Q: client's public key (pG)
    //
    // V = oU + oQ
    //
    // (3) Message's decryption
    //
    // R: recovered commit (f(V1, V2, ...Vi)) using Lagrange interpolation
    // p: client's private key
    // M': decrypted message
    //
    // M' = C - (R - pA)

    let a = public_key;
    let r = suite.scalar().pick(&mut suite.random_stream());
    let m = suite
        .point()
        .embed(Some(message), &mut suite.random_stream());
    let c = suite.point().add(
        // rA + M
        &suite.point().mul(&r, Some(&a)), // rA
        &m,
    );
    let u = suite.point().mul(&r, None); // rG

    let p = suite.scalar().pick(&mut suite.random_stream());
    let q = suite.point().mul(&p, None); // pG

    let mut partials = Vec::with_capacity(n);
    let mut pub_shares = Vec::with_capacity(n);
    for (i, node) in nodes.iter().enumerate() {
        let v = suite.point().add(
            // oU + oQ
            &suite.point().mul(&node.secret_share.v, Some(&u)), // oU
            &suite.point().mul(&node.secret_share.v, Some(&q)), // oQ
        );
        partials.push(v);
        pub_shares.push(Some(share::poly::PubShare {
            i,
            v: partials[i].clone(),
        }));
    }

    let r_caps = share::poly::recover_commit(suite, &pub_shares, n, n).unwrap(); // R = f(V1, V2, ...Vi)

    let decrypted_point = suite.point().sub(
        // C - (R - pA)
        &c,
        &suite.point().sub(
            // R - pA
            &r_caps,
            &suite.point().mul(&p, Some(&a)), // pA
        ),
    );
    let decrypted_message = decrypted_point.data().unwrap();
    assert_eq!(decrypted_message, message.to_vec());

    // 9. The following shows a re-share of the dkg key, which will invalidates
    // the current shares on each node and produce a new public key. After that
    // steps 3, 4, 5 need to be done in order to get the new shares and public
    // key.
    for node in nodes.iter_mut() {
        let share = node.dkg.dist_key_share().unwrap();
        let c = Config {
            suite,
            longterm: node.priv_key.clone(),
            old_nodes: pub_keys.clone(),
            new_nodes: pub_keys.clone(),
            share: Some(share),
            threshold: n,
            old_threshold: n,
            public_coeffs: None,
            reader: None,
            user_reader_only: false,
        };
        let new_dkg = new_dist_key_handler(c).unwrap();
        node.dkg = new_dkg;
    }
}
