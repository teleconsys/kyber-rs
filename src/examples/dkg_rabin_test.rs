/*
This example illustrates how to use the dkg/rabin API to generate a public
key and its corresponding private key that is shared among nodes. It shows the
different phases that each node must perform in order to construct the private
shares that will form the final private key. The example uses 3 nodes and shows
the "happy" path where each node does its job correctly.
*/

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    group::edwards25519::SuiteEd25519,
    share::{
        self,
        dkg,
    },
    Group, Point, Random, Scalar, Suite, sign::dss::DistKeyShare, encoding::BinaryMarshaler,
};

const NUM_NODES: usize = 3;
const THRESHOLD: usize = NUM_NODES;

struct Node<SUITE: Suite>
where
    SUITE::POINT: Serialize + DeserializeOwned,
    <SUITE::POINT as Point>::SCALAR: Serialize + DeserializeOwned,
{
    dkg: dkg::DistKeyGenerator<SUITE>,
    pub_key: SUITE::POINT,
    priv_key: <SUITE::POINT as Point>::SCALAR,
    deals: Vec<dkg::Deal<SUITE::POINT>>,
    resps: Vec<dkg::Response>,
    secret_share: share::poly::PriShare<<SUITE::POINT as Point>::SCALAR>,
    distributed_public_key: SUITE::POINT
}

#[test]
fn test_example_dkg() {
    let suite = SuiteEd25519::new_blake_sha256ed25519();

    let mut nodes = Vec::with_capacity(NUM_NODES);
    let mut pub_keys = Vec::with_capacity(NUM_NODES);

    // 1. Init the nodes
    for _ in 0..NUM_NODES {
        let priv_key = suite.scalar().pick(&mut suite.random_stream());
        let pub_key = suite.point().mul(&priv_key, None);
        pub_keys.push(pub_key.clone());
        nodes.push(Node::<SuiteEd25519> {
            dkg: Default::default(),
            pub_key,
            priv_key,
            deals: Vec::new(),
            resps: Vec::new(),
            secret_share: Default::default(),
            distributed_public_key: Default::default()
        });
    }

    // 2. Create the DKGs on each node
    for node in nodes.iter_mut() {
        let dkg = dkg::new_dist_key_generator(suite, node.priv_key.clone(), &pub_keys, THRESHOLD)
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
            continue
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

    // 6. Process justifications on each node (if any)
    for (i, node) in nodes.iter_mut().enumerate() {
		for j in all_justifications.clone() {
			if j.is_none() {
                continue
            }
            let justification = j.unwrap();
            if justification.index == i as u32 {
                continue
            }            
			assert!(node.dkg.process_justification(&justification).is_ok(), "dealer misbehaved")
		}
	}

    // 7. Check and print the qualified shares
	for (i, node) in nodes.iter().enumerate() {
        assert!(node.dkg.certified());
        assert_eq!(THRESHOLD, node.dkg.qual().len());
		println!("Qualified nodes (from node {} prospective): {:?}", i, node.dkg.qual());
	}

    // 8. Generate and broadcast secret commits
    let mut scs = Vec::new();
	for (i, node) in nodes.iter_mut().enumerate() {
        let sc = node.dkg.secret_commits().unwrap();
        scs.push(sc);

	}

    // 9. Process secret commits 
    let mut ccs = Vec::new();
    for sc in scs.iter() {
        for node in nodes.iter_mut() {
            let cc = node.dkg.process_secret_commits(sc).unwrap();
            ccs.push(cc);
        }
    }

    // 10. Process complaints (if any)
    let mut rcs = Vec::new();
    for (i, node) in nodes.iter_mut().enumerate() {
        for cc in ccs.clone() {
            if cc.is_none() {
                continue
            }
            let complaint = cc.unwrap();
            if complaint.index == i as u32 {
                continue;
            }

            let rc = node.dkg.process_complaint_commits(&complaint).unwrap();
            rcs.push(rc);
        }
    }

    // 11. Process renconstructed commits (if any)
    for rc in rcs.clone() {
        for node in nodes.iter_mut() {
           node.dkg.process_reconstruct_commits(&rc).unwrap();
        }
    }

    // 12. Now everyone should be able to compute the distributed key 
    for (i, node) in nodes.iter_mut().enumerate() {
        let dks = node.dkg.dist_key_share().unwrap();
        node.secret_share = dks.pri_share();
        node.distributed_public_key = dks.public();
        println!("Distributed public key (from node {} prospective): {:?}", i, node.distributed_public_key.marshal_binary().unwrap());
    }

}
