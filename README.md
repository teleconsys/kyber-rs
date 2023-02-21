Advanced Crypto Library for Rust
====================================

This library is an unofficial (partial) porting of [DEDIS kyber](https://github.com/dedis/kyber) library to pure Rust. 

This library provides a toolbox of advanced cryptographic primitives for Rust,
that need more than straightforward signing and encryption.
Please see the
[Rust crate documentation for this package](...)
for details on the library's purpose and API functionality.

The following table shows the already implemented features in compared with the original library.

| Feature                                                               | Not started | Partial | Mostly done | Done |
|-----------------------------------------------------------------------|-------------|---------|-------------|------|
| Blake3 XOF                                                            |             |         |             |   ✔️  |
| [Util package](https://github.com/dedis/kyber/tree/master/util)       |             |         |      🔶      |      |
| DH                                                                    |             |         |             |   ✔️  |
| KYBER point                                                           |             |         |             |   ✔️  |
| KYBER scalar                                                          |             |         |             |   ✔️  |
| KYBER group                                                           |             |         |      🔶      |      |
| VSS                                                                   |             |         |             |   ✔️  |
| DKG                                                                   |             |         |             |   ✔️  |
| [Shuffle package](https://github.com/dedis/kyber/tree/master/shuffle) |      🔶      |         |             |      |
| [PVSS](https://github.com/dedis/kyber/tree/master/share/pvss)         |      🔶      |         |             |      |
| [BLS](https://github.com/dedis/kyber/tree/master/sign/bls)            |      🔶      |         |             |      |
| [tBLS](https://github.com/dedis/kyber/tree/master/sign/tbls)          |      🔶      |         |             |      |
| [cosi](https://github.com/dedis/kyber/tree/master/sign/cosi)          |      🔶      |         |             |      |
| [bdn](https://github.com/dedis/kyber/tree/master/sign/bdn)            |      🔶      |         |             |      |
| [anon](https://github.com/dedis/kyber/tree/master/sign/anon)          |      🔶      |         |             |      |
| EdDsa                                                                 |             |         |             |   ✔️  |
| Schnorr signature                                                     |             |         |             |   ✔️  |
| DSS                                                                   |             |         |             |   ✔️  |
| Encryption                                                            |             |         |             |   ✔️  |
| [Pairing package](https://github.com/dedis/kyber/tree/master/pairing) |      🔶      |         |             |      |
| [Proof package](https://github.com/dedis/kyber/tree/master/proof)     |      🔶      |         |             |      |
| Keccak XOF                                                            |      🔶      |         |             |      |
| Blake2 XOF                                                            |      🔶      |         |             |      |

This first release's task is to provide DKG APIs intended to be used with Ed25519 Signature Scheme.

Using the module
----------------

You can include this library by adding it to the `Cargo.toml` file in your project.

```toml
[dependencies]
kyber_rs = "0.1"
```

In order to understand how to use this library, examples are provided under `src/examples`

A note on deriving shared secrets
---------------------------------

Traditionally, ECDH (Elliptic curve Diffie-Hellman) derives the shared secret
from the x point only. In this framework, you can either manually retrieve the
value or use the MarshalBinary method to take the combined (x, y) value as the
shared secret. We recommend the latter process for new softare/protocols using
this framework as it is cleaner and generalizes across different types of groups
(e.g., both integer and elliptic curves), although it will likely be
incompatible with other implementations of ECDH. See [the Wikipedia
page](http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) on
ECDH.

Reporting security problems
---------------------------

This library is offered as-is, and without a guarantee. It will need an
independent security review before it should be considered ready for use in
security-critical applications. If you integrate Kyber into your application it
is YOUR RESPONSIBILITY to arrange for that audit.
