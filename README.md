Advanced Crypto Library for Rust
====================================

This library is a partial porting of [DEDIS kyber](https://github.com/dedis/kyber) library to pure Rust. 

This library provides a toolbox of advanced cryptographic primitives for Rust,
that need more than straightforward signing and encryption.
Please see the
[Rust crate documentation for this package](...)
for details on the library's purpose and API functionality.

The following table shows the already implemented features in compared with the [DEDIS](https://github.com/dedis/kyber)' library.

| Feature                                                               | Mostly done | Done |
|-----------------------------------------------------------------------|-------------|------|
| Blake3 XOF                                                            |             |   ✔️  |
| [Util package](https://github.com/dedis/kyber/tree/master/util)       |      🔶      |      |
| DH                                                                    |             |   ✔️  |
| KYBER point                                                           |             |   ✔️  |
| KYBER scalar                                                          |             |   ✔️  |
| KYBER group                                                           |      🔶      |      |
| VSS                                                                   |             |   ✔️  |
| DKG                                                                   |             |   ✔️  |
| Encryption                                                            |             |   ✔️  |
| EdDsa                                                                 |             |   ✔️  |
| Schnorr signature                                                     |             |   ✔️  |
| DSS                                                                   |             |   ✔️  |
| [Shuffle package](https://github.com/dedis/kyber/tree/master/shuffle) |             |      |
| [PVSS](https://github.com/dedis/kyber/tree/master/share/pvss)         |             |      |
| [More signature schemes](https://github.com/dedis/kyber/tree/master/sign)            |             |      |
| [Pairing package](https://github.com/dedis/kyber/tree/master/pairing) |             |      |
| [Proof package](https://github.com/dedis/kyber/tree/master/proof)     |             |      |
| Keccak XOF                                                            |             |      |
| Blake2 XOF                                                            |             |      |

This first release's task is to provide DKG APIs intended to be used with Ed25519 Signature Scheme in a pure Rust implementation.
Tests and benchmarks are also fully implemented.

Using the module
----------------

You can include this library by adding it to the `Cargo.toml` file in your project.

```toml
[dependencies]
kyber_rs = "0.1.0-alpha"
```

In order to understand how to use this library, examples are provided under `src/examples`

Contributing
---------------------------------

If want to add additional features or propose fixes to this library you are welcome to do so!
To contribute directly to the repository, simply fork the project, push your changes to your fork and create a pull request.


Contacts
---------------------------------

If you want to get in touch with us feel free to contact us at <g.pescetelli@teleconsys.it>


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
