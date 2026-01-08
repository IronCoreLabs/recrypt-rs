# Recrypt

[![crates](https://img.shields.io/crates/v/recrypt.svg)](https://crates.io/crates/recrypt) [![docs](https://docs.rs/recrypt/badge.svg)](https://docs.rs/recrypt) [![CI](https://github.com/IronCoreLabs/recrypt-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/IronCoreLabs/recrypt-rs/actions/workflows/ci.yaml)

A pure-Rust library that implements a set of cryptographic primitives for building a _multi-hop Proxy Re-encryption_ scheme, known as Transform Encryption.

## What is Transform Encryption?

Suppose you have two (public, private) key pairs: **(A, AA)** and **(B, BB)**.

Transform Encryption allows data encrypted to one public key (A) to be _transformed_ so that it can be decrypted using another user's private key (BB). This transformation process requires a special _transform key_ (A -> B) that is computed using the first user's private key (AA) and the second user's public key (B). **Having a transform key and performing the transformation does not allow the person doing this process to decrypt the data or to recover either user's private key.**

See the [Single-hop Transform Encryption Example](https://docs.rs/recrypt/) for more details on computing a transform key and applying a transform using recrypt.

## Usage

If you are building an application and would like to use Transform Encryption, you might try looking at the IronCore SDKs as they provide higher level of abstraction as part of the IronCore Privacy Platform:

- [ironweb](https://github.com/IronCoreLabs/ironweb) - Javascript implementation of IronCore's Privacy Platform. Appropriate for all modern browsers.
- [ironoxide](https://github.com/IronCoreLabs/ironoxide) - Pure Rust implementation of IronCore's Privacy Platform.
- [ironoxide-java](https://github.com/IronCoreLabs/ironoxide-java) - Java bindings for `ironoxide`. Appropriate for all JVM languages.
- [ironoxide-scala](https://github.com/IronCoreLabs/ironoxide-scala) - Scala wrappers around `ironoxide-java`.
- [ironode](https://github.com/IronCoreLabs/ironnode) - NodeJS implementation of IronCore's Privacy Platform.

All SDKs are intended to be compatible with one another.

### Rust Dependency

See [crates](https://crates.io/crates/recrypt) for the most recent version.

### Feature Flags

Recrypt uses feature flags to select the underlying arithmetic backend. Exactly one backend must be enabled:

| Feature        | Default | Description                                                               |
|----------------|---------|---------------------------------------------------------------------------|
| `u64_backend`  | Yes     | Uses 62-bit limbs for field arithmetic. Faster on 64-bit architectures.   |
| `u32_backend`  | No      | Uses 31-bit limbs for field arithmetic. Required for WebAssembly targets. |

Additional features:

| Feature            | Default | Description                                                                                                                           |
|--------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------|
| `wasm`             | No      | Enables `u32_backend` plus wasm-specific dependencies (`getrandom/wasm_js`, `clear_on_drop/no_cc`). Use this for WebAssembly builds.  |
| `disable_memlock`  | No      | Disables automatic memory locking via mlock. Use on platforms that don't support mlock.                                               |

Example usage:

```toml
# Default (64-bit backend)
recrypt = "0.14"

# For WebAssembly
recrypt = { version = "0.14", default-features = false, features = ["wasm"] }

# 32-bit backend without wasm
recrypt = { version = "0.14", default-features = false, features = ["u32_backend"] }
```

Enabling both `u64_backend` and `u32_backend` (or neither) is a compile error.

### Other bindings

In addition to the native Rust implementation, we provide additional bindings to Recrypt:

- [Node.js](https://github.com/IronCoreLabs/recrypt-node-binding)
- [WebAssembly](https://github.com/IronCoreLabs/recrypt-wasm-binding)

A [Scala implementation](https://github.com/IronCoreLabs/recrypt) of recrypt is also available.

## API Documentation and Example Usage

See https://recrypt.rs

## Security and Audits

NCC Group's [Cryptography Services](https://www.nccgroup.com/us/technical-assurance/cryptography-encryption/) team has conducted an audit of this library - release [0.6.2](https://github.com/IronCoreLabs/recrypt-rs/releases/tag/0.6.2) contains all of the audited code, including updates that were created to resolve issues that were discovered during the audit. The NCC Group audit found that the chosen pairing and elliptic curve are cryptographically sound, and that the Rust implementation is a faithful and correct embodiment of the target protocol. In addition, the audit confirmed that the implementation does not leak secret information via timing or memory access pattern side-channel attacks.

To learn more about our approach to cryptography and to read our publications, please [go here](https://ironcorelabs.com/docs/concepts/ironcore-cryptography).

### Memory Protection

Recrypt supports memory protection via mlock to prevent sensitive cryptographic material from being swapped to disk. This is detected and enabled automatically on supported platforms (Linux, macOS, Windows). If you need to disable this behavior, use the `disable_memlock` feature flag (see [Feature Flags](#feature-flags)).

## Benchmarks

### Results from 0.14.1 (Jan 8, 2025)

_Note: The most accurate way to characterize performance is to [run the benchmarks for yourself](#running-benchmarks) in your target environment!_

These benchmarks were done on an Macbook Pro M1 Max.

If you are unfamiliar with the output of criterion.rs benchmarks, please see [the docs](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_output.html) for how to interpret the output.

```
  256-bit generate key pair        time: [317.03 µs 318.42 µs 320.27 µs]
  256-bit generate plaintext       time: [1.1955 ms 1.2065 ms 1.2187 ms]
  256-bit generate ed25519 keypair time: [13.819 µs 14.042 µs 14.372 µs]
  256-bit generate transform key   time: [6.1809 ms 6.1905 ms 6.1995 ms]
  256-bit compute public key       time: [317.00 µs 318.14 µs 319.01 µs]
  256-bit derive symmetric key     time: [2.5810 µs 2.9923 µs 3.4567 µs]
  256-bit encrypt (level 0)        time: [2.8864 ms 2.8907 ms 2.8950 ms]
  256-bit decrypt (level 0)        time: [2.5649 ms 2.5731 ms 2.5850 ms]
  256-bit transform (level 1)      time: [7.4683 ms 7.5562 ms 7.7222 ms]
  256-bit decrypt (level 1)        time: [9.4527 ms 9.4668 ms 9.4800 ms]
  256-bit transform (level 2)      time: [17.265 ms 17.294 ms 17.322 ms]
  256-bit decrypt (level 2)        time: [15.974 ms 16.037 ms 16.098 ms]
```

## Contributing

### Building

Rust (stable) is required.

```sh
cargo build
```

### Running Tests

```sh
cargo test
```

### Running Benchmarks

```sh
cargo bench
```

## Proxy Re-Encryption Background

In the academic literature, _transform encryption_ is referred to as _proxy re-encryption_. A proxy re-encryption (PRE) scheme is a public-key encryption scheme, where each participant has a pair of related keys, one public and one private, which are mathematically related. Alice encrypts a message to Bob using his public key, and Bob decrypts the encrypted message using his public key to retrieve the original message.

PRE allows someone (the _delegator_) to delegate the ability to decrypt her messages to another person (the _delegatee_). Rather than just sharing her private key with the delegatee, the delegator computes a _transform key_ (or _re-encryption key_) that allows messages encrypted to her public key to be transformed so they appear can be decrypted using the delegatee's private key. Computing this transform key requires the delegator's private key and the delegatee's public key; once it is computed, the key is stored on a _semi-trusted proxy_.

When the proxy receives a message encrypted to the delegator, it applies the transform algorithm using the transform key and delivers the transformed message to the delegatee. **The proxy does not need to be trusted, because possession of the transform key does not allow the proxy to decrypt the message or to recover any information about either the delegator's or the delegatee's private keys, even if it collaborates with the delegatee.**

When the delegator no longer wants to allow access, she just requests that the proxy discard the transform key. She must trust the proxy to perform this action.

### PRE Scheme Properties

There are a number of ways to categorize PRE schemes; some of the most important are the following:

- _Directionality_ describes whether delegate from A to B also allows transformation from B to A. Unidirectional schemes do not allow this.
- _Interactivity_ describes whether both parties must be actively involved in order to generate the transform key. A non-interactive scheme only requires the public key of the delegatee.
- _Transitivity_ describes whether a proxy can re-delegate encryption. That is, if the proxy holds a transform key from A to B and a transform key from B to C, can it generate a transform key from a to C? A non-transitive scheme does not allow this.
- _Collusion safety_ describes whether it is possible for a delegatee to collude with the proxy that holds a transform key to that delegatee in order to recover the private key of the delegator. A collusion-safe scheme does not allow this.
- _Multi-hop_ describes whether it is possible to allow a delegatee to also be a delegator. That is, does the scheme allow a ciphertext that has already been transformed from Alice to Bob to subsequently be transformed from Bob to Carol. In a multi-hop situation, the proxies would chain the transformations, so any delegatee in the chain could decrypt any message that one of her delegators could decrypt.

The Recrypt library implements a PRE scheme that is unidirectional, non-interactive, non-transitive, collusion-safe, and multi-hop.

### Algorithms

The PRE algorithm implemented here was originally suggested in a short paper titled "A Fully Secure Unidirectional and Multi-user Proxy Re-encryption Scheme" by H. Wang and Z. Cao, published in the proceedings of the ACM Conference on Computer and Communications Security (CCS) in 2009. The algorithm was enhanced in a paper titled "A Multi-User CCA-Secure Proxy Re-Encryption Scheme" by Y. Cai and X. Liu, published in the proceedings of the IEEE 12th International Conference on Dependable, Autonomic, and Secure Computing in 2014.

We provide a synopsis of the algorithms, along with a description of how they can be used to implement an access control system, in the paper "Cryptographically Enforced Orthogonal Access Control at Scale" by B. Wall and P. Walsh, published in SCC '18, the proceedings of the 6th International Workshop on Security in Cloud Computing in 2018.

The algorithms in these papers were very generic and made no implementation choices. They specified only the use of a bilinear pairing function. We made a number of implementation choices. Foremost, we use the optimal Ate pairing as our pairing function. This requires a "pairing-friendly" elliptic curve; we chose a Barreto-Naehrig curve, which supports efficient implementation of the pairing.

Our implementation was guided by the following papers:

- "Pairing-Friendly Elliptic Curves of Prime Order" by P.S.L.M. Barreto and M. Naehrig, published in _Proceedings of the 12th International Workshop on Selected Areas in Cryptography (SAC)_, 2006, pp. 319-331.

- "Constructing Tower Extensions of Finite Fields for Implementation of Pairing-Based Cryptography" by N. Benger and M. Scott, published in _Proceedings of the 3rd International Workshop on Arithmetic of Finite Fields_, 2010, pp. 180-195.

- "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves" by J. Beuchat et al., published in _Proceedings from the 4th International Conference on Pairing-Based Cryptography_, 2010, pp. 21-39.

- "Implementing Cryptographic Pairings over Barreto-Naehrig Curves" by A. J. Devegili et al., published in _Proceedings from the 1st International Conference on Pairing-Based Cryptography_, 2007, pp. 197-207.

- "Multiplication and Squaring on Pairing-Friendly Fields" by A. J. Devegili et al., published in 2006 and available at http://eprint.iacr.org/2006/471.

- "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions" by R. Granger and M. Scott, published in _Proceedings from the 13th International Conferencee on Practice and Theory in Public Key Cryptography (PKC)_, 2010, pp. 209-223.

- "Multiplication of Multidigit Numbers on Automata" by A. Karatsuba and Y. Ofman, in the journal _Soviet Physics Doklady_, vol. 7, Jan. 1963.

- "New Software Speed Records for Cryptographic Pairings" by M. Naehrig, R. Niederhagen, and P. Schwabe, in _Proceedings of the 1st International Conference on Progress in Cryptology and Information Security in Latin America (LATINCRYPT)_, 2010, pp. 109-123.

- "On the Final Exponentiation for Calculating Pairings on Ordinary Elliptic Curves" by M. Scott et al., published in _Proceedings of the 3rd International Converence on Pairing-Based Cryptography (PKC)_, 2009, pp. 78-88.

And by the book:
_Guide to Pairing-Based Cryptography_ by N.E. Mrabet and M. Joye, Chapman and Hall/CRC Cryptography and Network Security Series, 2016.

## Intellectual Property

Recrypt-rust incorporates technology that is protected by the following patents (additional patents may be pending in the U.S. and elsewhere):

- US 10,659,222 - Orthogonal Access Control for Groups via Multi-Hop Transform Encryption
- US 11,146,391 - Orthogonal Access Control for Groups via Multi-Hop Transform Encryption
- WO2018201062A1 - Orthogonal Access Control for Groups via Multi-Hop Transform Encryption
- EP3616384A4 - Orthogonal Access Control for Groups via Multi-Hop Transform Encryption
- KR20200027921 A - Orthogonal Access Control for Groups via Multi-Hop Transform Encryption

## Cryptography Notice

This repository includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See https://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002, which includes information security software using or performing cryptographic functions. The form and manner of this distribution makes it eligible for export under the License Exception ENC (see the BIS Export Administration Regulations, Section 740.17.B.3.i.B and also the publicly available source code exemption, under 742.15; notice has been given to BIS and NSA).

## License

Recrypt-rust is licensed under the [GNU Affero General Public License](LICENSE).
We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information.

Copyright (c) 2018-present IronCore Labs, Inc.
All rights reserved.
