# Changelog


## 0.11.1

### Public API changes

- [[#115](https://github.com/IronCoreLabs/recrypt-rs/pull/115)]
  - Add explicit 32-bit and 64-bit backends as features: `u64_backend`, `u32_backend`

### Notable internal changes

- [[#108](https://github.com/IronCoreLabs/recrypt-rs/pull/108)]
  - Add memory protections for secret values (disable with `disable_memlock`)


## 0.11.0

### Public API changes

- [[#105](https://github.com/IronCoreLabs/recrypt-rs/pull/105)]
  - Upgrade dependencies (`rand`, `rand_chacha`, `ed25519-dalek`, `gridiron`)

## 0.10.0

### Public API changes

- [[#104](https://github.com/IronCoreLabs/recrypt-rs/pull/104)]

  - Eliminate the `Revealed` struct.
  - Add `Hash` for all public types except `Recrypt`.
  - Add `Eq` for all types which had `PartialEq`.

- [[#101](https://github.com/IronCoreLabs/recrypt-rs/pull/101)]
  - Eliminate the `Revealed` wrappers for `PrivateKey`, `Plaintext`, and `DerivedSymmetricKey`.
  - Implement `PartialEq` for `PrivateKey`, `Plaintext`, and `DerivedSymmetricKey`.

### Notable internal changes

- [[#101](https://github.com/IronCoreLabs/recrypt-rs/pull/101)]

  - Eliminate the `Revealed` wrapper for `SigningKeypair`.
  - Implement `PartialEq` for `SigningKeypair`.

- [[#104](https://github.com/IronCoreLabs/recrypt-rs/pull/104)]
  - Move to use constant time eq for all properties that have `bytes()`.
  - Use derivative to derive `PartialEq` and `Hash` instead of hand crafted implementations.

## 0.9.2

### Public API changes

- [[#99](https://github.com/IronCoreLabs/recrypt-rs/pull/99)] Implement `Clone` for `Plaintext`.

## 0.9.1

### Notable internal changes

- [[#98](https://github.com/IronCoreLabs/recrypt-rs/pull/98)] Fix the dependency pinning for `ed25519-dalek` to be exact.

## 0.9.0

### Public API changes

- [[#95](https://github.com/IronCoreLabs/recrypt-rs/pull/95)]
  - Remove `Add` and `Sub` from `PrivateKey`.
  - Add `augment` and `augment_minus` to `PrivateKey`, which correctly support private key rotation.

## 0.8.4

### Notable internal changes

- Fix a regression introduced in 0.8.0 where the randomness for some operations was reduced.

Affected 256-bit operations in 0.8.0 through 0.8.3 were:

- `CryptoOps::gen_plaintext`
- `CryptoOps::transform`
- `KeyGenOps::generate_transform_key`

480-bit operations were not affected.

## 0.8.3

### Notable internal changes

- [[#90](https://github.com/IronCoreLabs/recrypt-rs/pull/90)] Update lazy_static to 1.4.

## 0.8.2

### Public API changes

- [[#87](https://github.com/IronCoreLabs/recrypt-rs/pull/87)] Implement `Add` and `Sub` for `PrivateKey` to support private key augmentation.

## 0.8.1

### Notable internal changes

- [[#85](https://github.com/IronCoreLabs/recrypt-rs/pull/85)] Update lazy_static to 1.3.

## 0.8.0

### Public API changes

- [[#82](https://github.com/IronCoreLabs/recrypt-rs/pull/82)]
  - Remove mutable references from public API. This makes sharing a single `Recrypt` among threads possible.
  - Change default RNG from `ThreadRng` to `ReseedingRng<rand_chacha::ChaChaCore, EntropyRng>`.
  - Add `DefaultRng` type alias to public API.

## 0.7.1

### Notable internal changes

- [[#81](https://github.com/IronCoreLabs/recrypt-rs/pull/81)] Add a default set of features to enable `ed2559-dalek`'s 64-bit backend and a `wasm` feature that will instead use a 32-bit backend.

## 0.7.0

### Public API changes

- [[#57](https://github.com/IronCoreLabs/recrypt-rs/pull/57)]
  - Rename `api::Api` to `api::Recrypt`.
  - Rename `api_480::Api480` to `api_480::Recrypt480`.
  - Rename `ApiErr` to `RecryptErr` and publicly export `RecryptErr`.
  - Make `PrivateKey::ENCODED_SIZE_BYTES` public.
- [[#63](https://github.com/IronCoreLabs/recrypt-rs/pull/63)]
  - Add a prelude for easier importing of common types and traits.
    - `use recrypt::prelude::*`
- [[#70](https://github.com/IronCoreLabs/recrypt-rs/pull/70)]
  - Implement `DerivedSymmetricKey.to_private_key`.
  - Change `PublicKey` APIs to take all arguments as borrows.
- [[#71](https://github.com/IronCoreLabs/recrypt-rs/pull/71)]
  - Implement `From<SigningKeyPair>` instance for `[u8; 64]`.
  - Implement `Clone` for `PrivateKey`.
  - Allow many wrapped byte types to be consumed to get the underlying bytes without copying.
- [[#72](https://github.com/IronCoreLabs/recrypt-rs/pull/72)] Change `PublicSigningKey.bytes` method to return a reference instead of copying.

## 0.6.2

### Notable internal changes

- [[#54](https://github.com/IronCoreLabs/recrypt-rs/pull/54)] Consume gridiron 0.6.0, fixing some performance issues.
- [[#55](https://github.com/IronCoreLabs/recrypt-rs/pull/55)] Optimize Xi inverse, multiplication, etc.

## 0.6.1

### Notable internal changes

- [[#47](https://github.com/IronCoreLabs/recrypt-rs/pull/47)] Document behavior of `normalize` for `HomogeneousPoint` and `TwistedHPoint` and remove panic from pairing.
- [[#50](https://github.com/IronCoreLabs/recrypt-rs/pull/50)] Update to use Monty representation for all 256-bit operations.
- [[#52](https://github.com/IronCoreLabs/recrypt-rs/pull/52)] Update to use Monty representation for all 480-bit operations.

## 0.6.0

### Public API changes

- [[#35](https://github.com/IronCoreLabs/recrypt-rs/pull/35)] Implement 480-bit public API. See api_480.rs.

### Notable internal changes

- [[#27](https://github.com/IronCoreLabs/recrypt-rs/pull/27)] Use Rust 2018 edition.
- Progress toward Constant Time algorithms
  - [[#42](https://github.com/IronCoreLabs/recrypt-rs/pull/42)] Document Fp `is_one` and `is_zero` to not be constant time.
  - [[#40](https://github.com/IronCoreLabs/recrypt-rs/pull/40)] Use `u32` for Fp `Mul` and `Add` and document to not be constant time.
  - [[#39](https://github.com/IronCoreLabs/recrypt-rs/pull/39)] Implement point negation in constant time.
  - [[#37](https://github.com/IronCoreLabs/recrypt-rs/pull/37)] Document Fp12 and Fp6 `to_fp2` constant time behavior.
  - [[#26](https://github.com/IronCoreLabs/recrypt-rs/pull/26)] Implement point double and add functions in constant time.

## 0.5.1

- [[#24](https://github.com/IronCoreLabs/recrypt-rs/pull/24)] Add better errors for `Ed25519` and `NonEmptyVec`.

## 0.5.0

- [[#21](https://github.com/IronCoreLabs/recrypt-rs/pull/21)]
  - Consume gridiron 0.4.0 (primatives are now constant time).
  - Rename `NonAdjacentForm` to `BitRepr`.

## 0.4.0

- [[#20](https://github.com/IronCoreLabs/recrypt-rs/pull/20)] Update dependencies (rand 0.6, sha 0.8, ed25519 1.0.0-pre.0).
- [[#18](https://github.com/IronCoreLabs/recrypt-rs/pull/18)] Add a way to hash a Plaintext to 32 bytes.
- [[#17](https://github.com/IronCoreLabs/recrypt-rs/pull/17)] Add quick_error for all of our error ADTs.
- [[#14](https://github.com/IronCoreLabs/recrypt-rs/issues/14)] Add benchmarking on Travis.

## 0.3.0

- [[#13](https://github.com/IronCoreLabs/recrypt-rs/pull/13)] Implement `Hashable` for `TransformKey`.
- [[#12](https://github.com/IronCoreLabs/recrypt-rs/pull/12)] Add lto for release builds to show more realistic performance.
- [[#10](https://github.com/IronCoreLabs/recrypt-rs/pull/10)] Change `Ed25519` `PrivateKey` type to `SigningKeypair`.
- [[#9](https://github.com/IronCoreLabs/recrypt-rs/pull/9)] Change README to remove hardcoded versions and point to recrypt.rs.
- [[#8](https://github.com/IronCoreLabs/recrypt-rs/pull/8)] Rework macros to eliminate compiler warnings.
