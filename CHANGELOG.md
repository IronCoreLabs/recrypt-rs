# Changelog

## 0.8.4

### Notable Internal Changes
- Fixes a regression introduced in 0.8.0 where the randomness for some operations was reduced.
  
  Affected 256-bit operations in 0.8.0 through 0.8.3 were:
  * CryptoOps::gen_plaintext
  * CryptoOps::transform
  * KeyGenOps::generate_transform_key
  
  480-bit operations were not affected.

## 0.8.3

### Notable Internal Changes

- [#90](#90)
  - lazy_static to 1.4

## 0.8.2

### Public API changes

- [#87](#87)
  - Adding add/sub to PrivateKey type to support key augmentation.

## 0.8.1

### Notable Internal Changes

Bumped lazy_static version to 1.3.

## 0.8.0

### Public API changes

- [[#82](#82)]
  - Public API no longer contains mutable references. This makes sharing a single Recrypt among threads possible.
  - Default RNG changed from `ThreadRng` to `ReseedingRng<rand_chacha::ChaChaCore, EntropyRng>`
  - `DefaultRng` type alias added to public API

## 0.7.1

### Notable Internal Changes

- [[#80](#80)] Added a default set of features to enable `ed2559-dalek`s 64 bit backend and added a `wasm` feature that will instead use a 32 bit backend

## 0.7.0

### Public API changes
 - [[#57](#57)]
   - `api::Api` renamed to `api::Recrypt`
   - `api_480::Api480` renamed to `api_480::Recrypt480`
   - `ApiErr` renamed to `RecryptErr` and `RecryptErr` is now publicly exported
   - `PrivateKey::ENCODED_SIZE_BYTES` is now pub
 - [[#63](#63)] Added a prelude for easier importing of common types and traits
   - `use recrypt::prelude::*`
 - [[#70](#70)]
   - `DerivedSymmetricKey` now has a `to_private_key`
   - `PublicKey` APIs now take all arguments as borrows
 - [[#71](#71)]
   - provide `From<SigningKeyPair>` instance for `[u8; 64]`
   - provide `Clone` for `PrivateKey`
   - many wrapped byte types can be consumed to get the underlying bytes out without copying
 - [[#72](#72)] `PublicSigningKey`'s `bytes()` method now returns a reference instead of copying

## 0.6.2

### Notable Internal Changes

- [[#54](#54)] Consume gridiron 0.6.0, which fixes some perf issues.
- [[#55](#55)] Optimize inverse, xi multiplications, etc.

## 0.6.1

### Notable Internal Changes

- [[#47](#47)] Document HomogeneousPoint / TwistedHPoint normalize behavior and remove panic from pairing
- [[#50](#50)] Update to use Monty represenation for all 256 bit operations.
- [[#52](#52)] Update to use Monty represenation for all 480 bit operations.

## 0.6.0
### Public API changes
  * [[#35](#35)] 480-bit public API available. See api_480.rs
### Notable Internal Changes
- [[#27](#27)] Use Rust 2018 edition
- Progress toward Constant Time algorithms
  * [[#42](#42)] Fp `is_one` and `is_zero` documented to not be constant time
  * [[#40](#40)] Fp `Mul<u64>` and `Add<u64>` now use `u32` and are documented to not be constant time
  * [[#39](#39)] Point negation is constant time
  * [[#37](#37)] Fp12/6 `to_fp2` constant time behavior documented
  * [[#26](#26)] Point double and add functions are constant time

## 0.5.1
- [[#24](#24)] Added better errors for Ed25519 and NonEmptyVec

## 0.5.0
- [[#21](#21)] Consume gridiron 0.4.0 (primatives are now constant time)
  * `NonAdjacentForm` renamed to `BitRepr`
  * Upgrade to Rust 1.31.0

## 0.4.0
- [#20] Update dependencies (rand 0.6, sha 0.8, ed25519 1.0.0-pre.0)
- [#18] Add a way to hash a Plaintext to 32 bytes.
- [#17] Add quick_error to all of our error ADTS
- [#14] Add benchmarking on Travis
## 0.3.0

- Add hashable instance for TransformKey (#13)
- Add lto for release builds to show more realistic perf (#12)
- Change Ed25519 PrivateKey type to SigningKeypair (#10)
- small changes to README to remove hardcoded versions and point to recrypt.rs (#9)
- Rework macros to eliminate compiler warnings (#8)
