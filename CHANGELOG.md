Changelog
====================

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
