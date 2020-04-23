#![cfg_attr(feature = "unstable", feature(test))]
#![doc(html_no_source)] // use github for source browsing

//! Recrypt implements a set of cryptographic primitives for building a
//! multi-hop proxy re-encryption scheme, known as Transform Encryption.
//!
//! Start exploring the [Api documentation](api/index.html)
//!
//! ## Basic Encrypt/Decrypt Example
//! ```
//! use recrypt::prelude::*;

//!
//! // create a new recrypt
//! let mut recrypt = Recrypt::new();
//!
//! // generate a plaintext to encrypt
//! let pt = recrypt.gen_plaintext();
//!
//! // generate a public/private keypair and some signing keys
//! let (priv_key, pub_key) = recrypt.generate_key_pair().unwrap();
//! let signing_keypair = recrypt.generate_ed25519_key_pair();
//!
//! // encrypt!
//! let encrypted_val = recrypt.encrypt(&pt, &pub_key, &signing_keypair).unwrap();
//!
//! // decrypt!
//! let decrypted_val = recrypt.decrypt(encrypted_val, &priv_key).unwrap();
//!
//! // plaintext recovered.
//! assert_eq!(pt, decrypted_val)
//! ```

//! ## Single-hop Transform Encryption Example
//! Encrypt a message to public key `initial_pub_key` and decrypt it with `target_priv_key`
//! after transforming the encrypted message.
//! ```
//! use recrypt::prelude::*;
//!
//! // create a new recrypt
//! let mut recrypt = Recrypt::new();
//!
//! // generate a plaintext to encrypt
//! let pt = recrypt.gen_plaintext();
//!
//! // generate signing keys
//! let signing_keypair= recrypt.generate_ed25519_key_pair();
//!
//! // generate a public/private keypair to encrypt the data to initially.
//! let (initial_priv_key, initial_pub_key) = recrypt.generate_key_pair().unwrap();
//!
//! // encrypt the data to `initial_pub_key`!
//! let encrypted_val = recrypt.encrypt(&pt, &initial_pub_key, &signing_keypair).unwrap();
//!
//! // generate a second public/private keypair as the target of the transform.
//! // after applying the transform, `target_priv_key` will be able to decrypt the data!
//! let (target_priv_key, target_pub_key) = recrypt.generate_key_pair().unwrap();
//!
//! // generate a transform key that will change which private key can decrypt the data
//! let initial_to_target_transform_key = recrypt.generate_transform_key(
//!     &initial_priv_key,
//!     &target_pub_key,
//!     &signing_keypair).unwrap();
//!
//! // Transform the plaintext to be encrypted to the target!
//! // The data is _not_ decrypted here. Simply transformed!
//! let transformed_val = recrypt.transform(
//!     encrypted_val,
//!     initial_to_target_transform_key,
//!     &signing_keypair).unwrap();
//!
//! // decrypt the transformed value with the target private key and recover the plaintext
//! let decrypted_val = recrypt.decrypt(transformed_val, &target_priv_key).unwrap();
//!
//! // plaintext recovered.
//! assert_eq!(pt, decrypted_val);
//! ```
//!
//! ## Constant Time and Equality
//!
//! We have done a lot of work in recrypt-rs to ensure that operations dealing with secret data
//! are [constant time](https://www.bearssl.org/constanttime.html) and not susceptible to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).
//! The public API is also constant time.
//!
//! ## Implementing [Serde](https://docs.serde.rs/serde_json/) serialize/deserialize keys
//!
//! We provide an optional feature which allows private and public keys to be converted to a JSON string and/or a Vec<u8>. In addition, this optional feature also facilitates the private and public key data structures to be serialized to any `io::Write` i.e. a File or a TCP stream.
//! ### Configuration examples
//! Adding the optional Serde feature - a u64 backend example
//! ```
//! [dependencies]
//! recrypt = { version = "~0.11.0", features = ["serde"] }
//! ```
//! Adding the optional Serde feature - a u32 backend example
//! ```
//! [dependencies]
//! recrypt = { version = "~0.11.0", features = ["serde", "u32"], default-features = false } 
//! ```
//! Adding the optional Serde feature - a WebAssembly(Wasm) example
//! ```
//! [dependencies]
//! recrypt = { version = "~0.11.0", features = ["serde", "wasm"], default-features = false } 
//! ```
//! ### Usage examples
//! Convert public key to JSON string
//! ```
//! serde_json::to_string(&pub_key).unwrap()
//! ```
//! Convert public key to Vec<u8>
//! ```

pub mod prelude;
#[macro_use] // this is still required in Rust 2018
mod internal; // this needs to come before `api` as api relies on macros defined in `internal`
pub mod api;
pub mod api_480;
mod api_common;
pub mod nonemptyvec;
