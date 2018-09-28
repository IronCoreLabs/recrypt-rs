#![cfg_attr(feature = "unstable", feature(test))]
#![doc(html_no_source)] // use github for source browsing

//! Recrypt implements a set of cryptographic primitives for building a
//! multi-hop proxy re-encryption scheme, known as Transform Encryption.
//!
//! ## Basic Encrypt/Decrypt Example
//! ```
//! use recrypt::api::*;
//! // create a new recrypt api
//! let mut api = Api::new();
//!
//! // generate a plaintext to encrypt
//! let pt = api.gen_plaintext();
//!
//! // generate a public/private keypair and some signing keys
//! let (priv_key, pub_key) = api.generate_key_pair().unwrap();
//! let (priv_signing_key, pub_signing_key) = api.generate_ed25519_key_pair();
//!
//! // encrypt!
//! let encrypted_val = api.encrypt(pt, pub_key, pub_signing_key, priv_signing_key).unwrap();
//!
//! // decrypt!
//! let decrypted_val = api.decrypt(encrypted_val, priv_key).unwrap();
//!
//! assert_eq!(pt, decrypted_val)
//! ```

//! ## Single-hop Transform Encryption Example
//! Encrypt a message to public key `initial_pub_key` and decrypt it with `target_priv_key`
//! after transforming the encrypted message.
//! ```
//! use recrypt::api::*;
//! // create a new recrypt api
//! let mut api = Api::new();
//!
//! // generate a plaintext to encrypt
//! let pt = api.gen_plaintext();
//!
//! // generate signing keys
//! let (priv_signing_key, pub_signing_key) = api.generate_ed25519_key_pair();
//!
//! // generate a public/private keypair to encrypt the data to initially.
//! let (initial_priv_key, initial_pub_key) = api.generate_key_pair().unwrap();
//!
//! // encrypt the data to `initial_pub_key`!
//! let encrypted_val = api.encrypt(pt, initial_pub_key, pub_signing_key, priv_signing_key).unwrap();
//!
//! // generate a second public/private keypair as the target of the transform.
//! // after applying the transform, `target_priv_key` will be able to decrypt the data!
//! let (target_priv_key, target_pub_key) = api.generate_key_pair().unwrap();
//!
//! // generate a transform key that will change which private key can decrypt the data
//! let initial_to_target_transform_key = api.generate_transform_key(
//!     initial_priv_key,
//!     target_pub_key,
//!     pub_signing_key,
//!     priv_signing_key).unwrap();
//!
//! // Transform the plaintext to be encrypted to the target!
//! // The data is _not_ be decrypted here. Simply transformed!
//! let transformed_val = api.transform(
//!     encrypted_val,
//!     initial_to_target_transform_key,
//!     pub_signing_key,
//!     priv_signing_key).unwrap();
//!
//! // decrypt the transformed value with the target private key and recover the plaintext
//! let decrypted_val = api.decrypt(transformed_val, target_priv_key).unwrap();
//!
//! assert_eq!(pt, decrypted_val);
//! ```
extern crate arrayvec;
extern crate core;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate gridiron;
extern crate num_traits;
extern crate rand;
extern crate sha2;
extern crate clear_on_drop;

#[cfg(test)]
#[macro_use]
extern crate proptest;

#[cfg(test)]
extern crate hex;

#[macro_use]
extern crate lazy_static;

#[macro_use]
mod internal; // this needs to come before `api` as api relies on macros defined in `internal`
pub mod api;
pub mod nonemptyvec;
