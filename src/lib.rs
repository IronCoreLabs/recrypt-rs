#![cfg_attr(feature = "unstable", feature(test))]
#![doc(html_no_source)] // use github for source browsing

//! Recrypt implements a set of cryptographic primitives for building a
//! multi-hop proxy re-encryption scheme, known as Transform Encryption.
//!
//! Start exploring the [Api documentation](api/index.html)
//!
//! ## Basic Encrypt/Decrypt Example
//! ```rust
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
//! ```rust
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
//! ## Using serde_json to serialize/deserialize the bytes of keys
//!
//! The bytes of the PrivateKey and PublicKey data structures can be serialized and deserialized to and from JSON String and/or a Vec<u8> using the following methods.
//! Simply add [serde_json](https://crates.io/crates/serde_json) as a dependency to your application.
//! ```rust
//! use recrypt::prelude::*;
//! use recrypt::api::{PrivateKey, PublicKey};
//! // create a new recrypt
//! let mut recrypt = Recrypt::new();
//!
//! // generate a public/private keypair and some signing keys
//! let (priv_key, pub_key) = recrypt.generate_key_pair().unwrap();
//!
//! //Serialize public key (x and y values) to JSON string
//! let pub_key_str_json_x = serde_json::to_string(&pub_key.bytes_x_y().0).unwrap();
//! let pub_key_str_json_y = serde_json::to_string(&pub_key.bytes_x_y().1).unwrap();
//!
//! // Serialize private key (bytes) to JSON string
//! let priv_key_str_json = serde_json::to_string(priv_key.bytes()).unwrap();
//!
//! // Serialize public key (x and y values) to Vec<u8>
//! let pub_key_bytes_json_x = serde_json::to_vec(&pub_key.bytes_x_y().0).unwrap();
//! let pub_key_bytes_json_y = serde_json::to_vec(&pub_key.bytes_x_y().1).unwrap();
//!
//! // Serialize private key (bytes) to Vec<u8>
//! let priv_key_bytes_json = serde_json::to_vec(&priv_key.bytes()).unwrap();
//!
//! //Deserialize string into PrivateKey
//! let from_str_bytes: Vec<u8> = serde_json::from_str(&priv_key_str_json).unwrap();
//! let priv_key_from_str_bytes = PrivateKey::new_from_slice(&from_str_bytes).unwrap();
//!
//! // Deserialize JSON bytes into PrivateKey
//! let from_bytes_json: Vec<u8> = serde_json::from_slice(&priv_key_bytes_json).unwrap();
//! let priv_key_from_bytes_json = PrivateKey::new_from_slice(&from_bytes_json).unwrap();
//!
//! // Deserialize string into PublicKey
//! let from_str_bytes_x: Vec<u8> = serde_json::from_str(&pub_key_str_json_x).unwrap();
//! let from_str_bytes_y: Vec<u8> = serde_json::from_str(&pub_key_str_json_y).unwrap();
//! let from_str_bytes_json_x_as_tuple: &[u8] = &from_str_bytes_x;
//! let from_str_bytes_json_y_as_tuple: &[u8] = &from_str_bytes_y;
//! let pub_key_from_str_bytes_json = PublicKey::new_from_slice((from_str_bytes_json_x_as_tuple, from_str_bytes_json_y_as_tuple)).unwrap();
//!
//! // Deserialize JSON bytes into PublicKey
//! let from_bytes_json_x: Vec<u8> = serde_json::from_slice(&pub_key_bytes_json_x).unwrap();
//! let from_bytes_json_y: Vec<u8> = serde_json::from_slice(&pub_key_bytes_json_y).unwrap();
//! let from_bytes_json_x_as_tuple: &[u8] = &from_bytes_json_x;
//! let from_bytes_json_y_as_tuple: &[u8] = &from_bytes_json_y;
//! let pub_key_from_bytes_json = PublicKey::new_from_slice((from_bytes_json_x_as_tuple, from_bytes_json_y_as_tuple)).unwrap();
//! ```

pub mod prelude;
#[macro_use] // this is still required in Rust 2018
mod internal; // this needs to come before `api` as api relies on macros defined in `internal`
pub mod api;
pub mod api_480;
mod api_common;
pub mod nonemptyvec;
