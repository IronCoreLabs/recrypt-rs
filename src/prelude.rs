
//! Convenience re-export of common structs and traits needed for using Recrypt
//!
//! ```
//! use recrypt::prelude::*;
//! use rand::rngs::ThreadRng;
//!
//! let recrypt: Recrypt<Sha256, Ed25519, RandomBytes<ThreadRng>> = Recrypt::new();
//! ```

// necessary for instantiating and storing a Recrypt as a struct member
pub use crate::api::Recrypt;
pub use crate::api::Ed25519;
pub use crate::api::Sha256;
pub use crate::api::RandomBytes;

// traits that define functionality on Recrypt
pub use crate::api::KeyGenOps;
pub use crate::api::CryptoOps;
pub use crate::api::Ed25519Ops;
pub use crate::api::SchnorrOps;
