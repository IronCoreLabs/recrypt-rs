use crate::api_common::RecryptErr;
use crate::internal::ByteVector;
use crate::internal::hashable::Hashable;
use crate::internal::memlock;
use crate::internal::{array_split_64, take_lock};
use clear_on_drop::clear::Clear;
use ed25519_dalek;
use quick_error::quick_error;
use rand;
use std;
use std::fmt;
use std::sync::Mutex;

// CompressedY version of the PublicSigningKey
new_bytes_type!(PublicSigningKey, 32);

impl PublicSigningKey {
    ///
    /// Verify that the signature was signed by its private key over the hashable bytes of
    /// the message.
    ///
    /// Returns true if all the values are valid and the signature can be verified.
    ///
    pub fn verify<A: Hashable>(&self, message: &A, signature: &Ed25519Signature) -> bool {
        Ed25519.verify(message, signature, self)
    }
}

impl Hashable for PublicSigningKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes.to_vec()
    }
}

quick_error! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum Ed25519Error {
        PublicKeyInvalid(invalid_bytes: [u8; 32]){
            display("The signing public key provided was invalid.")
        }
        InputWrongSize(expected: usize, actual: usize) {
            display("The key pair provided was of an invalid length. Expected '{}', but found '{}'.", expected, actual)
        }
    }
}

// We don't derive Copy here on purpose. SigningKeypair is a sensitive value and
// should be passed by reference to avoid needless duplication
/// The first 32 bytes of this are the Secret Ed25519 key and the 2nd 32 bytes are the Compressed Y form
/// of the public key.
#[derive(Clone)]
pub struct SigningKeypair {
    pub(crate) bytes: [u8; 64],
}
bytes_only_debug!(SigningKeypair);

impl From<SigningKeypair> for [u8; 64] {
    fn from(t: SigningKeypair) -> Self {
        t.bytes
    }
}

impl SigningKeypair {
    const ENCODED_SIZE_BYTES: usize = 64;
    pub fn new<CR: rand::RngCore + rand::CryptoRng>(rng: &Mutex<CR>) -> SigningKeypair {
        let signing_key = ed25519_dalek::SigningKey::generate::<CR>(&mut *take_lock(rng));

        //Unchecked is safe because the public is on the curve and the size is statically guaranteed.
        SigningKeypair::new_unchecked(signing_key.to_keypair_bytes())
    }
    ///
    ///Create a SigningKeypair from a byte array slice. If the array is not the right length or if the public
    ///key doesn't match the private, it will return an Ed25519Error.
    ///
    pub fn from_byte_slice(bytes: &[u8]) -> Result<SigningKeypair, Ed25519Error> {
        let bytes_size = bytes.len();
        let sized_bytes = if bytes_size == SigningKeypair::ENCODED_SIZE_BYTES {
            let mut dest = [0u8; SigningKeypair::ENCODED_SIZE_BYTES];
            dest.copy_from_slice(bytes);
            Ok(dest)
        } else {
            Err(Ed25519Error::InputWrongSize(
                SigningKeypair::ENCODED_SIZE_BYTES,
                bytes_size,
            ))
        }?;
        SigningKeypair::from_bytes(&sized_bytes)
    }

    ///
    ///Create a SigningKeypair from a sized array of bytes. This can fail if the public key portion doesn't
    ///match the private key.
    ///
    pub fn from_bytes(sized_bytes: &[u8; 64]) -> Result<SigningKeypair, Ed25519Error> {
        let (priv_key, pub_key) = array_split_64(sized_bytes);
        let ed25519_dalek_secret = ed25519_dalek::SigningKey::from_bytes(&priv_key);
        //Calculate the public key to check that the value passed in is correct.

        let ed25519_dalek_pub = ed25519_dalek::VerifyingKey::from(&ed25519_dalek_secret);
        if ed25519_dalek_pub.to_bytes() == pub_key {
            Ok(SigningKeypair::new_unchecked(*sized_bytes))
        } else {
            Err(Ed25519Error::PublicKeyInvalid(pub_key))
        }
    }

    pub(crate) fn new_unchecked(bytes: [u8; 64]) -> SigningKeypair {
        let skp = SigningKeypair { bytes };
        memlock::mlock_slice(&skp.bytes[..]);
        skp
    }

    ///Get the public_key portion of this SigningKeypair.
    pub fn public_key(&self) -> PublicSigningKey {
        self.into()
    }

    ///Export the bytes of the keypair.
    pub fn bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    ///
    ///Create a signature by signing over the bytes produced by the hashable instance of `message`.
    ///
    pub fn sign<A: Hashable>(&self, message: &A) -> Ed25519Signature {
        Ed25519.sign(message, self)
    }
}
bytes_eq_and_hash!(SigningKeypair);

impl<'a> From<&'a SigningKeypair> for PublicSigningKey {
    fn from(kp: &SigningKeypair) -> PublicSigningKey {
        let (_, pub_bytes) = array_split_64(&kp.bytes);

        PublicSigningKey::new(pub_bytes)
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.bytes.clear();
        memlock::munlock_slice(&self.bytes[..])
    }
}
new_bytes_type!(Ed25519Signature, 64);

pub struct Ed25519;

impl Ed25519Signing for Ed25519 {
    fn sign<T: Hashable>(&self, t: &T, signing_key: &SigningKeypair) -> Ed25519Signature {
        use ed25519_dalek::Signer;
        let (priv_key, _) = array_split_64(&signing_key.bytes);
        let key_pair = ed25519_dalek::SigningKey::from_bytes(&priv_key);
        let sig = key_pair.sign(&t.to_bytes()[..]);

        Ed25519Signature::new(sig.to_bytes())
    }
    fn verify<T: Hashable>(
        &self,
        t: &T,
        signature: &Ed25519Signature,
        public_key: &PublicSigningKey,
    ) -> bool {
        use ed25519_dalek::Verifier;

        ed25519_dalek::VerifyingKey::from_bytes(&public_key.bytes)
            .and_then(|pk| {
                let sig = ed25519_dalek::Signature::from_bytes(&signature.bytes);
                pk.verify(&t.to_bytes()[..], &sig)
            })
            .map(|_| true)
            .unwrap_or(false)
    }
}
pub trait Ed25519Signing {
    ///
    ///Create a signature by signing over the bytes produced by the hashable instance of `t`.
    ///
    fn sign<T: Hashable>(&self, t: &T, signing_key: &SigningKeypair) -> Ed25519Signature;

    ///
    /// Use the public_key to verify that the signature was signed by its private key over the hashable bytes of
    /// t. Returns true if all the values are valid and the signature can be verified.
    ///
    fn verify<T: Hashable>(
        &self,
        t: &T,
        signature: &Ed25519Signature,
        public_key: &PublicSigningKey,
    ) -> bool;
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::internal::array_concat_32;

    pub fn good_signing_keypair() -> SigningKeypair {
        SigningKeypair::new_unchecked([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
            103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ])
    }

    #[test]
    fn real_ed25519_matches_verify_good_message() {
        let sec_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let keypair = SigningKeypair {
            bytes: sec_key.to_keypair_bytes(),
        };
        let message = [100u8; 32].to_vec();
        let result = Ed25519.sign(&message, &keypair);
        let verify_result = Ed25519.verify(&message, &result, &keypair.public_key());
        assert!(verify_result);
    }

    #[test]
    fn signing_keypair_from_bytes() {
        let bytes = [0u8; 63];
        let error = SigningKeypair::from_byte_slice(&bytes)
            .expect_err("Keypair should be too short so this can't happen.");
        assert_eq!(error, Ed25519Error::InputWrongSize(64, 63));

        let error2 = SigningKeypair::from_byte_slice(&[0u8; 64])
            .expect_err("Public key error should happen.");
        assert_eq!(error2, Ed25519Error::PublicKeyInvalid([0u8; 32]))
    }

    #[test]
    fn signing_keypair_into_bytes() {
        let dalek_pub_key = ed25519_dalek::VerifyingKey::from_bytes(&[1u8; 32]).unwrap();
        let key_pair = SigningKeypair {
            bytes: array_concat_32(&[1u8; 32], &dalek_pub_key.to_bytes()),
        };
        let key_pair_bytes = key_pair.bytes().clone();
        let bytes: [u8; 64] = key_pair.into();
        assert_eq!(key_pair_bytes[..], bytes[..])
    }

    #[test]
    fn signing_keypairs_equal() {
        let sk1 = good_signing_keypair();
        let sk2 = good_signing_keypair();
        assert_eq!(sk1, sk2)
    }

    #[test]
    fn signing_keypairs_not_equal() {
        let sk1 = good_signing_keypair();
        let sk2 = SigningKeypair::new_unchecked([
            1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
            103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ]);
        assert_ne!(sk1, sk2)
    }
}
