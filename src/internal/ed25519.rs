use crate::api_common::ApiErr;
use crate::internal::array_split_64;
use crate::internal::hashable::Hashable;
use crate::internal::ByteVector;
use clear_on_drop::clear::Clear;
use ed25519_dalek;
use ed25519_dalek::PublicKey;
use quick_error::quick_error;
use rand;
use std;
use std::fmt;

///CompressedY version of the PublicSigningKey
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

// we don't derive Copy or Clone here on purpose. SigningKeypair is a sensitive value and
// should be passed by reference to avoid needless duplication
/// The first 32 bytes of this are the Secret Ed25519 key and the 2nd 32 bytes are the Compressed Y form
/// of the public key.
pub struct SigningKeypair {
    pub(crate) bytes: [u8; 64],
}
bytes_only_debug!(SigningKeypair);
impl PartialEq for SigningKeypair {
    fn eq(&self, other: &SigningKeypair) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl Eq for SigningKeypair {}

impl SigningKeypair {
    const ENCODED_SIZE_BYTES: usize = 64;
    pub fn new<CR: rand::RngCore + rand::CryptoRng>(rng: &mut CR) -> SigningKeypair {
        let keypair = ed25519_dalek::Keypair::generate::<CR>(rng);
        //Unchecked is safe because the public is on the curve and the size is statically guaranteed.
        SigningKeypair::new_unchecked(keypair.to_bytes())
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
        //This can't fail because it's statically guaranteed to be 32 bytes long.
        let ed25519_dalek_secret = ed25519_dalek::SecretKey::from_bytes(&priv_key).unwrap();
        //Calculate the public key to check that the value passed in is correct.
        let ed25519_dalek_pub = ed25519_dalek::PublicKey::from(&ed25519_dalek_secret);
        if ed25519_dalek_pub.to_bytes() == pub_key {
            Ok(SigningKeypair::new_unchecked(*sized_bytes))
        } else {
            Err(Ed25519Error::PublicKeyInvalid(pub_key))
        }
    }

    pub(crate) fn new_unchecked(bytes: [u8; 64]) -> SigningKeypair {
        SigningKeypair { bytes }
    }

    ///Get the public_key portion of this SigningKeypair.
    pub fn public_key(&self) -> PublicSigningKey {
        PublicSigningKey::from(self)
    }

    ///Export the bytes of the keypair.
    pub fn bytes(&self) -> [u8; 64] {
        self.bytes
    }

    ///
    ///Create a signature by signing over the bytes produced by the hashable instance of `message`.
    ///
    pub fn sign<A: Hashable>(&self, message: &A) -> Ed25519Signature {
        Ed25519.sign(message, self)
    }
}

impl<'a> From<&'a SigningKeypair> for PublicSigningKey {
    fn from(kp: &SigningKeypair) -> PublicSigningKey {
        let (_, pub_bytes) = array_split_64(&kp.bytes);

        PublicSigningKey::new(pub_bytes)
    }
}

impl Drop for SigningKeypair {
    fn drop(&mut self) {
        self.bytes.clear()
    }
}
new_bytes_type!(Ed25519Signature, 64);

pub struct Ed25519;

impl Ed25519Signing for Ed25519 {
    fn sign<T: Hashable>(&self, t: &T, signing_key: &SigningKeypair) -> Ed25519Signature {
        //This unwrap cannot fail. The only thing that the `from_bytes` does for validation is that the
        //value is 64 bytes long, which we guarantee statically.
        let key_pair = ed25519_dalek::Keypair::from_bytes(&signing_key.bytes[..]).unwrap();
        let sig = key_pair.sign(&t.to_bytes()[..]);

        Ed25519Signature::new(sig.to_bytes())
    }
    fn verify<T: Hashable>(
        &self,
        t: &T,
        signature: &Ed25519Signature,
        public_key: &PublicSigningKey,
    ) -> bool {
        PublicKey::from_bytes(&public_key.bytes[..])
            .and_then(|pk| {
                ed25519_dalek::Signature::from_bytes(&signature.bytes[..])
                    .and_then(|sig| pk.verify(&t.to_bytes()[..], &sig))
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
    use ed25519_dalek::SecretKey;

    pub fn good_signing_keypair() -> SigningKeypair {
        SigningKeypair::new_unchecked([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
            103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ])
    }

    #[test]
    fn real_ed25519_matches_verify_good_message() {
        let sec_key = SecretKey::from_bytes(&[1; 32]).unwrap();
        let dalek_pub_key = ed25519_dalek::PublicKey::from(&sec_key);
        let priv_key = SigningKeypair {
            bytes: array_concat_32(&sec_key.to_bytes(), &dalek_pub_key.to_bytes()),
        };
        let message = [100u8; 32].to_vec();
        let result = Ed25519.sign(&message, &priv_key);
        let verify_result = Ed25519.verify(
            &message,
            &result,
            &PublicSigningKey::new(dalek_pub_key.to_bytes()),
        );
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
}
