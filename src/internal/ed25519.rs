use api::ApiErr;
use clear_on_drop::clear::Clear;
use ed25519_dalek;
use ed25519_dalek::PublicKey;
use internal::array_split_64;
use internal::hashable::Hashable;
use internal::ByteVector;
use sha2::Sha512;
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

// we don't derive Copy or Clone here on purpose. SigningKeypair is a sensitive value and
// should be passed by reference to avoid needless duplication
/// The first 32 bytes of this are the Secret Ed25519 key and the 2nd 32 bytes are the Compressed Y form
/// of the public key.
new_bytes_type_no_derive!(SigningKeypair, 64);

impl SigningKeypair {
    pub fn public_key(&self) -> PublicSigningKey {
        PublicSigningKey::from(self)
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
        //value is 64 bytes long, which we guarentee statically.
        let key_pair = ed25519_dalek::Keypair::from_bytes(&signing_key.bytes[..]).unwrap();
        let sig = key_pair.sign::<Sha512>(&t.to_bytes()[..]);

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
                    .and_then(|sig| pk.verify::<Sha512>(&t.to_bytes()[..], &sig))
            }).map(|_| true)
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
mod test {
    use super::*;
    use ed25519_dalek::SecretKey;
    use internal::array_concat_32;
    #[test]
    fn real_ed25519_matches_verify_good_message() {
        let sec_key = SecretKey::from_bytes(&[1; 32]).unwrap();
        let dalek_pub_key = ed25519_dalek::PublicKey::from_secret::<Sha512>(&sec_key);
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
}
