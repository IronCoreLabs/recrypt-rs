use api::ApiErr;
use clear_on_drop::clear::Clear;
use ed25519_dalek;
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
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
    pub fn verify<A: Hashable>(&self, message: &A, signature: &Signature) -> bool {
        Ed25519.verify(message, signature, self)
    }
}

impl Hashable for PublicSigningKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes.to_vec()
    }
}

// we don't derive Copy or Clone here on purpose. PrivateSigningKey is a sensitive value and
// should be passed by reference to avoid needless duplication
new_bytes_type_no_derive!(PrivateSigningKey, 64);

impl PrivateSigningKey {
    pub fn compute_public_key(&self) -> PublicSigningKey {
        let pub_key: PublicKey = ExpandedSecretKey::from_bytes(&self.bytes).unwrap().into();
        PublicSigningKey::new(pub_key.to_bytes())
    }

    ///
    ///Create a signature by signing over the bytes produced by the hashable instance of `message`.
    ///
    pub fn sign<A: Hashable>(&self, message: &A) -> Signature {
        Ed25519.sign(message, self)
    }
}

impl Drop for PrivateSigningKey {
    fn drop(&mut self) {
        self.bytes.clear()
    }
}
new_bytes_type!(Signature, 64);

pub struct Ed25519;

impl Ed25519Signing for Ed25519 {
    fn sign<T: Hashable>(&self, t: &T, private_key: &PrivateSigningKey) -> Signature {
        let private_key_bytes: [u8; 64] = private_key.bytes;
        //This unwrap cannot fail. The only thing that the `from_bytes` does for validation is that the
        //value is 64 bytes long, which we guarentee statically.
        let secret_key: ExpandedSecretKey =
            ExpandedSecretKey::from_bytes(&private_key_bytes).unwrap();
        let public_key: PublicKey = ExpandedSecretKey::from_bytes(&private_key_bytes)
            .unwrap()
            .into();
        let sig = secret_key.sign::<Sha512>(&t.to_bytes()[..], &public_key);

        Signature {
            bytes: sig.to_bytes(),
        }
    }
    fn verify<T: Hashable>(
        &self,
        t: &T,
        signature: &Signature,
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
    fn sign<T: Hashable>(&self, t: &T, private_key: &PrivateSigningKey) -> Signature;

    ///
    /// Use the public_key to verify that the signature was signed by its private key over the hashable bytes of
    /// t. Returns true if all the values are valid and the signature can be verified.
    ///
    fn verify<T: Hashable>(
        &self,
        t: &T,
        signature: &Signature,
        public_key: &PublicSigningKey,
    ) -> bool;
}

#[cfg(test)]
mod test {
    use super::*;
    use ed25519_dalek::SecretKey;
    #[test]
    fn real_ed25519_matches_verify_good_message() {
        let sec_key = SecretKey::from_bytes(&[1; 32]).unwrap();
        let priv_key = PrivateSigningKey {
            bytes: sec_key.expand::<Sha512>().to_bytes(),
        };
        let message = [100u8; 32].to_vec();
        let result = Ed25519.sign(&message, &priv_key);
        let verify_result = Ed25519.verify(
            &message,
            &result,
            &PublicSigningKey {
                bytes: [
                    138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
                    103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
                ],
            },
        );
        assert!(verify_result);
    }
}
