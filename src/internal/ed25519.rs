use api::ApiErr;
use clear_on_drop::clear::Clear;
use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek;
use ed25519_dalek::{ExpandedSecretKey, PublicKey};
use internal::hashable::Hashable;
use internal::ByteVector;
use sha2::Sha512;
use std;
use std::fmt;

///CompressedY version of the PublicSigningKey
new_bytes_type!(PublicSigningKey, 32);

impl Hashable for PublicSigningKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes.to_vec()
    }
}

new_bytes_type_no_derive!(PrivateSigningKey, 64);

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
        //The value used to compute the key is the bottom 32 bytes of the expanded key.
        //This can be removed when we resolve https://github.com/dalek-cryptography/ed25519-dalek/issues/39
        let secret_bytes: [u8; 32] = {
            let mut secret_bytes = [0; 32];
            secret_bytes.copy_from_slice(&private_key_bytes[0..32]);
            secret_bytes
        };
        //We compute the public key point and then push it into the sign call as the public key.
        let public_key_point =
            (&Scalar::from_bits(secret_bytes) * &constants::ED25519_BASEPOINT_TABLE).compress();
        let sig = secret_key.sign::<Sha512>(
            &t.to_bytes()[..],
            //unwrap cannot fail here. Will go away once the above ticket is resolved.
            &PublicKey::from_bytes(&public_key_point.to_bytes()).unwrap(),
        );

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
