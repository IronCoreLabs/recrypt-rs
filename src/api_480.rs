use crate::api_common::{ApiErr, Result};
use crate::internal;
use crate::internal::bytedecoder::{BytesDecoder, DecodeErr};
use crate::internal::curve;
pub use crate::internal::ed25519::{
    Ed25519, Ed25519Signature, Ed25519Signing, PublicSigningKey, SigningKeypair,
};
use crate::internal::fp::fr_480::Fr480;
use crate::internal::fp12elem::Fp12Elem;
pub use crate::internal::hashable::Hashable;
use crate::internal::hashable::Hashable60;
use crate::internal::homogeneouspoint::TwistedHPoint;
use crate::internal::pairing;
pub use crate::internal::rand_bytes::*;
use crate::internal::schnorr::{SchnorrSign, SchnorrSigning};
pub use crate::internal::sha256::{Sha256, Sha256Hashing};
pub use crate::internal::ByteVector;
use crate::nonemptyvec::NonEmptyVec;
use clear_on_drop::clear::Clear;
use gridiron::fp_480::Fp480;
use rand;
use std;
use std::fmt;

/// Recrypt public API - 480-bit
/// If you are looking better performance, you might consider the 256-bit API in `api.rs`
#[derive(Debug)]
pub struct Api480<H, S, R> {
    random_bytes: R,
    sha_256: H,
    ed25519: S,
    pairing: internal::pairing::Pairing<Fp480>,
    curve_points: &'static internal::curve::CurvePoints<Fp480>,
    schnorr_signing: SchnorrSign<Fp480, Fr480, H>,
}

impl Api480<Sha256, Ed25519, RandomBytes<rand::rngs::ThreadRng>> {
    pub fn new() -> Api480<Sha256, Ed25519, RandomBytes<rand::rngs::ThreadRng>> {
        Api480::new_with_rand(rand::thread_rng())
    }
}
impl<CR: rand::CryptoRng + rand::RngCore> Api480<Sha256, Ed25519, RandomBytes<CR>> {
    pub fn new_with_rand(r: CR) -> Api480<Sha256, Ed25519, RandomBytes<CR>> {
        let pairing = pairing::Pairing::new();
        let curve_points = &*curve::FP_480_CURVE_POINTS;
        let schnorr_signing = internal::schnorr::SchnorrSign::<Fp480, Fr480, Sha256>::new_480();
        Api480 {
            random_bytes: RandomBytes::new(r),
            sha_256: Sha256,
            ed25519: Ed25519,
            pairing,
            curve_points,
            schnorr_signing,
        }
    }
}

/// Hashed but not encrypted Plaintext used for envelope encryption
new_bytes_type!(DerivedSymmetricKey, 32);

/// A value included in an encrypted message that can be used when the message is decrypted
/// to ensure that you got the same value out as the one that was originally encrypted.
/// It is a hash of the plaintext.
new_bytes_type!(AuthHash, 32);

/// Encrypted Plaintext (Fp12Elem)
new_bytes_type!(EncryptedMessage, Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES);

/// Not hashed, not encrypted Fp12Elem
/// See DecryptedSymmetricKey and EncryptedMessage
// we don't derive Copy or Clone here on purpose. Plaintext is a sensitive value and should be passed by reference
// to avoid needless duplication
pub struct Plaintext {
    bytes: [u8; Plaintext::ENCODED_SIZE_BYTES],
    _internal_fp12: Fp12Elem<Fp480>,
}

impl Plaintext {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES;

    /// Construct a Plaintext from raw bytes
    pub fn new(bytes: [u8; Plaintext::ENCODED_SIZE_BYTES]) -> Plaintext {
        // since new takes a fixed size array, we know it is safe to decode the resultant vector
        Plaintext::from(
            Fp12Elem::<Fp480>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }

    new_from_slice!(Plaintext);

    pub fn bytes(&self) -> &[u8; Plaintext::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    pub(crate) fn internal_fp12(&self) -> &Fp12Elem<Fp480> {
        &self._internal_fp12
    }
}

bytes_only_debug!(Plaintext);

impl From<Fp12Elem<Fp480>> for Plaintext {
    fn from(fp12: Fp12Elem<Fp480>) -> Self {
        Plaintext {
            bytes: fp12.to_bytes_fp480(),
            _internal_fp12: fp12,
        }
    }
}

impl Default for Plaintext {
    fn default() -> Self {
        Plaintext {
            bytes: [0u8; Plaintext::ENCODED_SIZE_BYTES],
            _internal_fp12: Fp12Elem::default(),
        }
    }
}
impl Drop for Plaintext {
    fn drop(&mut self) {
        self.bytes.clear();
        self._internal_fp12.clear();
    }
}
impl BytesDecoder for Plaintext {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES;

    fn decode(bytes: ByteVector) -> std::result::Result<Plaintext, DecodeErr> {
        Ok(Plaintext::from(Fp12Elem::decode(bytes)?))
    }
}

impl Hashable for Plaintext {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// Describes a single transform. Multiple `TransformBlocks` (in series) describe multi-hop transforms.
#[derive(Debug, Clone, Copy)]
pub struct TransformBlock {
    /// public key corresponding to private key used to encrypt the temp key.
    public_key: PublicKey,
    /// random value generated for the transform key and encrypted to the delegatee. Copied from the parent `TransformKey`
    encrypted_temp_key: EncryptedTempKey,
    /// public key corresponding to the private key used to encrypt the random re-encryption `encrypted_random_transform_temp_key`
    random_transform_public_key: PublicKey,
    /// encrypted temp key value. Used to go from the transformed value to the encrypted value
    encrypted_random_transform_temp_key: EncryptedTempKey,
    _internal_re_block: internal::ReencryptionBlock<Fp480>,
}

impl TransformBlock {
    /// Construct TransformBlock from constituent parts.
    /// - `public_key`                    - public key corresponding to private key used to encrypt the temp key
    /// - `encrypted_temp_key`            - random value generated for the transform key and encrypted to the delegatee. Copied from the parent `TransformKey`
    /// - `random_transform_public_key`   - public key corresponding to the private key used to encrypt the random re-encryption `encrypted_random_transform_temp_key`
    /// - `encrypted_random_transform_temp_key` - encrypted temp key value. Used to go from the transformed value to the encrypted value
    pub fn new(
        public_key: &PublicKey,
        encrypted_temp_key: &EncryptedTempKey,
        random_transform_public_key: &PublicKey,
        encrypted_random_transform_temp_key: &EncryptedTempKey,
    ) -> Result<TransformBlock> {
        let re_block_internal = internal::ReencryptionBlock {
            public_key: public_key._internal_key,
            encrypted_temp_key: encrypted_temp_key._internal_fp12,
            rand_re_public_key: random_transform_public_key._internal_key,
            encrypted_rand_re_temp_key: encrypted_random_transform_temp_key._internal_fp12,
        };
        TransformBlock::try_from(re_block_internal)
    }
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn encrypted_temp_key(&self) -> &EncryptedTempKey {
        &self.encrypted_temp_key
    }
    pub fn random_transform_public_key(&self) -> &PublicKey {
        &self.random_transform_public_key
    }
    pub fn encrypted_random_transform_temp_key(&self) -> &EncryptedTempKey {
        &self.encrypted_random_transform_temp_key
    }

    fn try_from(re_block: internal::ReencryptionBlock<Fp480>) -> Result<Self> {
        Ok(TransformBlock {
            public_key: PublicKey::try_from(&re_block.public_key)?,
            encrypted_temp_key: EncryptedTempKey::from_fp12(re_block.encrypted_temp_key),
            random_transform_public_key: PublicKey::try_from(&re_block.rand_re_public_key)?,
            encrypted_random_transform_temp_key: EncryptedTempKey::from_fp12(
                re_block.encrypted_rand_re_temp_key,
            ),
            _internal_re_block: re_block,
        })
    }
}
/// Encrypted value that is either initially encrypted or one that has been
/// transformed one or more times
#[derive(Debug, Clone)] //cannot derive Copy because of NonEmptyVec
pub enum EncryptedValue {
    /// Value which has been encrypted, but not transformed
    /// `ephemeral_public_key`  - public key of the ephemeral private key that was used to encrypt
    /// `encrypted_message`     - encrypted symmetric key
    /// `auth_hash`             - authentication hash for the Plaintext
    /// `public_signing_key`    - public portion of Ed25519 signing key
    /// `signature`             - Ed25519-produced signature
    EncryptedOnceValue {
        ephemeral_public_key: PublicKey,
        encrypted_message: EncryptedMessage,
        auth_hash: AuthHash,
        public_signing_key: PublicSigningKey,
        signature: Ed25519Signature,
    },
    /// Value which has been encrypted and then transformed n times for n > 0.
    /// `ephemeral_public_key`  - public key of the ephemeral private key that was used to encrypt
    /// `encrypted_message`     - encrypted symmetric key
    /// `auth_hash`             - authentication hash for the Plaintext
    /// `transform_blocks`      - information used in transformation process. One entry for each transform.
    /// `public_signing_key`    - public portion of Ed25519 signing key
    /// `signature`             - Ed25519-produced signature
    TransformedValue {
        ephemeral_public_key: PublicKey,
        encrypted_message: EncryptedMessage,
        auth_hash: AuthHash,
        transform_blocks: NonEmptyVec<TransformBlock>,
        public_signing_key: PublicSigningKey,
        signature: Ed25519Signature,
    },
}

impl EncryptedValue {
    fn try_from(
        signed_value: internal::SignedValue<internal::EncryptedValue<Fp480>>,
    ) -> Result<EncryptedValue> {
        use crate::api_480::EncryptedValue as EncryptedValueP;

        match signed_value.payload {
            internal::EncryptedValue::EncryptedOnce(internal::EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
            }) => {
                let result = EncryptedValueP::EncryptedOnceValue {
                    ephemeral_public_key: PublicKey::try_from(&ephemeral_public_key)?,
                    encrypted_message: EncryptedMessage::new(encrypted_message.to_bytes_fp480()),
                    auth_hash: AuthHash::new(auth_hash.bytes),
                    public_signing_key: signed_value.public_signing_key,
                    signature: signed_value.signature,
                };
                Ok(result)
            }
            internal::EncryptedValue::Reencrypted(internal::ReencryptedValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                encryption_blocks,
            }) => {
                let maybe_first_block = TransformBlock::try_from(*encryption_blocks.first());
                let maybe_transform_blocks_rest: Result<Vec<TransformBlock>> = encryption_blocks
                    .rest()
                    .iter()
                    .map(|re_block| TransformBlock::try_from(*re_block))
                    .collect();
                match (maybe_first_block, maybe_transform_blocks_rest) {
                    (Ok(good_first), Ok(good_rest)) => {
                        let result = EncryptedValueP::TransformedValue {
                            ephemeral_public_key: PublicKey::try_from(&ephemeral_public_key)?,
                            encrypted_message: EncryptedMessage::new(
                                encrypted_message.to_bytes_fp480(),
                            ),
                            auth_hash: AuthHash::new(auth_hash.bytes),
                            transform_blocks: NonEmptyVec::new(good_first, good_rest),
                            public_signing_key: signed_value.public_signing_key,
                            signature: signed_value.signature,
                        };
                        Ok(result)
                    }
                    (Err(e), _) => Err(e),
                    (_, Err(e)) => Err(e),
                }
            }
        }
    }

    /// Convert an EncryptedValue into the internal API's SignedValue.
    ///
    /// This is defined here instead of in the internal api to give more efficient access
    /// to the Public API's PublickKey
    fn try_into(
        ev: EncryptedValue,
    ) -> std::result::Result<
        internal::SignedValue<internal::EncryptedValue<Fp480>>,
        internal::bytedecoder::DecodeErr,
    > {
        match ev {
            EncryptedValue::EncryptedOnceValue {
                ephemeral_public_key: pub_key,
                encrypted_message:
                    EncryptedMessage {
                        bytes: encrypted_message,
                    },
                auth_hash,
                public_signing_key,
                signature,
            } => {
                let fp12 = Fp12Elem::<Fp480>::decode(encrypted_message.to_vec())?;
                Ok(internal::SignedValue::<internal::EncryptedValue<Fp480>> {
                    public_signing_key,
                    signature,
                    payload: internal::EncryptedValue::EncryptedOnce(
                        internal::EncryptedOnceValue {
                            ephemeral_public_key: pub_key._internal_key,
                            encrypted_message: fp12,
                            auth_hash: internal::AuthHash {
                                bytes: auth_hash.bytes,
                            },
                        },
                    ),
                })
            }
            EncryptedValue::TransformedValue {
                ephemeral_public_key: pub_key,
                encrypted_message:
                    EncryptedMessage {
                        bytes: encrypted_message,
                    },
                auth_hash,
                transform_blocks,
                public_signing_key,
                signature,
            } => {
                let fp12 = Fp12Elem::<Fp480>::decode(encrypted_message.to_vec())?;
                let first_block = transform_blocks.first()._internal_re_block;
                let rest_blocks = transform_blocks
                    .rest()
                    .iter()
                    .map(|tb| tb._internal_re_block)
                    .collect();
                Ok(internal::SignedValue::<internal::EncryptedValue<Fp480>> {
                    public_signing_key,
                    signature,
                    payload: internal::EncryptedValue::Reencrypted(internal::ReencryptedValue {
                        ephemeral_public_key: pub_key._internal_key,
                        encrypted_message: fp12,
                        auth_hash: internal::AuthHash {
                            bytes: auth_hash.bytes,
                        },
                        encryption_blocks: NonEmptyVec::new(first_block, rest_blocks),
                    }),
                })
            }
        }
    }
}

/// Random Fp12, encrypted to the delegatee. Used to unroll transforms.
#[derive(Clone, Copy)]
pub struct EncryptedTempKey {
    bytes: [u8; EncryptedTempKey::ENCODED_SIZE_BYTES],
    _internal_fp12: Fp12Elem<Fp480>,
}

impl Hashable for EncryptedTempKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl EncryptedTempKey {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES;

    fn from_fp12(fp12: Fp12Elem<Fp480>) -> Self {
        EncryptedTempKey {
            bytes: fp12.to_bytes_fp480(),
            _internal_fp12: fp12,
        }
    }
    pub fn new(bytes: [u8; EncryptedTempKey::ENCODED_SIZE_BYTES]) -> Self {
        EncryptedTempKey::from_fp12(
            Fp12Elem::<Fp480>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }
    pub fn bytes(&self) -> &[u8; EncryptedTempKey::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    new_from_slice!(EncryptedTempKey);
}

bytes_only_debug!(EncryptedTempKey);

/// A combination of the hash of `EncryptedTempKey` and the `PrivateKey` of the delegator.
/// Used to recover the plaintext from an `EncryptedTempKey`
#[derive(Clone, Copy)]
pub struct HashedValue {
    bytes: [u8; HashedValue::ENCODED_SIZE_BYTES],
    _internal_value: TwistedHPoint<Fp480>,
}

impl Hashable for HashedValue {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl HashedValue {
    const ENCODED_SIZE_BYTES: usize = TwistedHPoint::<Fp480>::ENCODED_SIZE_BYTES;

    pub fn new(bytes: [u8; HashedValue::ENCODED_SIZE_BYTES]) -> Result<Self> {
        Ok(
            TwistedHPoint::<Fp480>::decode(bytes.to_vec()).map(|hpoint| HashedValue {
                bytes,
                _internal_value: hpoint,
            })?,
        )
    }
    pub fn bytes(&self) -> &[u8; HashedValue::ENCODED_SIZE_BYTES] {
        &self.bytes
    }
    pub fn new_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == HashedValue::ENCODED_SIZE_BYTES {
            let mut dest = [0u8; HashedValue::ENCODED_SIZE_BYTES];
            dest.copy_from_slice(bytes);
            Ok(HashedValue::new(dest)?)
        } else {
            Err(ApiErr::InputWrongSize(
                "HashedValue",
                HashedValue::ENCODED_SIZE_BYTES,
            ))
        }
    }
}

bytes_only_debug!(HashedValue);

impl From<TwistedHPoint<Fp480>> for HashedValue {
    fn from(hp: TwistedHPoint<Fp480>) -> Self {
        // convert hashed_k to fixed array.
        // Assume the point is valid (on the curve, etc) since we're coming from internal types
        let src = &hp.to_bytes()[..];
        let mut dest = [0u8; HashedValue::ENCODED_SIZE_BYTES];
        dest.copy_from_slice(src);
        HashedValue {
            bytes: dest,
            _internal_value: hp,
        }
    }
}

/// TransformKeys allow a message encrypted to one public key (the key of the delegator)
/// to be transformed and appear as if it was encrypted to another public key (the key of hte delegatee),
/// or put another way, a TransformKey changes which private_key can decrypt the data.
///
/// TransfomKeys cannot, themselves, decrypt any data!
///
/// `ephemeral_public_key`  - ephemeral key unique to this TransforKey. Key that encrypted the `encrypted_k` value
/// `to_public_key`         - public key of the delagatee
/// `encrypted_k`           - random value K, encrypted to the delegatee; used to un-roll successive levels of multi-hop transform encryption
/// `hashed_k`              - combination of the hash of K and the secret key of the delegator; used to recover K from `encrypted_k`
#[derive(Debug, Clone)] //can't derive Copy because of NonEmptyVec
#[cfg_attr(test, derive(PartialEq))]
pub struct TransformKey {
    ephemeral_public_key: PublicKey,
    to_public_key: PublicKey,
    encrypted_temp_key: EncryptedTempKey,
    hashed_temp_key: HashedValue,
    public_signing_key: PublicSigningKey,
    signature: Ed25519Signature,
    _internal_key: internal::SignedValue<internal::ReencryptionKey<Fp480>>,
}

impl Hashable for TransformKey {
    fn to_bytes(&self) -> ByteVector {
        (
            &self.ephemeral_public_key,
            &self.to_public_key,
            &self.encrypted_temp_key,
            &self.hashed_temp_key,
            &self.public_signing_key,
        )
            .to_bytes()
    }
}

impl TransformKey {
    pub fn ephemeral_public_key(&self) -> &PublicKey {
        &self.ephemeral_public_key
    }
    pub fn to_public_key(&self) -> &PublicKey {
        &self.to_public_key
    }
    pub fn encrypted_temp_key(&self) -> &EncryptedTempKey {
        &self.encrypted_temp_key
    }
    pub fn hashed_temp_key(&self) -> &HashedValue {
        &self.hashed_temp_key
    }
    pub fn public_signing_key(&self) -> &PublicSigningKey {
        &self.public_signing_key
    }
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
    fn try_from_internal(
        re_key: internal::SignedValue<internal::ReencryptionKey<Fp480>>,
    ) -> Result<TransformKey> {
        let result = TransformKey {
            ephemeral_public_key: PublicKey::try_from(&re_key.payload.re_public_key)?,
            to_public_key: PublicKey::try_from(&re_key.payload.to_public_key)?,
            encrypted_temp_key: EncryptedTempKey::from_fp12(re_key.payload.encrypted_k),
            hashed_temp_key: HashedValue::from(re_key.payload.hashed_k),
            public_signing_key: re_key.public_signing_key,
            signature: re_key.signature,
            _internal_key: re_key,
        };
        Ok(result)
    }

    /// Public constructor. See [`TransformKey`].
    pub fn new(
        ephemeral_public_key: PublicKey, //The ephemeral public key who encrypted the value
        to_public_key: PublicKey,        //The person or device that can decrypt the result
        encrypted_temp_key: EncryptedTempKey, //The encrypted K value, which is used to go from the reencrypted value to the encrypted value
        hashed_temp_key: HashedValue,
        public_signing_key: PublicSigningKey,
        signature: Ed25519Signature,
    ) -> TransformKey {
        let reencryption_key = internal::ReencryptionKey {
            re_public_key: ephemeral_public_key._internal_key,
            to_public_key: to_public_key._internal_key,
            encrypted_k: encrypted_temp_key._internal_fp12,
            hashed_k: hashed_temp_key._internal_value,
        };

        let internal_key = internal::SignedValue {
            payload: reencryption_key,
            signature,
            public_signing_key,
        };

        // we can use all the params directly as they are all valid by construction
        TransformKey {
            ephemeral_public_key,
            to_public_key,
            encrypted_temp_key,
            hashed_temp_key,
            public_signing_key,
            signature,
            _internal_key: internal_key,
        }
    }

    ///Augment the TransformKey using private_key. If the private_key the TransformKey was delegating from was unaugmented
    ///this can be used to make the TransformKey useful for delegation.
    pub fn augment(&self, private_key: &PrivateKey) -> Result<TransformKey> {
        let new_internal = self
            ._internal_key
            .payload
            .augment(&private_key.into(), &curve::FP_480_CURVE_POINTS.g1);
        TransformKey::try_from_internal(internal::SignedValue {
            payload: new_internal,
            ..self._internal_key
        })
    }
}

pub trait SchnorrOps {
    ///Create a signature for the message using `priv_key`.
    ///- `priv_key` - The private key which is used to generate the signature.
    ///- `pub_key` the public key which will be used to validate the signature.
    ///- `message` the message to sign.
    fn schnorr_sign<A: Hashable>(
        &mut self,
        priv_key: &PrivateKey,
        pub_key: PublicKey,
        message: &A,
    ) -> SchnorrSignature;

    ///Verify that the message was signed by the matching private key to `pub_key`. Note that if `pub_key` was augmented
    ///the private key used in the augmentation should be passed in as `augmenting_priv_key`.
    /// - `pub_key` - The pub_key that was used in the signing process.
    /// - `augmenting_priv_key` - If the `pub_key` was augmented, pass the private key that was used to augment.
    ///                           None if no augmentation was done.
    /// - `message` - Message that was signed.
    /// - `signature` - The signature that was generated from `schnorr_sign`.
    fn schnorr_verify<A: Hashable>(
        &self,
        pub_key: PublicKey,
        augmenting_priv_key: Option<&PrivateKey>,
        message: &A,
        signature: SchnorrSignature,
    ) -> bool;
}

impl<H: Sha256Hashing, S, CR: rand::RngCore + rand::CryptoRng> SchnorrOps
    for Api480<H, S, RandomBytes<CR>>
{
    fn schnorr_sign<A: Hashable>(
        &mut self,
        priv_key: &PrivateKey,
        pub_key: PublicKey,
        message: &A,
    ) -> SchnorrSignature {
        let k = Fr480::from_rand_no_bias(&mut self.random_bytes);
        self.schnorr_signing
            .sign(priv_key.into(), pub_key._internal_key, message, k)
            .unwrap() //The  curve we're using _cannot_ produce an x value which would be zero, so this can't happen
            .into()
    }

    fn schnorr_verify<A: Hashable>(
        &self,
        pub_key: PublicKey,
        augmenting_priv_key: Option<&PrivateKey>,
        message: &A,
        signature: SchnorrSignature,
    ) -> bool {
        self.schnorr_signing.verify(
            pub_key._internal_key,
            augmenting_priv_key.map(|key| key.into()),
            message,
            signature.into(),
        )
    }
}

pub trait Ed25519Ops {
    ///Generate a signing key pair for use with the `Ed25519Signing` trait.
    fn generate_ed25519_key_pair(&mut self) -> SigningKeypair;
}

impl<H, S, CR: rand::RngCore + rand::CryptoRng> Ed25519Ops for Api480<H, S, RandomBytes<CR>> {
    ///Generate a signing key pair for use with the `Ed25519Signing` trait using the random number generator
    ///used to back the `RandomBytes` struct.
    fn generate_ed25519_key_pair(&mut self) -> SigningKeypair {
        SigningKeypair::new(&mut self.random_bytes.rng)
    }
}

/// Key generation operations
pub trait KeyGenOps {
    /// Compute a `PublicKey` given a `PrivateKey`
    fn compute_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey>;

    /// Generate a random private key.
    ///
    /// Relies on `Api::random_bytes` to generate cryptographically secure random bytes
    fn random_private_key(&mut self) -> PrivateKey;

    /// Generate a public/private keypair.
    ///
    /// Relies on `Api::random_bytes` to generate cryptographically secure random bytes
    fn generate_key_pair(&mut self) -> Result<(PrivateKey, PublicKey)>;

    /// Generate a transform key which is used to delegate to the `to_public_key` from the `from_private_key`.
    ///
    /// # Arguments
    /// - `from_private_key`   - key that can currently decrypt the value. (delegator)
    /// - `to_public_key`      - key that we want to let decrypt the value. (delegatee)
    /// - `from_signing_keypair`  - The signing keypair of the person (or device) who is generating this transform key
    ///
    /// # Return
    /// Key which allows a proxy to compute the transform. See `EncryptOps.transform`.
    ///
    fn generate_transform_key(
        &mut self,
        from_private_key: &PrivateKey,
        to_public_key: PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> KeyGenOps for Api480<H, S, R> {
    fn compute_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey> {
        let pub_key_internal = internal::public_keygen(
            internal::PrivateKey::from(private_key),
            self.curve_points.generator,
        );
        PublicKey::try_from(&pub_key_internal)
    }

    fn random_private_key(&mut self) -> PrivateKey {
        let rand_bytes = self.random_bytes.random_bytes_60();
        PrivateKey::new(rand_bytes)
    }

    fn generate_key_pair(&mut self) -> Result<(PrivateKey, PublicKey)> {
        let priv_key = self.random_private_key();
        let maybe_pub_key = self.compute_public_key(&priv_key);
        maybe_pub_key.map(|pub_key| (priv_key, pub_key))
    }

    fn generate_transform_key(
        &mut self,
        from_private_key: &PrivateKey,
        to_public_key: PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey> {
        let ephem_reencryption_private_key = self.random_private_key();
        let temp_key = internal::KValue(gen_random_fp12(&mut self.random_bytes));
        let reencryption_key = internal::generate_reencryption_key(
            from_private_key._internal_key,
            to_public_key._internal_key,
            ephem_reencryption_private_key._internal_key,
            temp_key,
            signing_keypair,
            &self.curve_points,
            &self.pairing,
            &self.sha_256,
            &self.ed25519,
        );

        TransformKey::try_from_internal(reencryption_key)
    }
}

/// Encrypt, Decrypt, Transform, and supporting operations.
pub trait CryptoOps {
    /// Using the random_bytes, generate a random element of G_T, which is one of the rth roots of unity in FP12.
    ///
    /// What it means to be an rth root (for Fp480):
    /// let curve_order = 6500054969564660373279643874235990574257040605390378638988106296904416679996; (this is "r" -- also defined as the prime for Fr480)
    /// let rth_pow = plaintext.pow(curve_order);
    /// assert_eq!(rth_pow, Fp12Elem::one());
    /// Note that this cannot be implemented here as we do not define a way to do: Fp12.pow(Fp480)
    fn gen_plaintext(&mut self) -> Plaintext;

    /// Convert our plaintext into a DecryptedSymmetricKey by hashing it.
    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey;

    ///Compute the stable hash of a value. This can be used to hash a Plaintext into a symmetric key or to generate a
    ///PrivateKey from a Plaintext which you're encrypting to someone else.
    fn hash_256<T: Hashable>(&self, to_hash: &T) -> [u8; 32];

    /// Encrypt the plaintext to the `to_public_key`.
    ///
    /// # Arguments
    /// - `plaintext`             - value to encrypt.
    /// - `to_public_key`         - identity to encrypt to.
    /// - `signing_keypair`       - signing keypair of the person (or device) who is encrypting this value
    ///
    /// # Return
    /// EncryptedValue which can be decrypted by the matching private key of `to_public_key` or ApiErr.
    fn encrypt(
        &mut self,
        plaintext: &Plaintext,
        to_public_key: PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue>;

    /// Decrypt the value using `private_key`.
    ///
    /// # Arguments
    /// - `encrypted_value` - value we want to decrypt.
    /// - `private_key` - PrivateKey which we want to use to decrypt the EncryptedValue.
    ///
    /// # Return
    /// An error if the key didn't match or something was corrupted in the EncryptedValue, otherwise the recovered plaintext.
    fn decrypt(
        &self,
        encrypted_value: EncryptedValue,
        private_key: &PrivateKey,
    ) -> Result<Plaintext>;

    /// Transform the value `encrypted_value` using the `transform_key`.
    /// The returned value can be decrypted by the private key associated to the `to_public_key` in the `transform_key`.
    ///
    /// The transformed value will be signed using the `private_signing_key` and will embed
    /// the `public_signing_key` into the returned value.
    fn transform(
        &mut self,
        encrypted_value: EncryptedValue,
        transform_key: TransformKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> CryptoOps for Api480<H, S, R> {
    fn gen_plaintext(&mut self) -> Plaintext {
        let rand_fp12 = gen_random_fp12(&mut self.random_bytes);
        Plaintext::from(rand_fp12)
    }

    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey {
        DerivedSymmetricKey::new(self.hash_256(decrypted_value))
    }

    fn hash_256<T: Hashable>(&self, to_hash: &T) -> [u8; 32] {
        self.sha_256.hash(to_hash)
    }

    fn encrypt(
        &mut self,
        plaintext: &Plaintext,
        to_public_key: PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue> {
        //generate a ephemeral private key
        let ephem_private_key = self.random_private_key();
        let plaintext_fp12 = plaintext._internal_fp12;

        let encrypted_value_internal = internal::encrypt(
            to_public_key._internal_key,
            plaintext_fp12,
            internal::PrivateKey::from(ephem_private_key),
            signing_keypair,
            &self.pairing,
            &self.curve_points,
            &self.sha_256,
            &self.ed25519,
        );

        EncryptedValue::try_from(encrypted_value_internal)
    }

    fn decrypt(
        &self,
        encrypted_value: EncryptedValue,
        private_key: &PrivateKey,
    ) -> Result<Plaintext> {
        Ok(internal::decrypt(
            internal::PrivateKey::from(private_key),
            EncryptedValue::try_into(encrypted_value)?,
            &self.pairing,
            &self.curve_points,
            &self.sha_256,
            &self.ed25519,
        )
        .map(Plaintext::from)?)
    }

    fn transform(
        &mut self,
        encrypted_value: EncryptedValue,
        transform_key: TransformKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue> {
        let plaintext = self.gen_plaintext();
        let random_private_key = self.random_private_key();
        EncryptedValue::try_from(internal::reencrypt(
            transform_key._internal_key,
            EncryptedValue::try_into(encrypted_value)?,
            internal::PrivateKey::from(random_private_key),
            plaintext.into(),
            signing_keypair,
            &self.ed25519,
            &self.sha_256,
            &self.curve_points,
            &self.pairing,
        )?)
    }
}

fn gen_random_fp12<R: RandomBytesGen>(random_bytes: &mut R) -> Fp12Elem<Fp480> {
    // generate 12 random Fp values
    internal::gen_rth_root(
        &pairing::Pairing::new(),
        Fp12Elem::create_from_t(
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
            Fp480::from(random_bytes.random_bytes_60()),
        ),
    )
}

/// Wrapper around 60 byte array so what we can add Debug, Eq, etc
#[derive(Clone, Copy)]
struct SixtyBytes([u8; Fp480::ENCODED_SIZE_BYTES]);

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PublicKey {
    x: SixtyBytes,
    y: SixtyBytes,
    _internal_key: internal::PublicKey<Fp480>,
}

impl fmt::Debug for SixtyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0.to_vec())
    }
}

impl fmt::LowerHex for SixtyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_vec()))
    }
}

impl Default for SixtyBytes {
    fn default() -> Self {
        SixtyBytes([0u8; 60])
    }
}

impl Hashable for PublicKey {
    fn to_bytes(&self) -> ByteVector {
        self._internal_key.to_bytes()
    }
}

impl PublicKey {
    pub const ENCODED_SIZE_BYTES: usize = Fp480::ENCODED_SIZE_BYTES * 2;

    fn try_from(internal_key: &internal::PublicKey<Fp480>) -> Result<PublicKey> {
        Ok(internal_key
            .to_byte_vectors_60()
            .map(|(x, y)| PublicKey {
                x: SixtyBytes(x),
                y: SixtyBytes(y),
                _internal_key: *internal_key,
            })
            .ok_or_else(|| internal::homogeneouspoint::PointErr::ZeroPoint)?)
    }

    pub fn new(
        (x_bytes, y_bytes): (
            [u8; Fp480::ENCODED_SIZE_BYTES],
            [u8; Fp480::ENCODED_SIZE_BYTES],
        ),
    ) -> Result<PublicKey> {
        let x = Fp480::from(x_bytes);
        let y = Fp480::from(y_bytes);
        let i_pk = internal::PublicKey::from_x_y(x, y)?;
        PublicKey::try_from(&i_pk)
    }

    pub fn new_from_slice(bytes: (&[u8], &[u8])) -> Result<Self> {
        if bytes.0.len() == Fp480::ENCODED_SIZE_BYTES && bytes.1.len() == Fp480::ENCODED_SIZE_BYTES
        {
            let mut x_dest = [0u8; Fp480::ENCODED_SIZE_BYTES];
            x_dest.copy_from_slice(bytes.0);
            let mut y_dest = [0u8; Fp480::ENCODED_SIZE_BYTES];
            y_dest.copy_from_slice(bytes.1);

            Ok(PublicKey::new((x_dest, y_dest))?)
        } else {
            Err(ApiErr::InputWrongSize(
                "PublicKey",
                PublicKey::ENCODED_SIZE_BYTES,
            ))
        }
    }
    pub fn bytes_x_y(
        &self,
    ) -> (
        &[u8; Fp480::ENCODED_SIZE_BYTES],
        &[u8; Fp480::ENCODED_SIZE_BYTES],
    ) {
        (&self.x.0, &self.y.0)
    }

    ///Augment the PublicKey so that messages encrypted to that key cannot be decrypted by this PublicKey's PrivateKey.
    ///This can be useful if you want to force delegation via transform. See `TransformKey.augment`.
    ///Note that by augmenting a PublicKey you're committing to augmenting all `TransformKeys` that are created from
    ///this keypair. Otherwise the transformed data will not be able to be correctly decrypted.
    pub fn augment(&self, other: &PublicKey) -> Result<PublicKey> {
        let new_point = self._internal_key.value + other._internal_key.value;
        PublicKey::try_from(&internal::PublicKey::new(new_point))
    }
}

#[derive(Default, Debug)]
#[cfg_attr(test, derive(PartialEq))] // derive PartialEq only for the tests
pub struct PrivateKey {
    bytes: SixtyBytes,
    _internal_key: internal::PrivateKey<Fp480>,
}

impl PrivateKey {
    const ENCODED_SIZE_BYTES: usize = Fp480::ENCODED_SIZE_BYTES;

    pub fn bytes(&self) -> &[u8; PrivateKey::ENCODED_SIZE_BYTES] {
        &self.bytes.0
    }

    pub fn new(bytes: [u8; PrivateKey::ENCODED_SIZE_BYTES]) -> PrivateKey {
        let internal_key = internal::PrivateKey::from_fp480(Fp480::from(bytes));
        PrivateKey {
            bytes: SixtyBytes(internal_key.value.to_bytes_60()),
            _internal_key: internal_key,
        }
    }

    new_from_slice!(PrivateKey);
}
impl Hashable60 for PrivateKey {
    fn to_bytes_60(&self) -> [u8; 60] {
        self.bytes.0
    }
}

impl Hashable for PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_60().to_vec()
    }
}

impl From<internal::PrivateKey<Fp480>> for PrivateKey {
    fn from(internal_pk: internal::PrivateKey<Fp480>) -> Self {
        PrivateKey {
            bytes: SixtyBytes(internal_pk.value.to_bytes_60()),
            _internal_key: internal_pk,
        }
    }
}

// use Drop to call clear on members of PrivateKey to zero memory before moving the stack pointer
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.bytes.clear();
        self._internal_key.clear()
    }
}
new_bytes_type!(SchnorrSignature, 120);

impl From<internal::schnorr::SchnorrSignature<Fr480>> for SchnorrSignature {
    fn from(internal: internal::schnorr::SchnorrSignature<Fr480>) -> Self {
        SchnorrSignature::new(internal::array_concat_60(
            &internal.r().to_bytes_60(),
            &internal.s().to_bytes_60(),
        ))
    }
}

impl From<SchnorrSignature> for internal::schnorr::SchnorrSignature<Fr480> {
    fn from(sig: SchnorrSignature) -> Self {
        let (r_bytes, s_bytes) = internal::array_split_120(&sig.bytes);
        internal::schnorr::SchnorrSignature::new(Fr480::from(r_bytes), Fr480::from(s_bytes))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::internal::ed25519;
    use crate::internal::fp::fp480_unsafe_from;
    use hex;
    use rand_chacha;

    impl PartialEq for Plaintext {
        // only derive for tests
        fn eq(&self, other: &Plaintext) -> bool {
            self.bytes[..] == other.bytes[..] && self._internal_fp12 == other._internal_fp12
        }
    }
    impl PartialEq for HashedValue {
        fn eq(&self, other: &HashedValue) -> bool {
            self.bytes[..] == other.bytes[..] && self._internal_value == other._internal_value
        }
    }
    impl PartialEq for EncryptedTempKey {
        fn eq(&self, other: &EncryptedTempKey) -> bool {
            self.bytes[..] == other.bytes[..] && self._internal_fp12 == other._internal_fp12
        }
    }
    impl PartialEq for SixtyBytes {
        fn eq(&self, other: &SixtyBytes) -> bool {
            self.0[..] == other.0[..]
        }
    }

    impl Eq for SixtyBytes {}
    pub struct DummyEd25519;
    impl Ed25519Signing for DummyEd25519 {
        fn sign<T: Hashable>(&self, _t: &T, _signing_keypair: &SigningKeypair) -> Ed25519Signature {
            Ed25519Signature::new([0; 64])
        }

        fn verify<T: Hashable>(
            &self,
            _t: &T,
            _signature: &Ed25519Signature,
            _public_key: &PublicSigningKey,
        ) -> bool {
            true
        }
    }

    #[derive(Default)]
    pub(crate) struct DummyRandomBytes;
    impl RandomBytesGen for DummyRandomBytes {
        fn random_bytes_32(&mut self) -> [u8; 32] {
            [std::u8::MAX; 32]
        }

        fn random_bytes_60(&mut self) -> [u8; 60] {
            [std::u8::MAX; 60]
        }
    }

    fn api_with<R: RandomBytesGen + Default, S: Ed25519Signing>(
        random_bytes: Option<R>,
        ed25519: S,
    ) -> Api480<Sha256, S, R> {
        let api = Api480::new();
        Api480 {
            random_bytes: random_bytes.unwrap_or_default(),
            sha_256: api.sha_256,
            ed25519,
            pairing: api.pairing,
            curve_points: api.curve_points,
            schnorr_signing: internal::schnorr::SchnorrSign::<Fp480, Fr480, Sha256>::new_480(),
        }
    }

    #[test]
    fn schnorr_signing_roundtrip_augmented() {
        let mut api = Api480::new();
        let (private_key, pub_key) = api.generate_key_pair().unwrap();
        let (aug_private_key, aug_pub_key) = api.generate_key_pair().unwrap();
        let message = vec![1u8, 2u8];
        let augmented_pub = pub_key.augment(&aug_pub_key).unwrap();
        let sig = api.schnorr_sign(&private_key, augmented_pub, &message);
        let result = api.schnorr_verify(augmented_pub, Some(&aug_private_key), &message, sig);
        assert!(result);
    }
    #[test]
    fn schnorr_signing_roundtrip_unaugmented() {
        let mut api = Api480::new();
        let (private_key, pub_key) = api.generate_key_pair().unwrap();
        let message = vec![1u8, 2u8, 3u8, 4u8];
        let sig = api.schnorr_sign(&private_key, pub_key, &message);
        let result = api.schnorr_verify(pub_key, None, &message, sig);
        assert!(result);
    }

    #[test]
    fn public_key_roundtrip_with_internal() {
        let (_, pub_key_api) = Api480::new().generate_key_pair().unwrap();

        let internal_pk = pub_key_api._internal_key;
        let roundtrip = PublicKey::try_from(&internal_pk).unwrap();

        assert_eq!(pub_key_api, roundtrip)
    }

    #[test]
    fn private_key_roundtrip_with_internal() {
        let (priv_key_api, _) = Api480::new().generate_key_pair().unwrap();

        let internal_pk = internal::PrivateKey::<Fp480>::from(&priv_key_api);
        let roundtrip = PrivateKey::from(internal_pk);

        assert_eq!(priv_key_api, roundtrip);
        assert_eq!(internal_pk, priv_key_api._internal_key)
    }

    #[test]
    fn gen_plaintext_len() {
        let api = &mut Api480::new();

        let result = api.gen_plaintext();
        assert_eq!(Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES, result.bytes.len());
    }

    #[test]
    fn test_generate_key_pair_max_private_key() {
        let mut api = api_with(Some(DummyRandomBytes), DummyEd25519);
        let (_, pub_key) = api.generate_key_pair().unwrap();
        let internal_pk = internal::PublicKey::from_x_y(
            fp480_unsafe_from("b4ba49325c3450b8fe080cf8617223b9c40fe9e45e522ccc198df68b68fb937ceb2eb976fb74e9b531853ac1a68c32c000b3696673b09553914d6d98"),
            fp480_unsafe_from("7781287474854f030c553e5ade3511659ec9969743d28b91d1322a8b798297127b26f7ad3b3314cfa79b7b0bfedb050df5773b96e2a1fffceab2b3fd"),
        )
        .unwrap();
        let expected_pub_key = PublicKey::try_from(&internal_pk).unwrap();
        assert_eq!(expected_pub_key, pub_key)
    }

    #[test]
    fn test_handle_zero_point() {
        let mut api = api_with(Some(TestZeroBytes), DummyEd25519);
        assert!(api.generate_key_pair().is_err())
    }

    #[derive(Default)]
    struct TestZeroBytes;
    impl RandomBytesGen for TestZeroBytes {
        fn random_bytes_32(&mut self) -> [u8; 32] {
            unimplemented!() // not needed for 480
        }

        fn random_bytes_60(&mut self) -> [u8; 60] {
            [0u8; 60]
        }
    }

    fn good_transform_key() -> TransformKey {
        let mut api = Api480::new();
        let signing_key = ed25519::test::good_signing_keypair();
        let (master_priv, master_pub) = api.generate_key_pair().unwrap();
        api.generate_transform_key(&master_priv, master_pub, &signing_key)
            .unwrap()
    }

    #[test]
    fn roundtrip_hashedvalue() {
        let tk = good_transform_key();
        let hashedvalue = tk.hashed_temp_key;
        assert_eq!(
            tk._internal_key.payload.hashed_k,
            TwistedHPoint::<Fp480>::decode(hashedvalue.bytes.to_vec()).unwrap()
        )
    }

    #[test]
    fn roundtrip_encrypted_temp_key() {
        let tk = good_transform_key();
        let etk = tk.encrypted_temp_key;
        assert_eq!(
            tk._internal_key.payload.encrypted_k,
            Fp12Elem::decode(etk.bytes.to_vec()).unwrap()
        )
    }

    #[test]
    fn roundtrip_transform_block() {
        let mut api = Api480::new();
        let pub_key1 = api.generate_key_pair().unwrap().1;
        let pub_key2 = api.generate_key_pair().unwrap().1;
        let ee1 = EncryptedTempKey::new(api.gen_plaintext().bytes);
        let ee2 = EncryptedTempKey::new(api.gen_plaintext().bytes);

        let tb = TransformBlock::new(&pub_key1, &ee1, &pub_key2, &ee2).unwrap();
        assert_eq!(pub_key1, tb.public_key);
        assert_eq!(ee1, tb.encrypted_temp_key);
        assert_eq!(pub_key2, tb.random_transform_public_key);
        assert_eq!(ee2, tb.encrypted_random_transform_temp_key);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<()> {
        use rand::SeedableRng;
        let mut api = Api480::new_with_rand(rand_chacha::ChaChaRng::from_seed([0u8; 32]));
        let pt = api.gen_plaintext();
        let (priv_key, pub_key) = api.generate_key_pair().unwrap();
        let priv_signing_key = api.generate_ed25519_key_pair();

        let encrypted_val = api.encrypt(&pt, pub_key, &priv_signing_key).unwrap();

        let decrypted_val = api.decrypt(encrypted_val, &priv_key).unwrap();

        // compare the bytes as a vec as Plaintext and [u8; 384] don't define Eq
        assert_eq!(pt.bytes.to_vec(), decrypted_val.bytes.to_vec());
        Ok(())
    }

    use std::default::Default;
    #[test]
    fn transform_to_same_key() {
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);
        let signing_key = ed25519::test::good_signing_keypair();

        let plaintext = api.gen_plaintext();
        let (master_priv, master_pub) = api.generate_key_pair().unwrap();
        let enc_value = api.encrypt(&plaintext, master_pub, &signing_key).unwrap();
        let master_to_master_transform_key = api
            .generate_transform_key(&master_priv, master_pub, &signing_key)
            .unwrap();
        let transformed_value = api
            .transform(enc_value, master_to_master_transform_key, &signing_key)
            .unwrap();
        let decrypted_plaintext = api.decrypt(transformed_value, &master_priv).unwrap();
        assert_eq!(plaintext, decrypted_plaintext)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_unaugmented_keys() {
        let signing_key = ed25519::test::good_signing_keypair();
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);

        let pt = api.gen_plaintext();
        let (master_private_key, master_public_key) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let encrypted_msg = api.encrypt(&pt, master_public_key, &signing_key).unwrap();
        let master_to_device_transform_key = api
            .generate_transform_key(&master_private_key, device_public_key, &signing_key)
            .unwrap();

        let transformed_msg = api
            .transform(encrypted_msg, master_to_device_transform_key, &signing_key)
            .unwrap();
        let decrypted_pt = api.decrypt(transformed_msg, &device_private_key).unwrap();

        assert_eq!(pt, decrypted_pt)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_augmented_keys() {
        let mut api = Api480::new();
        let signing_key = api.generate_ed25519_key_pair();
        let pt = api.gen_plaintext();
        let (master_private_key, client_generated_pub) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let (server_private, server_public) = api.generate_key_pair().unwrap();
        let master_public_key = client_generated_pub.augment(&server_public).unwrap();
        let encrypted_msg = api.encrypt(&pt, master_public_key, &signing_key).unwrap();
        let master_to_device_transform_key = api
            .generate_transform_key(&master_private_key, device_public_key, &signing_key)
            .unwrap();
        let augmented_transform_key = master_to_device_transform_key
            .augment(&server_private)
            .unwrap();
        let transformed_msg = api
            .transform(encrypted_msg, augmented_transform_key, &signing_key)
            .unwrap();
        let decrypted_pt = api.decrypt(transformed_msg, &device_private_key).unwrap();

        assert_eq!(pt, decrypted_pt)
    }

    #[test]
    fn two_level_transform_roundtrip() {
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);
        let signing_key = api.generate_ed25519_key_pair();

        let pt = api.gen_plaintext();
        let (group_master_private_key, group_master_public_key) = api.generate_key_pair().unwrap();
        let (user_master_private_key, user_master_public_key) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let encrypted_msg = api
            .encrypt(&pt, group_master_public_key, &signing_key)
            .unwrap();

        // now create two transform keys. Group -> User -> Device (arrows are the transform keys)
        let group_to_user_transform_key = api
            .generate_transform_key(
                &group_master_private_key,
                user_master_public_key,
                &signing_key,
            )
            .unwrap();

        let user_to_device_transform_key = api
            .generate_transform_key(&user_master_private_key, device_public_key, &signing_key)
            .unwrap();

        let transformed_to_user = api
            .transform(encrypted_msg, group_to_user_transform_key, &signing_key)
            .unwrap();
        let transformed_to_device = api
            .transform(
                transformed_to_user,
                user_to_device_transform_key,
                &signing_key,
            )
            .unwrap();
        let decrypted_result = api
            .decrypt(transformed_to_device, &device_private_key)
            .unwrap();

        assert_eq!(pt, decrypted_result)
    }

    #[test]
    //written against AuthHash, but valid for all types generated from that macro
    fn new_byte_type_from_slice() {
        let input: [u8; 32] = [42u8; 32];
        let slice: &[u8] = &input;
        let auth_hash_from_fixed = AuthHash::new(input);
        let auth_hash_from_slice = AuthHash::new_from_slice(slice);

        assert_eq!(auth_hash_from_fixed, auth_hash_from_slice.unwrap());

        assert_eq!(
            ApiErr::InputWrongSize("AuthHash", 32),
            AuthHash::new_from_slice(&input[..30]).unwrap_err()
        )
    }

    #[test]
    fn hashedvalue_new_from_slice() {
        let input: [u8; 240] = good_transform_key().hashed_temp_key.bytes;
        let slice: &[u8] = &input;
        let hv_from_fixed = HashedValue::new(input);
        let hv_from_slice = HashedValue::new_from_slice(slice);

        assert_eq!(hv_from_fixed.unwrap(), hv_from_slice.unwrap());

        assert_eq!(
            ApiErr::InputWrongSize("HashedValue", 240),
            HashedValue::new_from_slice(&input[..30]).unwrap_err()
        )
    }
    #[test]
    fn publickey_new_from_slice() {
        let mut api = Api480::new();
        let (_, pk1) = api.generate_key_pair().unwrap();
        let input = (pk1.x.0, pk1.y.0);
        let slice: (&[u8], &[u8]) = (&input.0, &input.1);
        let pk_from_fixed = PublicKey::new(input);
        let pk_from_slice = PublicKey::new_from_slice(slice);

        assert_eq!(pk_from_fixed.unwrap(), pk_from_slice.unwrap());

        assert_eq!(
            ApiErr::InputWrongSize("PublicKey", 120),
            PublicKey::new_from_slice((&input.0[..30], &input.1[..32])).unwrap_err()
        )
    }

    // note that this doesn't show that Drop is working properly, just that clear does
    #[test]
    fn private_key_clear() {
        let (mut priv_key, _) = Api480::new().generate_key_pair().unwrap();
        priv_key.clear();
        assert_eq!(SixtyBytes(priv_key.bytes().clone()), SixtyBytes([0u8; 60]));
        assert_eq!(priv_key._internal_key, Default::default())
    }
}
