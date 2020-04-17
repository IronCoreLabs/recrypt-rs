pub use crate::api_common::DefaultRng;
use crate::api_common::RecryptErr;
use crate::api_common::Result;
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
use derivative::Derivative;
use gridiron::fp_480::Fp480;
use gridiron::fp_480::Monty as Monty480;
use rand;
use rand::rngs::adapter::ReseedingRng;
use rand::SeedableRng;
use std;
use std::fmt;
// Optional serde for PrivateKey and PublicKey structs
use serde_big_array::big_array;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};
/// Recrypt public API - 480-bit
/// If you are looking better performance, you might consider the 256-bit API in `api.rs`
#[derive(Debug)]
pub struct Recrypt480<H, S, R> {
    random_bytes: R,
    sha_256: H,
    ed25519: S,
    pairing: internal::pairing::Pairing<Monty480>,
    curve_points: &'static internal::curve::CurvePoints<Monty480>,
    schnorr_signing: SchnorrSign<Monty480, Fr480, H>,
}

impl Recrypt480<Sha256, Ed25519, RandomBytes<DefaultRng>> {
    /// Construct a new Recrypt480 with pre-selected CSPRNG implementation.
    ///
    /// The RNG will periodically reseed itself from the system's best entropy source.
    pub fn new() -> Recrypt480<Sha256, Ed25519, RandomBytes<DefaultRng>> {
        // 2 MB
        const BYTES_BEFORE_RESEEDING: u64 = 2 * 1024 * 1024;
        Recrypt480::new_with_rand(ReseedingRng::new(
            rand_chacha::ChaChaCore::from_entropy(),
            BYTES_BEFORE_RESEEDING,
            rand::rngs::OsRng::default(),
        ))
    }
}

impl Default for Recrypt480<Sha256, Ed25519, RandomBytes<DefaultRng>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<CR: rand::CryptoRng + rand::RngCore> Recrypt480<Sha256, Ed25519, RandomBytes<CR>> {
    /// Construct a Recrypt480 with the given RNG. Unless you have specific needs using `new()` is recommended.
    pub fn new_with_rand(r: CR) -> Recrypt480<Sha256, Ed25519, RandomBytes<CR>> {
        let pairing = pairing::Pairing::new();
        let curve_points = &*curve::FP_480_CURVE_POINTS;
        let schnorr_signing = internal::schnorr::SchnorrSign::<Monty480, Fr480, Sha256>::new_480();
        Recrypt480 {
            random_bytes: RandomBytes::new(r),
            sha_256: Sha256,
            ed25519: Ed25519,
            pairing,
            curve_points,
            schnorr_signing,
        }
    }
}

// Hashed but not encrypted Plaintext used for envelope encryption
new_bytes_type_no_copy!(DerivedSymmetricKey, 32);

// A value included in an encrypted message that can be used when the message is decrypted
// to ensure that you got the same value out as the one that was originally encrypted.
// It is a hash of the plaintext.
new_bytes_type!(AuthHash, 32);

// Encrypted Plaintext (Fp12Elem)
new_bytes_type!(EncryptedMessage, Fp12Elem::<Monty480>::ENCODED_SIZE_BYTES);

// Not hashed, not encrypted Fp12Elem
// See DecryptedSymmetricKey and EncryptedMessage
#[derive(Clone)]
pub struct Plaintext {
    bytes: [u8; Plaintext::ENCODED_SIZE_BYTES],
    _internal_fp12: Fp12Elem<Monty480>,
}

impl Plaintext {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty480>::ENCODED_SIZE_BYTES;

    /// Construct a Plaintext from raw bytes
    pub fn new(bytes: [u8; Plaintext::ENCODED_SIZE_BYTES]) -> Plaintext {
        // since new takes a fixed size array, we know it is safe to decode the resultant vector
        Plaintext::from(
            Fp12Elem::<Monty480>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }

    new_from_slice!(Plaintext);

    pub fn bytes(&self) -> &[u8; Plaintext::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    pub(crate) fn internal_fp12(&self) -> &Fp12Elem<Monty480> {
        &self._internal_fp12
    }
}

bytes_only_debug!(Plaintext);
bytes_eq_and_hash!(Plaintext);

impl From<Fp12Elem<Monty480>> for Plaintext {
    fn from(fp12: Fp12Elem<Monty480>) -> Self {
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
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty480>::ENCODED_SIZE_BYTES;

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
#[derivative(PartialEq, Eq, Hash)]
#[derive(Derivative, Debug, Clone, Copy)]
pub struct TransformBlock {
    /// public key corresponding to private key used to encrypt the temp key.
    public_key: PublicKey,
    /// random value generated for the transform key and encrypted to the delegatee. Copied from the parent `TransformKey`
    encrypted_temp_key: EncryptedTempKey,
    /// public key corresponding to the private key used to encrypt the random re-encryption `encrypted_random_transform_temp_key`
    random_transform_public_key: PublicKey,
    /// encrypted temp key value. Used to go from the transformed value to the encrypted value
    encrypted_random_transform_temp_key: EncryptedTempKey,
    #[derivative(Hash = "ignore", PartialEq = "ignore")]
    _internal_re_block: internal::ReencryptionBlock<Monty480>,
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

    fn try_from(re_block: internal::ReencryptionBlock<Monty480>) -> Result<Self> {
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
#[derive(Debug, Clone, PartialEq)] //cannot derive Copy because of NonEmptyVec
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
        signed_value: internal::SignedValue<internal::EncryptedValue<Monty480>>,
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
        internal::SignedValue<internal::EncryptedValue<Monty480>>,
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
                let fp12 = Fp12Elem::<Monty480>::decode(encrypted_message.to_vec())?;
                Ok(
                    internal::SignedValue::<internal::EncryptedValue<Monty480>> {
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
                    },
                )
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
                let fp12 = Fp12Elem::<Monty480>::decode(encrypted_message.to_vec())?;
                let first_block = transform_blocks.first()._internal_re_block;
                let rest_blocks = transform_blocks
                    .rest()
                    .iter()
                    .map(|tb| tb._internal_re_block)
                    .collect();
                Ok(
                    internal::SignedValue::<internal::EncryptedValue<Monty480>> {
                        public_signing_key,
                        signature,
                        payload: internal::EncryptedValue::Reencrypted(
                            internal::ReencryptedValue {
                                ephemeral_public_key: pub_key._internal_key,
                                encrypted_message: fp12,
                                auth_hash: internal::AuthHash {
                                    bytes: auth_hash.bytes,
                                },
                                encryption_blocks: NonEmptyVec::new(first_block, rest_blocks),
                            },
                        ),
                    },
                )
            }
        }
    }
}

/// Random Fp12, encrypted to the delegatee. Used to unroll transforms.
#[derive(Clone, Copy)]
pub struct EncryptedTempKey {
    bytes: [u8; EncryptedTempKey::ENCODED_SIZE_BYTES],
    _internal_fp12: Fp12Elem<Monty480>,
}

impl Hashable for EncryptedTempKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl EncryptedTempKey {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty480>::ENCODED_SIZE_BYTES;

    fn from_fp12(fp12: Fp12Elem<Monty480>) -> Self {
        EncryptedTempKey {
            bytes: fp12.to_bytes_fp480(),
            _internal_fp12: fp12,
        }
    }
    pub fn new(bytes: [u8; EncryptedTempKey::ENCODED_SIZE_BYTES]) -> Self {
        EncryptedTempKey::from_fp12(
            Fp12Elem::<Monty480>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }
    pub fn bytes(&self) -> &[u8; EncryptedTempKey::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    new_from_slice!(EncryptedTempKey);
}

bytes_only_debug!(EncryptedTempKey);

bytes_eq_and_hash!(EncryptedTempKey);

/// A combination of the hash of `EncryptedTempKey` and the `PrivateKey` of the delegator.
/// Used to recover the plaintext from an `EncryptedTempKey`
#[derive(Clone, Copy)]
pub struct HashedValue {
    bytes: [u8; HashedValue::ENCODED_SIZE_BYTES],
    _internal_value: TwistedHPoint<Monty480>,
}

impl Hashable for HashedValue {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl HashedValue {
    const ENCODED_SIZE_BYTES: usize = TwistedHPoint::<Monty480>::ENCODED_SIZE_BYTES;

    pub fn new(bytes: [u8; HashedValue::ENCODED_SIZE_BYTES]) -> Result<Self> {
        Ok(
            TwistedHPoint::<Monty480>::decode(bytes.to_vec()).map(|hpoint| HashedValue {
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
            Err(RecryptErr::InputWrongSize(
                "HashedValue",
                HashedValue::ENCODED_SIZE_BYTES,
            ))
        }
    }
}

bytes_only_debug!(HashedValue);
bytes_eq_and_hash!(HashedValue);

impl From<TwistedHPoint<Monty480>> for HashedValue {
    fn from(hp: TwistedHPoint<Monty480>) -> Self {
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
#[derivative(PartialEq, Eq, Hash)]
#[derive(Derivative, Debug, Clone)] //can't derive Copy because of NonEmptyVec
pub struct TransformKey {
    ephemeral_public_key: PublicKey,
    to_public_key: PublicKey,
    encrypted_temp_key: EncryptedTempKey,
    hashed_temp_key: HashedValue,
    public_signing_key: PublicSigningKey,
    signature: Ed25519Signature,
    #[derivative(Hash = "ignore", PartialEq = "ignore")]
    _internal_key: internal::SignedValue<internal::ReencryptionKey<Monty480>>,
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
        re_key: internal::SignedValue<internal::ReencryptionKey<Monty480>>,
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
        &self,
        priv_key: &PrivateKey,
        pub_key: &PublicKey,
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
        pub_key: &PublicKey,
        augmenting_priv_key: Option<&PrivateKey>,
        message: &A,
        signature: SchnorrSignature,
    ) -> bool;
}

impl<H: Sha256Hashing, S, CR: rand::RngCore + rand::CryptoRng> SchnorrOps
    for Recrypt480<H, S, RandomBytes<CR>>
{
    fn schnorr_sign<A: Hashable>(
        &self,
        priv_key: &PrivateKey,
        pub_key: &PublicKey,
        message: &A,
    ) -> SchnorrSignature {
        let k = Fr480::from_rand_no_bias(&self.random_bytes);
        self.schnorr_signing
            .sign(priv_key.into(), pub_key._internal_key, message, k)
            .unwrap() //The  curve we're using _cannot_ produce an x value which would be zero, so this can't happen
            .into()
    }

    fn schnorr_verify<A: Hashable>(
        &self,
        pub_key: &PublicKey,
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
    fn generate_ed25519_key_pair(&self) -> SigningKeypair;
}

impl<H, S, CR: rand::RngCore + rand::CryptoRng> Ed25519Ops for Recrypt480<H, S, RandomBytes<CR>> {
    ///Generate a signing key pair for use with the `Ed25519Signing` trait using the random number generator
    ///used to back the `RandomBytes` struct.
    fn generate_ed25519_key_pair(&self) -> SigningKeypair {
        SigningKeypair::new(&self.random_bytes.rng)
    }
}

/// Key generation operations
pub trait KeyGenOps {
    /// Compute a `PublicKey` given a `PrivateKey`
    fn compute_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey>;

    /// Generate a random private key.
    ///
    /// Relies on `Api::random_bytes` to generate cryptographically secure random bytes
    fn random_private_key(&self) -> PrivateKey;
    /// Generate a public/private keypair.
    ///
    /// Relies on `Api::random_bytes` to generate cryptographically secure random bytes
    fn generate_key_pair(&self) -> Result<(PrivateKey, PublicKey)>;
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
        &self,
        from_private_key: &PrivateKey,
        to_public_key: &PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> KeyGenOps for Recrypt480<H, S, R> {
    fn compute_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey> {
        let pub_key_internal = internal::public_keygen(
            internal::PrivateKey::from(private_key),
            self.curve_points.generator,
        );
        PublicKey::try_from(&pub_key_internal)
    }

    fn random_private_key(&self) -> PrivateKey {
        let rand_bytes = self.random_bytes.random_bytes_60();
        PrivateKey::new(rand_bytes)
    }

    fn generate_key_pair(&self) -> Result<(PrivateKey, PublicKey)> {
        let priv_key = self.random_private_key();
        let maybe_pub_key = self.compute_public_key(&priv_key);
        maybe_pub_key.map(|pub_key| (priv_key, pub_key))
    }

    fn generate_transform_key(
        &self,
        from_private_key: &PrivateKey,
        to_public_key: &PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey> {
        let ephem_reencryption_private_key = self.random_private_key();
        let temp_key = internal::KValue(gen_random_fp12(&self.random_bytes));
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
        )?;

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
    fn gen_plaintext(&self) -> Plaintext;

    /// Convert our plaintext into a DecryptedSymmetricKey by hashing it.
    /// Typically you either use `derive_private_key` or `derive_symmetric_key` but not both.
    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey;

    ///Derive a private key for a plaintext by hashing it twice (with known leading bytes) and modding it by the prime.
    ///Typically you either use `derive_private_key` or `derive_symmetric_key` but not both.
    fn derive_private_key(&self, plaintext: &Plaintext) -> PrivateKey;

    /// Encrypt the plaintext to the `to_public_key`.
    ///
    /// # Arguments
    /// - `plaintext`             - value to encrypt.
    /// - `to_public_key`         - identity to encrypt to.
    /// - `signing_keypair`       - signing keypair of the person (or device) who is encrypting this value
    ///
    /// # Return
    /// EncryptedValue which can be decrypted by the matching private key of `to_public_key` or RecryptErr.
    fn encrypt(
        &self,
        plaintext: &Plaintext,
        to_public_key: &PublicKey,
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
        &self,
        encrypted_value: EncryptedValue,
        transform_key: TransformKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> CryptoOps for Recrypt480<H, S, R> {
    fn gen_plaintext(&self) -> Plaintext {
        let rand_fp12 = gen_random_fp12(&self.random_bytes);
        Plaintext::from(rand_fp12)
    }

    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey {
        DerivedSymmetricKey::new(self.sha_256.hash(decrypted_value))
    }

    fn derive_private_key(&self, plaintext: &Plaintext) -> PrivateKey {
        let mut result_bytes = [0u8; 60];

        //we're defining the mapping of plaintext to private key as 0 and plaintext hashed combined with 1 and plaintext hashed.
        //We then chop it to 60 and let the mod happen in the private key constructor.
        result_bytes[0..28].copy_from_slice(&self.sha_256.hash(&(&0u8, plaintext))[4..]);
        result_bytes[28..60].copy_from_slice(&self.sha_256.hash(&(&1u8, plaintext))[..]);
        PrivateKey::new(result_bytes)
    }

    fn encrypt(
        &self,
        plaintext: &Plaintext,
        to_public_key: &PublicKey,
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
        )?;

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
        &self,
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

fn gen_random_fp12<R: RandomBytesGen>(random_bytes: &R) -> Fp12Elem<Monty480> {
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
        )
        .map(&|fp| fp.to_monty()),
    )
}

/// Wrapper around 60 byte array so what we can add Debug, Eq, etc
big_array! {
    BigArray;
    60,
}
#[derive(Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize, Default),
    serde(crate = "serde_crate")
)]
struct SixtyBytes {
    #[serde(with = "BigArray")]
    arr: [u8; Monty480::ENCODED_SIZE_BYTES],
}

impl SixtyBytes {
    fn bytes(&self) -> &[u8; Monty480::ENCODED_SIZE_BYTES] {
        &self.arr
    }
}

impl fmt::Debug for SixtyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.arr.to_vec())
    }
}

impl fmt::LowerHex for SixtyBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.arr.to_vec()))
    }
}

impl Default for SixtyBytes {
    fn default() -> Self {
        SixtyBytes::default()
    }
}

bytes_eq_and_hash!(SixtyBytes);

#[derive(Derivative, Debug, Clone, Copy)]
#[derivative(PartialEq, Hash, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct PublicKey {
    x: SixtyBytes,
    y: SixtyBytes,
    #[derivative(Hash = "ignore", PartialEq = "ignore")]
    _internal_key: internal::PublicKey<Monty480>,
}

impl Hashable for PublicKey {
    fn to_bytes(&self) -> ByteVector {
        self._internal_key.to_bytes()
    }
}

impl PublicKey {
    pub const ENCODED_SIZE_BYTES: usize = Monty480::ENCODED_SIZE_BYTES * 2;

    fn try_from(internal_key: &internal::PublicKey<Monty480>) -> Result<PublicKey> {
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
            [u8; Monty480::ENCODED_SIZE_BYTES],
            [u8; Monty480::ENCODED_SIZE_BYTES],
        ),
    ) -> Result<PublicKey> {
        let x = Fp480::from(x_bytes).to_monty();
        let y = Fp480::from(y_bytes).to_monty();
        let i_pk = internal::PublicKey::from_x_y(x, y)?;
        PublicKey::try_from(&i_pk)
    }

    pub fn new_from_slice(bytes: (&[u8], &[u8])) -> Result<Self> {
        if bytes.0.len() == Monty480::ENCODED_SIZE_BYTES
            && bytes.1.len() == Monty480::ENCODED_SIZE_BYTES
        {
            let mut x_dest = [0u8; Monty480::ENCODED_SIZE_BYTES];
            x_dest.copy_from_slice(bytes.0);
            let mut y_dest = [0u8; Monty480::ENCODED_SIZE_BYTES];
            y_dest.copy_from_slice(bytes.1);

            Ok(PublicKey::new((x_dest, y_dest))?)
        } else {
            Err(RecryptErr::InputWrongSize(
                "PublicKey",
                PublicKey::ENCODED_SIZE_BYTES,
            ))
        }
    }
    pub fn bytes_x_y(
        &self,
    ) -> (
        &[u8; Monty480::ENCODED_SIZE_BYTES],
        &[u8; Monty480::ENCODED_SIZE_BYTES],
    ) {
        (&self.x.arr, &self.y.arr)
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

#[derive(Default, Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct PrivateKey {
    bytes: SixtyBytes,
    _internal_key: internal::PrivateKey<Monty480>,
}

impl PrivateKey {
    pub const ENCODED_SIZE_BYTES: usize = Monty480::ENCODED_SIZE_BYTES;

    pub fn bytes(&self) -> &[u8; PrivateKey::ENCODED_SIZE_BYTES] {
        &self.bytes.arr
    }

    pub fn new(bytes: [u8; PrivateKey::ENCODED_SIZE_BYTES]) -> PrivateKey {
        let internal_key = internal::PrivateKey::from_fp480(Fp480::from(bytes).to_monty());
        PrivateKey {
            bytes: SixtyBytes(internal_key.value.to_bytes_60()),
            _internal_key: internal_key,
        }
    }

    new_from_slice!(PrivateKey);

    ///Augment the private key with another. This function performs the addition in Fr,
    ///which matches the cycle of the elliptic curve. This allows augmented private keys to line up
    ///correctly with public keys generated from them.
    pub fn augment_plus(&self, other: &PrivateKey) -> PrivateKey {
        PrivateKey::augment(self, other, false)
    }
    ///Augment the private key with another. This function performs the subtraction in Fr,
    ///which matches the cycle of the elliptic curve. This allows augmented private keys to line up
    ///correctly with public keys generated from them.
    pub fn augment_minus(&self, other: &PrivateKey) -> PrivateKey {
        PrivateKey::augment(self, other, true)
    }
    ///Convert the keys to Frs and either add or subtract them, then turn it back into a PrivateKey.
    fn augment(first: &PrivateKey, second: &PrivateKey, subtract: bool) -> PrivateKey {
        let first_fr = Fr480::from(first.bytes.arr[0]);
        let second_fr = Fr480::from(second.bytes.arr[0]);
        let fr_result = if subtract {
            first_fr - second_fr
        } else {
            first_fr + second_fr
        };
        PrivateKey::new(fr_result.to_bytes_60())
    }
}

bytes_eq_and_hash!(PrivateKey);

impl Hashable60 for PrivateKey {
    fn to_bytes_60(&self) -> [u8; 60] {
        self.bytes.arr
    }
}

impl Hashable for PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_60().to_vec()
    }
}

impl From<internal::PrivateKey<Monty480>> for PrivateKey {
    fn from(internal_pk: internal::PrivateKey<Monty480>) -> Self {
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
    use rand_chacha;

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
        fn random_bytes_32(&self) -> [u8; 32] {
            [std::u8::MAX; 32]
        }

        fn random_bytes_60(&self) -> [u8; 60] {
            [std::u8::MAX; 60]
        }
    }

    fn api_with<R: RandomBytesGen + Default, S: Ed25519Signing>(
        random_bytes: Option<R>,
        ed25519: S,
    ) -> Recrypt480<Sha256, S, R> {
        let api = Recrypt480::new();
        Recrypt480 {
            random_bytes: random_bytes.unwrap_or_default(),
            sha_256: api.sha_256,
            ed25519,
            pairing: api.pairing,
            curve_points: api.curve_points,
            schnorr_signing: internal::schnorr::SchnorrSign::<Monty480, Fr480, Sha256>::new_480(),
        }
    }

    #[test]
    fn schnorr_signing_roundtrip_augmented() {
        let api = Recrypt480::new();
        let (private_key, pub_key) = api.generate_key_pair().unwrap();
        let (aug_private_key, aug_pub_key) = api.generate_key_pair().unwrap();
        let message = vec![1u8, 2u8];
        let augmented_pub = pub_key.augment(&aug_pub_key).unwrap();
        let sig = api.schnorr_sign(&private_key, &augmented_pub, &message);
        let result = api.schnorr_verify(&augmented_pub, Some(&aug_private_key), &message, sig);
        assert!(result);
    }
    #[test]
    fn schnorr_signing_roundtrip_unaugmented() {
        let api = Recrypt480::new();
        let (private_key, pub_key) = api.generate_key_pair().unwrap();
        let message = vec![1u8, 2u8, 3u8, 4u8];
        let sig = api.schnorr_sign(&private_key, &pub_key, &message);
        let result = api.schnorr_verify(&pub_key, None, &message, sig);
        assert!(result);
    }

    #[test]
    fn public_key_roundtrip_with_internal() {
        let (_, pub_key_api) = Recrypt480::new().generate_key_pair().unwrap();

        let internal_pk = pub_key_api._internal_key;
        let roundtrip = PublicKey::try_from(&internal_pk).unwrap();

        assert_eq!(pub_key_api, roundtrip)
    }

    #[test]
    fn private_key_roundtrip_with_internal() {
        let (priv_key_api, _) = Recrypt480::new().generate_key_pair().unwrap();

        let internal_pk = internal::PrivateKey::<Monty480>::from(&priv_key_api);
        let roundtrip = PrivateKey::from(internal_pk);

        assert_eq!(priv_key_api, roundtrip);
        assert_eq!(internal_pk, priv_key_api._internal_key)
    }

    #[test]
    fn gen_plaintext_len() {
        let api = &mut Recrypt480::new();

        let result = api.gen_plaintext();
        assert_eq!(Fp12Elem::<Monty480>::ENCODED_SIZE_BYTES, result.bytes.len());
    }

    #[test]
    fn test_generate_key_pair_max_private_key() {
        let api = api_with(Some(DummyRandomBytes), DummyEd25519);
        let (_, pub_key) = api.generate_key_pair().unwrap();
        let internal_pk = internal::PublicKey::from_x_y(
            fp480_unsafe_from("b4ba49325c3450b8fe080cf8617223b9c40fe9e45e522ccc198df68b68fb937ceb2eb976fb74e9b531853ac1a68c32c000b3696673b09553914d6d98").to_monty(),
            fp480_unsafe_from("7781287474854f030c553e5ade3511659ec9969743d28b91d1322a8b798297127b26f7ad3b3314cfa79b7b0bfedb050df5773b96e2a1fffceab2b3fd").to_monty(),
        )
        .unwrap();
        let expected_pub_key = PublicKey::try_from(&internal_pk).unwrap();
        assert_eq!(expected_pub_key, pub_key)
    }

    #[test]
    fn test_handle_zero_point() {
        let api = api_with(Some(TestZeroBytes), DummyEd25519);
        assert!(api.generate_key_pair().is_err())
    }

    #[derive(Default)]
    struct TestZeroBytes;
    impl RandomBytesGen for TestZeroBytes {
        fn random_bytes_32(&self) -> [u8; 32] {
            unimplemented!() // not needed for 480
        }

        fn random_bytes_60(&self) -> [u8; 60] {
            [0u8; 60]
        }
    }

    fn good_transform_key() -> TransformKey {
        let api = Recrypt480::new();
        let signing_key = ed25519::test::good_signing_keypair();
        let (master_priv, master_pub) = api.generate_key_pair().unwrap();
        api.generate_transform_key(&master_priv, &master_pub, &signing_key)
            .unwrap()
    }

    #[test]
    fn roundtrip_hashedvalue() {
        let tk = good_transform_key();
        let hashedvalue = tk.hashed_temp_key;
        assert_eq!(
            tk._internal_key.payload.hashed_k,
            TwistedHPoint::<Monty480>::decode(hashedvalue.bytes.to_vec()).unwrap()
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
        let api = Recrypt480::new();
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
        let api = Recrypt480::new_with_rand(rand_chacha::ChaChaRng::from_seed([0u8; 32]));
        let pt = api.gen_plaintext();
        let (priv_key, pub_key) = api.generate_key_pair().unwrap();
        let priv_signing_key = api.generate_ed25519_key_pair();

        let encrypted_val = api.encrypt(&pt, &pub_key, &priv_signing_key).unwrap();

        let decrypted_val = api.decrypt(encrypted_val, &priv_key).unwrap();

        // compare the bytes as a vec as Plaintext and [u8; 384] don't define Eq
        assert_eq!(pt.bytes.to_vec(), decrypted_val.bytes.to_vec());
        Ok(())
    }

    use std::default::Default;
    #[test]
    fn transform_to_same_key() {
        let api = api_with(Some(RandomBytes::default()), DummyEd25519);
        let signing_key = ed25519::test::good_signing_keypair();

        let plaintext = api.gen_plaintext();
        let (master_priv, master_pub) = api.generate_key_pair().unwrap();
        let enc_value = api.encrypt(&plaintext, &master_pub, &signing_key).unwrap();
        let master_to_master_transform_key = api
            .generate_transform_key(&master_priv, &master_pub, &signing_key)
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
        let api = api_with(Some(RandomBytes::default()), DummyEd25519);

        let pt = api.gen_plaintext();
        let (master_private_key, master_public_key) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let encrypted_msg = api.encrypt(&pt, &master_public_key, &signing_key).unwrap();
        let master_to_device_transform_key = api
            .generate_transform_key(&master_private_key, &device_public_key, &signing_key)
            .unwrap();

        let transformed_msg = api
            .transform(encrypted_msg, master_to_device_transform_key, &signing_key)
            .unwrap();
        let decrypted_pt = api.decrypt(transformed_msg, &device_private_key).unwrap();

        assert_eq!(pt, decrypted_pt)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_augmented_keys() {
        let api = Recrypt480::new();
        let signing_key = api.generate_ed25519_key_pair();
        let pt = api.gen_plaintext();
        let (master_private_key, client_generated_pub) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let (server_private, server_public) = api.generate_key_pair().unwrap();
        let master_public_key = client_generated_pub.augment(&server_public).unwrap();
        let encrypted_msg = api.encrypt(&pt, &master_public_key, &signing_key).unwrap();
        let master_to_device_transform_key = api
            .generate_transform_key(&master_private_key, &device_public_key, &signing_key)
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
        let api = api_with(Some(RandomBytes::default()), DummyEd25519);
        let signing_key = api.generate_ed25519_key_pair();

        let pt = api.gen_plaintext();
        let (group_master_private_key, group_master_public_key) = api.generate_key_pair().unwrap();
        let (user_master_private_key, user_master_public_key) = api.generate_key_pair().unwrap();
        let (device_private_key, device_public_key) = api.generate_key_pair().unwrap();
        let encrypted_msg = api
            .encrypt(&pt, &group_master_public_key, &signing_key)
            .unwrap();

        // now create two transform keys. Group -> User -> Device (arrows are the transform keys)
        let group_to_user_transform_key = api
            .generate_transform_key(
                &group_master_private_key,
                &user_master_public_key,
                &signing_key,
            )
            .unwrap();

        let user_to_device_transform_key = api
            .generate_transform_key(&user_master_private_key, &device_public_key, &signing_key)
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
            RecryptErr::InputWrongSize("AuthHash", 32),
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
            RecryptErr::InputWrongSize("HashedValue", 240),
            HashedValue::new_from_slice(&input[..30]).unwrap_err()
        )
    }

    #[test]
    fn derive_private_key_is_known_value() {
        let api = api_with(Some(RandomBytes::default()), DummyEd25519);
        let bytes = hex::decode("a5e480feba36757014d53c9efd823cd69ae0f8a175c1dd8740fa402faaebe6a114fabec5aa4815d20b41ec651df6cb5ab880849b50509234cbae117a6e59eb77959515d01f9f943c70450183c2d72d3b9ec31e65db41fc90978b31f80537f8b77a5a119b83e8f5420837541402ba85d824325b3641f6d3de35c40ea246804db5a68b0d4897b5169488d76d0a32d2006cdf754e15bbfd4813501a2e88fa3beb1a4dcebf4ccf88d8ba9ea0a9f53355fdc8d44b77caca7c73ad939f9e57d3edabb3c3f60328fc2c01b41bcb4cb533a95477107f447e36a12456abf8c550d1ae359d0f7087a16d4528832a3120f28793d2383f2a2574853f19210895d39bf3840ef106729b7fbdff3ba208666c21b657c2fcdae9e9d801dc205922ee25edbdc6b789907b7fb49d41460184e9b570d3ae6c25ee801c2178ed6874c67901d7fbb73838d7433fa9ae7638ce007ed83fb517e5b0bb8b939b22097ff3db80dd647dbfbda0126e1a35270606e1b28936dfcc8decf4992448d567977bda52fbb4d4c147bb73c6aab1195d8f79e4e458141869569e9cee435140cff55224a94b204a4a103ddad3a8082a1665ad7c52cef851a9376efbf07f6310481a04ea49d0a58072f5089db9fdc54022c52b9321b2b10bd94ad1a739ba8fa4f54d3dade5a62c611bcb4362d7dfb8b0913df8d66021a5f2870aa75e334a72a8c77f8dfb0d5e88a5828017289ba62636dbaa95eebda33b79714e594f19dff834510366a89cab27f7d5af4cc496ae109d5eb907cb9386bd126706d963ed9e6d56439e8bbd735f506243aa2e38474cc53c153b37392e5e56b4c271d7182dd4d31395b3c76f0e6ec6fb79cf02498742c265daa98cccab211d0d1eef2e9e7009defd5c5b0fc2e9d6f3c1518fc964cdd98aa019b4b2a1db22f734788f6dcbe6e8b3fdeb9dfea69410c14c039ee6ec4489171f744e2af555773da6886a2a7a3ad5b032b85e91d56d2baf4176004a37a60e6a00b8dc08b99031d316766af541").unwrap();
        let pt = Plaintext::from(Fp12Elem::decode(bytes).unwrap());
        let src = &hex::decode("e8fe0292045bda2a9102749497e24e9502dd00d94670b6990e9aca44b7eed3416888bfba59e19bed709f7309a05e701b3a78dad9abd7764a6d5c4dfe")
            .unwrap()[..];
        let mut dest = [0u8; 60];
        dest.copy_from_slice(src);
        let expected_result = PrivateKey::new(dest);
        assert_eq!(api.derive_private_key(&pt), expected_result);
    }

    #[test]
    fn publickey_new_from_slice() {
        let api = Recrypt480::new();
        let (_, pk1) = api.generate_key_pair().unwrap();
        let input = (pk1.x.0, pk1.y.0);
        let slice: (&[u8], &[u8]) = (&input.0, &input.1);
        let pk_from_fixed = PublicKey::new(input);
        let pk_from_slice = PublicKey::new_from_slice(slice);

        assert_eq!(pk_from_fixed.unwrap(), pk_from_slice.unwrap());

        assert_eq!(
            RecryptErr::InputWrongSize("PublicKey", 120),
            PublicKey::new_from_slice((&input.0[..30], &input.1[..32])).unwrap_err()
        )
    }

    #[test]
    fn private_key_new_from_slice() {
        let rand_bytes = DummyRandomBytes;
        let input: [u8; 60] = rand_bytes.random_bytes_60();
        let slice: &[u8] = &input;
        let from_fixed = PrivateKey::new(input);
        let from_slice = PrivateKey::new_from_slice(slice);

        assert_eq!(from_fixed, from_slice.unwrap());

        assert_eq!(
            RecryptErr::InputWrongSize("PrivateKey", 60),
            PrivateKey::new_from_slice(&input[..59]).unwrap_err()
        )
    }

    // note that this doesn't show that Drop is working properly, just that clear does
    #[test]
    fn private_key_clear() {
        let (mut priv_key, _) = Recrypt480::new().generate_key_pair().unwrap();
        priv_key.clear();
        assert_eq!(SixtyBytes(priv_key.bytes().clone()), SixtyBytes([0u8; 60]));
        assert_eq!(priv_key._internal_key, Default::default())
    }

    #[test]
    fn private_key_augment_plus() {
        let priv_key_sum = PrivateKey::new(Fp480::from(1u8).to_bytes_array())
            .augment_plus(&PrivateKey::new(Fp480::from(2u8).to_bytes_array()));
        assert_eq!(
            priv_key_sum,
            PrivateKey::new((Fr480::from(1u8) + Fr480::from(2u8)).to_bytes_60())
        );
    }

    #[test]
    fn private_key_augment_minus() {
        let priv_key_sum = PrivateKey::new(Fp480::from(1u8).to_bytes_array())
            .augment_minus(&PrivateKey::new(Fp480::from(2u8).to_bytes_array()));
        assert_eq!(
            priv_key_sum,
            PrivateKey::new((Fr480::from(1u8) - Fr480::from(2u8)).to_bytes_60())
        );
    }

    // check the equality functions for private keys, plaintexts, and derived symmetric keys
    #[test]
    fn private_keys_equal() -> Result<()> {
        let priv_key1 = PrivateKey::new_from_slice(&hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )?)?;
        let priv_key2 = PrivateKey::new_from_slice(&hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )?)?;
        assert_eq!(priv_key1, priv_key2);
        Ok(())
    }

    #[test]
    fn private_keys_not_equal() -> Result<()> {
        let priv_key1 = PrivateKey::new_from_slice(&hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )?)?;
        let priv_key2 = PrivateKey::new_from_slice(&hex::decode(
            "ef0123456789abcd0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )?)?;
        assert_ne!(priv_key1, priv_key2);
        Ok(())
    }

    // Also derives symmetric keys from the plaintexts and compares those.
    #[test]
    fn plaintexts_equal() -> Result<()> {
        let pt1 = Plaintext::new_from_slice(&hex::decode("a5e480feba36757014d53c9efd823cd69ae0f8a175c1dd8740fa402faaebe6a114fabec5aa4815d20b41ec651df6cb5ab880849b50509234cbae117a6e59eb77959515d01f9f943c70450183c2d72d3b9ec31e65db41fc90978b31f80537f8b77a5a119b83e8f5420837541402ba85d824325b3641f6d3de35c40ea246804db5a68b0d4897b5169488d76d0a32d2006cdf754e15bbfd4813501a2e88fa3beb1a4dcebf4ccf88d8ba9ea0a9f53355fdc8d44b77caca7c73ad939f9e57d3edabb3c3f60328fc2c01b41bcb4cb533a95477107f447e36a12456abf8c550d1ae359d0f7087a16d4528832a3120f28793d2383f2a2574853f19210895d39bf3840ef106729b7fbdff3ba208666c21b657c2fcdae9e9d801dc205922ee25edbdc6b789907b7fb49d41460184e9b570d3ae6c25ee801c2178ed6874c67901d7fbb73838d7433fa9ae7638ce007ed83fb517e5b0bb8b939b22097ff3db80dd647dbfbda0126e1a35270606e1b28936dfcc8decf4992448d567977bda52fbb4d4c147bb73c6aab1195d8f79e4e458141869569e9cee435140cff55224a94b204a4a103ddad3a8082a1665ad7c52cef851a9376efbf07f6310481a04ea49d0a58072f5089db9fdc54022c52b9321b2b10bd94ad1a739ba8fa4f54d3dade5a62c611bcb4362d7dfb8b0913df8d66021a5f2870aa75e334a72a8c77f8dfb0d5e88a5828017289ba62636dbaa95eebda33b79714e594f19dff834510366a89cab27f7d5af4cc496ae109d5eb907cb9386bd126706d963ed9e6d56439e8bbd735f506243aa2e38474cc53c153b37392e5e56b4c271d7182dd4d31395b3c76f0e6ec6fb79cf02498742c265daa98cccab211d0d1eef2e9e7009defd5c5b0fc2e9d6f3c1518fc964cdd98aa019b4b2a1db22f734788f6dcbe6e8b3fdeb9dfea69410c14c039ee6ec4489171f744e2af555773da6886a2a7a3ad5b032b85e91d56d2baf4176004a37a60e6a00b8dc08b99031d316766af541")?)?;
        let pt2 = Plaintext::new_from_slice(&hex::decode("a5e480feba36757014d53c9efd823cd69ae0f8a175c1dd8740fa402faaebe6a114fabec5aa4815d20b41ec651df6cb5ab880849b50509234cbae117a6e59eb77959515d01f9f943c70450183c2d72d3b9ec31e65db41fc90978b31f80537f8b77a5a119b83e8f5420837541402ba85d824325b3641f6d3de35c40ea246804db5a68b0d4897b5169488d76d0a32d2006cdf754e15bbfd4813501a2e88fa3beb1a4dcebf4ccf88d8ba9ea0a9f53355fdc8d44b77caca7c73ad939f9e57d3edabb3c3f60328fc2c01b41bcb4cb533a95477107f447e36a12456abf8c550d1ae359d0f7087a16d4528832a3120f28793d2383f2a2574853f19210895d39bf3840ef106729b7fbdff3ba208666c21b657c2fcdae9e9d801dc205922ee25edbdc6b789907b7fb49d41460184e9b570d3ae6c25ee801c2178ed6874c67901d7fbb73838d7433fa9ae7638ce007ed83fb517e5b0bb8b939b22097ff3db80dd647dbfbda0126e1a35270606e1b28936dfcc8decf4992448d567977bda52fbb4d4c147bb73c6aab1195d8f79e4e458141869569e9cee435140cff55224a94b204a4a103ddad3a8082a1665ad7c52cef851a9376efbf07f6310481a04ea49d0a58072f5089db9fdc54022c52b9321b2b10bd94ad1a739ba8fa4f54d3dade5a62c611bcb4362d7dfb8b0913df8d66021a5f2870aa75e334a72a8c77f8dfb0d5e88a5828017289ba62636dbaa95eebda33b79714e594f19dff834510366a89cab27f7d5af4cc496ae109d5eb907cb9386bd126706d963ed9e6d56439e8bbd735f506243aa2e38474cc53c153b37392e5e56b4c271d7182dd4d31395b3c76f0e6ec6fb79cf02498742c265daa98cccab211d0d1eef2e9e7009defd5c5b0fc2e9d6f3c1518fc964cdd98aa019b4b2a1db22f734788f6dcbe6e8b3fdeb9dfea69410c14c039ee6ec4489171f744e2af555773da6886a2a7a3ad5b032b85e91d56d2baf4176004a37a60e6a00b8dc08b99031d316766af541")?)?;
        assert_eq!(pt1, pt2);
        let dk1 = Recrypt480::new().derive_symmetric_key(&pt1);
        let dk2 = Recrypt480::new().derive_symmetric_key(&pt2);
        assert_eq!(dk1, dk2);
        Ok(())
    }

    // Also derives symmetric keys from the plaintexts and compares those.
    #[test]
    fn plaintexts_not_equal() -> Result<()> {
        let pt1 = Plaintext::new_from_slice(&hex::decode("a5e480feba36757014d53c9efd823cd69ae0f8a175c1dd8740fa402faaebe6a114fabec5aa4815d20b41ec651df6cb5ab880849b50509234cbae117a6e59eb77959515d01f9f943c70450183c2d72d3b9ec31e65db41fc90978b31f80537f8b77a5a119b83e8f5420837541402ba85d824325b3641f6d3de35c40ea246804db5a68b0d4897b5169488d76d0a32d2006cdf754e15bbfd4813501a2e88fa3beb1a4dcebf4ccf88d8ba9ea0a9f53355fdc8d44b77caca7c73ad939f9e57d3edabb3c3f60328fc2c01b41bcb4cb533a95477107f447e36a12456abf8c550d1ae359d0f7087a16d4528832a3120f28793d2383f2a2574853f19210895d39bf3840ef106729b7fbdff3ba208666c21b657c2fcdae9e9d801dc205922ee25edbdc6b789907b7fb49d41460184e9b570d3ae6c25ee801c2178ed6874c67901d7fbb73838d7433fa9ae7638ce007ed83fb517e5b0bb8b939b22097ff3db80dd647dbfbda0126e1a35270606e1b28936dfcc8decf4992448d567977bda52fbb4d4c147bb73c6aab1195d8f79e4e458141869569e9cee435140cff55224a94b204a4a103ddad3a8082a1665ad7c52cef851a9376efbf07f6310481a04ea49d0a58072f5089db9fdc54022c52b9321b2b10bd94ad1a739ba8fa4f54d3dade5a62c611bcb4362d7dfb8b0913df8d66021a5f2870aa75e334a72a8c77f8dfb0d5e88a5828017289ba62636dbaa95eebda33b79714e594f19dff834510366a89cab27f7d5af4cc496ae109d5eb907cb9386bd126706d963ed9e6d56439e8bbd735f506243aa2e38474cc53c153b37392e5e56b4c271d7182dd4d31395b3c76f0e6ec6fb79cf02498742c265daa98cccab211d0d1eef2e9e7009defd5c5b0fc2e9d6f3c1518fc964cdd98aa019b4b2a1db22f734788f6dcbe6e8b3fdeb9dfea69410c14c039ee6ec4489171f744e2af555773da6886a2a7a3ad5b032b85e91d56d2baf4176004a37a60e6a00b8dc08b99031d316766af541")?)?;
        let pt2 = Plaintext::new_from_slice(&hex::decode("a5e480feba36757014d53c9efd823cd69ae0f8a175c1dd8740fa402faaebe6a114fabec5aa4815d20b41ec651df6cb5ab880849b50509234cbae117a6e59eb77959515d01f9f943c70450183c2d72d3b9ec31e65db41fc90978b31f80537f8b77a5a119b83e8f5420837541402ba85d824325b3641f6d3de35c40ea246804db5a68b0d4897b5169488d76d0a32d2006cdf754e15bbfd4813501a2e88fa3beb1a4dcebf4ccf88d8ba9ea0a9f53355fdc8d44b77caca7c73ad939f9e57d3edabb3c3f60328fc2c01b41bcb4cb533a95477107f447e36a12456abf8c550d1ae359d0f7087a16d4528832a3120f28793d2383f2a2574853f19210895d39bf3840ef106729b7fbdff3ba208666c21b657c2fcdae9e9d801dc205922ee25edbdc6b789907b7fb49d41460184e9b570d3ae6c25ee801c2178ed6874c67901d7fbb73838d7433fa9ae7638ce007ed83fb517e5b0bb8b939b22097ff3db80dd647dbfbda0126e1a35270606e1b28936dfcc8decf4992448d567977bda52fbb4d4c147bb73c6aab1195d8f79e4e458141869569e9cee435140cff55224a94b204a4a103ddad3a8082a1665ad7c52cef851a9376efbf07f6310481a04ea49d0a58072f5089db9fdc54022c52b9321b2b10bd94ad1a739ba8fa4f54d3dade5a62c611bcb4362d7dfb8b0913df8d66021a5f2870aa75e334a72a8c77f8dfb0d5e88a5828017289ba62636dbaa95eebda33b79714e594f19dff834510366a89cab27f7d5af4cc496ae109d5eb907cb9386bd126706d963ed9e6d56439e8bbd735f506243aa2e38474cc53c153b37392e5e56b4c271d7182dd4d31395b3c76f0e6ec6fb79cf02498742c265daa98cccab211d0d1eef2e9e7009defd5c5b0fc2e9d6f3c1518fc964cdd98aa019b4b2a1db22f734788f6dcbe6e8b3fdeb9dfea69410c14c039ee6ec4489171f744e2af555773da6886a2a7a3ad5b032b85e91d56d2baf4176004a37a60e6a00b8dc08b99031d316766af641")?)?;
        assert_ne!(pt1, pt2);
        let dk1 = Recrypt480::new().derive_symmetric_key(&pt1);
        let dk2 = Recrypt480::new().derive_symmetric_key(&pt2);
        assert_ne!(dk1, dk2);
        Ok(())
    }
}
