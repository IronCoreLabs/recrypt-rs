pub use crate::api_common::RecryptErr;
use crate::api_common::Result;
use crate::internal;
use crate::internal::bytedecoder::{BytesDecoder, DecodeErr};
use crate::internal::curve;
pub use crate::internal::ed25519::{
    Ed25519, Ed25519Signature, Ed25519Signing, PublicSigningKey, SigningKeypair,
};
use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp12elem::Fp12Elem;
pub use crate::internal::hashable::Hashable;
use crate::internal::hashable::Hashable32;
use crate::internal::homogeneouspoint::TwistedHPoint;
use crate::internal::pairing;
pub use crate::internal::rand_bytes::*;
use crate::internal::schnorr::{SchnorrSign, SchnorrSigning};
pub use crate::internal::sha256::{Sha256, Sha256Hashing};
pub use crate::internal::ByteVector;
use crate::nonemptyvec::NonEmptyVec;
use crate::Revealed;
use clear_on_drop::clear::Clear;
use gridiron::fp_256::Fp256;
use gridiron::fp_256::Monty as Monty256;
use rand;
use std;
use std::fmt;

/// Recrypt public API - 256-bit
#[derive(Debug)]
pub struct Recrypt<H, S, R> {
    random_bytes: R,
    sha_256: H,
    ed25519: S,
    pairing: internal::pairing::Pairing<Monty256>,
    curve_points: &'static internal::curve::CurvePoints<Monty256>,
    schnorr_signing: SchnorrSign<Monty256, Fr256, H>,
}

impl Recrypt<Sha256, Ed25519, RandomBytes<rand::rngs::ThreadRng>> {
    pub fn new() -> Recrypt<Sha256, Ed25519, RandomBytes<rand::rngs::ThreadRng>> {
        Recrypt::new_with_rand(rand::thread_rng())
    }
}

impl Default for Recrypt<Sha256, Ed25519, RandomBytes<rand::rngs::ThreadRng>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<CR: rand::CryptoRng + rand::RngCore> Recrypt<Sha256, Ed25519, RandomBytes<CR>> {
    pub fn new_with_rand(r: CR) -> Recrypt<Sha256, Ed25519, RandomBytes<CR>> {
        let pairing = internal::pairing::Pairing::new();
        let curve_points = &*curve::FP_256_CURVE_POINTS;
        let schnorr_signing = internal::schnorr::SchnorrSign::<Monty256, Fr256, Sha256>::new_256();
        Recrypt {
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
/// If you are looking for PartialEq for DerivedSymmetricKey, see PartialEq for Revealed<DerivedSymmetricKey>
new_bytes_type_no_eq!(DerivedSymmetricKey, 32);

impl PartialEq for Revealed<DerivedSymmetricKey> {
    fn eq(&self, other: &Revealed<DerivedSymmetricKey>) -> bool {
        self.0.bytes == other.0.bytes
    }
}

/// A value included in an encrypted message that can be used when the message is decrypted
/// to ensure that you got the same value out as the one that was originally encrypted.
/// It is a hash of the plaintext.
new_bytes_type!(AuthHash, 32);

/// Encrypted Plaintext (Fp12Elem)
new_bytes_type!(EncryptedMessage, Fp12Elem::<Monty256>::ENCODED_SIZE_BYTES);

/// Not hashed, not encrypted Fp12Elem
/// See DecryptedSymmetricKey and EncryptedMessage
// we don't derive Copy or Clone here on purpose. Plaintext is a sensitive value and should be passed by reference
// to avoid needless duplication
pub struct Plaintext {
    bytes: [u8; Plaintext::ENCODED_SIZE_BYTES],
    _internal_fp12: Fp12Elem<Monty256>,
}

impl Plaintext {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty256>::ENCODED_SIZE_BYTES;

    /// Construct a Plaintext from raw bytes
    pub fn new(bytes: [u8; Plaintext::ENCODED_SIZE_BYTES]) -> Plaintext {
        // since new takes a fixed size array, we know it is safe to decode the resultant vector
        Plaintext::from(
            Fp12Elem::<Monty256>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }

    new_from_slice!(Plaintext);

    pub fn bytes(&self) -> &[u8; Plaintext::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    pub(crate) fn internal_fp12(&self) -> &Fp12Elem<Monty256> {
        &self._internal_fp12
    }
}

bytes_only_debug!(Plaintext);

impl PartialEq for Revealed<Plaintext> {
    fn eq(&self, other: &Revealed<Plaintext>) -> bool {
        self.0.bytes[..] == other.0.bytes[..]
    }
}

/// If you are looking for PartialEq for Plaintext, see PartialEq for Revealed<Plaintext>
#[cfg(test)]
impl PartialEq for Plaintext {
    fn eq(&self, other: &Plaintext) -> bool {
        self.bytes[..] == other.bytes[..] && self._internal_fp12 == other._internal_fp12
    }
}

impl From<Fp12Elem<Monty256>> for Plaintext {
    fn from(fp12: Fp12Elem<Monty256>) -> Self {
        Plaintext {
            bytes: fp12.to_bytes_fp256(),
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
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty256>::ENCODED_SIZE_BYTES;

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
    _internal_re_block: internal::ReencryptionBlock<Monty256>,
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

    fn try_from(re_block: internal::ReencryptionBlock<Monty256>) -> Result<Self> {
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

impl PartialEq for TransformBlock {
    fn eq(&self, other: &TransformBlock) -> bool {
        self.public_key == other.public_key
            && self.encrypted_temp_key == other.encrypted_temp_key
            && self.random_transform_public_key == other.random_transform_public_key
            && self.encrypted_random_transform_temp_key == other.encrypted_random_transform_temp_key
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
        signed_value: internal::SignedValue<internal::EncryptedValue<Monty256>>,
    ) -> Result<EncryptedValue> {
        use crate::api::EncryptedValue as EncryptedValueP;

        match signed_value.payload {
            internal::EncryptedValue::EncryptedOnce(internal::EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
            }) => {
                let result = EncryptedValueP::EncryptedOnceValue {
                    ephemeral_public_key: PublicKey::try_from(&ephemeral_public_key)?,
                    encrypted_message: EncryptedMessage::new(encrypted_message.to_bytes_fp256()),
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
                                encrypted_message.to_bytes_fp256(),
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
        internal::SignedValue<internal::EncryptedValue<Monty256>>,
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
                let fp12 = Fp12Elem::<Monty256>::decode(encrypted_message.to_vec())?;
                Ok(
                    internal::SignedValue::<internal::EncryptedValue<Monty256>> {
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
                let fp12 = Fp12Elem::<Monty256>::decode(encrypted_message.to_vec())?;
                let first_block = transform_blocks.first()._internal_re_block;
                let rest_blocks = transform_blocks
                    .rest()
                    .iter()
                    .map(|tb| tb._internal_re_block)
                    .collect();
                Ok(
                    internal::SignedValue::<internal::EncryptedValue<Monty256>> {
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
    _internal_fp12: Fp12Elem<Monty256>,
}

impl Hashable for EncryptedTempKey {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl EncryptedTempKey {
    const ENCODED_SIZE_BYTES: usize = Fp12Elem::<Monty256>::ENCODED_SIZE_BYTES;

    fn from_fp12(fp12: Fp12Elem<Monty256>) -> Self {
        EncryptedTempKey {
            bytes: fp12.to_bytes_fp256(),
            _internal_fp12: fp12,
        }
    }
    pub fn new(bytes: [u8; EncryptedTempKey::ENCODED_SIZE_BYTES]) -> Self {
        EncryptedTempKey::from_fp12(
            Fp12Elem::<Monty256>::decode(bytes.to_vec())
                .expect("Developer error: did you change ENCODED_SIZE_BYTES?"),
        )
    }
    pub fn bytes(&self) -> &[u8; EncryptedTempKey::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    new_from_slice!(EncryptedTempKey);
}

bytes_only_debug!(EncryptedTempKey);

impl PartialEq for EncryptedTempKey {
    fn eq(&self, other: &EncryptedTempKey) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

/// A combination of the hash of `EncryptedTempKey` and the `PrivateKey` of the delegator.
/// Used to recover the plaintext from an `EncryptedTempKey`
#[derive(Clone, Copy)]
pub struct HashedValue {
    bytes: [u8; HashedValue::ENCODED_SIZE_BYTES],
    _internal_value: TwistedHPoint<Monty256>,
}

impl Hashable for HashedValue {
    fn to_bytes(&self) -> ByteVector {
        self.bytes().to_vec()
    }
}

impl HashedValue {
    const ENCODED_SIZE_BYTES: usize = TwistedHPoint::<Monty256>::ENCODED_SIZE_BYTES;

    pub fn new(bytes: [u8; HashedValue::ENCODED_SIZE_BYTES]) -> Result<Self> {
        Ok(
            TwistedHPoint::<Monty256>::decode(bytes.to_vec()).map(|hpoint| HashedValue {
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
impl PartialEq for HashedValue {
    fn eq(&self, other: &HashedValue) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl From<TwistedHPoint<Monty256>> for HashedValue {
    fn from(hp: TwistedHPoint<Monty256>) -> Self {
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
pub struct TransformKey {
    ephemeral_public_key: PublicKey,
    to_public_key: PublicKey,
    encrypted_temp_key: EncryptedTempKey,
    hashed_temp_key: HashedValue,
    public_signing_key: PublicSigningKey,
    signature: Ed25519Signature,
    _internal_key: internal::SignedValue<internal::ReencryptionKey<Monty256>>,
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
        re_key: internal::SignedValue<internal::ReencryptionKey<Monty256>>,
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
            .augment(&private_key.into(), &curve::FP_256_CURVE_POINTS.g1);
        TransformKey::try_from_internal(internal::SignedValue {
            payload: new_internal,
            ..self._internal_key
        })
    }
}

impl PartialEq for TransformKey {
    fn eq(&self, other: &TransformKey) -> bool {
        self.ephemeral_public_key == other.ephemeral_public_key
            && self.to_public_key == other.to_public_key
            && self.encrypted_temp_key == other.encrypted_temp_key
            && self.hashed_temp_key == other.hashed_temp_key
            && self.public_signing_key == other.public_signing_key
            && self.signature == other.signature
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
    for Recrypt<H, S, RandomBytes<CR>>
{
    fn schnorr_sign<A: Hashable>(
        &mut self,
        priv_key: &PrivateKey,
        pub_key: &PublicKey,
        message: &A,
    ) -> SchnorrSignature {
        let k = Fr256::from_rand_no_bias(&mut self.random_bytes);
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
    fn generate_ed25519_key_pair(&mut self) -> SigningKeypair;
}

impl<H, S, CR: rand::RngCore + rand::CryptoRng> Ed25519Ops for Recrypt<H, S, RandomBytes<CR>> {
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
        to_public_key: &PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> KeyGenOps for Recrypt<H, S, R> {
    fn compute_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey> {
        let pub_key_internal = internal::public_keygen(
            internal::PrivateKey::from(private_key),
            self.curve_points.generator,
        );
        PublicKey::try_from(&pub_key_internal)
    }

    fn random_private_key(&mut self) -> PrivateKey {
        let rand_bytes = self.random_bytes.random_bytes_32();
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
        to_public_key: &PublicKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<TransformKey> {
        let ephem_reencryption_private_key = self.random_private_key();
        let temp_key = internal::KValue(gen_random_fp12(&self.pairing, &mut self.random_bytes));
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
    /// What it means to be an rth root (for Fp256):
    /// let curve_order = 6500054969564660373279643874235990574257040605390378638988106296904416679996; (this is "r" -- also defined as the prime for Fr256)
    /// let rth_pow = plaintext.pow(curve_order);
    /// assert_eq!(rth_pow, Fp12Elem::one());
    /// Note that this cannot be implemented here as we do not define a way to do: Fp12.pow(Fp256)
    fn gen_plaintext(&mut self) -> Plaintext;

    /// Convert our plaintext into a DecryptedSymmetricKey by hashing it.
    /// Typically you either use `derive_private_key` or `derive_symmetric_key` but not both.
    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey;

    ///Derive a private key for a plaintext by hashing it and modding it by the prime.
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
        &mut self,
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
        &mut self,
        encrypted_value: EncryptedValue,
        transform_key: TransformKey,
        signing_keypair: &SigningKeypair,
    ) -> Result<EncryptedValue>;
}

impl<R: RandomBytesGen, H: Sha256Hashing, S: Ed25519Signing> CryptoOps for Recrypt<H, S, R> {
    fn gen_plaintext(&mut self) -> Plaintext {
        let rand_fp12 = gen_random_fp12(&self.pairing, &mut self.random_bytes);
        Plaintext::from(rand_fp12)
    }

    fn derive_symmetric_key(&self, decrypted_value: &Plaintext) -> DerivedSymmetricKey {
        DerivedSymmetricKey::new(self.sha_256.hash(decrypted_value))
    }

    fn derive_private_key(&self, plaintext: &Plaintext) -> PrivateKey {
        PrivateKey::new(self.sha_256.hash(plaintext))
    }

    fn encrypt(
        &mut self,
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

fn gen_random_fp12<R: RandomBytesGen>(
    pairing: &pairing::Pairing<Monty256>,
    random_bytes: &mut R,
) -> Fp12Elem<Monty256> {
    // generate 12 random Fp values
    internal::gen_rth_root(
        pairing,
        Fp12Elem::create_from_t(
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
            Fp256::from(random_bytes.random_bytes_32()),
        )
        .map(&|fp256| fp256.to_monty()),
    )
}

#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    x: [u8; 32],
    y: [u8; 32],
    _internal_key: internal::PublicKey<Monty256>,
}

impl Hashable for PublicKey {
    fn to_bytes(&self) -> ByteVector {
        self._internal_key.to_bytes()
    }
}

impl PublicKey {
    pub const ENCODED_SIZE_BYTES: usize = Monty256::ENCODED_SIZE_BYTES * 2;

    fn try_from(internal_key: &internal::PublicKey<Monty256>) -> Result<PublicKey> {
        Ok(internal_key
            .to_byte_vectors_32()
            .map(|(x, y)| PublicKey {
                x,
                y,
                _internal_key: *internal_key,
            })
            .ok_or_else(|| internal::homogeneouspoint::PointErr::ZeroPoint)?)
    }

    pub fn new(
        (x_bytes, y_bytes): (
            [u8; Monty256::ENCODED_SIZE_BYTES],
            [u8; Monty256::ENCODED_SIZE_BYTES],
        ),
    ) -> Result<PublicKey> {
        let x = Fp256::from(x_bytes).to_monty();
        let y = Fp256::from(y_bytes).to_monty();
        let i_pk = internal::PublicKey::from_x_y(x, y)?;
        PublicKey::try_from(&i_pk)
    }

    pub fn new_from_slice(bytes: (&[u8], &[u8])) -> Result<Self> {
        if bytes.0.len() == Monty256::ENCODED_SIZE_BYTES
            && bytes.1.len() == Monty256::ENCODED_SIZE_BYTES
        {
            let mut x_dest = [0u8; Monty256::ENCODED_SIZE_BYTES];
            x_dest.copy_from_slice(bytes.0);
            let mut y_dest = [0u8; Monty256::ENCODED_SIZE_BYTES];
            y_dest.copy_from_slice(bytes.1);

            Ok(PublicKey::new((x_dest, y_dest))?)
        } else {
            Err(RecryptErr::InputWrongSize(
                "PublicKey",
                PublicKey::ENCODED_SIZE_BYTES,
            ))
        }
    }
    pub fn bytes_x_y(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.x, &self.y)
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

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.x == other.x && self.y == other.y
    }
}

#[derive(Default, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
// If you are looking for PartialEq for PrivateKey, see PartialEq for Revealed<PrivateKey>
pub struct PrivateKey {
    bytes: [u8; PrivateKey::ENCODED_SIZE_BYTES],
    _internal_key: internal::PrivateKey<Monty256>,
}

impl PrivateKey {
    pub const ENCODED_SIZE_BYTES: usize = Monty256::ENCODED_SIZE_BYTES;

    pub fn bytes(&self) -> &[u8; PrivateKey::ENCODED_SIZE_BYTES] {
        &self.bytes
    }

    pub fn new(bytes: [u8; PrivateKey::ENCODED_SIZE_BYTES]) -> PrivateKey {
        let internal_key = internal::PrivateKey::from_fp256(Fp256::from(bytes).to_monty());
        PrivateKey {
            bytes: internal_key.value.to_bytes_32(),
            _internal_key: internal_key,
        }
    }

    new_from_slice!(PrivateKey);
}

impl PartialEq for Revealed<PrivateKey> {
    fn eq(&self, other: &Revealed<PrivateKey>) -> bool {
        self.0.bytes[..] == other.0.bytes
    }
}

impl Hashable32 for PrivateKey {
    fn to_bytes_32(&self) -> [u8; 32] {
        self.bytes
    }
}

impl From<internal::PrivateKey<Monty256>> for PrivateKey {
    fn from(internal_pk: internal::PrivateKey<Monty256>) -> Self {
        PrivateKey {
            bytes: internal_pk.value.to_bytes_32(),
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
new_bytes_type!(SchnorrSignature, 64);

impl From<internal::schnorr::SchnorrSignature<Fr256>> for SchnorrSignature {
    fn from(internal: internal::schnorr::SchnorrSignature<Fr256>) -> Self {
        SchnorrSignature::new(internal::array_concat_32(
            &internal.r().to_bytes_32(),
            &internal.s().to_bytes_32(),
        ))
    }
}

impl From<SchnorrSignature> for internal::schnorr::SchnorrSignature<Fr256> {
    fn from(sig: SchnorrSignature) -> Self {
        let (r_bytes, s_bytes) = internal::array_split_64(&sig.bytes);
        internal::schnorr::SchnorrSignature::new(Fr256::from(r_bytes), Fr256::from(s_bytes))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::internal::ed25519;
    use crate::internal::fp::fp256_unsafe_from;
    use hex;
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
        fn random_bytes_32(&mut self) -> [u8; 32] {
            [std::u8::MAX; 32]
        }

        fn random_bytes_60(&mut self) -> [u8; 60] {
            unimplemented!() //not needed for Fp256
        }
    }

    fn api_with<R: RandomBytesGen + Default, S: Ed25519Signing>(
        random_bytes: Option<R>,
        ed25519: S,
    ) -> Recrypt<Sha256, S, R> {
        let api = Recrypt::new();
        Recrypt::<Sha256, S, R> {
            random_bytes: random_bytes.unwrap_or_default(),
            schnorr_signing: internal::schnorr::SchnorrSign::new_256(),
            sha_256: api.sha_256,
            ed25519: ed25519,
            pairing: api.pairing,
            curve_points: api.curve_points,
        }
    }

    #[test]
    fn schnorr_signing_roundtrip_augmented() {
        let mut api = Recrypt::new();
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
        let mut api = Recrypt::new();
        let (private_key, pub_key) = api.generate_key_pair().unwrap();
        let message = vec![1u8, 2u8, 3u8, 4u8];
        let sig = api.schnorr_sign(&private_key, &pub_key, &message);
        let result = api.schnorr_verify(&pub_key, None, &message, sig);
        assert!(result);
    }

    #[test]
    fn public_key_roundtrip_with_internal() {
        let (_, pub_key_api) = Recrypt::new().generate_key_pair().unwrap();

        let internal_pk = pub_key_api._internal_key;
        let roundtrip = PublicKey::try_from(&internal_pk).unwrap();

        assert_eq!(pub_key_api, roundtrip)
    }

    #[test]
    fn private_key_roundtrip_with_internal() {
        let (priv_key_api, _) = Recrypt::new().generate_key_pair().unwrap();

        let internal_pk = internal::PrivateKey::<Monty256>::from(&priv_key_api);
        let roundtrip = PrivateKey::from(internal_pk);

        assert_eq!(priv_key_api, roundtrip);
        assert_eq!(internal_pk, priv_key_api._internal_key)
    }

    #[test]
    fn gen_plaintext_len() {
        let api = &mut Recrypt::new();

        let result = api.gen_plaintext();
        assert_eq!(Fp12Elem::<Monty256>::ENCODED_SIZE_BYTES, result.bytes.len());
    }

    #[test]
    fn test_compute_public_key() {
        let api = &mut Recrypt::new();
        //37777967648492203239675772600961898148040325589588086812374811831221462604944
        let parsed_priv_key =
            fp256_unsafe_from("5385926b9f6135086d1912901e5a433ffcebc19a30fadbd0ee8cee26ba719c90")
                .to_monty();
        let private_key = &PrivateKey::new(parsed_priv_key.to_bytes_32());

        //56377452267431283559088187378398270325210563762492926393848580098576649271541
        let parsed_pub_key_x =
            fp256_unsafe_from("7ca481d71abbae43395152eb7baa230d60543d43e2e8f89a18d182ecf8c3b8f5")
                .to_monty();
        //46643694276241842996939080253335644316475473619096522181405937227991761798154
        let parsed_pub_key_y =
            fp256_unsafe_from("671f653900901fc3688542e5939ba6c064a7768f34fe45492a49e1f6d4d7c40a")
                .to_monty();
        let public_key_expected = PublicKey::try_from(
            &internal::PublicKey::from_x_y(parsed_pub_key_x, parsed_pub_key_y).unwrap(),
        )
        .unwrap();

        let computed_pub_key = api
            .compute_public_key(private_key)
            .expect("compute_public_key FAILED");
        assert_eq!(computed_pub_key, public_key_expected);
        let _computed_pub_key2 = api.compute_public_key(private_key); //second invocation to prove move semantics
    }

    #[test]
    fn test_generate_key_pair_max_private_key() {
        let mut api = api_with(Some(DummyRandomBytes), DummyEd25519);
        let (_, pub_key) = api.generate_key_pair().unwrap();
        let internal_pk = internal::PublicKey::from_x_y(
            //58483620629232886210555514960799664032881966270053836377116209031946678864174
            fp256_unsafe_from("814c8e65863238dbd86f9fbdbe8f166e536140343b7f3c22e79c82b8af70892e")
                .to_monty(),
            //39604663823550822619127054070927331080305575010367415285113646212320556073913
            fp256_unsafe_from("578f72028091b2efa1c946c4caf9e883c9e8d3311e23050f560672795a7dc3b9")
                .to_monty(),
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
            [0u8; 32]
        }

        fn random_bytes_60(&mut self) -> [u8; 60] {
            unimplemented!() // not needed for Fp256
        }
    }

    fn good_transform_key() -> TransformKey {
        let mut api = Recrypt::new();
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
            TwistedHPoint::<Monty256>::decode(hashedvalue.bytes.to_vec()).unwrap()
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
        let mut api = Recrypt::new();
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
    fn decrypt_known_value() -> Result<()> {
        let expected_pt = Plaintext::new_from_slice(&hex::decode("3e0348980131e4db298445c3ef424ad60ebfa816069689be559f5ffeecf5e635201172f1bc931833b431a8d7a118e90d516de84e6e4de2f3105695b7699104ee18dd4598f93417ed736b40515a4817499a748be1bf126c132a8a4e8da83780a9054d6e1de22e21e446dbaa3a121d103fdf813a31afac09881beb0a3ae974ffdd537049eea02dade975525c720d152c87b4f0e76645c4cf46ee0e731378ad5c5d12630a32d0610c52c3c56fc0d7666ad6464adeca698a2ee4c44666c05d2e58154b961a595a445b156ce0bdd3e13ffa5b296e8c364aecec6208a0aa54cdea40455032a11458b08d143a51013dcdb8febd01bd93966bff2fc8bbd121efc19fedcb576d82e70838f8f987c5cb887a857d4a6d68c8bbf9196d72b98bea0a62d3fda109a46c28c6d87851223f38712226ba8a5c36197ee016baa27051c398a95c184820e6493c972f7e53936a2abd9c22483d3595fee87ad2a2771af0cc847548bc233f258d4bf77df8265b566ef54c288ad3a8034d18b3af4cb1d71b2da649200fa1")?)?;
        let encrypted = EncryptedValue::EncryptedOnceValue{
                ephemeral_public_key: PublicKey::new_from_slice((&hex::decode("7013008e19061384a3e6ba1f1a98834cb787b671a0fe181c3adeae15e24c0bba").unwrap(), &hex::decode("3165123233dc537c870673495c7db71239a51647d29113a0d3f5f99eea8de513").unwrap()))?,
                encrypted_message: EncryptedMessage::new_from_slice(&hex::decode("2aab5397ef54cd3ea6f3ea3313df53059a47fb35786fb9374dda260af183d0150b062c9ee31feded7c2f966c5323d51954c382c583bb14123ad220c7d1457f7e849e95a28f434df3406561c303084644c6a950218996f871a45e0ebf842d65e828ce3bb04067bc7674edee95b0f697764d546ec760c416c390b869bc18c458c7867fee841d6c50f85a4db4591a4a95b7fbabc2add2f09e4a574d3c21f54b8846247ba2ec7373db45a86df589dd1b5cb5e9178aa14502877fb12d243626081ebd7eb4d501bb9da3d21ba1b4b779d4ffdd468f25e8c2f0cbecca3cd4e0c5960ab55471e42a6183714da09cfc0e70c8bd4ea720618a077c296b4744dfdf898bc95016f5d38e776d750b51da8fc98ef68894f7087730ad7e60d23062c8f216bfc4293c10d1d966203601db3db27eaa50afab06ab1eba9e9bb1f8b8ebc42cf01c73284f0861aab05d492c7d98137a1dcacdca45b277fcb51f665690e21a5549758b0c3654e38745c39c17b953ebfd66e685153a6b6aae1ac2a87f866896bda8d14012")?)?,
                auth_hash: AuthHash::new_from_slice(&hex::decode("334bad3490633ebb346fb22a628356f19c299b2be90e5efe0ec344039662c307")?)?,
                public_signing_key: PublicSigningKey::new_from_slice(&hex::decode("7ada8837de936ec230afd05b73a378987784534d731ba35f68ecb777846232ab")?)?,
                signature: Ed25519Signature::new_from_slice(&hex::decode("312901e121e0637eb0814b1411ec6772147d5ab2063ae781ec2f227748059ac5d892a6eed7c66e1638649903fe3ecbb9c2b5674e87e9b9c39009a175f2177e0f")?)?,
            };
        let priv_key = PrivateKey::new_from_slice(&hex::decode(
            "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
        )?)?;
        let api = Recrypt::new();
        let pt = api.decrypt(encrypted, &priv_key)?;
        assert_eq!(pt, expected_pt);
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<()> {
        use rand::SeedableRng;
        let mut api = Recrypt::new_with_rand(rand_chacha::ChaChaRng::from_seed([0u8; 32]));
        let pt = api.gen_plaintext();
        let (priv_key, pub_key) = api.generate_key_pair().unwrap();
        let priv_signing_key = api.generate_ed25519_key_pair();

        let encrypted_val = api.encrypt(&pt, &pub_key, &priv_signing_key).unwrap();

        let decrypted_val = api.decrypt(encrypted_val, &priv_key).unwrap();

        // compare the bytes as a vec as Plaintext and [u8; 384] don't define Eq
        assert_eq!(pt.bytes.to_vec(), decrypted_val.bytes.to_vec());
        Ok(())
    }

    #[test]
    fn derive_known_symmetric_key() {
        let bytes = hex::decode("28c0f558c02d983d7c652f16acbe91a566ac420fe02e41cf6d4f09a107f75cf76b6776ebb53365100ebeb7fa332995ae7bdddf0779fe79e1f43d5c51a73ced0a8cf5789804a79960ccf1a64bd55a923f4786d31ec06bf33e739254016d077b838e739f85586087e52ab659471df3904035e5e1f7ad6ac7b9f9dba6daf39e3f882b583e309c03e35ae7dfd4ed063b6c226bb3338627772e4c9a556fee7f3f96030ae1e265654fc322015a1c2d50eb273cd8b0e1e0353e6b09749343b5fe72ae2f302bebc527aca6ec465a95c4b41efe174eb5165993a30a922434a6f45cbafda201d6540bf2202c65751c90e4cd87e1b690997d9cd23474ef9ace4def3f17cbdd648c8545eaceb3f28c166f720fd8dd87b47523c55a52e32f8c1595a586763276411e8bd4400fac41234277cc560e919f76b21d757cda7c253078927e75482ee2759b222bf4fb070ab3032c9556a069d754efc3c0e63533311b29334108a5121a7e4018782324bf2c1517b6fe4df7a1bbb34c985c6d0796ff1e18ed80fd78d402").unwrap();
        let pt = Plaintext::from(Fp12Elem::decode(bytes).unwrap());
        let src = &hex::decode("0e62a3e388cb0ca3279792353f7fcad75acf180d430a5c69e0a68be96520f454")
            .unwrap()[..];
        let mut dest: [u8; 32] = [0u8; 32];
        dest.copy_from_slice(src);
        let expected_result = DerivedSymmetricKey::new(dest);
        let result = Recrypt::new().derive_symmetric_key(&pt);
        assert_eq!(Revealed(expected_result), Revealed(result))
    }

    #[test]
    ///This test is meant to show that if the top byte is too large the private key and derived symmetric key might actually be different.
    fn derive_known_symmetric_key_not_same_bytes_as_private_key() {
        let api = Recrypt::default();
        let bytes = hex::decode("34f36d6fb086b38435823c96f016fc8e41c7ab39c1abb02a773333b88f8d1f1409289fccaa485629e15d3273768e2a039368c68dc5873353b5c18a2d0eb02adf04519ded7fc4bd07c2b405b8f9075b96be28915f793f3e90b3e5488f20c666ff00839462c603d7f1f9d5c86556a0590bc2a76fb5d2d6dc2afa53fb5470af3a5521dd82ee76290502a84a0bc5e7e37b183332dc761fb808b8e7ba138cbee30a802f9257b5f2117452025a1e92e45b9624ad29f46db639f223e7c067e1fdb3c93d4f55165a15ec90451272325f19678f2d3e6230736916ec562fbda94f920d5149506b7efe1211ac62e826f1b8d2f8c41f10c1cf4d53a7222d5124b536c3707b0b86198131f9f4ef2cfdf7ff9d13bc6b6e21f8e0a337a0acda48055d10143381760e783473a14153b371b1147c18852acb4af0a3d4d9dd7e738b04e7cd0c0a6b5a1b826f3aa4817cfab2ccb73ab03258e42b7baa54cde8a903de4d3a6b8c7742e92b9976fdf64c496dab1d143f4d65bc86d9f8f6e3ee38e97da3faa8bbdf461688").unwrap();
        let pt = Plaintext::from(Fp12Elem::decode(bytes).unwrap());
        //This is a manually computed symmetric key based on the above plaintext (which was chosen because this value is greater than P)
        let src = &hex::decode("cd1b366b2575f2a69390c51b3b1e0c3e2eace761e0a4cee2a1895175071f6700")
            .unwrap()[..];
        let mut dest: [u8; 32] = [0u8; 32];
        dest.copy_from_slice(src);
        let expected_result = DerivedSymmetricKey::new(dest);
        let result = api.derive_symmetric_key(&pt);
        assert_eq!(Revealed(expected_result), Revealed(result));
        //This hashes, but also mods the value so it's not the same.
        let private_key_result = api.derive_private_key(&pt);
        assert_ne!(private_key_result.bytes(), result.bytes());
    }

    use std::default::Default;
    #[test]
    fn transform_to_same_key() {
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);
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
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);

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
        let mut api = Recrypt::new();
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
        let mut api = api_with(Some(RandomBytes::default()), DummyEd25519);
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
    fn generate_ed25519_key_pair() {
        use rand::SeedableRng;
        let mut api = Recrypt::new_with_rand(rand_chacha::ChaChaRng::from_seed([0u8; 32]));
        let signing_keypair = Revealed(api.generate_ed25519_key_pair());
        let expected_signing_keypair = Revealed(SigningKeypair::new_unchecked([
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199, 32, 253, 186, 201,
            177, 11, 117, 135, 187, 167, 181, 188, 22, 59, 206, 105, 231, 150, 215, 30, 78, 212,
            76, 16, 252, 180, 72, 134, 137, 247, 161, 68,
        ]));
        let expected_pub = PublicSigningKey::new([
            32, 253, 186, 201, 177, 11, 117, 135, 187, 167, 181, 188, 22, 59, 206, 105, 231, 150,
            215, 30, 78, 212, 76, 16, 252, 180, 72, 134, 137, 247, 161, 68,
        ]);
        assert_eq!(signing_keypair, expected_signing_keypair);
        assert_eq!(signing_keypair.0.public_key(), expected_pub);

        //Assert that the generation doesn't just return the same value.
        let keypair_two = Revealed(api.generate_ed25519_key_pair());
        assert_ne!(keypair_two, expected_signing_keypair);
        assert_ne!(keypair_two.0.public_key(), expected_pub);
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
        let input: [u8; 128] = good_transform_key().hashed_temp_key.bytes;
        let slice: &[u8] = &input;
        let hv_from_fixed = HashedValue::new(input);
        let hv_from_slice = HashedValue::new_from_slice(slice);

        assert_eq!(hv_from_fixed.unwrap(), hv_from_slice.unwrap());

        assert_eq!(
            RecryptErr::InputWrongSize("HashedValue", 128),
            HashedValue::new_from_slice(&input[..30]).unwrap_err()
        )
    }
    #[test]
    fn publickey_new_from_slice() {
        let mut api = Recrypt::new();
        let (_, pk1) = api.generate_key_pair().unwrap();
        let input: ([u8; 32], [u8; 32]) = (pk1.x, pk1.y);
        let slice: (&[u8], &[u8]) = (&input.0, &input.1);
        let pk_from_fixed = PublicKey::new(input);
        let pk_from_slice = PublicKey::new_from_slice(slice);

        assert_eq!(pk_from_fixed.unwrap(), pk_from_slice.unwrap());

        assert_eq!(
            RecryptErr::InputWrongSize("PublicKey", 64),
            PublicKey::new_from_slice((&input.0[..30], &input.1[..32])).unwrap_err()
        )
    }

    #[test]
    fn private_key_new_from_slice() {
        let mut rand_bytes = DummyRandomBytes;
        let input: [u8; 32] = rand_bytes.random_bytes_32();
        let slice: &[u8] = &input;
        let from_fixed = PrivateKey::new(input);
        let from_slice = PrivateKey::new_from_slice(slice);

        assert_eq!(from_fixed, from_slice.unwrap());

        assert_eq!(
            RecryptErr::InputWrongSize("PrivateKey", 32),
            PrivateKey::new_from_slice(&input[..30]).unwrap_err()
        )
    }

    // note that this doesn't show that Drop is working properly, just that clear does
    #[test]
    fn private_key_clear() {
        let (mut priv_key, _) = Recrypt::new().generate_key_pair().unwrap();
        priv_key.clear();
        assert_eq!(priv_key.bytes(), &[0u8; 32]);
        assert_eq!(priv_key._internal_key, Default::default())
    }
}
