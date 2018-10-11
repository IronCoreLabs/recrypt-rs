use clear_on_drop::clear::Clear;
use gridiron::fp_256::Fp256;
use internal::curve::CurvePoints;
use internal::ed25519::{Ed25519Signature, Ed25519Signing, PrivateSigningKey, PublicSigningKey};
use internal::field::ExtensionField;
use internal::field::Field;
use internal::fp::fr_256::Fr256;
use internal::fp12elem::Fp12Elem;
use internal::fp2elem::Fp2Elem;
use internal::hashable::{Hashable, Hashable32};
use internal::homogeneouspoint::{HomogeneousPoint, PointErr};
use internal::non_adjacent_form::NonAdjacentForm;
use internal::pairing::Pairing;
use internal::pairing::PairingConfig;
use internal::sha256::Sha256Hashing;
use nonemptyvec::NonEmptyVec;
use num_traits::{One, Zero};
use std::ops::{Add, Mul, Neg};
#[macro_use]
pub mod macros;
pub mod bytedecoder;
pub mod curve;
pub mod ed25519;
pub mod field;
pub mod fp;
pub mod fp12elem;
pub mod fp2elem;
pub mod fp6elem;
pub mod hashable;
pub mod homogeneouspoint;
pub mod non_adjacent_form;
pub mod pairing;
pub mod rand_bytes;
pub mod schnorr;
pub mod sha256;

use api;

pub type ByteVector = Vec<u8>;
pub type ErrorOr<T> = Result<T, InternalError>;

#[derive(Debug)]
pub enum InternalError {
    AuthHashMatchFailed,
    SignatureFailed,
    PrivateKeyFailed,
    PointInvalid(PointErr),
    BytesDecodeFailed(bytedecoder::DecodeErr),
    CorruptReencryptionKey,
}

impl From<PointErr> for InternalError {
    fn from(p: PointErr) -> InternalError {
        InternalError::PointInvalid(p)
    }
}

impl From<bytedecoder::DecodeErr> for InternalError {
    fn from(decode_err: bytedecoder::DecodeErr) -> Self {
        InternalError::BytesDecodeFailed(decode_err)
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PublicKey<T: Field> {
    pub value: HomogeneousPoint<T>,
}

impl<T: Field + Hashable32> PublicKey<T> {
    pub fn to_byte_vectors_32(&self) -> Option<([u8; 32], [u8; 32])> {
        self.value
            .normalize()
            .map(|(x, y)| (x.to_bytes_32(), y.to_bytes_32()))
    }

    pub fn new(point: HomogeneousPoint<T>) -> PublicKey<T> {
        PublicKey { value: point }
    }
}

impl PublicKey<Fp256> {
    pub fn from_x_y_fp256(x: Fp256, y: Fp256) -> Result<PublicKey<Fp256>, InternalError> {
        let result = HomogeneousPoint::from_x_y((x, y)).map(|value| PublicKey { value })?;
        Ok(result)
    }
}

impl<T: Field + Hashable> Hashable for PublicKey<T> {
    fn to_bytes(&self) -> ByteVector {
        self.value.to_bytes()
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug, Default)]
pub struct PrivateKey<T> {
    pub value: T,
}
impl From<api::PrivateKey> for PrivateKey<Fp256> {
    fn from(api_pk: api::PrivateKey) -> Self {
        PrivateKey {
            value: Fp256::from(api_pk.to_bytes_32()),
        }
    }
}

impl<'a> From<&'a api::PrivateKey> for PrivateKey<Fp256> {
    fn from(api_pk: &'a api::PrivateKey) -> Self {
        PrivateKey {
            value: Fp256::from(api_pk.to_bytes_32()),
        }
    }
}

impl PrivateKey<Fp256> {
    pub fn from_fp256(fp256: Fp256) -> PrivateKey<Fp256> {
        PrivateKey { value: fp256 }
    }
}

impl<T> NonAdjacentForm for PrivateKey<T>
where
    T: NonAdjacentForm + Copy,
{
    fn to_naf(&self) -> Vec<i8> {
        self.value.to_naf()
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct SignedValue<T> {
    pub public_signing_key: PublicSigningKey,
    pub signature: Ed25519Signature,
    pub payload: T,
}

/// A value included in an encrypted message that can be used when the message is decrypted
/// to ensure that you got the same value out as the one that was originally encrypted.
/// It is a hash of the plaintext.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct AuthHash {
    pub bytes: [u8; 32],
}

impl Hashable for AuthHash {
    fn to_bytes(&self) -> ByteVector {
        self.bytes.to_vec()
    }
}

impl AuthHash {
    pub fn create<A: Hashable, F: Sha256Hashing>(hash_func: &F, a: &A) -> AuthHash {
        AuthHash {
            bytes: hash_func.hash(a),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum EncryptedValue<T: Field + Hashable> {
    EncryptedOnce(EncryptedOnceValue<T>),
    Reencrypted(ReencryptedValue<T>),
}

/// A value that has been transformed at least once - this is comprised of the initial encrypted message
/// followed by a set of reencryption blocks, one that is added for each reencryption hop.
/// The number of reencryption hops is equal to the length of the encryptionBlocks Vector.
///
/// ephemeralPublicKey - public key of the private key that was used to encrypt
/// encryptedMessage - the encrypted value.
/// authHash - Authentication hash for the plaintext.
/// encryptionBlocks - A vector of blocks which describes how to transform the encrypted data to be decrypted by another party.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ReencryptedValue<T: Field> {
    pub ephemeral_public_key: PublicKey<T>,
    pub encrypted_message: Fp12Elem<T>,
    pub auth_hash: AuthHash,
    pub encryption_blocks: NonEmptyVec<ReencryptionBlock<T>>,
}

impl<FP: Field + Hashable> ReencryptedValue<FP> {
    fn from_encrypted_once(
        encrypted_value: &EncryptedOnceValue<FP>,
        re_blocks: NonEmptyVec<ReencryptionBlock<FP>>,
    ) -> ReencryptedValue<FP> {
        ReencryptedValue {
            ephemeral_public_key: encrypted_value.ephemeral_public_key,
            encrypted_message: encrypted_value.encrypted_message,
            auth_hash: encrypted_value.auth_hash,
            encryption_blocks: re_blocks,
        }
    }

    fn with_new_re_blocks(
        &self,
        new_blocks: NonEmptyVec<ReencryptionBlock<FP>>,
    ) -> ReencryptedValue<FP> {
        ReencryptedValue {
            ephemeral_public_key: self.ephemeral_public_key,
            encrypted_message: self.encrypted_message,
            auth_hash: self.auth_hash,
            encryption_blocks: new_blocks,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ReencryptionBlock<T: Field> {
    pub public_key: PublicKey<T>,
    pub encrypted_temp_key: Fp12Elem<T>,
    pub rand_re_public_key: PublicKey<T>,
    pub encrypted_rand_re_temp_key: Fp12Elem<T>,
}

impl<FP: Field + Hashable> ReencryptionBlock<FP> {
    fn with_temp_key(
        &self,
        encrypted_temp_key: Fp12Elem<FP>,
        encrypted_rand_re_temp_key: Fp12Elem<FP>,
    ) -> ReencryptionBlock<FP> {
        ReencryptionBlock {
            public_key: self.public_key,
            encrypted_temp_key,
            rand_re_public_key: self.rand_re_public_key,
            encrypted_rand_re_temp_key,
        }
    }
}

impl<FP: Field + Hashable> Hashable for ReencryptionBlock<FP> {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.public_key.to_bytes()[..],
            &self.encrypted_temp_key.to_bytes()[..],
            &self.rand_re_public_key.to_bytes()[..],
            &self.encrypted_rand_re_temp_key.to_bytes()[..],
        ]
            .concat()
    }
}
/// A value which has been encrypted, but not transformed.
/// `ephemeral_public_key`  - public key of the private key that was used to encrypt
/// `encrypted_message`     - the encrypted value.
/// `auth_hash`             - Authentication hash for the plaintext.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct EncryptedOnceValue<T: Field> {
    pub ephemeral_public_key: PublicKey<T>,
    pub encrypted_message: Fp12Elem<T>,
    pub auth_hash: AuthHash,
}

impl<T: Field + Hashable> Hashable for EncryptedValue<T> {
    fn to_bytes(&self) -> ByteVector {
        match self {
            EncryptedValue::EncryptedOnce(EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
            }) => vec![
                ephemeral_public_key.to_bytes(),
                encrypted_message.to_bytes(),
                auth_hash.to_bytes(),
            ].to_bytes(),
            EncryptedValue::Reencrypted(ReencryptedValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                encryption_blocks,
            }) => vec![
                ephemeral_public_key.to_bytes(),
                encrypted_message.to_bytes(),
                auth_hash.to_bytes(),
                encryption_blocks.to_bytes(),
            ].to_bytes(),
        }
    }
}

pub trait Square {
    fn square(&self) -> Self;
}

impl Square for Fp256 {
    fn square(&self) -> Self {
        self.square()
    }
}

impl Square for Fr256 {
    fn square(&self) -> Self {
        self.square()
    }
}

///Sum t n times.
fn sum_n<T: Add<Output = T> + Copy + Zero + PartialEq>(t: T, n: u64) -> T {
    if n == 0 {
        Zero::zero()
    } else {
        sum_n_loop(t, n - 1, t)
    }
}

fn sum_n_loop<T: Add<Output = T> + Copy>(t: T, k: u64, extra: T) -> T {
    if k == 1 {
        t + extra
    } else {
        let x = if (k & 1) == 1 { t + extra } else { extra };
        sum_n_loop(t + t, k >> 1, x)
    }
}

fn pow_for_square<T: One + Mul<T, Output = T> + Copy + Square>(t: T, exp: u64) -> T {
    if exp == 0 {
        T::one()
    } else {
        let mut mut_exp = exp;
        let mut y = T::one();
        let mut x = t;
        while mut_exp > 1 {
            if mut_exp & 1 == 1 {
                y = x * y;
                x = x.square();
            } else {
                x = x.square();
            }
            mut_exp >>= 1;
        }
        y * x
    }
}

pub fn array_concat_32<T: Copy + Zero>(one: &[T; 32], two: &[T; 32]) -> [T; 64] {
    let mut result: [T; 64] = [T::zero(); 64];
    result[0..32].copy_from_slice(&one[..]);
    result[32..64].copy_from_slice(&two[..]);
    result
}

pub fn array_split_64<T: Copy + Zero>(array: &[T; 64]) -> ([T; 32], [T; 32]) {
    let mut one = [T::zero(); 32];
    let mut two = [T::zero(); 32];
    one.copy_from_slice(&array[0..32]);
    two.copy_from_slice(&array[32..64]);
    (one, two)
}

/// Generate one of the rth roots of unity (an element of G_T) given an FP12Elem.
/// Useful for calling `encrypt`
pub fn gen_rth_root<T>(pairing: &Pairing<T>, fp12_elem: Fp12Elem<T>) -> Fp12Elem<T>
where
    T: Field + ExtensionField + Square + PairingConfig,
{
    pairing.final_exp(fp12_elem)
}

///Generate a public key using the private key and generator point.
pub fn public_keygen<T>(private_key: PrivateKey<T>, generator: HomogeneousPoint<T>) -> PublicKey<T>
where
    T: Field + NonAdjacentForm,
{
    PublicKey {
        value: generator * private_key.value,
    }
}

/// Signs some value of type `T` (and the publicSigningKey) with privateSigningKey.
///
/// # Arguments
/// `payload` - value to sign; must be a type with an associated Hashable instance
/// `public_signing_key` - the Ed25519 public key to embed in the output; can be used to validate signature
/// `private_signing_key` - the Ed25519 private key that is used to compute the signature
/// `ed25519` - Implementation of `Ed25519Signing` trait
///
/// # Return
/// SignedValue<T> - contains the value `payload`, the public signingkey, and the computed signature
fn sign_value<T, F: Ed25519Signing>(
    payload: T,
    public_signing_key: PublicSigningKey,
    private_signing_key: &PrivateSigningKey,
    ed25519: &F,
) -> SignedValue<T>
where
    T: Hashable + Clone,
{
    let signature = ed25519.sign(&(public_signing_key, payload.clone()), private_signing_key);
    SignedValue {
        public_signing_key,
        signature,
        payload,
    }
}

/// Encrypt plaintext to publicKey. This public key encryption is not meant to encrypt arbitrary
/// data; instead, you should generate a random plaintext value (an element of G_T), apply a
/// SHA256 hash to it to generate a 32-bit number, and use that as a key for a symmetric algorithm
/// like AES256-GCM to encrypt the data. Then use this method to encrypt the plaintext.
///
/// Note that the encrypting privateKey is ephemeral.
///
/// The result will have the `public_signing_key` embedded and be signed by the `private_signing_key`.
/// It also includes a authentication hash that the decrypter can use to confirm that the final
/// result after decryption matches the value that was encrypted.
///
/// # Arguments
/// `to_public_key`         - the public key to encrypt to
/// `plaintext`             - the value to encrypt - must be an element of G_T
/// `encrypting_key`        - a random private key value chosen just for this plaintext
/// `public_signing_key`    - the public portion of the encrypter's signing key pair
/// `private_signing_key`   - the private portion of the encrypter's signing key pair
/// `pairing`               - Optimal Ate Pairing
/// `curve_points`          - IronCore's curve
/// `hash`                  - Sha256Hashing instance
/// `sign`                  - Ed25519Signing instance
///
/// # Return
/// SignedValue[EncryptedValue] - the plaintext encrypted to the specified public key,
/// along with the authHash, public signing key, and signature
pub fn encrypt<T: Clone, F: Sha256Hashing, G: Ed25519Signing>(
    to_public_key: PublicKey<T>,
    plaintext: Fp12Elem<T>, // @clintfred can this be any fp12? or an rth root?
    encrypting_key: PrivateKey<T>,
    public_signing_key: PublicSigningKey,
    private_signing_key: &PrivateSigningKey,
    pairing: &Pairing<T>,
    curve_points: &CurvePoints<T>,
    hash: &F,
    sign: &G,
) -> SignedValue<EncryptedValue<T>>
where
    T: Field + ExtensionField + PairingConfig + NonAdjacentForm + Hashable,
{
    let ephem_pub_key = PublicKey {
        value: curve_points.generator * encrypting_key,
    };
    let encrypted_message =
        pairing.pair(to_public_key.value.times(&encrypting_key), curve_points.g1) * plaintext;
    let auth_hash = AuthHash::create(hash, &(ephem_pub_key, plaintext));
    sign_value(
        EncryptedValue::EncryptedOnce(EncryptedOnceValue {
            ephemeral_public_key: ephem_pub_key,
            encrypted_message,
            auth_hash,
        }),
        public_signing_key,
        private_signing_key,
        sign,
    )
}

/// Decrypt the signed_encrypted_value, verifying that the embedded public signing key matches the
/// signing private key and that the plaintext hash matches the included `auth_hash`. This method
/// handles both "encrypted once" and "reencrypted" messages.
///
/// # Arguments
/// `privateKey`                - private key of the recipient of the message
/// `signed_encrypted_value`    - the output of encrypt() or reencrypt()
/// `pairing`                   - Optimal Ate Pairing
/// `curve_points`              - IronCore's curve
/// `hash`                      - Sha256Hashing instance
/// `signing`                   - Ed25519Signing instance
///
/// # Return
/// ErrorOr[FP12Elem] the decrypted value, which is an element of G_T, or an error (which might be
/// caused by an authHash comparision failure or a signature validation failure)
pub fn decrypt<T, H: Sha256Hashing, G: Ed25519Signing>(
    private_key: PrivateKey<T>,
    signed_encrypted_value: SignedValue<EncryptedValue<T>>,
    pairing: &Pairing<T>,
    curve_points: &CurvePoints<T>,
    hash: &H,
    signing: &G,
) -> ErrorOr<Fp12Elem<T>>
where
    T: Field
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + Hashable
        + From<[u8; 64]>
        + Default,
{
    verify_signed_value(signed_encrypted_value, signing).map_or(
        Result::Err(InternalError::SignatureFailed),
        |good_encrypted_value| match good_encrypted_value {
            EncryptedValue::EncryptedOnce(encrypted_once_value) => {
                let unverified_plaintext = decrypt_encrypted_once(
                    private_key,
                    &encrypted_once_value,
                    &pairing,
                    curve_points,
                );
                compute_and_compare_auth_hash(
                    encrypted_once_value.auth_hash,
                    encrypted_once_value.ephemeral_public_key,
                    unverified_plaintext,
                    hash,
                )
            }
            EncryptedValue::Reencrypted(re_value) => {
                let unverified_plaintext =
                    decrypt_reencrypted_value(private_key, &re_value, curve_points, pairing, hash);
                compute_and_compare_auth_hash(
                    re_value.auth_hash,
                    re_value.ephemeral_public_key,
                    unverified_plaintext,
                    hash,
                )
            }
        },
    )
}

fn compute_and_compare_auth_hash<FP, H: Sha256Hashing>(
    candidate_auth_hash: AuthHash,
    public_key: PublicKey<FP>,
    unverified_plaintext: Fp12Elem<FP>,
    hash: &H,
) -> ErrorOr<Fp12Elem<FP>>
where
    FP: Field + ExtensionField + PairingConfig + NonAdjacentForm + Hashable,
{
    let computed_auth_hash = AuthHash::create(hash, &(public_key, unverified_plaintext));

    if candidate_auth_hash != computed_auth_hash {
        Result::Err(InternalError::AuthHashMatchFailed)
    } else {
        Result::Ok(unverified_plaintext)
    }
}

/// Decrypt an `EncryptedOnceValue` using private_key.
///
/// # Arguments
/// `private_key`       - private_key matching the publicKey that was used in encrypt.
/// `encrypted_value`   - encrypted_value which needs to be decrypted.
/// `pairing`           - Optimal Ate Pairing
/// `curve_points`      - IronCore's curve
///
/// # Return
/// decrypted value as an FP12 element
fn decrypt_encrypted_once<T>(
    private_key: PrivateKey<T>,
    encrypted_value: &EncryptedOnceValue<T>,
    pairing: &Pairing<T>,
    curve_points: &CurvePoints<T>,
) -> Fp12Elem<T>
where
    T: Field + ExtensionField + PairingConfig + NonAdjacentForm,
{
    let g1 = curve_points.g1;
    let EncryptedOnceValue {
        ephemeral_public_key,
        encrypted_message,
        ..
    } = encrypted_value; //works for now since their is only one case for this enum

    //This is because:
    // m*pair(P,Q)*pair(P,-Q) = m*pair(P,Q)*pair(P,Q)^(-1) = m
    *encrypted_message * pairing.pair(-(ephemeral_public_key.value * private_key.value), g1)
}
/// Decrypt a reencryptedValue using the provided privateKey.
///
/// # Arguments
/// `private_key`       - private key that the ReencryptedValue is destined for.
/// `reencrypted_value` - reencrypted value to decrypt.
///
/// # Return
///  decrypted value as FP12 element
fn decrypt_reencrypted_value<FP, H>(
    private_key: PrivateKey<FP>,
    reencrypted_value: &ReencryptedValue<FP>,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
    sha256: &H,
) -> Fp12Elem<FP>
where
    FP: Field
        + Hashable
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + From<[u8; 64]>
        + Default,
    H: Sha256Hashing,
{
    let re_blocks = &reencrypted_value.encryption_blocks;
    // algorithm specifies that we should operate on the last element of the reencryption blocks
    let re_blocks_last = re_blocks.last();
    let ReencryptionBlock {
        public_key: re_pub_key_last,
        encrypted_temp_key: encrypted_k_last,
        rand_re_public_key: rand_re_pub_key_last,
        encrypted_rand_re_temp_key: enc_rand_re_k_last,
    } = re_blocks_last;

    let sec_to_last_k = KValue(
        *encrypted_k_last
            * pairing.pair(-re_pub_key_last.value * private_key.value, curve_points.g1),
    );
    let sec_to_last_rand_re_k = KValue(
        *enc_rand_re_k_last * pairing.pair(
            -rand_re_pub_key_last.value * private_key.value,
            curve_points.g1,
        ),
    );
    //We're going through the list backwards because we unravel the reencryption blocks from last to first, the last one is special so it's done first.
    let (first_k, first_rand_re_k) = re_blocks.to_vec().iter().rev().skip(1).fold(
        (sec_to_last_k, sec_to_last_rand_re_k),
        |(curr_k, curr_rand_re_k), curr_re_block| {
            let ReencryptionBlock {
                public_key: next_re_pub_key,
                encrypted_temp_key: next_enc_k,
                rand_re_public_key: next_rand_re_pub_key,
                encrypted_rand_re_temp_key: next_enc_rand_re_k,
            } = curr_re_block;
            let curr_k_hash = hash2(curr_k, curve_points, sha256);
            let new_k = KValue(*next_enc_k * pairing.pair(-next_re_pub_key.value, curr_k_hash));
            let new_rand_re_k = KValue(
                *next_enc_rand_re_k * pairing.pair(
                    -next_rand_re_pub_key.value,
                    hash2(curr_rand_re_k, curve_points, sha256) + curr_k_hash,
                ),
            );
            (new_k, new_rand_re_k)
        },
    );
    reencrypted_value.encrypted_message * pairing.pair(
        reencrypted_value.ephemeral_public_key.value.neg(),
        hash2(first_k, curve_points, sha256) + hash2(first_rand_re_k, curve_points, sha256),
    )
}

/// Verifies the Ed25519 signature on a signed value.
///
/// # Arguments
/// `signed_value`  - encrypted value with the public signing key and signature
/// `sign`          - Ed25519Signing signing
///
/// # Return
/// Some around the payload if the signature was valid, or None otherwise
///
fn verify_signed_value<T: Hashable + Clone, G: Ed25519Signing>(
    signed_value: SignedValue<T>,
    sign: &G,
) -> Option<T> {
    if sign.verify(
        &(
            signed_value.public_signing_key,
            signed_value.payload.clone(),
        ),
        &signed_value.signature,
        &signed_value.public_signing_key,
    ) {
        Some(signed_value.payload)
    } else {
        None
    }
}

/// Generate a reencryption key which allows the private key of `to_public_key` to decrypt a message
/// from a (different) from_public_key.
/// The result will be signed using the signingKey.
///
/// # Arguments
/// `from_private_key`          - The privateKey matching the from_public_key
/// `to_public_key`             - the public key to transform to
/// `reencryption_private_key`  - a random private key
/// `new_k`                     - a random FP12 element
/// `public_signing_key`        - Ed25519 public key to include to validate signature
/// `private_signing_key`       - Ed25519 private key to use to sign reencryption key
/// `curve_points`              - IronCore's curve
/// `sha256`                    - Sha256 instance
/// `ed25519`                   - Ed25519Signing instance
///
/// # Return
///  reencryption key, along with an Ed25519 public signing key and Ed25519 signature
/// @clintfred are there some equations or papers we can reference here?
///
pub fn generate_reencryption_key<FP, H, S>(
    from_private_key: PrivateKey<FP>,
    to_public_key: PublicKey<FP>,
    reencryption_private_key: PrivateKey<FP>,
    new_k: KValue<FP>,
    public_signing_key: PublicSigningKey,
    private_signing_key: &PrivateSigningKey,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
    sha256: &H,
    ed25519: &S,
) -> SignedValue<ReencryptionKey<FP>>
where
    FP: Field
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + Hashable
        + From<[u8; 64]>
        + Default,
    H: Sha256Hashing,
    S: Ed25519Signing,
{
    let g1 = curve_points.g1;

    let re_public_key = public_keygen(reencryption_private_key, curve_points.generator);
    let p = to_public_key.value * reencryption_private_key.value;
    let encrypted_k = pairing.pair(p, g1) * new_k.0;
    let hashed_k = hash2(new_k, &curve_points, sha256) + (g1.neg() * from_private_key);
    let reencryption_key = ReencryptionKey {
        re_public_key,
        to_public_key,
        encrypted_k,
        hashed_k,
    };

    sign_value(
        reencryption_key,
        public_signing_key,
        private_signing_key,
        ed25519,
    )
}

/// Fp12Elem that is private and is used in the transform/decrypt algorithms
// we don't derive Copy or Clone here on purpose. KValue is a sensitive value.
pub struct KValue<FP: Clear + Default>(pub(crate) Fp12Elem<FP>);

/// Before KValue is dropped, we want to clear the Fp12, to reduce the value's exposure to snooping.
impl<FP: Default> Drop for KValue<FP> {
    fn drop(&mut self) {
        self.0.clear()
    }
}

impl<'a, FP> Hashable for &'a KValue<FP>
where
    FP: Hashable + Default + Clear + Copy,
{
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl From<api::Plaintext> for KValue<Fp256> {
    fn from(pt: api::Plaintext) -> Self {
        KValue(*pt.internal_fp12())
    }
}

/// Arbitrary hash function to hash an integer into points base field subgroup of the elliptic curve
///
/// # Arguments
/// `k_value`       - Fp12 element to use in the hash
/// `curve_points`  - IronCore's curve
/// `sha256`        - Sha256 implementation
///
fn hash2<FP, H>(
    k_value: KValue<FP>,
    curve_points: &CurvePoints<FP>,
    sha256: &H,
) -> HomogeneousPoint<Fp2Elem<FP>>
where
    FP: Field + Hashable + From<[u8; 64]> + NonAdjacentForm + Default,
    H: Sha256Hashing,
{
    let hash_element = curve_points.hash_element;
    //Produce a 512 bit byte vector, which ensures we have a big enough value for 480 and Fp
    //We use a constant value combined with the entire fp12 element so we don't leak information about the fp12 structure.
    let bytes = array_concat_32(
        &sha256.hash(&(0u8, &k_value)),
        &sha256.hash(&(1u8, &k_value)),
    );
    let fp = FP::from(bytes);
    hash_element * fp
}

/// A reencryption key allows a message encrypted to one public key (the key of the delegator)
/// to be transformed as if it was encrypted to another public key (the key of hte delegatee),
/// so it can be decrypted using the delegatee's private key.
///
/// `re_public_key` - ephemeral key that encrypted the `encrypted_k` value; unique to this ReencryptionKey
/// `to_public_key` - public key of the delegatee (user/device)
/// `encrypted_k`   - random value K, encrypted to the delegatee, that is used to unroll
///                   successive levels of multi-hop transform encryption
/// `hashed_k`      - a combination of the hash of K and the secret key of the delegator,
///                   used to recover `K` from `encrypted_k`
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ReencryptionKey<FP: Field> {
    pub re_public_key: PublicKey<FP>,
    pub to_public_key: PublicKey<FP>,
    pub encrypted_k: Fp12Elem<FP>,
    pub hashed_k: HomogeneousPoint<Fp2Elem<FP>>,
}

impl<FP: Field + Hashable> Hashable for ReencryptionKey<FP> {
    fn to_bytes(&self) -> ByteVector {
        let clone = self;
        (
            &clone.re_public_key,
            &clone.to_public_key,
            &clone.encrypted_k,
        )
            .to_bytes()
    }
}

impl<FP: Field + NonAdjacentForm> ReencryptionKey<FP> {
    ///Augment this ReencryptionKey with a priv_key. This is useful if the ReencryptionKey was from an unaugmented
    ///private key.
    pub fn augment(
        &self,
        priv_key: &PrivateKey<FP>,
        g1: &HomogeneousPoint<Fp2Elem<FP>>,
    ) -> ReencryptionKey<FP> {
        //Note that because priv_key is an Fp negating it would not work, we have to negate the point or the result of
        //the multiplication.
        let new_hashed_k = -(*g1 * priv_key.value) + self.hashed_k;
        ReencryptionKey {
            hashed_k: new_hashed_k,
            ..*self
        }
    }
}

/// Reencrypt an EncryptedValue to a new user. This can be the output of either encrypt() or reencrypt().
/// Will fail if the transformKey signature fails to verify.
///
/// # Arguments
/// `signed_reencryption_key` - A signed version of the reencryption key,which allows a transform from a delegater to a delegatee
/// `signed_encrypted_value`  - A signed version of the encrypted value, which is encrypted to the delegating user.
/// `rand_re_priv_key`            - A new random private key, which will be used to encrypt the rand_re_k.
/// `rand_re_k`                 - A new random integer which is used to ensure that the reencryption block cannot be reused.
/// `private_signing_key`     - The ED25519 private key to sign the reencryption block.
/// `public_signing_key`      - The ED25519 public key matching the private_signing_key.
///
/// # Return
/// ReencryptedValue - if the value could be successfully reencrypted
/// - Left(SignatureFailed|ReencryptionKeyIsCorrupt) - if the signatures weren't valid.
pub fn reencrypt<FP, S, H>(
    signed_reencryption_key: SignedValue<ReencryptionKey<FP>>,
    signed_encrypted_value: SignedValue<EncryptedValue<FP>>,
    rand_re_priv_key: PrivateKey<FP>,
    rand_re_k: KValue<FP>,
    public_signing_key: PublicSigningKey,
    private_signing_key: &PrivateSigningKey,
    ed25519: &S,
    sha256: &H,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
) -> Result<SignedValue<EncryptedValue<FP>>, InternalError>
where
    FP: Field
        + Hashable
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + From<[u8; 64]>
        + Default,
    H: Sha256Hashing,
    S: Ed25519Signing,
{
    match (
        verify_signed_value(signed_encrypted_value, ed25519),
        verify_signed_value(signed_reencryption_key, ed25519),
    ) {
        (Some(EncryptedValue::EncryptedOnce(encrypted_val)), Some(re_key)) => Ok(sign_value(
            EncryptedValue::Reencrypted(reencrypt_encrypted_once(
                re_key,
                encrypted_val,
                rand_re_priv_key,
                rand_re_k,
                curve_points,
                pairing,
                sha256,
            )),
            public_signing_key,
            private_signing_key,
            ed25519,
        )),

        (Some(EncryptedValue::Reencrypted(encrypted_val)), Some(re_key)) => Ok(sign_value(
            EncryptedValue::Reencrypted(reencrypt_reencrypted_value(
                re_key,
                &encrypted_val,
                rand_re_priv_key,
                rand_re_k,
                curve_points,
                pairing,
                sha256,
            )),
            public_signing_key,
            private_signing_key,
            ed25519,
        )),
        (None, _) => Err(InternalError::SignatureFailed),
        (_, None) => Err(InternalError::CorruptReencryptionKey),
    }
}

/**
 * Reencrypt an EncryptedValue to a new key.
 * `reencryption_key` - The reencryption key, which allows a transform from a delegating user to another user
 * `encrypted_value`  - The encrypted value, which is encrypted to the delegating user.
 * `rand_re_priv_key` - A new random private key, which will be used to encrypt the rand_re_temp_key.
 * `rand_re_temp_key` - A new random integer which is used to ensure that the reencryption block cannot be reused.
 * @return - ReencryptedValue as FP12 element
 */
fn reencrypt_encrypted_once<FP, H>(
    ReencryptionKey {
        re_public_key,
        to_public_key,
        encrypted_k,
        hashed_k,
    }: ReencryptionKey<FP>,
    EncryptedOnceValue {
        ephemeral_public_key,
        encrypted_message,
        auth_hash,
    }: EncryptedOnceValue<FP>,
    rand_re_priv_key: PrivateKey<FP>,
    rand_re_temp_key: KValue<FP>,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
    sha256: &H,
) -> ReencryptedValue<FP>
where
    FP: Field
        + Hashable
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + From<[u8; 64]>
        + Default,
    H: Sha256Hashing,
{
    // encrypt and product auth hashes for the rand_re_temp_key
    let rand_re_public_key = public_keygen(rand_re_priv_key, curve_points.generator);

    let encrypted_rand_re_temp_key =
        pairing.pair(to_public_key.value * rand_re_priv_key, curve_points.g1) * rand_re_temp_key.0;
    // Because this is the first reencryption, modify the encrypted_message using rand_re_temp_key
    // Note that this can be decrypted using the reencryption key
    let encrypted_msg_prime = pairing.pair(
        ephemeral_public_key.value,
        hashed_k + hash2(rand_re_temp_key, curve_points, sha256),
    ) * encrypted_message;
    let new_encypted_data = EncryptedOnceValue {
        ephemeral_public_key,
        encrypted_message: encrypted_msg_prime,
        auth_hash,
    };
    let reencryption_block = ReencryptionBlock {
        public_key: re_public_key,
        encrypted_temp_key: encrypted_k,
        rand_re_public_key,
        encrypted_rand_re_temp_key,
    };
    ReencryptedValue::from_encrypted_once(
        &new_encypted_data,
        NonEmptyVec::new_first(reencryption_block),
    )
}

/**
 * Reencrypt a value which was already Reencrypted to yet another person. This is hops 3 through N and can be chained indefinitely.
 * reencryption_key - The key which allows the transform from the current last reencyption block to the reencryption_key.toPublicKey
 * reencrypted_value - Reencrypted value which is going to be transformed
 * rand_re_priv_key - A new random private key, which will be used to encrypt the rand_re_temp_key.
 * rand_re_temp_key - A new random integer which is used to ensure that the reencryption block cannot be reused.
 */
fn reencrypt_reencrypted_value<FP, H>(
    ReencryptionKey {
        re_public_key,
        to_public_key,
        encrypted_k,
        hashed_k,
    }: ReencryptionKey<FP>,
    reencrypted_value: &ReencryptedValue<FP>,
    rand_re_priv_key: PrivateKey<FP>,
    rand_re_temp_key: KValue<FP>,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
    sha256: &H,
) -> ReencryptedValue<FP>
where
    FP: Field
        + Hashable
        + ExtensionField
        + PairingConfig
        + NonAdjacentForm
        + From<[u8; 64]>
        + Default,
    H: Sha256Hashing,
{
    let re_blocks = reencrypted_value.encryption_blocks.clone();
    // algorithm specifies that we should operate on the last element of the reencryption blocks
    let re_blocks_last = re_blocks.last();
    let ReencryptionBlock {
        public_key: re_pub_key_last,
        encrypted_temp_key: encrypted_k_last,
        rand_re_public_key: rand_re_pub_key_last,
        encrypted_rand_re_temp_key: enc_rand_re_k_last,
    } = re_blocks_last;
    let encrypted_k_prime_last = *encrypted_k_last * pairing.pair(re_pub_key_last.value, hashed_k); // re-encrypted K
    let rand_re_pub_key = public_keygen(rand_re_priv_key, curve_points.generator);
    let enc_rand_re_temp_key =
        pairing.pair(to_public_key.value * rand_re_priv_key, curve_points.g1) * rand_re_temp_key.0;
    // Modify the enc_rand_re_temp_key of the last block with the new random reencryption K
    let rand_re_k_last_prime = *enc_rand_re_k_last * pairing.pair(
        rand_re_pub_key_last.value,
        hash2(rand_re_temp_key, curve_points, sha256) + hashed_k,
    );
    let re_block_last_prime =
        re_blocks_last.with_temp_key(encrypted_k_prime_last, rand_re_k_last_prime);
    let new_re_block = ReencryptionBlock {
        public_key: re_public_key,
        encrypted_temp_key: encrypted_k,
        rand_re_public_key: rand_re_pub_key,
        encrypted_rand_re_temp_key: enc_rand_re_temp_key,
    };
    // Because we modified the last block, replace it and append the new block as well
    let new_len = re_blocks.len() - 1;
    let new_blocks_vec = NonEmptyVec::new_last(
        &re_blocks.to_vec()[..new_len],
        NonEmptyVec::new(re_block_last_prime, vec![new_re_block]),
    );
    reencrypted_value.with_new_re_blocks(new_blocks_vec)
}

#[cfg(test)]
mod test {
    use super::*;
    use api::test::DummyRandomBytes;
    use internal::ed25519::Ed25519;
    use internal::fp12elem::test::arb_fp12;
    use internal::homogeneouspoint::test::arb_homogeneous;
    use internal::sha256::Sha256;
    use internal::sum_n;
    use num_traits::Pow;
    use proptest::arbitrary::any;
    use proptest::prelude::*;
    prop_compose! {
        [pub] fn arb_fp256()(seed in any::<u64>()) -> Fp256 {
            if seed == 0 {
                Fp256::zero()
            } else if seed == 1 {
                Fp256::one()
            } else {
                Fp256::from(seed).pow(seed)
            }
        }
    }

    struct Mocks;

    impl Ed25519Signing for Mocks {
        fn sign<T: Hashable>(&self, _t: &T, _private_key: &PrivateSigningKey) -> Ed25519Signature {
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

    impl Sha256Hashing for Mocks {
        fn hash<T: Hashable>(&self, _t: &T) -> [u8; 32] {
            [0; 32]
        }
    }

    struct AlwaysFailVerifyEd25519Signing;

    impl Ed25519Signing for AlwaysFailVerifyEd25519Signing {
        fn sign<T: Hashable>(&self, _t: &T, _private_key: &PrivateSigningKey) -> Ed25519Signature {
            Ed25519Signature::new([0; 64])
        }

        fn verify<T: Hashable>(
            &self,
            _t: &T,
            _signature: &Ed25519Signature,
            _public_key: &PublicSigningKey,
        ) -> bool {
            false
        }
    }

    //copied from API as it's private there
    fn gen_random_fp12<R: rand_bytes::RandomBytesGen>(random_bytes: &mut R) -> Fp12Elem<Fp256> {
        // generate 12 random Fp values
        gen_rth_root(
            &pairing::Pairing::new(),
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
            ),
        )
    }

    #[test]
    fn array_concat_32_array_split_roundtrip() {
        let one = [1u8; 32];
        let two = [2u8; 32];
        let concat = array_concat_32(&one, &two);
        let (res1, res2) = array_split_64(&concat);
        assert_eq!(one, res1);
        assert_eq!(two, res2);
    }

    #[test]
    fn pow_for_square_works() {
        let v = Fp256::from(10);
        let result = pow_for_square(v, 2);
        assert_eq!(result, v.pow(2));
        let result2 = pow_for_square(v, 5);
        assert_eq!(result2, v.pow(5));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn create_transform_key_known_value() {
        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let ref ed25519 = api::test::DummyEd25519;
        let pbsk = PublicSigningKey::new([0;32]);
        let pvsk = PrivateSigningKey::new([0;64]);

        //37777967648492203239675772600961898148040325589588086812374811831221462604944
        let parsed_priv_key = Fp256::new(
            [17189375727870516368,
             18224873185075715024,
             7861335034745733951,
             6018377467983639816]);
        let private_key = PrivateKey {
            value: parsed_priv_key
        };

        //22002131259228303741090495322318969764532178674829148099822698556219881568451
        let re_private_parsed = Fp256::new(
            [4788877933930756291,
             4788243223430685001,
             12830453561780987202,
             3505141733675108717]
        );
        let re_private_key = PrivateKey {
            value: re_private_parsed
        };

        //56377452267431283559088187378398270325210563762492926393848580098576649271541
        let parsed_pub_key_x = Fp256::new(
            [1788354481340266741,
             6941240287463798938,
             4130173504620995341,
             8981446317750070851]
        );
        //46643694276241842996939080253335644316475473619096522181405937227991761798154
        let parsed_pub_key_y = Fp256::new([3047215073141965834,
             7252896082344953161,
             7531499505638418112,
             7430769205681594307]
        );
        let public_key = PublicKey::from_x_y_fp256(parsed_pub_key_x, parsed_pub_key_y).unwrap();

        let salt = KValue(Fp12Elem::create_from_t(
            //20621517740542501009268492188240231175004875885443969425948886451683622135253
            Fp256::new([18092919563963868629,
                7535312703102788932,
                186825010492696858,
                3285197310773262209]
            ),
            //34374877744619883729582518521480375735530540362125629015072222432427068254516
            Fp256::new([17874798795115358516, 10509553017551504414, 17012896929314934145, 5476233968112089136]),
            //3061516916225902041514148805993070634368655849312514173666756917317148753791
            Fp256::new([2796847722043686783, 16414031163437355558, 14261424020660524668, 487727783503465407]),
            //36462333850830053304472867079357777410712443208968594405185610332940263631144
            Fp256::new([416187413262903592, 14122611974139580613, 17310812515621325570, 5808784911876835769]),
            //61512103449194136219283269928242996434577060883392017268158197606945715641345
            Fp256::new([7642361093456649217, 5130777198153281356, 11536797972669047883, 9799443444165379604]),
            //6400685679296646713554926627062187315936943674688629293503755450503276487519
            Fp256::new([8431854297172108127, 7450944574332271141, 2874140390769630277, 1019688058138881344]),
            //53751186939356616119935218564341196608994152768328518524478036628068165341835
            Fp256::new([3519691940394553995, 11232323575149724221, 14985771333848137161, 8563058112685733978]),
            //24086990466602794093787211540995552936111869178774386613517233502609109093865
            Fp256::new([5738022665900723689, 11696368252523858187, 9012076498597896774, 3837278967586940365]),
            //61396452992397102589850224464045014903468298857108669606429537125544948220026
            Fp256::new([6727065639392985210, 4848553194461313843, 11191929622260275755, 9781019263441166863]),
            //15909384434160564083979503677021998800821775569159782381560100961841901513229
            Fp256::new([17260445456023464461, 3557834823344504179, 3352261581837594978, 2534511165315774091]),
            //60608834117224548548490931258722195552088501100182383267798941700183023164589
            Fp256::new([5004153509371452589, 16294162787904550875, 220950411748700060, 9655544337531903215]),
            //17433339776741835027827317970122814431745024562995872600925458287403992082321
            Fp256::new([716814800932300689, 17116457880960511458, 14343763253984106508, 2777291258235104886])
        ));

        let re_key = generate_reencryption_key(
            private_key,
            public_key,
            re_private_key,
            salt,
            pbsk,
            &pvsk,
            curve_points,
            &pairing,
            sha256,
            ed25519).payload;


        let good_encrypted_k = Fp12Elem::create_from_t(
            //12468319166808038973695145957420708896894989833062445136258751614714728860674
            Fp256::new([7407619104651529218, 11463625481515793061, 5779432075019267186, 1986317841005960384]),
            //2128854359484213588380497318350091194644767868675298191307887815867151037785
            Fp256::new([5296659303137686873, 4280257893045319426, 13321863481405346776, 339146066007335840]),
            //21445177129013608048665933252873170350264030103628078278539253145170500354896
            Fp256::new([11955219787330847568, 17307907405273938070, 6050002638559171205, 3416413821703424493]),
            //56038156109742185788555899045964131128124373881320309662221006159550412032591
            Fp256::new([11028330629390207567, 16277126227596076559, 4506129636556298670, 8927393321320788585]),
            //26914485966895326452176682212429959307113556759541870452048350761624956307220
            Fp256::new([14929701004962957076, 11618023364955498545, 11149460125633770324, 4287724988614884330]),
            //47982890198790824855446467783137770650698480322416616491158632550503307113855
            Fp256::new([16663177338467743103, 9761509637791858731, 6430727702093942934, 7644115424845028812]),
            //10711644709861300386519729424210641312562914145500366805337572652137411248028
            Fp256::new([11454739616096583580, 18111719416759575391, 463464369169095836, 1706463454220476131]),
            //43347748542964759695743884414110499509686690671474974704725984636415455585090
            Fp256::new([3018797931778597698, 10419318108488400682, 14645641859123347738, 6905694756960070262]),
            //17596819370787728602670144220164446940512614719945259504347007792221644397210
            Fp256::new([13171388654358895258, 15528195738974811681, 16793703368871851779, 2803335060126077892]),
            //38746694397885185117442963327077624722941852366420178940757070667288257609651
            Fp256::new([16075574095286747059, 5527914106918380322, 14163459131246838794, 6172704542839199181]),
            //38002592948627699884055358711985526413232379309204607956998925141882284407414
            Fp256::new([8615044640359185014, 4124215179308147679, 8986594639588272636, 6054162342851795720]),
            //49941783284737700171954796486309114156831309184207470337019703077683277143423
            Fp256::new([4319420581507833215, 8897085582877617929, 10387143255934299553, 7956185097844554281])
        );

        let good_hashed_k = HomogeneousPoint {
            x: fp2elem::Fp2Elem {
                //22422077836615563303859289302360681993513791649150629779433386726239734002618
                elem1: Fp256::new([15317763025871500218, 6390131415937895053, 2333868648931173919, 3572043083229448878]),
                //52027607726191528801608200848909742835559726958532705354275625739433988283036
                elem2: Fp256::new([14223329351633427100, 16393628357177966161, 4178163731932019692, 8288476102416800248])
            },
            y: fp2elem::Fp2Elem {
                //4645247538810084127206561896955679361089846324400619601984418530338530410972
                elem1: Fp256::new([6377061368106074588, 1323000841828716335, 3985357987373299809, 740030627928627720]),
                //34485967566945102067940948289591403523736094597232197502117656471251591927196
                elem2: Fp256::new([5040653610201421212, 6584711892080312693, 9762190934038319400, 5493931597847633801])
            },
            z: fp2elem::Fp2Elem {
                //2258730050599105467979057492418988601962605970075660368624801947296357678159
                elem1: Fp256::new([15628823850961861711, 10372016414646397245, 6029716315346157217, 359836457304122956]),
                //18358874287282838450918898019272385250887285769392485811015731318886010089831
                elem2: Fp256::new([5575879339459113319, 6203973355951852449, 15340759962329721833, 2924737412456785480])
            }
        };

        assert_eq!(good_encrypted_k, re_key.encrypted_k);
        assert_eq!(good_hashed_k, re_key.hashed_k)
    }

    #[test]
    fn reencrypt_roundtrip_with_known_keys() {
        let pt_fp12 = Fp12Elem::create_from_t(
            Fp256::from(1),
            Fp256::from(2),
            Fp256::from(3),
            Fp256::from(4),
            Fp256::from(5),
            Fp256::from(6),
            Fp256::from(7),
            Fp256::from(8),
            Fp256::from(9),
            Fp256::from(10),
            Fp256::from(11),
            Fp256::from(12),
        );
        let salt_fp12 = Fp12Elem::create_from_t(
            Fp256::from(11),
            Fp256::from(12),
            Fp256::from(13),
            Fp256::from(14),
            Fp256::from(15),
            Fp256::from(16),
            Fp256::from(17),
            Fp256::from(18),
            Fp256::from(19),
            Fp256::from(110),
            Fp256::from(111),
            Fp256::from(112),
        );
        let rand_re_k_fp12 = Fp12Elem::create_from_t(
            Fp256::from(21),
            Fp256::from(22),
            Fp256::from(23),
            Fp256::from(24),
            Fp256::from(25),
            Fp256::from(26),
            Fp256::from(27),
            Fp256::from(28),
            Fp256::from(29),
            Fp256::from(210),
            Fp256::from(211),
            Fp256::from(212),
        );

        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let ref ed25519 = api::test::DummyEd25519;
        let salt = KValue(gen_rth_root(&pairing, salt_fp12));
        let pbsk = PublicSigningKey::new([0; 32]);
        let pvsk = PrivateSigningKey::new([0; 64]);

        let re_private = PrivateKey::from_fp256(
            //22002131259228303741090495322318969764532178674829148099822698556219881568451
            Fp256::new([
                4788877933930756291,
                4788243223430685001,
                12830453561780987202,
                3505141733675108717,
            ]),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //24550233719269254106556478663938123459765238883583743938937070753673053032673
            Fp256::new([
                14793504136496500961,
                15175545718199138505,
                10822834284350498357,
                3911077875457902790,
            ]),
        );
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            Fp256::new([
                4343411144194473122,
                3301349774239543721,
                14670225672814360477,
                7004277019202547328,
            ]),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let plaintext = pt_fp12;
        let encrypt_result = encrypt(
            pub_key,
            plaintext,
            ephem_priv_key,
            pbsk,
            &pvsk,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        );
        let rand_re_priv_key = PrivateKey::from_fp256(
            //17561965855055966875289582496525889116201409974621952158489640859240156546764
            Fp256::new([
                12307718303527388876,
                9236064098299522403,
                14597629839067767666,
                2797782574727398164,
            ]),
        );
        let rand_re_k = KValue(gen_rth_root(&pairing, rand_re_k_fp12));
        let re_key = generate_reencryption_key(
            priv_key,
            pub_key,
            re_private,
            salt,
            pbsk,
            &pvsk,
            curve_points,
            &pairing,
            sha256,
            ed25519,
        );

        let reencrypted_value = reencrypt(
            re_key,
            encrypt_result,
            rand_re_priv_key,
            rand_re_k,
            pbsk,
            &pvsk,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        ).unwrap();

        let decrypted_value = decrypt(
            priv_key,
            reencrypted_value,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        ).unwrap();
        assert_eq!(decrypted_value, plaintext)
    }

    #[test]
    fn fail_when_verify_fails() {
        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let salt1 = gen_rth_root(&pairing, gen_random_fp12(&mut DummyRandomBytes));
        let pbsk = PublicSigningKey::new([0; 32]);
        let pvsk = PrivateSigningKey::new([0; 64]);
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            Fp256::new([
                4343411144194473122,
                3301349774239543721,
                14670225672814360477,
                7004277019202547328,
            ]),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //88866559432365357341903140497410248873099149633601160471165130153973144042888
            Fp256::new([
                4343411144194473352,
                5979978379713320361,
                12081649158504707828,
                14157259700187258052,
            ]),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let encrypted_value = encrypt(
            pub_key,
            salt1,
            ephem_priv_key,
            pbsk,
            &pvsk,
            &pairing,
            curve_points,
            sha256,
            &AlwaysFailVerifyEd25519Signing,
        );
        let decrypt_result = decrypt(
            priv_key,
            encrypted_value,
            &pairing,
            curve_points,
            sha256,
            &AlwaysFailVerifyEd25519Signing,
        );
        if let Err(InternalError::SignatureFailed) = decrypt_result {
            //pass
        } else {
            assert!(false, "Error should have been returned")
        }
    }

    #[test]
    fn fail_when_auth_hash_does_not_match_wrong_priv_key() {
        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let salt1 = gen_rth_root(&pairing, gen_random_fp12(&mut DummyRandomBytes));
        let pbsk = PublicSigningKey::new([0; 32]);
        let pvsk = PrivateSigningKey::new([0; 64]);
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            Fp256::new([
                4343411144194473122,
                3301349774239543721,
                14670225672814360477,
                7004277019202547328,
            ]),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //88866559432365357341903140497410248873099149633601160471165130153973144042888
            Fp256::new([
                4343411144194473352,
                5979978379713320361,
                12081649158504707828,
                14157259700187258052,
            ]),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let encrypted_value = encrypt(
            pub_key,
            salt1,
            ephem_priv_key,
            pbsk,
            &pvsk,
            &pairing,
            curve_points,
            sha256,
            &Mocks,
        );

        let diff_priv_key = PrivateKey::from_fp256(Fp256::from(42));
        let decrypt_result = decrypt(
            diff_priv_key,
            encrypted_value,
            &pairing,
            curve_points,
            sha256,
            &Mocks,
        );

        if let Err(InternalError::AuthHashMatchFailed) = decrypt_result {
            //pass
        } else {
            assert!(false, "Auth hash check should fail")
        }
    }
    #[test]
    fn reencrypt_2nd_level_roundtrip_with_known_keys_and_auth_hash_checks() {
        let pt_fp12 = Fp12Elem::create_from_t(
            Fp256::from(1),
            Fp256::from(2),
            Fp256::from(3),
            Fp256::from(4),
            Fp256::from(5),
            Fp256::from(6),
            Fp256::from(7),
            Fp256::from(8),
            Fp256::from(9),
            Fp256::from(10),
            Fp256::from(11),
            Fp256::from(12),
        );
        let salt_1_fp12 = Fp12Elem::create_from_t(
            Fp256::from(11),
            Fp256::from(12),
            Fp256::from(13),
            Fp256::from(14),
            Fp256::from(15),
            Fp256::from(16),
            Fp256::from(17),
            Fp256::from(18),
            Fp256::from(19),
            Fp256::from(110),
            Fp256::from(111),
            Fp256::from(112),
        );
        let rand_re_k_1_fp12 = Fp12Elem::create_from_t(
            Fp256::from(21),
            Fp256::from(22),
            Fp256::from(23),
            Fp256::from(24),
            Fp256::from(25),
            Fp256::from(26),
            Fp256::from(27),
            Fp256::from(28),
            Fp256::from(29),
            Fp256::from(210),
            Fp256::from(211),
            Fp256::from(212),
        );
        let salt_2_fp12 = Fp12Elem::create_from_t(
            Fp256::from(31),
            Fp256::from(32),
            Fp256::from(33),
            Fp256::from(34),
            Fp256::from(35),
            Fp256::from(36),
            Fp256::from(37),
            Fp256::from(38),
            Fp256::from(39),
            Fp256::from(310),
            Fp256::from(311),
            Fp256::from(312),
        );
        let rand_re_k_2_fp12 = Fp12Elem::create_from_t(
            Fp256::from(41),
            Fp256::from(42),
            Fp256::from(43),
            Fp256::from(44),
            Fp256::from(45),
            Fp256::from(46),
            Fp256::from(47),
            Fp256::from(48),
            Fp256::from(49),
            Fp256::from(410),
            Fp256::from(411),
            Fp256::from(412),
        );

        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let ref ed25519 = api::test::DummyEd25519;
        let salt1 = KValue(gen_rth_root(&pairing, salt_1_fp12));
        let pbsk = PublicSigningKey::new([0; 32]);
        let pvsk = PrivateSigningKey::new([0; 64]);

        let re_private = PrivateKey::from_fp256(
            //22002131259228303741090495322318969764532178674829148099822698556219881568451
            Fp256::new([
                4788877933930756291,
                4788243223430685001,
                12830453561780987202,
                3505141733675108717,
            ]),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //24550233719269254106556478663938123459765238883583743938937070753673053032673
            Fp256::new([
                14793504136496500961,
                15175545718199138505,
                10822834284350498357,
                3911077875457902790,
            ]),
        );
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            Fp256::new([
                4343411144194473122,
                3301349774239543721,
                14670225672814360477,
                7004277019202547328,
            ]),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let priv_key2 = PrivateKey::from_fp256(
            //22266559432365357341903140497410248873090149633601160471165130153973144042608
            Fp256::new([
                17194266036165098608,
                9037271175465250277,
                11853952711362131111,
                3547267572045125887,
            ]),
        );
        let pub_key2 = public_keygen(priv_key2, curve_points.generator);
        let priv_key3 = PrivateKey::from_fp256(
            //33333359432365357341903140497410248873090149633601160471165130153973144042608
            Fp256::new([
                17194266036165098608,
                12893008869371042789,
                10789969574966048103,
                5310310528257188173,
            ]),
        );
        let pub_key3 = public_keygen(priv_key3, curve_points.generator);

        let plaintext = gen_rth_root(&pairing, pt_fp12);

        // First level encryption
        let encrypt_result = encrypt(
            pub_key,
            plaintext,
            ephem_priv_key,
            pbsk,
            &pvsk,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        );
        let rand_re_priv_key = PrivateKey::from_fp256(
            //17561965855055966875289582496525889116201409974621952158489640859240156546764
            Fp256::new([
                12307718303527388876,
                9236064098299522403,
                14597629839067767666,
                2797782574727398164,
            ]),
        );
        let rand_re_k = KValue(gen_rth_root(&pairing, rand_re_k_1_fp12));
        let re_key = generate_reencryption_key(
            priv_key,
            pub_key2,
            re_private,
            salt1,
            pbsk,
            &pvsk,
            curve_points,
            &pairing,
            sha256,
            ed25519,
        );

        //first level of REencryption
        let reencrypted_value = reencrypt(
            re_key,
            encrypt_result,
            rand_re_priv_key,
            rand_re_k,
            pbsk,
            &pvsk,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        ).unwrap();

        // the fun has just begun! Do a second level of reencryption
        let rand_re_priv_key_2 = PrivateKey::from_fp256(
            //1756196585505596687528958249652588911620140997462195215848000000000
            Fp256::new([
                14537025737697333248,
                14405801590671684734,
                8720510408043004481,
                279778257,
            ]),
        );
        let re_priv_2 = PrivateKey::from_fp256(
            //22002131259228303741090495322318969763333178674829148099822698556219881568451
            Fp256::new([
                9459678164233369795,
                13577299277762900646,
                12830453561780987198,
                3505141733675108717,
            ]),
        );
        let rand_re_k_2 = KValue(gen_rth_root(&pairing, rand_re_k_2_fp12));
        let salt2 = KValue(gen_rth_root(&pairing, salt_2_fp12));
        let reencryption_key_2 = generate_reencryption_key(
            priv_key2,
            pub_key3,
            re_priv_2,
            salt2,
            pbsk,
            &pvsk,
            curve_points,
            &pairing,
            sha256,
            ed25519,
        );

        let reencrypted_value_2 = reencrypt(
            reencryption_key_2,
            reencrypted_value,
            rand_re_priv_key_2,
            rand_re_k_2,
            pbsk,
            &pvsk,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        ).unwrap();

        if let EncryptedValue::Reencrypted(v) = reencrypted_value_2.payload.clone() {
            assert_eq!(2, v.encryption_blocks.len())
        } else {
            assert!(false, "This should be a reencrypted value")
        }

        let decrypted_value = decrypt(
            priv_key3,
            reencrypted_value_2.clone(),
            &pairing,
            curve_points,
            sha256,
            ed25519,
        ).unwrap();
        assert_eq!(decrypted_value, plaintext);

        //finally, show that a invalid private key will force an auth hash failure
        let invalid_priv_key = PrivateKey::from_fp256(Fp256::from(42));
        let decrypt_auth_failure = decrypt(
            invalid_priv_key,
            reencrypted_value_2,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        );
        if let Err(InternalError::AuthHashMatchFailed) = decrypt_auth_failure {
            // pass
        } else {
            assert!(false, "Private key should have caused an auth hash failure")
        }
    }

    fn good_signing_keys() -> (PrivateSigningKey, PublicSigningKey) {
        // pub/priv signing keys precomputed
        let pub_signing_key = ed25519::PublicSigningKey::new([
            138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9,
            191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ]);
        let priv_signing_key = ed25519::PrivateSigningKey::new([
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
            103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ]);
        (priv_signing_key, pub_signing_key)
    }

    proptest! {
        #[test]
        fn sign_verify_roundtrip(fp256 in arb_fp256()) {
            let (priv_signing_key, pub_signing_key) = good_signing_keys();
            let signed_value = sign_value(fp256, pub_signing_key, &priv_signing_key, &Ed25519);
            let verified = verify_signed_value(signed_value, &Ed25519);
            prop_assert!(verified.is_some())
        }
        #[test]
        fn encrypt_decrypt_roundtrip(priv_key in arb_priv_key(), plaintext in arb_fp12().prop_filter("", |a| !(*a == Fp12Elem::<Fp256>::zero()))) {
            let pub_key = public_keygen(priv_key, curve::FP_256_CURVE_POINTS.generator);
            let ephem_secret_key = PrivateKey::from_fp256(Fp256::new_from_u64(42));
            let (priv_signing_key, pub_signing_key) = good_signing_keys();
            let pairing = pairing::Pairing::new();
            let curve_points = &*curve::FP_256_CURVE_POINTS;
            let encrypt_result = encrypt(
                pub_key,
                plaintext,
                ephem_secret_key,
                pub_signing_key,
                &priv_signing_key,
                &pairing,
                curve_points,
                &Sha256,
                &Ed25519
            );
            let decrypt_result = decrypt(
                priv_key,
                encrypt_result,
                &pairing,
                curve_points,
                &Sha256,
                &Ed25519
            ).unwrap();
            assert_eq!(plaintext, decrypt_result);
        }

        #[test]
        fn sum_n_is_times(x in any::<i32>(), n in any::<i32>()) {
            //all the casts are to ensure we don't overflow.
            let computed_result = if n < 0 {
                -sum_n(x as i64, n.abs() as u64)
            } else{
                sum_n(x as i64, n as u64)
            };
            prop_assert_eq!(computed_result, (x as i64) * (n as i64));
        }

        #[test]
        fn generate_reencryption_key_sig_not_over_hashedk(
            signed_re_key in arb_reencryption_key(),
            fp in arb_fp256()
            ) {

            let cpoints = &*curve::FP_256_CURVE_POINTS;
            let new_hashed_k = cpoints.g1 * fp;
            let re_key: ReencryptionKey<Fp256> = signed_re_key.payload.clone();

            // clone the ReencryptionKey, replacing the hashed_k with the arb one
            let re_key_copy = ReencryptionKey {
                re_public_key: re_key.re_public_key,
                to_public_key: re_key.to_public_key,
                encrypted_k: re_key.encrypted_k,
                hashed_k: new_hashed_k // replaced hashed_k!

            };

            prop_assert_eq!(signed_re_key.payload.to_bytes(), re_key_copy.to_bytes())
        }
    }

    prop_compose! {
        [pub] fn arb_pub_key()(ref hpoint in arb_homogeneous().prop_filter("", |a| !(*a == Zero::zero()))) -> PublicKey<Fp256> {
            PublicKey { value: *hpoint }
        }
    }

    prop_compose! {
        [pub] fn arb_priv_key()(fp256 in arb_fp256().prop_filter("", |a| !(*a == Zero::zero()))) -> PrivateKey<Fp256> {
            PrivateKey { value: fp256 }
        }
    }

    prop_compose! {
        fn arb_reencryption_key()
        (ref reencryption_private_key in arb_priv_key(),
         ref new_k in arb_fp12(),
         to_public_key in arb_pub_key(),
         from_private_key in arb_priv_key())
         -> SignedValue<ReencryptionKey<Fp256>> {
            let pairing = pairing::Pairing::new();
            let curve_points = &*curve::FP_256_CURVE_POINTS;

            generate_reencryption_key(
                from_private_key,
                to_public_key,
                *reencryption_private_key,
                KValue(*new_k),
                PublicSigningKey::new([0; 32]),
                &PrivateSigningKey::new([0;64]),
                &curve_points,
                &pairing,
                &Mocks,
                &Mocks
            )
        }
    }
}
