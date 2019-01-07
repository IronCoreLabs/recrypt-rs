use crate::internal::bit_repr::BitRepr;
use crate::internal::curve::CurvePoints;
use crate::internal::ed25519::{
    Ed25519Signature, Ed25519Signing, PublicSigningKey, SigningKeypair,
};
use crate::internal::field::ExtensionField;
use crate::internal::field::Field;
use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::internal::fp12elem::Fp12Elem;
use crate::internal::hashable::{Hashable, Hashable32, Hashable60};
use crate::internal::homogeneouspoint::{HomogeneousPoint, PointErr, TwistedHPoint};
use crate::internal::pairing::Pairing;
use crate::internal::pairing::PairingConfig;
use crate::internal::sha256::Sha256Hashing;
use crate::nonemptyvec::NonEmptyVec;
use clear_on_drop::clear::Clear;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;
use num_traits::{One, Zero};
use quick_error::quick_error;
use std::ops::{Add, Mul, Neg};
#[macro_use]
pub mod macros;
pub mod bit_repr;
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
pub mod pairing;
pub mod rand_bytes;
pub mod schnorr;
pub mod sha256;

use crate::api;
use crate::api_480;

pub type ByteVector = Vec<u8>;
pub type ErrorOr<T> = Result<T, InternalError>;

quick_error! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum InternalError {
        AuthHashMatchFailed {}
        InvalidEncryptedMessageSignature {}
        PointInvalid(err: PointErr) {
            cause(err)
            from()
        }
        CorruptReencryptionKey {}
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PublicKey<T: Field> {
    pub value: HomogeneousPoint<T>,
}

impl<T: Field + From<u32> + Hashable> PublicKey<T> {
    pub fn new(point: HomogeneousPoint<T>) -> PublicKey<T> {
        PublicKey { value: point }
    }

    pub fn from_x_y(x: T, y: T) -> ErrorOr<PublicKey<T>> {
        Ok(HomogeneousPoint::from_x_y((x, y)).map(|value| PublicKey { value })?)
    }
}

impl PublicKey<Fp256> {
    pub fn to_byte_vectors_32(&self) -> Option<([u8; 32], [u8; 32])> {
        self.value
            .normalize()
            .map(|(x, y)| (x.to_bytes_32(), y.to_bytes_32()))
    }
}

impl PublicKey<Fp480> {
    pub fn to_byte_vectors_60(&self) -> Option<([u8; 60], [u8; 60])> {
        self.value
            .normalize()
            .map(|(x, y)| (x.to_bytes_60(), y.to_bytes_60()))
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

impl From<api_480::PrivateKey> for PrivateKey<Fp480> {
    fn from(api_pk: api_480::PrivateKey) -> Self {
        PrivateKey {
            value: Fp480::from(api_pk.to_bytes_60()),
        }
    }
}

impl<'a> From<&'a api_480::PrivateKey> for PrivateKey<Fp480> {
    fn from(api_pk: &'a api_480::PrivateKey) -> Self {
        PrivateKey {
            value: Fp480::from(api_pk.to_bytes_60()),
        }
    }
}

impl PrivateKey<Fp480> {
    pub fn from_fp480(fp480: Fp480) -> PrivateKey<Fp480> {
        PrivateKey { value: fp480 }
    }
}

impl<T> BitRepr for PrivateKey<T>
where
    T: BitRepr + Copy,
{
    fn to_bits(&self) -> Vec<u8> {
        self.value.to_bits()
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct SignedValue<T> {
    pub public_signing_key: PublicSigningKey,
    pub signature: Ed25519Signature,
    pub payload: T,
}

impl<T: Hashable> Hashable for SignedValue<T> {
    fn to_bytes(&self) -> ByteVector {
        (&self.public_signing_key, &self.payload).to_bytes()
    }
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
            ]
            .to_bytes(),
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
            ]
            .to_bytes(),
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
impl Square for gridiron::fp_480::Fp480 {
    fn square(&self) -> Self {
        self.square()
    }
}

impl Square for Fr480 {
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

pub fn array_concat_60<T: Copy + Zero>(one: &[T; 60], two: &[T; 60]) -> [T; 120] {
    let mut result: [T; 120] = [T::zero(); 120];
    result[0..60].copy_from_slice(&one[..]);
    result[60..120].copy_from_slice(&two[..]);
    result
}

pub fn array_split_64<T: Copy + Zero>(array: &[T; 64]) -> ([T; 32], [T; 32]) {
    let mut one = [T::zero(); 32];
    let mut two = [T::zero(); 32];
    one.copy_from_slice(&array[0..32]);
    two.copy_from_slice(&array[32..64]);
    (one, two)
}

//TODO duplication
pub fn array_split_120<T: Copy + Zero>(array: &[T; 120]) -> ([T; 60], [T; 60]) {
    let mut one = [T::zero(); 60];
    let mut two = [T::zero(); 60];
    one.copy_from_slice(&array[0..60]);
    two.copy_from_slice(&array[60..120]);
    (one, two)
}
/// Generate one of the rth roots of unity (an element of G_T) given an FP12Elem.
/// Useful for calling `encrypt`
pub fn gen_rth_root<T>(pairing: &Pairing<T>, fp12_elem: Fp12Elem<T>) -> Fp12Elem<T>
where
    T: ExtensionField + PairingConfig,
{
    pairing.final_exp(fp12_elem)
}

///Generate a public key using the private key and generator point.
pub fn public_keygen<T>(private_key: PrivateKey<T>, generator: HomogeneousPoint<T>) -> PublicKey<T>
where
    T: Field + BitRepr,
{
    PublicKey {
        value: generator * private_key.value,
    }
}

/// Signs some value of type `T` (and the publicSigningKey) with privateSigningKey.
///
/// # Arguments
/// `payload` - value to sign; must be a type with an associated Hashable instance
/// `signing_keypair` - the Ed25519 keypair that is used to compute the signature
/// `ed25519` - Implementation of `Ed25519Signing` trait
///
/// # Return
/// SignedValue<T> - contains the value `payload`, the public signingkey, and the computed signature
fn sign_value<T, F: Ed25519Signing>(
    payload: T,
    signing_keypair: &SigningKeypair,
    ed25519: &F,
) -> SignedValue<T>
where
    T: Hashable + Clone,
{
    let public_signing_key = signing_keypair.public_key();
    let signature = ed25519.sign(&(&public_signing_key, &payload), signing_keypair);
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
/// `signing_keypair`       - the public portion of the encrypter's signing key pair
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
    signing_keypair: &SigningKeypair,
    pairing: &Pairing<T>,
    curve_points: &CurvePoints<T>,
    hash: &F,
    sign: &G,
) -> SignedValue<EncryptedValue<T>>
where
    T: ExtensionField + PairingConfig + BitRepr + Hashable,
{
    let ephem_pub_key = PublicKey {
        value: curve_points.generator * encrypting_key,
    };
    let encrypted_message =
        pairing.pair(to_public_key.value.times(&encrypting_key), curve_points.g1) * plaintext;
    let auth_hash = AuthHash::create(hash, &(&ephem_pub_key, &plaintext));
    sign_value(
        EncryptedValue::EncryptedOnce(EncryptedOnceValue {
            ephemeral_public_key: ephem_pub_key,
            encrypted_message,
            auth_hash,
        }),
        signing_keypair,
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
    T: ExtensionField + PairingConfig + BitRepr + Hashable + From<[u8; 64]> + Default,
{
    verify_signed_value(signed_encrypted_value, signing).map_or(
        Result::Err(InternalError::InvalidEncryptedMessageSignature),
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
    FP: ExtensionField + PairingConfig + BitRepr + Hashable,
{
    let computed_auth_hash = AuthHash::create(hash, &(&public_key, &unverified_plaintext));

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
    T: ExtensionField + PairingConfig + BitRepr,
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
    FP: Hashable + ExtensionField + PairingConfig + BitRepr + From<[u8; 64]> + Default,
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
        *enc_rand_re_k_last
            * pairing.pair(
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
                *next_enc_rand_re_k
                    * pairing.pair(
                        -next_rand_re_pub_key.value,
                        hash2(curr_rand_re_k, curve_points, sha256) + curr_k_hash,
                    ),
            );
            (new_k, new_rand_re_k)
        },
    );
    reencrypted_value.encrypted_message
        * pairing.pair(
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
        &signed_value,
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
/// `signing_keypair`           - Ed25519 keypair to use to sign reencryption key
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
    signing_keypair: &SigningKeypair,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
    sha256: &H,
    ed25519: &S,
) -> SignedValue<ReencryptionKey<FP>>
where
    FP: ExtensionField + PairingConfig + BitRepr + Hashable + From<[u8; 64]> + Default,
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

    sign_value(reencryption_key, signing_keypair, ed25519)
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

impl<FP> Hashable for KValue<FP>
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
impl From<api_480::Plaintext> for KValue<Fp480> {
    fn from(pt: api_480::Plaintext) -> Self {
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
) -> TwistedHPoint<FP>
where
    FP: Hashable + From<[u8; 64]> + BitRepr + Default + ExtensionField,
    H: Sha256Hashing,
{
    let hash_element = curve_points.hash_element;
    //Produce a 512 bit byte vector, which ensures we have a big enough value for 480 and Fp
    //We use a constant value combined with the entire fp12 element so we don't leak information about the fp12 structure.
    let bytes = array_concat_32(
        &sha256.hash(&(&0u8, &k_value)),
        &sha256.hash(&(&1u8, &k_value)),
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
pub struct ReencryptionKey<FP: ExtensionField> {
    pub re_public_key: PublicKey<FP>,
    pub to_public_key: PublicKey<FP>,
    pub encrypted_k: Fp12Elem<FP>,
    pub hashed_k: TwistedHPoint<FP>,
}

impl<FP: Hashable + ExtensionField> Hashable for ReencryptionKey<FP> {
    fn to_bytes(&self) -> ByteVector {
        (&self.re_public_key, &self.to_public_key, &self.encrypted_k).to_bytes()
    }
}

impl<FP: BitRepr + ExtensionField> ReencryptionKey<FP> {
    ///Augment this ReencryptionKey with a priv_key. This is useful if the ReencryptionKey was from an unaugmented
    ///private key.
    pub fn augment(
        &self,
        priv_key: &PrivateKey<FP>,
        g1: &TwistedHPoint<FP>,
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
/// Ok(ReencryptedValue) - if the value could be successfully reencrypted
/// - Err(InvalidEncryptedMessageSignature|ReencryptionKeyIsCorrupt) - if the signatures weren't valid.
pub fn reencrypt<FP, S, H>(
    signed_reencryption_key: SignedValue<ReencryptionKey<FP>>,
    signed_encrypted_value: SignedValue<EncryptedValue<FP>>,
    rand_re_priv_key: PrivateKey<FP>,
    rand_re_k: KValue<FP>,
    signing_keypair: &SigningKeypair,
    ed25519: &S,
    sha256: &H,
    curve_points: &CurvePoints<FP>,
    pairing: &Pairing<FP>,
) -> ErrorOr<SignedValue<EncryptedValue<FP>>>
where
    FP: Hashable + ExtensionField + PairingConfig + BitRepr + From<[u8; 64]> + Default,
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
            signing_keypair,
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
            signing_keypair,
            ed25519,
        )),
        (None, _) => Err(InternalError::InvalidEncryptedMessageSignature),
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
    FP: Hashable + ExtensionField + PairingConfig + BitRepr + From<[u8; 64]> + Default,
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
    FP: Hashable + ExtensionField + PairingConfig + BitRepr + From<[u8; 64]> + Default,
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
    let rand_re_k_last_prime = *enc_rand_re_k_last
        * pairing.pair(
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
    use crate::api::test::DummyRandomBytes;
    use crate::internal::ed25519::Ed25519;
    use crate::internal::fp::fp256_unsafe_from;
    use crate::internal::fp12elem::test::arb_fp12;
    use crate::internal::homogeneouspoint::test::arb_homogeneous;
    use crate::internal::sha256::Sha256;
    use crate::internal::sum_n;
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
    prop_compose! {
        [pub] fn arb_fp480()(seed in any::<u64>()) -> Fp480 {
            if seed == 0 {
                Fp480::zero()
            } else if seed == 1 {
                Fp480::one()
            } else {
                Fp480::from(seed).pow(seed)
            }

        }
    }

    struct Mocks;

    impl Ed25519Signing for Mocks {
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

    impl Sha256Hashing for Mocks {
        fn hash<T: Hashable>(&self, _t: &T) -> [u8; 32] {
            [0; 32]
        }
    }

    struct AlwaysFailVerifyEd25519Signing;

    impl Ed25519Signing for AlwaysFailVerifyEd25519Signing {
        fn sign<T: Hashable>(&self, _t: &T, _signing_keypair: &SigningKeypair) -> Ed25519Signature {
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
        let v = Fp256::from(10u8);
        let result = pow_for_square(v, 2);
        assert_eq!(result, v.pow(2));
        let result2 = pow_for_square(v, 5);
        assert_eq!(result2, v.pow(5));
    }
    #[test]
    fn fp480_pow_for_square_works() {
        let v = Fp480::from(10u8);
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
            let signing_keypair = ed25519::test::good_signing_keypair();

            //37777967648492203239675772600961898148040325589588086812374811831221462604944
            let private_key = PrivateKey {
                value: fp256_unsafe_from("5385926b9f6135086d1912901e5a433ffcebc19a30fadbd0ee8cee26ba719c90")
            };

            //22002131259228303741090495322318969764532178674829148099822698556219881568451
            let re_private_key = PrivateKey {
                value: fp256_unsafe_from("30a4c3d5f31a096db20eed892919e542427341d7aec1e1494275831bbca638c3")
            };

            //56377452267431283559088187378398270325210563762492926393848580098576649271541
            let parsed_pub_key_x = fp256_unsafe_from("7ca481d71abbae43395152eb7baa230d60543d43e2e8f89a18d182ecf8c3b8f5");
            //46643694276241842996939080253335644316475473619096522181405937227991761798154
            let parsed_pub_key_y = fp256_unsafe_from("671f653900901fc3688542e5939ba6c064a7768f34fe45492a49e1f6d4d7c40a");
            let public_key = PublicKey::from_x_y(parsed_pub_key_x, parsed_pub_key_y).unwrap();

            let salt = KValue(Fp12Elem::create_from_t(
                //20621517740542501009268492188240231175004875885443969425948886451683622135253
                fp256_unsafe_from("2d975d8c65b577810297bc5b7193691a6892cefacbee2544fb16f67ba7c825d5")
                ,
                //34374877744619883729582518521480375735530540362125629015072222432427068254516
                              fp256_unsafe_from("4bff7dc7983fb830ec19f39e78268d8191d96ec9974ac41ef8100acca66e6934"),
                //3061516916225902041514148805993070634368655849312514173666756917317148753791
            fp256_unsafe_from("6c4c1d5c2d00bbfc5eac19626b1967ce3ca5a60bce0122626d0662f53463f7f"),
                //36462333850830053304472867079357777410712443208968594405185610332940263631144
                fp256_unsafe_from("509cf319e11149b9f03c5c442efecb02c3fd98c4034490c505c6983f4f862928"),
                //61512103449194136219283269928242996434577060883392017268158197606945715641345
                fp256_unsafe_from("87fe9de48e020614a01af0a1ae62a44b47342ead7d99af4c6a0f1eec6cbfdc01"),
                //6400685679296646713554926627062187315936943674688629293503755450503276487519
                fp256_unsafe_from("e26a8e2e7136d4027e2ff75226d1c456767129d1232fa257503f6cf34cb635f"),
                //53751186939356616119935218564341196608994152768328518524478036628068165341835
                fp256_unsafe_from("76d617fc05a8f85acff827a14f3ffdc99be13ac7bb0b823d30d8752bf205d28b"),
                //24086990466602794093787211540995552936111869178774386613517233502609109093865
                fp256_unsafe_from("3540c0e3e718e5cd7d1153d3d392e246a251d8f4a5d7490b4fa18d369a270de9"),
                //61396452992397102589850224464045014903468298857108669606429537125544948220026
                fp256_unsafe_from("87bd2932b2a9e20f9b51b8b1adfeda2b434985710e73bb335d5b568eb8c1407a"),
                //15909384434160564083979503677021998800821775569159782381560100961841901513229
                fp256_unsafe_from("232c6479f7e8768b2e85a025cb9e7162315ff7ebeef6bd73ef896bb14748aa0d"),
                //60608834117224548548490931258722195552088501100182383267798941700183023164589
                fp256_unsafe_from("85ff626aef9f9cef0310f93a9541ef9ce2207eb9b57077db4572531a879c1cad"),
                //17433339776741835027827317970122814431745024562995872600925458287403992082321
                fp256_unsafe_from("268aebaf44e6ae76c70f48aed806180ced89dfc17f962de209f2a3437b4fe791")
            ));

            let re_key = generate_reencryption_key(
                private_key,
                public_key,
                re_private_key,
                salt,
                &signing_keypair,
                curve_points,
                &pairing,
                sha256,
                ed25519).payload;


            let good_encrypted_k = Fp12Elem::create_from_t(
                //12468319166808038973695145957420708896894989833062445136258751614714728860674
                fp256_unsafe_from("1b90d18d6c2e5cc05034aad9fb05ac729f16faa377dd7aa566cd26541426cc02"),
                //2128854359484213588380497318350091194644767868675298191307887815867151037785
                fp256_unsafe_from("4b4e38cd756a3a0b8e0c4410b6a13d83b6687e03e07370249818392c3ca3559"),
                //21445177129013608048665933252873170350264030103628078278539253145170500354896
                fp256_unsafe_from("2f698a45185e09ed53f5ed58717ed285f0320a1578b4b896a5e9790e1b938350"),
                //56038156109742185788555899045964131128124373881320309662221006159550412032591
                fp256_unsafe_from("7be478ed278532693e88fd07aacc59aee1e3f810680ee60f990c8046de5d0a4f"),
                //26914485966895326452176682212429959307113556759541870452048350761624956307220
                fp256_unsafe_from("3b810f28e8f4bbea9abad6e971c87354a13b82b20c5c6831cf30f3f68b9c0714"),
                //47982890198790824855446467783137770650698480322416616491158632550503307113855
                fp256_unsafe_from("6a155a7a87f8ddcc593e88c60a92d0968777d94c0022c02be73f7f8108b5757f"),
                //10711644709861300386519729424210641312562914145500366805337572652137411248028
                fp256_unsafe_from("17ae93786aff5ee3066e8e63625fdc9cfb59c0d97b7fe35f9ef768fdb407ff9c"),
                //43347748542964759695743884414110499509686690671474974704725984636415455585090
                fp256_unsafe_from("5fd5f4cb23e1ea76cb3fc5acc8a3811a9098da9da23eff2a29e4ecb98458e342"),
                //17596819370787728602670144220164446940512614719945259504347007792221644397210
                fp256_unsafe_from("26e772626d3693c4e90f383cb4e33703d77f3bc0b053f621b6ca2c3235ac1a9a"),
                //38746694397885185117442963327077624722941852366420178940757070667288257609651
                fp256_unsafe_from("55a9da13cb5ed5cdc48eb709e4bb040a4cb7189793bda322df17e977b609bfb3"),
                //38002592948627699884055358711985526413232379309204607956998925141882284407414
                fp256_unsafe_from("5404b493123a5b087cb6cc363116a9fc393c27dac3efa3df778ec974b8bdfa76"),
                //49941783284737700171954796486309114156831309184207470337019703077683277143423
                fp256_unsafe_from("6e6a0c315c47fa2990268bc2010eeda17b78cc32e7ab6f093bf1aa2234491d7f")
            );

            let good_hashed_k = TwistedHPoint {
                x: fp2elem::Fp2Elem {
                    //22422077836615563303859289302360681993513791649150629779433386726239734002618
                    elem1: fp256_unsafe_from("319272423a484aae2063912bbbf6a61f58ae4eaa9b0aca8dd493a050a6aef3ba"),
                    //52027607726191528801608200848909742835559726958532705354275625739433988283036
                    elem2: fp256_unsafe_from("73069519d5de19f839fbd1c6ff3a7bece381de22395cfe51c5636aafd77f5a9c")
                },
                y: fp2elem::Fp2Elem {
                    //4645247538810084127206561896955679361089846324400619601984418530338530410972
                    elem1: fp256_unsafe_from("a451def6c985a08374ed5f96426b861125c3e418ebe4f2f587fdf86f4d441dc"),
                    //34485967566945102067940948289591403523736094597232197502117656471251591927196
                    elem2: fp256_unsafe_from("4c3e5dae1e009f89877a44eea4e491285b6198941bbcc17545f3ffc07fd8959c")
                },
                z: fp2elem::Fp2Elem {
                    //2258730050599105467979057492418988601962605970075660368624801947296357678159
                    elem1: fp256_unsafe_from("4fe6559f6d8e64c53addb0ac095bea18ff0cdf9cf84e93dd8e4bc7cc5bbfc4f"),
                    //18358874287282838450918898019272385250887285769392485811015731318886010089831
                    elem2: fp256_unsafe_from("2896c12e42c82648d4e553e82b32abe95618f0e5ad7f8ba14d6180b78ae67167")
                }
            };

            assert_eq!(good_encrypted_k, re_key.encrypted_k);
            assert_eq!(good_hashed_k, re_key.hashed_k)
        }

    #[test]
    fn reencrypt_roundtrip_with_known_keys() {
        let pt_fp12 = Fp12Elem::create_from_t(
            Fp256::from(1u8),
            Fp256::from(2u8),
            Fp256::from(3u8),
            Fp256::from(4u8),
            Fp256::from(5u8),
            Fp256::from(6u8),
            Fp256::from(7u8),
            Fp256::from(8u8),
            Fp256::from(9u8),
            Fp256::from(10u8),
            Fp256::from(11u8),
            Fp256::from(12u8),
        );
        let salt_fp12 = Fp12Elem::create_from_t(
            Fp256::from(11u8),
            Fp256::from(12u8),
            Fp256::from(13u8),
            Fp256::from(14u8),
            Fp256::from(15u8),
            Fp256::from(16u8),
            Fp256::from(17u8),
            Fp256::from(18u8),
            Fp256::from(19u8),
            Fp256::from(110u8),
            Fp256::from(111u8),
            Fp256::from(112u8),
        );
        let rand_re_k_fp12 = Fp12Elem::create_from_t(
            Fp256::from(21u8),
            Fp256::from(22u8),
            Fp256::from(23u8),
            Fp256::from(24u8),
            Fp256::from(25u8),
            Fp256::from(26u8),
            Fp256::from(27u8),
            Fp256::from(28u8),
            Fp256::from(29u8),
            Fp256::from(210u8),
            Fp256::from(211u8),
            Fp256::from(212u8),
        );

        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let ref ed25519 = api::test::DummyEd25519;
        let salt = KValue(gen_rth_root(&pairing, salt_fp12));
        let signing_keypair = ed25519::test::good_signing_keypair();

        let re_private = PrivateKey::from_fp256(
            //22002131259228303741090495322318969764532178674829148099822698556219881568451
            fp256_unsafe_from("30a4c3d5f31a096db20eed892919e542427341d7aec1e1494275831bbca638c3"),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //24550233719269254106556478663938123459765238883583743938937070753673053032673
            fp256_unsafe_from("3646f09b1f8ec8c696326e7095a16635d29a5e6d5df5b8c9cd4d15a1ff2550e1"),
        );
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            fp256_unsafe_from("613430d6b5ffee80cb971c85f2ea779d2dd0c020dcdd31a93c46e56c5b2f3ca2"),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let plaintext = pt_fp12;
        let encrypt_result = encrypt(
            pub_key,
            plaintext,
            ephem_priv_key,
            &signing_keypair,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        );
        let rand_re_priv_key = PrivateKey::from_fp256(
            //17561965855055966875289582496525889116201409974621952158489640859240156546764
            fp256_unsafe_from("26d3b86dad678314ca9532ff4046e372802d175cd5e1ad63aacdcc968552c6cc"),
        );
        let rand_re_k = KValue(gen_rth_root(&pairing, rand_re_k_fp12));
        let re_key = generate_reencryption_key(
            priv_key,
            pub_key,
            re_private,
            salt,
            &signing_keypair,
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
            &signing_keypair,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        )
        .unwrap();

        let decrypted_value = decrypt(
            priv_key,
            reencrypted_value,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        )
        .unwrap();
        assert_eq!(decrypted_value, plaintext)
    }

    #[test]
    fn fail_when_verify_fails() {
        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let salt1 = gen_rth_root(&pairing, gen_random_fp12(&mut DummyRandomBytes));
        let signing_keypair = ed25519::test::good_signing_keypair();
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            fp256_unsafe_from("613430d6b5ffee80cb971c85f2ea779d2dd0c020dcdd31a93c46e56c5b2f3ca2"),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //88866559432365357341903140497410248873099149633601160471165130153973144042888
            fp256_unsafe_from("c478b0b05e9d5cc4a7aaa3e5f991f6f452fd26a72f5415a93c46e56c5b2f3d88"),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let encrypted_value = encrypt(
            pub_key,
            salt1,
            ephem_priv_key,
            &signing_keypair,
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
        if let Err(InternalError::InvalidEncryptedMessageSignature) = decrypt_result {
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
        let signing_keypair = ed25519::test::good_signing_keypair();
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            fp256_unsafe_from("613430d6b5ffee80cb971c85f2ea779d2dd0c020dcdd31a93c46e56c5b2f3ca2"),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //88866559432365357341903140497410248873099149633601160471165130153973144042888
            fp256_unsafe_from("c478b0b05e9d5cc4a7aaa3e5f991f6f452fd26a72f5415a93c46e56c5b2f3d88"),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let encrypted_value = encrypt(
            pub_key,
            salt1,
            ephem_priv_key,
            &signing_keypair,
            &pairing,
            curve_points,
            sha256,
            &Mocks,
        );

        let diff_priv_key = PrivateKey::from_fp256(Fp256::from(42u8));
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
            Fp256::from(1u32),
            Fp256::from(2u32),
            Fp256::from(3u32),
            Fp256::from(4u32),
            Fp256::from(5u32),
            Fp256::from(6u32),
            Fp256::from(7u32),
            Fp256::from(8u32),
            Fp256::from(9u32),
            Fp256::from(10u32),
            Fp256::from(11u32),
            Fp256::from(12u32),
        );
        let salt_1_fp12 = Fp12Elem::create_from_t(
            Fp256::from(11u32),
            Fp256::from(12u32),
            Fp256::from(13u32),
            Fp256::from(14u32),
            Fp256::from(15u32),
            Fp256::from(16u32),
            Fp256::from(17u32),
            Fp256::from(18u32),
            Fp256::from(19u32),
            Fp256::from(110u32),
            Fp256::from(111u32),
            Fp256::from(112u32),
        );
        let rand_re_k_1_fp12 = Fp12Elem::create_from_t(
            Fp256::from(21u32),
            Fp256::from(22u32),
            Fp256::from(23u32),
            Fp256::from(24u32),
            Fp256::from(25u32),
            Fp256::from(26u32),
            Fp256::from(27u32),
            Fp256::from(28u32),
            Fp256::from(29u32),
            Fp256::from(210u32),
            Fp256::from(211u32),
            Fp256::from(212u32),
        );
        let salt_2_fp12 = Fp12Elem::create_from_t(
            Fp256::from(31u32),
            Fp256::from(32u32),
            Fp256::from(33u32),
            Fp256::from(34u32),
            Fp256::from(35u32),
            Fp256::from(36u32),
            Fp256::from(37u32),
            Fp256::from(38u32),
            Fp256::from(39u32),
            Fp256::from(310u32),
            Fp256::from(311u32),
            Fp256::from(312u32),
        );
        let rand_re_k_2_fp12 = Fp12Elem::create_from_t(
            Fp256::from(41u32),
            Fp256::from(42u32),
            Fp256::from(43u32),
            Fp256::from(44u32),
            Fp256::from(45u32),
            Fp256::from(46u32),
            Fp256::from(47u32),
            Fp256::from(48u32),
            Fp256::from(49u32),
            Fp256::from(410u32),
            Fp256::from(411u32),
            Fp256::from(412u32),
        );

        let pairing = pairing::Pairing::new();
        let ref curve_points = *curve::FP_256_CURVE_POINTS;
        let ref sha256 = sha256::Sha256;
        let ref ed25519 = api::test::DummyEd25519;
        let salt1 = KValue(gen_rth_root(&pairing, salt_1_fp12));
        let signing_keypair = ed25519::test::good_signing_keypair();

        let re_private = PrivateKey::from_fp256(
            //22002131259228303741090495322318969764532178674829148099822698556219881568451
            fp256_unsafe_from("30a4c3d5f31a096db20eed892919e542427341d7aec1e1494275831bbca638c3"),
        );
        let ephem_priv_key = PrivateKey::from_fp256(
            //24550233719269254106556478663938123459765238883583743938937070753673053032673
            fp256_unsafe_from("3646f09b1f8ec8c696326e7095a16635d29a5e6d5df5b8c9cd4d15a1ff2550e1"),
        );
        let priv_key = PrivateKey::from_fp256(
            //43966559432365357341903140497410248873099149633601160471165130153973144042658
            fp256_unsafe_from("613430d6b5ffee80cb971c85f2ea779d2dd0c020dcdd31a93c46e56c5b2f3ca2"),
        );
        let pub_key = public_keygen(priv_key, curve_points.generator);
        let priv_key2 = PrivateKey::from_fp256(
            //22266559432365357341903140497410248873090149633601160471165130153973144042608
            fp256_unsafe_from("313a6d10030318ffa481b32fa104b4a77d6ad640a87bade5ee9e4ddc5b2f3c70"),
        );
        let pub_key2 = public_keygen(priv_key2, curve_points.generator);
        let priv_key3 = PrivateKey::from_fp256(
            //33333359432365357341903140497410248873090149633601160471165130153973144042608
            fp256_unsafe_from("49b2034a4bc9614d95bdac29251fb567b2ed2b41b0d25be5ee9e4ddc5b2f3c70"),
        );
        let pub_key3 = public_keygen(priv_key3, curve_points.generator);

        let plaintext = gen_rth_root(&pairing, pt_fp12);

        // First level encryption
        let encrypt_result = encrypt(
            pub_key,
            plaintext,
            ephem_priv_key,
            &signing_keypair,
            &pairing,
            curve_points,
            sha256,
            ed25519,
        );
        let rand_re_priv_key = PrivateKey::from_fp256(
            //17561965855055966875289582496525889116201409974621952158489640859240156546764
            fp256_unsafe_from("26d3b86dad678314ca9532ff4046e372802d175cd5e1ad63aacdcc968552c6cc"),
        );
        let rand_re_k = KValue(gen_rth_root(&pairing, rand_re_k_1_fp12));
        let re_key = generate_reencryption_key(
            priv_key,
            pub_key2,
            re_private,
            salt1,
            &signing_keypair,
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
            &signing_keypair,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        )
        .unwrap();

        // the fun has just begun! Do a second level of reencryption
        let rand_re_priv_key_2 = PrivateKey::from_fp256(
            //1756196585505596687528958249652588911620140997462195215848000000000
            fp256_unsafe_from("0000000010ad13d179057a034b800241c7ebb038b4be347ec9bde3e352291000"),
        );
        let re_priv_2 = PrivateKey::from_fp256(
            //22002131259228303741090495322318969763333178674829148099822698556219881568451
            fp256_unsafe_from("30a4c3d5f31a096db20eed892919e53ebc6c41c1ec39b2a68347872bbca638c3"),
        );
        let rand_re_k_2 = KValue(gen_rth_root(&pairing, rand_re_k_2_fp12));
        let salt2 = KValue(gen_rth_root(&pairing, salt_2_fp12));
        let reencryption_key_2 = generate_reencryption_key(
            priv_key2,
            pub_key3,
            re_priv_2,
            salt2,
            &signing_keypair,
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
            &signing_keypair,
            ed25519,
            sha256,
            curve_points,
            &pairing,
        )
        .unwrap();

        if let EncryptedValue::Reencrypted(v) = reencrypted_value_2.payload.clone() {
            assert_eq!(2, v.encryption_blocks.len())
        } else {
            assert!(false, "This should be a reencrypted value")
        }
        //Assert that the to_bytes is a known value which matches recrypt scala.
        let known_to_bytes_value = hex::decode("8538d52016446c7e8f4fa28e333cef771e4c17389682a8515a9e2fbb88caf3f94af54e76c9f0163854b907c19b71a1970877884286173dc8842a80dd46aa9e615ac6a2157793862320033c4024ab86e06417d199811499127bb8b2eb8d69ec833be81a2b786f2fedc61737bb8864d55786547cd09e2f9b640c760355aa86ef685528d7fae7c42389a9a0260b3d20585ff33bf92bc08d2d1a91783a021f169fca1862fb0e038af94b4de96e8eb882437e3a9bd5d8920f2d7feb991efd09f47fb35768b0e0d8d0c3512551ca92bfd0539d7178a3bc6eb0e21d467fc1e2fcf6ad542e1dc66cc03e6b846012bf8f85eaabfc596e3de6044fc0561723431b7f6a5bd8577945d6b3870cecc29b89522b63acea10956d188a5eb74d22686e9248e85c403aca90a727f1f0cefe6e07b9ce6976aa91441a8f52f9acc1df61bf63af6ea5ef1661815f56697f1d5da1028a25917bc0ae8c9d844edc39c955fbe9bb73c5745f288e8f6cef6bf2bc6971bb2f18f227415a6f6fb9112f8a787840da96a5a0a4452fc6dc1ca38196e9ae4420171d71d3a9cdc3bca78047ec363678abcffbc51b743db43e23027edddeba64bcd3074955fce91f00210a910fa6b337afbfbd5f981399a5fe86e2c2dbdfd528730f26e70aadeed4103aab96196911da5900508cf6c571bdc397623d278d8a82224111e7441509d72faba0d8fd8994d74674025c20e34194d9ca607479e476bba584c87e53b33b70bc8b4a200b13eab6f00bcfc4a3ea2ceeee59f1a59c17f8e4934b137e7c2bdaa3a131bf276424a4340e34b57fbc7708ef779ced7c8d3915f4f982d8bd11246b7ed989c19c9826b4ea61ba9cce06320eff550399ee97908b0ba353d5ced125c5edb679a31c1604bd848f77c94d619348cb07a089a743ecbf56cd5e6fb77b719068bcbf4ef57ff8c5f791a4ea807c863f63ff7cbdc105d5b92d666f1fc05a0dad33597da211b5864e9b15969b3bdfd57d5efaad7a15f75d3d4d055c9920d7a2be72d257104ae75721368a645920f43e38b84350522b8d2c589d661ec296d9f9ef6bda55e43760924698d22d16f7cbd51c565ef386e92a600f3414dfe7efd4bdeec09bff1c3bbcf3673b6b0bcd9b74fc183c2079da10c4466af7b39d4cd963611536b67e9b992aec8cc5432f6b38ae20665e8da1bf3474675b4711e91e4ce9d15765ef9b30a67ee68a2dc2cfce6e84415fe38b3acb03a01afb815c232ded3089f258aec45850a672eb18d18e90ea55ee1626528543178f59238b848631640e04b9d55758dc6b32ea92ce00248a7dd5617a0490ffe984617ed44e0748e5fb99f1ada2d26c36b1f9dcf34b2c5247eeefda0c0ed47500da3c806cfcc7035bb1abe6b63dbcd4c1bdbcfe6b369d46117cd6be33b7cc44d2085344dde3ba832a3394ed03d0de5676dac700449765c29f92d3230141e2782d140790878dd447d25faa9da250764e37a5cec2651959dba1a290f3519663b71c8de3618f4b0efbd98dea89b719c3b4513994949acd3bbc3de9c18f8df4a0d1baed760f1bc501d288a58acd18b97bb12746ed5e497366edc75050684a1a7a190a095345a821a1dc167fbbe2a6ba87fe44608c8cbfad83644896bc22477f8e620884815a4eb36a0e2378adcd0c74aa7e941cf166b17554ec66c9265258278bc1b6cf4e2a7ca76f3769bd7a22e10303901abf8c1b19e12c182f7ebc985f68c9376646bce71d39347fd04184ea9bc0eb23dbc11c1f4a2672a6101bc64b549354d40195e682b2ce53f616672170117e23ab1e1eaf141553fd6f759bc8c061c483fb5b287c65a82d6c239b63c73e1f67686acc1d776c72158833e80581f8440fd15ecd376435d8412cc20f965e90e87af8406807b1484d1d8da5c45eb09f3963ebb3de7c120f0542bfb2024adca8956a8da32f03112f91f3bf8c5302a597388f252631820de477856e29e6397c006ee0e28c990ddc3964760eab0d148c5509e606038ef59941322cd535bb6c8e9a8d673213917e6ba1a5119cd7b642303b8c3ad06651f60cc6f8ee75d2a08f561fdec73237471eb0a20f15ac73cf2d7d8476a01bd5fa63b550242fe1bbc1192567a9a80005a974b034f8df8891d926e0dd31c9e575dfce569a7a5d777a67bb9c453d20b62828dc29ed150cff4a9b168c7a8a4989d1b3aa06d8a879a0440f860d4e0b25a8e8c2e30a348d9a151e7a7ceeaf4fa6bc2617e561a83e31cc4bb7a870a413f4d37ead4496eb7e27b07b012b28eb67151af8b26cb2e6c2edfda62d114c67697e53d17911292a398f2087f80744a3030029995e7e7759356374fc431b8cdf4a09544f5699bd429930c6b6152dc2bb07e062c74422e1439293abcc5825fac6ddf3f33d9bf6eb5bd259538aea49758b704cccf440f512680a4bfdb46c90a0b6381d99d390f2c2721970c939b0cce41449fa8eb23f5b941d3aaa6e2cbe94ddb645c16eaf0f3d068d6da459925c9bcfb377cc269bf995d768095d225046792f991edff225ad955f2b6cd5543cac46751c58b7abc78e498b949eec0da842a877f6872c79b96f3220cccc1e3f7adcbf787162dc7841f58943fd97a01945537b294bc285dde3ff6a543875517b0403f1888e0b21d0253b74dbcf8518a89bbeef68d82035a66ac9bc5a2161665295f0fec47f533f124ba35597bf0dded2d67a77688db1e5d8dfd7a38cb8a8efa5ec68fdb6cf04b9254fd2aafa2b0e55089da484507a92d666d0309406cdcc72e0232d9c57138cc52c1ddf36bd51a1078b946496f3559bfc6dd1692ce4a41736dc49c09519f70edff330cd253b7b2797fd89941c330fc07251153f489fa93183c6c7563a792c80c9c52e26f1f63e335776216e534bef47d4771430e9ec2e54fd667385a2619a5f47d42b0f9c025d6df3ee2c81af97e9dcfb17a50b4454d53827ee484296635d30bba9ec1a2537f2084fa4a0fcd4c4a60ba75c8194487c0b95ef8ade74f738fc1f4f97deaca40502105598bc6069e621e297869be84cf6c3b8c3ddb57e27002d10104d20ca31de39336753953faf07e0e0a7124d3fd3b0814e750ac6942b1bdf752440f186a6c0d201dfebf9a97ee62647a817a0dfac3eecc9288d39d567b1d40b11a4265ffdd470565fca9a418d3cb4d62e7964c19e1c3f2984a1d5eb5c0cea2d952b3af8f75014000438f1be0c23e1a151e4eca1018bc7b14bc4df3784f578").unwrap();
        assert_eq!(reencrypted_value_2.payload.to_bytes(), known_to_bytes_value);

        let decrypted_value = decrypt(
            priv_key3,
            reencrypted_value_2.clone(),
            &pairing,
            curve_points,
            sha256,
            ed25519,
        )
        .unwrap();
        assert_eq!(decrypted_value, plaintext);

        //finally, show that a invalid private key will force an auth hash failure
        let invalid_priv_key = PrivateKey::from_fp256(Fp256::from(42u8));
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

    fn good_signing_keys() -> SigningKeypair {
        ed25519::test::good_signing_keypair()
    }

    proptest! {
        #[test]
        fn sign_verify_roundtrip(fp256 in arb_fp256()) {
            let priv_signing_key = good_signing_keys();
            let signed_value = sign_value(fp256, &priv_signing_key, &Ed25519);
            let verified = verify_signed_value(signed_value, &Ed25519);
            prop_assert!(verified.is_some())
        }
        #[test]
        fn encrypt_decrypt_roundtrip(priv_key in arb_priv_key(), plaintext in arb_fp12().prop_filter("", |a| !(*a == Fp12Elem::<Fp256>::zero()))) {
            let pub_key = public_keygen(priv_key, curve::FP_256_CURVE_POINTS.generator);
            let ephem_secret_key = PrivateKey::from_fp256(Fp256::from(42u8));
            let priv_signing_key = good_signing_keys();
            let pairing = pairing::Pairing::new();
            let curve_points = &*curve::FP_256_CURVE_POINTS;
            let encrypt_result = encrypt(
                pub_key,
                plaintext,
                ephem_secret_key,
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
                &ed25519::test::good_signing_keypair(),
                &curve_points,
                &pairing,
                &Mocks,
                &Mocks
            )
        }
    }
}
