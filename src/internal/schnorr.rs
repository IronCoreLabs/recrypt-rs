use crate::internal::array_concat_32;
use crate::internal::bit_repr::BitRepr;
use crate::internal::curve::{FP_256_MONTY_CURVE_POINTS, FP_480_CURVE_POINTS};
use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::internal::hashable::Hashable;
use crate::internal::homogeneouspoint::HomogeneousPoint;
use crate::internal::sha256::Sha256;
use crate::internal::sha256::Sha256Hashing;
use crate::internal::{field, PrivateKey, PublicKey};
use gridiron::digits::constant_time_primitives::ConstantSwap;
use gridiron::fp_256;
use gridiron::fp_480::Fp480;
use std::marker::PhantomData;

/// `r` - the x coordinate for a point on the elliptic curve.
/// `s` - the signature.
/// These names are chosen because it's common terminology when working in `EC-Schnorr` algorithms.
///
/// PartialEq/Eq are not constant time, but SchnorrSignature is not secret
#[derive(Debug, PartialEq, Eq)]
pub struct SchnorrSignature<T> {
    r: T,
    s: T,
}

impl<T> SchnorrSignature<T> {
    pub fn new(r: T, s: T) -> SchnorrSignature<T> {
        SchnorrSignature { r, s }
    }
    pub fn r(&self) -> &T {
        &self.r
    }

    pub fn s(&self) -> &T {
        &self.s
    }
}

#[derive(Debug)]
pub struct SchnorrSign<FP, FR, H> {
    sha256: H,
    g: HomogeneousPoint<FP>,
    phantom: PhantomData<FR>,
}

impl SchnorrSign<fp_256::Monty, Fr256, Sha256> {
    pub fn new_256() -> SchnorrSign<fp_256::Monty, Fr256, Sha256> {
        SchnorrSign {
            sha256: Sha256,
            g: FP_256_MONTY_CURVE_POINTS.generator,
            phantom: PhantomData::<Fr256>,
        }
    }
}

impl SchnorrSign<Fp480, Fr480, Sha256> {
    pub fn new_480() -> SchnorrSign<Fp480, Fr480, Sha256> {
        SchnorrSign {
            sha256: Sha256,
            g: FP_480_CURVE_POINTS.generator,
            phantom: PhantomData::<Fr480>,
        }
    }
}

fn compute_double_hash<A: Hashable, B: Hashable, H: Sha256Hashing>(
    sha256: &H,
    a: &A,
    b: &B,
) -> [u8; 64] {
    array_concat_32(&sha256.hash(a), &sha256.hash(b))
}

impl<FP, FR, H> SchnorrSigning<FP, FR> for SchnorrSign<FP, FR, H>
where
    FP: field::Field + BitRepr + Hashable + From<[u8; 64]> + ConstantSwap,
    FR: field::Field + BitRepr + From<FP> + From<[u8; 64]> + Hashable + ConstantSwap,
    H: Sha256Hashing,
{
    fn sign<A: Hashable>(
        &self,
        priv_key: PrivateKey<FP>,
        pub_key: PublicKey<FP>,
        message: &A,
        k: FR,
    ) -> Option<SchnorrSignature<FR>> {
        (self.g * k).normalize().and_then(|(x, _)| {
            if x.is_zero() {
                None
            } else {
                let r = FR::from(x);
                let dh = compute_double_hash(
                    &self.sha256,
                    &(&r, &pub_key, message),
                    &(&pub_key, message, &r),
                );
                let h = FR::from(FP::from(dh));
                let s = k - h * FR::from(priv_key.value);
                Some(SchnorrSignature { r, s })
            }
        })
    }

    fn verify<A: Hashable>(
        &self,
        pub_key: PublicKey<FP>,
        augmenting_key: Option<PrivateKey<FP>>,
        message: &A,
        signature: SchnorrSignature<FR>,
    ) -> bool {
        use num_traits::Zero;
        let h = FR::from(FP::from(compute_double_hash(
            &self.sha256,
            &(&signature.r, &pub_key, message),
            &(&pub_key, message, &signature.r),
        )));
        let augmenting_pub_key = augmenting_key
            .map(|key| self.g * key.value)
            .unwrap_or_else(|| HomogeneousPoint::zero());
        let unaugmented_key = pub_key.value - augmenting_pub_key;
        let v = self.g * signature.s + unaugmented_key * h;
        let normalized = v.normalize();
        normalized
            .map(|(x, _)| FR::from(x) == signature.r) // `x` and `signature.r` revealed, but they are not secret
            .unwrap_or_else(|| false)
    }
}

pub trait SchnorrSigning<T: field::Field, U> {
    ///Sign a `message` using `priv_key`.
    ///- `priv_key` - Key to use for signing
    ///- `pub_key` - public key which will be used for verifying.
    ///- `message` - Message to sign.
    ///- `k` - Secret value which is used as part of the signature. Should be cryptographically random.
    fn sign<A: Hashable>(
        &self,
        priv_key: PrivateKey<T>,
        pub_key: PublicKey<T>,
        message: &A,
        k: U,
    ) -> Option<SchnorrSignature<U>>;

    ///verify a signature which was generated for `message` using `priv_key`.
    ///- `pub_key` - The public key that was passed in on sign.
    ///- `augmenting_key` - The augmenting private key (if there was one). If the public key was not augmented
    ///                     then None should be passed here.
    ///- `message` - The message to verify the signature over.
    ///- `signature` - The signature produced by sign.
    fn verify<A: Hashable>(
        &self,
        pub_key: PublicKey<T>,
        augmenting_key: Option<PrivateKey<T>>,
        message: &A,
        signature: SchnorrSignature<U>,
    ) -> bool;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::fp::fp256_unsafe_from;
    use crate::internal::fp::fr_256::Fr256;
    use crate::internal::test::arb_priv_key;
    use crate::internal::PublicKey;
    use num_traits::{One, Pow, Zero};
    use proptest::arbitrary::any;
    use proptest::prelude::*;

    prop_compose! {
        [pub] fn arb_fr256()(seed in any::<u32>()) -> Fr256 {
            if seed == 0 {
                Fr256::zero()
            } else if seed == 1 {
                Fr256::one()
            } else {
                Fr256::from(seed).pow(seed).pow(seed)
            }
        }
    }

    proptest! {
        #[test]
        fn schnorr_sign_verify_roundtrip(
            priv_key in arb_priv_key().prop_filter("", |a| !a.value.is_zero()),
            fr in arb_fr256().prop_filter("", |a| !a.is_zero()),
            aug_priv_key in arb_priv_key().prop_filter("", |a| !a.value.is_zero())) {
            let g = FP_256_MONTY_CURVE_POINTS.generator;
            let message = 1u8;
            let signing = SchnorrSign::new_256();
            let aug_pub_key = PublicKey::new(g * aug_priv_key);
            let pub_key = PublicKey::new(g * priv_key.value + aug_pub_key.value);
            let sig = signing.sign(priv_key,pub_key, &message, fr).unwrap();
            prop_assert!(signing.verify(pub_key, Some(aug_priv_key), &message, sig))
        }
    }

    #[test]
    fn schnorr_sign_matches_known_value() {
        //(9075820185742795654890598094411205548150334264083213193591644557522355485843,
        //46939991746311747972637410299323006395308387045114925817569453518797610905887)
        let pub_key = PublicKey::new(
            HomogeneousPoint::from_x_y((
                fp256_unsafe_from(
                    "1410bb708e0e14396243ca3cfa0e4907397abaf8ac6523e7b5e4c00740c9fc93",
                )
                .to_monty(),
                fp256_unsafe_from(
                    "67c71804fc824e10ffe0383425492a83642433ef8c75a869ef30f5856573711f",
                )
                .to_monty(),
            ))
            .unwrap(),
        );
        //65000549695646603732796438742359905742825358107623003571877145026864184071782
        let priv_key = PrivateKey::from_fp256(fp256_unsafe_from(
            "8fb501e34aa387f9aa6fecb86184dc21ee5b88d120b5b59e185cac6c5e089666",
        ));
        //65000549695646603732796438742359905742570406053903786389881062969044166799967
        let k = Fr256::new([
            1470919263, 878569654, 1621943440, 1953263767, 407749138, 1308464908, 685899370,
            1518399909, 143,
        ]);

        let message = 1u8;
        //SchnorrSignature(
        //  4062534355977912733299777421397494108926584881726437723242321564179011504485,
        //  54576864563267907144762780592548274163132236814713061179326750530890377205812)
        let expected_result = SchnorrSignature {
            r: Fr256::new([
                1172343141, 1124832653, 1210936679, 1999488104, 1636097057, 1423956336, 713957350,
                2108165914, 8,
            ]),
            s: Fr256::new([
                572266548, 1817264162, 947859163, 727064549, 1022507007, 908309245, 1790662289,
                1421119645, 120,
            ]),
        };

        let result = SchnorrSign::new_256()
            .sign(priv_key, pub_key, &message, k)
            .unwrap();
        assert_eq!(result, expected_result);
    }
}
