use core::fmt::Debug;
use gridiron::fp_256::Fp256;
use gridiron::fr_256::Fr256;
use internal::curve::FP_256_CURVE_POINTS;
use internal::hashable::Hashable;
use internal::homogeneouspoint::HomogeneousPoint;
use internal::non_adjacent_form::NonAdjacentForm;
use internal::sha256::Sha256;
use internal::sha256::Sha256Hashing;
use internal::{field, PrivateKey, PublicKey};
use num_traits::Zero;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct SchnorrSignature<T> {
    r: T,
    s: T,
}

pub struct SchnorrSign<FP, FR, H> {
    sha256: H,
    g: HomogeneousPoint<FP>,
    phantom: PhantomData<FR>,
}

impl SchnorrSign<Fp256, Fr256, Sha256> {
    pub fn new_256() -> SchnorrSign<Fp256, Fr256, Sha256> {
        SchnorrSign {
            sha256: Sha256,
            g: FP_256_CURVE_POINTS.generator,
            phantom: PhantomData::<Fr256>,
        }
    }
}

fn compute_double_hash<A: Hashable, B: Hashable, H: Sha256Hashing>(
    sha256: &H,
    a: &A,
    b: &B,
) -> [u8; 64] {
    let mut double_hash = [0u8; 64];
    double_hash[0..32].copy_from_slice(&sha256.hash(a));
    double_hash[32..64].copy_from_slice(&sha256.hash(b));
    double_hash
}

impl<FP, FR, H> SchnorrSigning<FP, FR> for SchnorrSign<FP, FR, H>
where
    FP: field::Field + NonAdjacentForm + Hashable + From<[u8; 64]> + Debug,
    FR: field::Field + NonAdjacentForm + From<FP> + From<[u8; 64]> + Hashable + Debug,
    H: Sha256Hashing,
{
    fn sign<A: Hashable + Copy>(
        &self,
        priv_key: PrivateKey<FP>,
        pub_key: PublicKey<FP>,
        message: A,
        k: FR,
    ) -> Option<SchnorrSignature<FR>> {
        (self.g * k).normalize().and_then(|(x, _)| {
            if x.is_zero() {
                None
            } else {
                let r = FR::from(x);
                let h = FR::from(compute_double_hash(
                    &self.sha256,
                    &(r, pub_key, message),
                    &(pub_key, message, r),
                ));
                let s = k - h * FR::from(priv_key.value);
                Some(SchnorrSignature { r, s })
            }
        })
    }

    fn verify<A: Hashable + Copy>(
        &self,
        pub_key: PublicKey<FP>,
        augmenting_key: PrivateKey<FP>,
        message: A,
        signature: SchnorrSignature<FR>,
    ) -> bool {
        let h = FR::from(compute_double_hash(
            &self.sha256,
            &(signature.r, pub_key, message),
            &(pub_key, message, signature.r),
        ));
        let augmenting_pub_key = self.g * augmenting_key.value;
        let unaugmented_key = pub_key.value - augmenting_pub_key;
        let v = self.g * signature.s + unaugmented_key * h;
        let normalized = v.normalize();
        normalized
            .map(|(x, _)| FR::from(x) == signature.r)
            .unwrap_or_else(|| false)
    }
}

trait SchnorrSigning<T: field::Field, U> {
    ///Sign a `message` using `priv_key`. `pub_key` should be the matching public key for the `priv_key` and must
    ///be also passed in on the verify call. `k` is a value that should be choosen wi
    fn sign<A: Hashable + Copy>(
        &self,
        priv_key: PrivateKey<T>,
        pub_key: PublicKey<T>,
        message: A,
        k: U,
    ) -> Option<SchnorrSignature<U>>;
    fn verify<A: Hashable + Copy>(
        &self,
        pub_key: PublicKey<T>,
        augmenting_key: PrivateKey<T>,
        message: A,
        signature: SchnorrSignature<U>,
    ) -> bool;
}

#[cfg(test)]
mod test {
    use super::*;
    use gridiron::fr_256::Fr256;
    use internal::test::arb_priv_key;
    use internal::PublicKey;
    use num_traits::{One, Pow};
    use proptest::arbitrary::any;
    use proptest::prelude::*;

    prop_compose! {
        [pub] fn arb_fr256()(seed in any::<u64>()) -> Fr256 {
            if seed == 0 {
                Fr256::zero()
            } else if seed == 1 {
                Fr256::one()
            } else {
                Fr256::from(seed).pow(seed)
            }
        }
    }

    proptest! {
        #[test]
        fn schnorr_sign_verify_roundtrip(
            priv_key in arb_priv_key().prop_filter("", |a| !a.value.is_zero()), 
            fr in arb_fr256().prop_filter("", |a| !a.is_zero()), 
            aug_priv_key in arb_priv_key().prop_filter("", |a| !a.value.is_zero())) {
            let g = FP_256_CURVE_POINTS.generator;
            let message = 1u8;
            let signing = SchnorrSign::new_256();
            let aug_pub_key = PublicKey::new(g * aug_priv_key);
            let pub_key = PublicKey::new(g * priv_key.value + aug_pub_key.value);
            let sig = signing.sign(priv_key,pub_key, message, fr).unwrap();
            prop_assert!(signing.verify(pub_key, aug_priv_key, message, sig))
        }
    }
}
