use gridiron::fp_256::Fp256;
use internal::array_concat_32;
use internal::curve::FP_256_CURVE_POINTS;
use internal::fp::fr_256::Fr256;
use internal::hashable::Hashable;
use internal::homogeneouspoint::HomogeneousPoint;
use internal::non_adjacent_form::NonAdjacentForm;
use internal::sha256::Sha256;
use internal::sha256::Sha256Hashing;
use internal::{field, PrivateKey, PublicKey};
use std::marker::PhantomData;

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
        &self.r
    }
}

#[derive(Debug)]
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
    array_concat_32(&sha256.hash(a), &sha256.hash(b))
}

impl<FP, FR, H> SchnorrSigning<FP, FR> for SchnorrSign<FP, FR, H>
where
    FP: field::Field + NonAdjacentForm + Hashable + From<[u8; 64]>,
    FR: field::Field + NonAdjacentForm + From<FP> + From<[u8; 64]> + Hashable,
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
            .map(|(x, _)| FR::from(x) == signature.r)
            .unwrap_or_else(|| false)
    }
}

pub trait SchnorrSigning<T: field::Field, U> {
    ///Sign a `message` using `priv_key`.
    ///- `priv_key` should be the matching public key for the `priv_key` and must
    ///- `pub_key`
    ///- `message`
    ///- `k`
    fn sign<A: Hashable>(
        &self,
        priv_key: PrivateKey<T>,
        pub_key: PublicKey<T>,
        message: &A,
        k: U,
    ) -> Option<SchnorrSignature<U>>;

    ///verify a signature which was generated for `message` using `priv_key`.
    ///- `pub_key` -
    ///- `augmenting_key` -
    ///- `message` -
    ///- `signature` -
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
    use internal::fp::fr_256::Fr256;
    use internal::test::arb_priv_key;
    use internal::PublicKey;
    use num_traits::{One, Pow, Zero};
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
                Fp256::new([
                    13106811952939269267,
                    4141828384527557607,
                    7080725402398640391,
                    1445861572479947833,
                ]),
                Fp256::new([
                    17235545727228408095,
                    7215949606901098601,
                    18437798671069817475,
                    7477972115967331856,
                ]),
            )).unwrap(),
        );
        //65000549695646603732796438742359905742825358107623003571877145026864184071782
        let priv_key = PrivateKey::from_fp256(Fp256::new([
            1755467536201717350,
            17175472035685840286,
            12281294985516866593,
            10355184993929758713,
        ]));
        //65000549695646603732796438742359905742570406053903786389881062969044166799967
        let k = Fr256::new([
            1886713967064937055,
            3354493509585025316,
            12281294985516866593,
            10355184993929758713,
        ]);
        let message = 1u8;
        //SchnorrSignature(
        //  4062534355977912733299777421397494108926584881726437723242321564179011504485,
        //  54576864563267907144762780592548274163132236814713061179326750530890377205812)
        let expected_result = SchnorrSignature {
            r: Fr256::new([
                16250617785508464997,
                2226388506837211993,
                11143874478056426946,
                647199062120609919,
            ]),
            s: Fr256::new([
                17737603127845853236,
                17684162376844168118,
                5021827597828301695,
                8694596147071348058,
            ]),
        };

        let result = SchnorrSign::new_256()
            .sign(priv_key, pub_key, &message, k)
            .unwrap();
        assert_eq!(result, expected_result);
    }
}
