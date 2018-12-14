use internal::bit_repr::BitRepr;
use internal::bytedecoder::{BytesDecoder, DecodeErr};
use internal::field::ExtensionField;
use internal::field::Field;
use internal::fp2elem::Fp2Elem;
use internal::hashable::Hashable;
use internal::ByteVector;
use num_traits::identities::{One, Zero};
use num_traits::zero;
use num_traits::Inv;
use num_traits::Pow;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use std::option::Option;

quick_error! {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PointErr {
        PointNotOnCurve(x: Vec<u8>, y: Vec<u8>) {
            //Note that this will print the vectors, but since this error isn't exposed directly to the user that's not a huge concern IMO
            display("The point represented by {:?},{:?} is not on the curve.", x, y)
        }
        ZeroPoint{}
    }
}

///HomogeneousPoint which is either Zero or an x,y coordinate which has a z it carries
///along. In order to get the real x,y you must call `normalize` which divides out by the z.
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct HomogeneousPoint<T> {
    pub x: T,
    pub y: T,
    pub z: T,
}

impl<T: One + Field + From<u32> + Hashable> HomogeneousPoint<T> {
    pub fn from_x_y((x, y): (T, T)) -> Result<HomogeneousPoint<T>, PointErr> {
        if x.pow(3) + T::from(3) == y.pow(2) {
            Ok(HomogeneousPoint {
                x,
                y,
                z: One::one(),
            })
        } else {
            Err(PointErr::PointNotOnCurve(x.to_bytes(), y.to_bytes()))
        }
    }
}

impl<T> PartialEq for HomogeneousPoint<T>
where
    T: Field,
{
    fn eq(&self, other: &HomogeneousPoint<T>) -> bool {
        match (*self, *other) {
            (ref p1, ref p2) if p1.is_zero() && p2.is_zero() => true,
            (ref p1, ref p2) if p1.is_zero() || p2.is_zero() => false,
            (
                HomogeneousPoint {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                HomogeneousPoint {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => x1 * z2 == x2 * z1 && y1 * z2 == y2 * z1,
        }
    }
}

impl<T> Eq for HomogeneousPoint<T> where T: Field {}

impl<T, U> Mul<U> for HomogeneousPoint<T>
where
    T: Field,
    U: BitRepr,
{
    type Output = HomogeneousPoint<T>;
    fn mul(self, rhs: U) -> HomogeneousPoint<T> {
        self.times(&rhs)
    }
}

impl<T> Add for HomogeneousPoint<T>
where
    T: Field + Eq,
{
    type Output = HomogeneousPoint<T>;
    fn add(self, other: HomogeneousPoint<T>) -> HomogeneousPoint<T> {
        match (self, other) {
            (
                HomogeneousPoint {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                HomogeneousPoint {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => {
                let x1x2 = x1 * x2;
                let y1y2 = y1 * y2;
                let z1z2 = z1 * z2;
                let cxy = (x1 + y1) * (x2 + y2) - x1x2 - y1y2;
                let cxz = (x1 + z1) * (x2 + z2) - x1x2 - z1z2;
                let cyz = (y1 + z1) * (y2 + z2) - y1y2 - z1z2;
                let tbzz = z1z2 * 9;
                let dmyz = y1y2 - tbzz;
                let dpyz = y1y2 + tbzz;
                let x3 = cxy * dmyz - cyz * cxz * 9;
                let y3 = dpyz * dmyz + x1x2 * 27 * cxz;
                let z3 = cyz * dpyz + x1x2 * 3 * cxy;
                HomogeneousPoint {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            }
        }
    }
}

impl<T> AddAssign for HomogeneousPoint<T>
where
    T: Field + Eq,
{
    fn add_assign(&mut self, other: HomogeneousPoint<T>) {
        *self = *self + other
    }
}

impl<T> Zero for HomogeneousPoint<T>
where
    T: Field + Eq,
{
    fn zero() -> HomogeneousPoint<T> {
        HomogeneousPoint {
            x: Zero::zero(),
            y: One::one(),
            z: Zero::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.z == Zero::zero()
    }
}

impl<T> Neg for HomogeneousPoint<T>
where
    T: Field,
{
    type Output = HomogeneousPoint<T>;
    fn neg(self) -> HomogeneousPoint<T> {
        if self.is_zero() {
            Zero::zero()
        } else {
            let neg_y: T = -self.y;
            HomogeneousPoint::<T> {
                x: self.x,
                y: neg_y,
                z: self.z,
            }
        }
    }
}

impl<T> Sub for HomogeneousPoint<T>
where
    T: Field + Eq,
{
    type Output = HomogeneousPoint<T>;
    fn sub(self, other: HomogeneousPoint<T>) -> HomogeneousPoint<T> {
        self + -other
    }
}

impl<T> SubAssign for HomogeneousPoint<T>
where
    T: Field + Eq,
{
    fn sub_assign(&mut self, other: HomogeneousPoint<T>) {
        *self = *self - other
    }
}

impl<T: Field + Hashable> Hashable for HomogeneousPoint<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.normalize().as_ref().to_bytes()
    }
}

impl<T> HomogeneousPoint<T>
where
    T: One,
{
    pub fn new(x: T, y: T) -> HomogeneousPoint<T> {
        HomogeneousPoint {
            x,
            y,
            z: One::one(),
        }
    }
}

impl<T> HomogeneousPoint<T>
where
    T: Field,
{
    pub fn double(&self) -> HomogeneousPoint<T> {
        let three_b = 9;
        let x = self.x;
        let y = self.y;
        let z = self.z;

        let y_squared = y.pow(2);
        let z_squared = z.pow(2);
        let three_b_times_z_squared = z_squared * three_b;
        let eight_times_y_squared = y_squared * 8u64; // 8Y^2
        let m1 = y_squared - (three_b_times_z_squared * 3u64); // Y^2 - 9bZ^2
        let m2 = y_squared + three_b_times_z_squared; // Y^2 + 3bZ^2
        let x3 = x * y * m1 * 2u64;
        let y3 = m1 * m2 + three_b_times_z_squared * eight_times_y_squared;
        let z3 = eight_times_y_squared * y * z;
        HomogeneousPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    ///Add self `multiple` times, where `multiple` is represented by the A, which must be able to be converted into a NAF.
    pub fn times<A: BitRepr>(&self, multiple: &A) -> HomogeneousPoint<T> {
        match self {
            ref p if p.is_zero() => Zero::zero(),
            HomogeneousPoint { y, .. } => {
                if *y == zero() {
                    *self
                } else {
                    let mut naf = multiple.to_bits();
                    naf.reverse();
                    naf.iter().fold(zero(), |res, &cur| {
                        let doubled = res.double();
                        if cur == 1 {
                            doubled + *self
                        } else {
                            doubled
                        }
                    })
                }
            }
        }
    }

    ///Divide out by the z we've been carrying around.
    pub fn normalize(&self) -> Option<(T, T)> {
        if self.is_zero() {
            Option::None
        } else {
            let z_inv: T = self.z.inv();
            Some((self.x * z_inv, self.y * z_inv))
        }
    }
}

///HomogeneousPoint on the twisted curve which is either Zero or an x,y coordinate which has a z it carries
///along. In order to get the real x,y you must call `normalize` which divides out by the z.
///
///Note that this assumes all points are Fp2Elem
#[derive(Clone, Debug, Copy)]
#[repr(C)]
pub struct TwistedHPoint<T> {
    pub x: Fp2Elem<T>,
    pub y: Fp2Elem<T>,
    pub z: Fp2Elem<T>,
}

impl<T> PartialEq for TwistedHPoint<T>
where
    T: Field + ExtensionField,
{
    fn eq(&self, other: &TwistedHPoint<T>) -> bool {
        match (*self, *other) {
            (ref p1, ref p2) if p1.is_zero() && p2.is_zero() => true,
            (ref p1, ref p2) if p1.is_zero() || p2.is_zero() => false,
            (
                TwistedHPoint {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                TwistedHPoint {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => x1 * z2 == x2 * z1 && y1 * z2 == y2 * z1,
        }
    }
}

impl<T> Eq for TwistedHPoint<T> where T: Field + ExtensionField {}

impl<T, U> Mul<U> for TwistedHPoint<T>
where
    T: Field + ExtensionField,
    U: BitRepr,
{
    type Output = TwistedHPoint<T>;
    fn mul(self, rhs: U) -> TwistedHPoint<T> {
        self.times(&rhs)
    }
}

impl<T> Add for TwistedHPoint<T>
where
    T: Field + Eq + ExtensionField,
{
    type Output = TwistedHPoint<T>;
    fn add(self, other: TwistedHPoint<T>) -> TwistedHPoint<T> {
        let three_b = T::xi_inv_times_9();
        match (self, other) {
            (
                TwistedHPoint {
                    x: x1,
                    y: y1,
                    z: z1,
                },
                TwistedHPoint {
                    x: x2,
                    y: y2,
                    z: z2,
                },
            ) => {
                let x1x2 = x1 * x2;
                let y1y2 = y1 * y2;
                let z1z2 = z1 * z2;
                let cxy = (x1 + y1) * (x2 + y2) - x1x2 - y1y2;
                let cxz = (x1 + z1) * (x2 + z2) - x1x2 - z1z2;
                let cyz = (y1 + z1) * (y2 + z2) - y1y2 - z1z2;
                let tbzz = three_b * z1z2;
                let hx = three_b * (cyz * cxz);
                let hy = three_b * (x1x2 * cxz);
                let dmyz = y1y2 - tbzz;
                let dpyz = y1y2 + tbzz;
                let x3 = cxy * dmyz - hx;
                let y3 = dpyz * dmyz + hy * 3;
                let z3 = cyz * dpyz + x1x2 * cxy * 3;
                TwistedHPoint {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            }
        }
    }
}

impl<T> AddAssign for TwistedHPoint<T>
where
    T: Field + ExtensionField + Eq,
{
    fn add_assign(&mut self, other: TwistedHPoint<T>) {
        *self = *self + other
    }
}

impl<T> Zero for TwistedHPoint<T>
where
    T: Field + Eq + ExtensionField,
{
    fn zero() -> TwistedHPoint<T> {
        TwistedHPoint {
            x: Zero::zero(),
            y: One::one(),
            z: Zero::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.z == Zero::zero()
    }
}

impl<T> Neg for TwistedHPoint<T>
where
    T: Field + ExtensionField,
{
    type Output = TwistedHPoint<T>;
    fn neg(self) -> TwistedHPoint<T> {
        if self.is_zero() {
            Zero::zero()
        } else {
            let neg_y: Fp2Elem<T> = -self.y;
            TwistedHPoint::<T> {
                x: self.x,
                y: neg_y,
                z: self.z,
            }
        }
    }
}

impl<T> Sub for TwistedHPoint<T>
where
    T: Field + Eq + ExtensionField,
{
    type Output = TwistedHPoint<T>;
    fn sub(self, other: TwistedHPoint<T>) -> TwistedHPoint<T> {
        self + -other
    }
}

impl<T> SubAssign for TwistedHPoint<T>
where
    T: Field + Eq + ExtensionField,
{
    fn sub_assign(&mut self, other: TwistedHPoint<T>) {
        *self = *self - other
    }
}

impl<T: Field + Hashable + ExtensionField> Hashable for TwistedHPoint<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.normalize().as_ref().to_bytes()
    }
}

impl<T: Field + ExtensionField + BytesDecoder> BytesDecoder for TwistedHPoint<T> {
    // TwistedHPoint<T> is 2 Fp2s -- x and y
    const ENCODED_SIZE_BYTES: usize = Fp2Elem::<T>::ENCODED_SIZE_BYTES * 2;

    /// Decodes and validates that the resultant TwistedHPoint is on the curve
    fn decode(bytes: ByteVector) -> Result<Self, DecodeErr> {
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            //   3 / (u + 3)
            let twisted_curve_const_coeff: Fp2Elem<T> = ExtensionField::xi().inv() * 3;

            let (x_bytes, y_bytes) = bytes.split_at(Self::ENCODED_SIZE_BYTES / 2);
            let hpoint = TwistedHPoint::new(
                Fp2Elem::<T>::decode(x_bytes.to_vec())?,
                Fp2Elem::<T>::decode(y_bytes.to_vec())?,
            );

            if hpoint.y.pow(2) == (hpoint.x.pow(3) + twisted_curve_const_coeff) {
                Result::Ok(hpoint)
            } else {
                Result::Err(DecodeErr::BytesInvalid {
                    message: "Point does not satisfy the curve equation".to_string(),
                    bad_bytes: bytes.clone(),
                })
            }
        } else {
            Result::Err(DecodeErr::BytesNotCorrectLength {
                required_length: Self::ENCODED_SIZE_BYTES,
                bad_bytes: bytes,
            })
        }
    }
}

impl<T> TwistedHPoint<T>
where
    T: Field,
{
    pub fn new(x: Fp2Elem<T>, y: Fp2Elem<T>) -> Self {
        TwistedHPoint {
            x,
            y,
            z: One::one(),
        }
    }
}

impl<T> TwistedHPoint<T>
where
    T: Field + ExtensionField,
{
    //   J. Renes, C. Castello, and L. Batina,
    //   "Complete addition formulas for prime order elliptic curves",
    //   https://eprint.iacr.org/2015/1060
    // (For y^2=x^3+b, doubling formulas, page 12.)
    // Mind that the main curve uses b = 3, but the twisted curve uses
    // b = 3/(u+3). The code below _assumes_ that the twisted curve is used
    // when the base field is FP2Elem (this is quite ugly).
    //
    // Since the formulas are complete, there is no need for make a special for zero.
    pub fn double(&self) -> TwistedHPoint<T> {
        let three_b = T::xi_inv_times_9();
        let x = self.x;
        let y = self.y;
        let z = self.z;

        let y_squared = y.pow(2);
        let z_squared = z.pow(2);
        let three_b_times_z_squared = three_b * z_squared;
        let eight_times_y_squared = y_squared * 8u64; // 8Y^2
        let m1 = y_squared - (three_b_times_z_squared * 3u64); // Y^2 - 9bZ^2
        let m2 = y_squared + three_b_times_z_squared; // Y^2 + 3bZ^2
        let x3 = x * y * m1 * 2u64;
        let y3 = m1 * m2 + three_b_times_z_squared * eight_times_y_squared;
        let z3 = eight_times_y_squared * y * z;
        TwistedHPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    ///Add self `multiple` times, where `multiple` is represented by the A, which must be able to be converted into a NAF.
    pub fn times<A: BitRepr>(&self, multiple: &A) -> TwistedHPoint<T> {
        match self {
            ref p if p.is_zero() => Zero::zero(),
            TwistedHPoint { y, .. } => {
                if *y == zero() {
                    *self
                } else {
                    let mut naf = multiple.to_bits();
                    naf.reverse();
                    naf.iter().fold(zero(), |res, &cur| {
                        let doubled = res.double();
                        let result = if cur == 1 { doubled + *self } else { doubled };
                        result
                    })
                }
            }
        }
    }

    ///Divide out by the z we've been carrying around.
    pub fn normalize(&self) -> Option<(Fp2Elem<T>, Fp2Elem<T>)> {
        if self.is_zero() {
            Option::None
        } else {
            let z_inv: Fp2Elem<T> = self.z.inv();
            Some((self.x * z_inv, self.y * z_inv))
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use gridiron::fp_256::Fp256;
    use hex;
    use internal::curve::FP_256_CURVE_POINTS;
    use internal::fp::fp256_unsafe_from;
    use internal::test::arb_fp256;
    use num_traits::One;
    use proptest::prelude::*;

    #[test]
    fn eq_will_divide_by_z() {
        let point = HomogeneousPoint {
            x: Fp256::from(100u32),
            y: Fp256::from(200u32),
            z: Fp256::from(100u32),
        };
        let point2 = HomogeneousPoint {
            x: Fp256::from(1u32),
            y: Fp256::from(2u32),
            z: Fp256::from(1u32),
        };
        assert_eq!(point, point2);
    }
    #[test]
    fn colt_xi() {
        let result = Fp256::xi().inv() * 3u64 * 3;
        println!("{:?}", result);
    }

    #[test]
    fn addition_to_self_laws() {
        let g2 = HomogeneousPoint {
            //65000549695646603732796438742359905742825358107623003571877145026864184071691
            x: fp256_unsafe_from(
                "8fb501e34aa387f9aa6fecb86184dc21ee5b88d120b5b59e185cac6c5e08960b",
            ),
            //65000549695646603732796438742359905742825358107623003571877145026864184071772
            y: fp256_unsafe_from(
                "8fb501e34aa387f9aa6fecb86184dc21ee5b88d120b5b59e185cac6c5e08965c",
            ),
            //64
            z: fp256_unsafe_from(
                "0000000000000000000000000000000000000000000000000000000000000040",
            ),
        };

        let computed_g2 = FP_256_CURVE_POINTS.generator + FP_256_CURVE_POINTS.generator;
        assert_eq!(g2, computed_g2);
        assert_eq!(
            FP_256_CURVE_POINTS.generator.times(&Fp256::from(2u8)),
            computed_g2
        );
        assert_eq!(FP_256_CURVE_POINTS.generator.double(), computed_g2);
    }

    #[test]
    fn point_minus_self_is_zero() {
        assert_eq!(
            FP_256_CURVE_POINTS.generator - FP_256_CURVE_POINTS.generator,
            zero()
        );
    }

    #[test]
    fn roundtrip_known_bytes() {
        let hashed_value_bytes = hex::decode("4a40fc771f0c5625d2ef6783013c52eece1697e71c6f82c3aa58396485c2a6c1713527192c3a7ed9103aca79a39f08a154723602bb768655fdd499f8062b461a5752395183b7743fb6ed688a856ef42aae259df29f52678ef0fccb91adb5374d10820c4e85917c4a1906cb06f537158c0556ecfaa55c874f388823ab9270a536").unwrap();

        let hpoint = TwistedHPoint::<Fp256>::decode(hashed_value_bytes.clone()).unwrap();

        assert_eq!(hashed_value_bytes, hpoint.to_bytes())
    }

    #[test]
    fn double_zero_is_zero() {
        let zero_fp256 = HomogeneousPoint {
            x: Fp256::zero(),
            y: Fp256::zero(),
            z: Fp256::zero(),
        };
        let double = zero_fp256.double();
        assert_eq!(zero_fp256, double);

        let zero_fp2: HomogeneousPoint<Fp2Elem<Fp256>> = HomogeneousPoint {
            x: Fp2Elem::zero(),
            y: Fp2Elem::zero(),
            z: Fp2Elem::zero(),
        };
        assert_eq!(zero_fp2, zero_fp2.double());
    }

    #[test]
    fn double_same_as_add() {
        let result = FP_256_CURVE_POINTS.g1 + FP_256_CURVE_POINTS.g1;
        let double_result = FP_256_CURVE_POINTS.g1.double();
        assert_eq!(result, double_result);
    }

    proptest! {
        #[test]
        fn identity(a in arb_homogeneous()) {
            prop_assert!(a * Fp256::one() == a);
            prop_assert!(a + Zero::zero() == a);
            prop_assert!(a - a == Zero::zero());
            prop_assert!(<HomogeneousPoint<Fp256> as Zero>::zero() + a == a);
        }

        #[test]
        fn commutative(a in arb_homogeneous(), b in arb_homogeneous()) {
            prop_assert!(a + b == b + a);
        }

        #[test]
        fn associative(a in arb_homogeneous(), b in arb_homogeneous(), c in arb_homogeneous()) {
            prop_assert!((a + b) + c == a + (b + c));
        }

        #[test]
        fn distributive(a in arb_fp256(), b in arb_homogeneous(), c in arb_homogeneous()) {
            prop_assert!((b + c) * a == b * a + c * a);
        }

        #[test]
        fn add_equals_mult(a in arb_homogeneous()) {
            prop_assert!(a + a == a * Fp256::from(2u64));
            prop_assert!(a + a + a == a * Fp256::from(3u64));
        }

        #[test]
        fn normalize_return_none_if_zero(a in arb_homogeneous()) {
            prop_assert_eq!(a.is_zero(), a.normalize() == None);
        }

        #[test]
        fn z_zero_means_none_normalize(a in arb_homogeneous()) {
            let b = match a {
               HomogeneousPoint {x, y, z: _ } =>
                   HomogeneousPoint { x: x, y: y, z: Fp256::zero()},
            };
            prop_assert_eq!(None, b.normalize());
        }

        #[test]
        fn twisted_identity(a in arb_homogeneous_fp2()) {
            prop_assert!(a * Fp256::one() == a);
            prop_assert!(a + Zero::zero() == a);
            prop_assert!(a - a == Zero::zero());
            prop_assert!(<TwistedHPoint<Fp256> as Zero>::zero() + a == a);
        }

        #[test]
        fn twisted_commutative(a in arb_homogeneous_fp2(), b in arb_homogeneous_fp2()) {
            prop_assert!(a + b == b + a);
        }

        #[test]
        fn twisted_associative(a in arb_homogeneous_fp2(), b in arb_homogeneous_fp2(), c in arb_homogeneous_fp2()) {
            prop_assert!((a + b) + c == a + (b + c));
        }

        #[test]
        fn twisted_distributive(a in arb_fp256(), b in arb_homogeneous_fp2(), c in arb_homogeneous_fp2()) {
            prop_assert!((b + c) * a == b * a + c * a);
        }

        #[test]
        fn twisted_add_equals_mult(a in arb_homogeneous_fp2()) {
            let added = a + a;
            prop_assert_eq!(added.normalize(),  (a * Fp256::from(2u64)).normalize());
            prop_assert!(a + a == a * Fp256::from(2u64));
            prop_assert!(a + a + a == a * Fp256::from(3u64));
        }

        #[test]
        fn twisted_normalize_return_none_if_zero(a in arb_homogeneous_fp2()) {
            prop_assert_eq!(a.is_zero(), a.normalize() == None);
        }

        #[test]
        fn twisted_z_zero_means_none_normalize(a in arb_homogeneous_fp2()) {
            let b = match a {
                TwistedHPoint {x, y, z: _ } =>
                   TwistedHPoint { x: x, y: y, z: zero()},
            };
            prop_assert_eq!(None, b.normalize());
        }


        #[test]
        fn roundtrip_bytes(arb_tw_hpoint in arb_homogeneous_fp2()) {
            prop_assume!(arb_tw_hpoint != zero());
            let hashed_value_bytes = arb_tw_hpoint.to_bytes();
            let hpoint = TwistedHPoint::<Fp256>::decode(hashed_value_bytes).unwrap();
            assert_eq!(arb_tw_hpoint, hpoint)
        }

        #[test]
        fn double_is_mul_2_fp256(arb_hpoint in arb_homogeneous()) {
            prop_assert_eq!(arb_hpoint.double(), arb_hpoint * Fp256::from(2u8));
        }

        #[test]
        fn double_is_mul_2_fp2(arb_hpoint_fp2 in arb_homogeneous_fp2()) {
            prop_assert_eq!(arb_hpoint_fp2.double(), arb_hpoint_fp2 * Fp256::from(2u8));
         prop_assert_eq!(arb_hpoint_fp2.double(), arb_hpoint_fp2 + arb_hpoint_fp2);
        }

        #[test]
        fn double_twice_is_mul_4_fp2(arb_hpoint_fp2 in arb_homogeneous_fp2()) {
            prop_assert_eq!(arb_hpoint_fp2.double().double(), arb_hpoint_fp2 * Fp256::from(4u8));
        }
    }

    prop_compose! {
        [pub] fn arb_homogeneous_fp2()(seed in any::<u64>()) -> TwistedHPoint<Fp256> {
            if seed == 0 {
                Zero::zero()
            } else if seed == 1 {
                FP_256_CURVE_POINTS.g1
            } else {
                FP_256_CURVE_POINTS.g1// * Fp256::from(seed)
            }
        }
    }

    prop_compose! {
        [pub] fn arb_homogeneous()(seed in any::<u64>()) -> HomogeneousPoint<Fp256> {
            if seed == 0 {
                Zero::zero()
            } else if seed == 1 {
                FP_256_CURVE_POINTS.generator
            } else {
                FP_256_CURVE_POINTS.generator * Fp256::from(seed)
            }
        }
    }
}
