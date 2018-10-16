use internal::bytedecoder::{BytesDecoder, DecodeErr};
use internal::field::ExtensionField;
use internal::field::Field;
use internal::fp2elem::Fp2Elem;
use internal::hashable::Hashable;
use internal::non_adjacent_form::NonAdjacentForm;
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
            //COLT: We should discuss how we want to represent x and y.
            display("The point represented by {:?},{:?} is not on the curve.", x, y)
            description("The point was not on the curve.")
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
    U: NonAdjacentForm,
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
            (ref p1, o) if p1.is_zero() => o,
            (o, ref p2) if p2.is_zero() => o,
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
            ) => if x1 == x2 && y1 == -(y2) && z1 == z2 {
                Zero::zero()
            } else if self == other {
                self.double()
            } else {
                let y_times_z2 = y1 * z2;
                let x_times_z2 = x1 * z2;
                let x2_times_z = x2 * z1;
                let a = (y2 * z1) - y_times_z2;
                let b = x2_times_z - x_times_z2;
                let z_times_z2 = z1 * z2;
                let b_squared = b.square();
                let b_cubed = b_squared * b;
                let a_squared = a.square();
                let z_times_z2_times_a_squared = z_times_z2 * a_squared;
                let x_times_z2_plus_x2_times_z = x_times_z2 + x2_times_z;
                let x3 =
                    b * (z_times_z2_times_a_squared - (b_squared * x_times_z2_plus_x2_times_z));
                let y3 = a * b_squared * (x_times_z2 + x_times_z2_plus_x2_times_z)
                    - ((z_times_z2_times_a_squared * a) + (y_times_z2 * b_cubed));
                let z3 = z_times_z2 * b_cubed;
                HomogeneousPoint {
                    x: x3,
                    y: y3,
                    z: z3,
                }
            },
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
            y: Zero::zero(),
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

/// It is important to note that this is a BytesDecoder for HomogeneousPoint<Fp2Elem<T>>, NOT HomogeneousPoint<T>
impl<T: Field + ExtensionField + BytesDecoder> BytesDecoder for HomogeneousPoint<Fp2Elem<T>> {
    // HomogeneousPoint<Fp2Elem<T>> is 2 Fp2s -- x and y
    const ENCODED_SIZE_BYTES: usize = Fp2Elem::<T>::ENCODED_SIZE_BYTES * 2;

    /// Decodes and validates that the resultant HomogeneousPoint is on the curve
    fn decode(bytes: ByteVector) -> Result<Self, DecodeErr> {
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            //   3 / (u + 3)
            let twisted_curve_const_coeff: Fp2Elem<T> = ExtensionField::xi().inv() * 3;

            let (x_bytes, y_bytes) = bytes.split_at(Self::ENCODED_SIZE_BYTES / 2);
            let hpoint = HomogeneousPoint::new(
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
        match *self {
            ref p if p.is_zero() => Zero::zero(),
            HomogeneousPoint { y, .. } if y == zero() => zero(),
            HomogeneousPoint { x, y, z } => {
                let x_cubed = x.pow(3);
                let y_squared = y.pow(2);
                let z_squared = z.pow(2);
                let y_squared_times_z = y_squared * z;
                let eight_times_y_squared_times_z = y_squared_times_z * 8;
                let nine_times_x_cubed = x_cubed * 9;
                let x2 = x * 2 * y * z * (nine_times_x_cubed - eight_times_y_squared_times_z);
                let y2 = nine_times_x_cubed * (y_squared_times_z * 4 - x_cubed * 3)
                    - eight_times_y_squared_times_z * y_squared_times_z;
                let z2: T = eight_times_y_squared_times_z * y * z_squared;
                HomogeneousPoint {
                    x: x2,
                    y: y2,
                    z: z2,
                }
            }
        }
    }

    ///Add self `multiple` times, where `multiple` is represented by the A, which must be able to be converted into a NAF.
    pub fn times<A: NonAdjacentForm>(&self, multiple: &A) -> HomogeneousPoint<T> {
        match self {
            ref p if p.is_zero() => Zero::zero(),
            HomogeneousPoint { y, .. } => if *y == zero() {
                *self
            } else {
                let mut naf = multiple.to_naf();
                naf.reverse();
                naf.iter().fold(zero(), |res, &cur| {
                    let doubled = res.double();
                    if cur == -1 {
                        (doubled - *self)
                    } else if cur == 1 {
                        doubled + *self
                    } else {
                        doubled
                    }
                })
            },
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

#[cfg(test)]
pub mod test {
    use super::*;
    use gridiron::fp_256::Fp256;
    use hex;
    use internal::curve;
    use internal::curve::FP_256_CURVE_POINTS;
    use internal::test::arb_fp256;
    use num_traits::One;
    use proptest::prelude::*;

    #[test]
    fn eq_will_divide_by_z() {
        let point = HomogeneousPoint {
            x: Fp256::from(100),
            y: Fp256::from(200),
            z: Fp256::from(100),
        };
        let point2 = HomogeneousPoint {
            x: Fp256::from(1),
            y: Fp256::from(2),
            z: Fp256::from(1),
        };
        assert_eq!(point, point2);
    }

    #[test]
    fn addition_to_self_laws() {
        let g2 = HomogeneousPoint {
            //65000549695646603732796438742359905742825358107623003571877145026864184071691
            x: Fp256::new([
                1755467536201717259,
                17175472035685840286,
                12281294985516866593,
                10355184993929758713,
            ]),
            //65000549695646603732796438742359905742825358107623003571877145026864184071772
            y: Fp256::new([
                1755467536201717340,
                17175472035685840286,
                12281294985516866593,
                10355184993929758713,
            ]),
            //64
            z: Fp256::new([64, 0, 0, 0]),
        };

        let computed_g2 = FP_256_CURVE_POINTS.generator + FP_256_CURVE_POINTS.generator;
        assert_eq!(g2, computed_g2);
        assert_eq!(
            FP_256_CURVE_POINTS.generator.times(&Fp256::from(2)),
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

        let hpoint =
            HomogeneousPoint::<Fp2Elem<Fp256>>::decode(hashed_value_bytes.clone()).unwrap();

        assert_eq!(hashed_value_bytes, hpoint.to_bytes())
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
        fn roundtrip_bytes(arb_hpoint in arb_homogeneous_fp2()) {
            let hashed_value_bytes = arb_hpoint.to_bytes();
            let hpoint = HomogeneousPoint::<Fp2Elem<Fp256>>::decode(hashed_value_bytes).unwrap();

            assert_eq!(arb_hpoint, hpoint)
        }
    }

    prop_compose! {
        fn arb_homogeneous_fp2()(
        fp256 in arb_fp256().prop_filter("", |a| !(*a == Zero::zero()))) -> HomogeneousPoint<Fp2Elem<Fp256>> {
            let curve_points = &*curve::FP_256_CURVE_POINTS;
            curve_points.g1 * fp256
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
