use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::fp6elem::Fp6Elem;
use crate::internal::Square;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;
use num_traits::{Inv, Pow};
use num_traits::{One, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

pub trait Field:
    One
    + Zero
    + Copy
    + Eq
    + Square
    + Neg<Output = Self>
    + Add<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Mul<u64, Output = Self>
    + Inv<Output = Self>
    + Pow<u64, Output = Self>
    + Sub<Output = Self>
{
    fn prop_semigroup(a: Self, b: Self, c: Self) -> bool {
        a + (b + c) == (a + b) + c
    }

    fn prop_monoid_identity(a: Self) -> bool {
        a + Zero::zero() == <Self as Zero>::zero() + a && a + Zero::zero() == a
    }

    fn prop_inv(a: Self, b: Self) -> bool {
        a == a * (b.inv() * b) && a == a * (b * b.inv())
    }

    fn prop_one_is_mul_identity(a: Self) -> bool {
        <Self as One>::one() * a == a && a == a * <Self as One>::one()
    }

    fn prop_zero_is_add_identity(a: Self) -> bool {
        <Self as Zero>::zero() + a == a && a == a + <Self as Zero>::zero()
    }

    fn prop_eq_reflexive(a: Self, b: Self) -> bool {
        if a == b {
            b == a
        } else {
            b != a
        }
    }

    fn prop_sub_same_as_neg_add(a: Self, b: Self) -> bool {
        a + -b == a - b
    }

    fn prop_mul_distributive(a: Self, b: Self, c: Self) -> bool {
        a * (b + c) == a * b + a * c
    }

    fn prop_mul_assoc(a: Self, b: Self, c: Self) -> bool {
        a * (b * c) == a * b * c
    }

    fn prop_mul_commutative(a: Self, b: Self, c: Self) -> bool {
        b * a * c == a * b * c
    }

    fn prop_add_assoc(a: Self, b: Self, c: Self) -> bool {
        a + (b + c) == a + b + c
    }

    fn prop_add_commutative(a: Self, b: Self, c: Self) -> bool {
        b + a + c == a + b + c
    }

    fn prop_pow_is_mul(a: Self) -> bool {
        a * a == a.pow(2) && a * a * a == a.pow(3)
    }

    fn prop_x_sub_y_eq_x_plus_y_mul_neg1(x: Self, y: Self) -> bool {
        // x - y == x + y * (-1)
        let expected = x - y;
        let result = x + y * -<Self as One>::one();

        expected == result
    }

    fn prop_square_same_as_mul_self(a: Self) -> bool {
        let expected = a * a;
        let result = a.square();

        expected == result
    }

    fn prop_square2_same_as_pow4(a: Self) -> bool {
        let expected = a.square().square();
        let result = a.pow(4);

        expected == result
    }
}

impl Field for Fp256 {}
impl Field for Fr256 {}
impl Field for Fp480 {}
impl Field for Fr480 {}

/// Contains the values needed to configure a new Fp type to be used as an extension field
/// (FP2Elem, FP6Elem, FP12Elem)
/// All `ExtensionField`s are `Field`s
pub trait ExtensionField: Field
where
    Self: Sized,
{
    /// Xi is u + 3 which is v^3.
    /// v^p == Xi^((p-1)/3) * v
    fn xi() -> Fp2Elem<Self>;

    ///Precomputed xi.inv() * 9
    fn xi_inv_times_9() -> Fp2Elem<Self>;

    /// Used in frobenius, this is Xi^((p-1)/3)
    /// Fp6Elem[A](Fp2Elem.Zero, Fp2Elem.One, Fp2Elem.Zero).frobenius
    /// Xi  ^ ((p - p % 3) /3) because of the prime we've chosen, p % 3 == 1
    fn frobenius_factor_1() -> Fp2Elem<Self>;

    /// Used in frobenius, this is frobeniusFactor1^2
    fn frobenius_factor_2() -> Fp2Elem<Self>;
    // if q = (p-1)/2
    // q % 3 == 0  -- For our p
    // Xi ^ ((q - q % 3)/3)
    fn frobenius_factor_fp12() -> Fp2Elem<Self>;

    ///v is the thing that cubes to xi
    ///v^3 = u+3, because by definition it is a solution to the equation y^3 - (u + 3)
    fn v() -> Fp6Elem<Self>;
}

impl ExtensionField for Fp256 {
    #[inline]
    fn xi() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: Self::one(),
            elem2: Self::from(3u8),
        }
    }

    //precalculate this since it's used in every double and add operation in the extension field.
    #[inline]
    fn xi_inv_times_9() -> Fp2Elem<Self> {
        Fp2Elem {
            //19500164908693981119838931622707971722847607432286901071563143508059255221534.str
            elem1: Fp256::new([
                0x29c2d1e, 0x41d13441, 0x2740738a, 0x2275485c, 0x74a8709, 0x30ff46ea, 0x7f76ff86,
                0xe59e217, 0x2b,
            ]),
            //6500054969564660373279643874235990574282535810762300357187714502686418407181
            elem2: Fp256::new([
                0x56340f0d, 0x6b45bc15, 0xd157bd8, 0xb7c6d74, 0x26e2d03, 0x3affc24e, 0x2a7cffd7,
                0x2f734b5d, 0xe,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            // 26098034838977895781559542626833399156321265654106457577426020397262786167059
            // num.digits(2^31) in sage gives the array
            elem1: Fp256::new([
                516587795, 432442066, 2081743774, 272481278, 216868981, 2047188942, 766684017,
                1501260986, 57,
            ]),
            // 15931493369629630809226283458085260090334794394361662678240713231519278691715
            elem2: Fp256::new([
                1018688899, 285125916, 381469398, 738635315, 809814760, 1686808322, 473749512,
                477359611, 35,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            // 19885131339612776214803633203834694332692106372356013117629940868870585019582
            elem1: Fp256::new([
                272985278, 337458509, 1511734401, 44257531, 567886726, 95238613, 670462112,
                2068509020, 43,
            ]),
            // 21645619881471562101905880913352894726728173167203616652430647841922248593627
            elem2: Fp256::new([
                129224923, 1627709782, 1853228136, 1045486385, 137170065, 710273374, 1587423245,
                1836993535, 47,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            // 8669379979083712429711189836753509758585994370025260553045152614783263110636
            elem1: Fp256::new([
                940766700, 726957870, 1193934117, 1012163387, 1658028813, 1288872574, 1205874830,
                358153140, 19,
            ]),
            // 19998038925833620163537568958541907098007303196759855091367510456613536016040
            elem2: Fp256::new([
                223094440, 382877345, 511765441, 618638984, 1337480992, 1694576735, 638506791,
                457086189, 44,
            ]),
        }
    }
    #[inline]
    fn v() -> Fp6Elem<Self> {
        Fp6Elem {
            elem1: Zero::zero(),
            elem2: One::one(),
            elem3: Zero::zero(),
        }
    }
}


impl ExtensionField for Fp480 {
    fn xi() -> Fp2Elem<Self> {
        unimplemented!()
    }

    fn xi_inv_times_9() -> Fp2Elem<Self> {
        unimplemented!()
    }

    fn frobenius_factor_1() -> Fp2Elem<Self> {
        unimplemented!()
    }

    fn frobenius_factor_2() -> Fp2Elem<Self> {
        unimplemented!()
    }

    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        unimplemented!()
    }

    fn v() -> Fp6Elem<Self> {
        unimplemented!()
    }
}

/*
//Additive laws permit all elements.
  implicit def pred[A]: Predicate[A] = Predicate.const(true)
  implicit def fp6Arb = Arbitrary(fp6Gen[Fp])
  implicit val fp480Arb = Arbitrary(nonZeroFp480Gen)
  implicit val fpArb = Arbitrary(nonZeroFpGen)

  implicit def fp6Arb480 = Arbitrary(fp6Gen[Fp480])
  checkAll("Fp256", RingLaws[Fp].field)
  checkAll("FP2Elem256", RingLaws[FP2Elem[Fp]].field)
  checkAll("FP6Elem256", RingLaws[FP6Elem[Fp]].field)
  checkAll("FP12Elem256", RingLaws[FP12Elem[Fp]].field)
  checkAll("HomogeneousPoint256", RingLaws[HomogeneousPoint[Fp]].additiveGroup)
  //Tests on the field instance for Fp480
  checkAll("Fp480", RingLaws[Fp480].field)
  checkAll("FP2Elem480", RingLaws[FP2Elem[Fp480]].field)
  checkAll("FP6Elem480", RingLaws[FP6Elem[Fp480]].field)
  checkAll("FP12Elem480", RingLaws[FP12Elem[Fp480]].field)
  checkAll("HomogeneousPoint480", RingLaws[HomogeneousPoint[Fp480]].additiveGroup)
  checkAll("HomogeneousPointFP2Elem480", RingLaws[HomogeneousPoint[FP2Elem[Fp480]]].additiveGroup)
*/
