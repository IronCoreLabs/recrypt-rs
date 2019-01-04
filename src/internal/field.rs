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
    Self: Sized + From<u8>,
{
    /// Xi is u + 3 which is v^3.
    /// v^p == Xi^((p-1)/3) * v
    fn xi() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: Self::one(),
            elem2: Self::from(3u8),
        }
    }
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
    fn v() -> Fp6Elem<Self> {
        Fp6Elem {
            elem1: Zero::zero(),
            elem2: One::one(),
            elem3: Zero::zero(),
        }
    }
}

impl ExtensionField for Fp256 {
    //precalculate this since it's used in every double and add operation in the extension field.
    // Fp256::xi().inv() * 9
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
}

impl ExtensionField for Fp480 {
    // precalculate this since it's used in every double and add operation in the extension field.
    // Fp480::xi().inv() * 9
    fn xi_inv_times_9() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: Fp480::new([
                0x2c7937c6, 0x3f331d0b, 0x1cddc7ca, 0x327d046a, 0x2255fb13, 0x6935454, 0x36a73701,
                0xa1abada, 0x103430a2, 0x16882d4e, 0x2b6116e, 0x6a60dfd0, 0x1a6591d0, 0x2c4f8de0,
                0x6e144ddc, 0x2665,
            ]),
            elem2: Fp480::new([
                0x397dbd45, 0x151109ae, 0x5ef497ee, 0x3b7f0178, 0x361ca906, 0x57867171, 0x678d1255,
                0x35e3e48, 0x5abc1036, 0x782b9c4, 0x563cb07a, 0x4e204a9a, 0x5e21db45, 0xec52f4a,
                0x4f5c19f4, 0xccc,
            ]),
        }
    }
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            // 2705020609406098470693743943193507017690525853579041639836321147125100162418094245778443957282985233325521741487078451689773015537700623376387510
            elem1: Fp480::new([
                1289162166, 138724829, 377249524, 1410516015, 1649183802, 1808893220, 2099893442,
                1613052070, 1271534030, 616853401, 1876231282, 773310939, 80164335, 2003460751,
                1588206447, 28393,
            ]),
            // 1651643729828744562959031609260204931467006255025965356538853937438900508750440674159520451455470865884696804132950675577710427706655106873786415
            elem2: Fp480::new([
                477724719, 2123594952, 1106539541, 600250264, 1564472042, 1937537843, 948293455,
                550173476, 897981975, 1628932098, 587901015, 969156276, 1317419705, 1782565297,
                1670845724, 17336,
            ]),
        }
    }

    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            // 2306651261022207350847683647334036061609898996050387019709069937614457385067216464366007100887697910705559503143400341307341852524867445116042081
            elem1: Fp480::new([
                1396636513, 1578821261, 1092430650, 1309873789, 762700047, 238274856, 585447501,
                330355371, 341111234, 1648355101, 582077952, 1115762901, 1455751468, 925169272,
                393911954, 24212,
            ]),
            // 2700715513864156317217817646762981219394581764002749630356081821581587105847754189716578562648186994801551242072586877237522675959303129100251619
            elem2: Fp480::new([
                635236835, 624246053, 2099448091, 1718272887, 1818939813, 1465844392, 1322326592,
                1282579346, 996132666, 1551423827, 390948370, 1787987376, 668506041, 2046466517,
                1181867369, 28348,
            ]),
        }
    }

    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            // 1656507924366244928424688705439191250492553228839737584554076474712325077234544758394965182643615114744030751122897661836350026981040666763359635
            elem1: Fp480::new([
                1334605203, 1827599780, 529391447, 1381967368, 251805170, 216998276, 602980270,
                266708112, 1531079225, 1198586746, 726932044, 1251262731, 1028183026, 1513346905,
                1795185920, 17387,
            ]),
            // 411347727129503104504468123876138850111359831064167067331474757563790630947112631916366442374487601276802707186517326847256605909760387475785136
            elem2: Fp480::new([
                747324848, 1152034816, 579621566, 423208337, 761265896, 1462212589, 2002170354,
                1072168795, 1348910927, 2067945986, 585062688, 570324324, 868980721, 996048971,
                1688016050, 4317,
            ]),
        }
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
