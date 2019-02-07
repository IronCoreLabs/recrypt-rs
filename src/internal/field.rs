use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::fp6elem::Fp6Elem;
use crate::internal::Square;
use gridiron::fp_256;
use gridiron::fp_480;
use num_traits::{Inv, Pow};
use num_traits::{One, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

#[cfg(test)]
macro_rules! field_props {
    () => {
        #[cfg(test)]
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

        #[allow(clippy::eq_op)] // necessary for commutative props
        fn prop_mul_commutative(a: Self, b: Self, c: Self) -> bool {
            b * a * c == a * b * c
        }

        fn prop_add_assoc(a: Self, b: Self, c: Self) -> bool {
            a + (b + c) == a + b + c
        }

        #[allow(clippy::eq_op)] // necessary for commutative props
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
    };
}

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
    + Mul<u32, Output = Self>
    + Inv<Output = Self>
    + Pow<u32, Output = Self>
    + Sub<Output = Self>
{
    #[cfg(test)]
    field_props!();
}

impl Field for fp_256::Monty {}
impl Field for fp_480::Monty {}
impl Field for Fr256 {}
impl Field for Fr480 {}

/// Contains the values needed to configure a new Fp type to be used as an extension field
/// (FP2Elem, FP6Elem, FP12Elem)
/// All `ExtensionField`s are `Field`s
pub trait ExtensionField: Field
where
    Self: Sized + From<u8>,
{
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
    #[inline]
    fn v() -> Fp6Elem<Self> {
        Fp6Elem {
            elem1: Zero::zero(),
            elem2: One::one(),
            elem3: Zero::zero(),
        }
    }

    /// 3 / (u+3)
    /// pre-calculate as an optimization
    /// ExtensionField::xi().inv() * 3;
    fn twisted_curve_const_coeff() -> Fp2Elem<Self>;
}

impl ExtensionField for fp_256::Monty {
    //precalculate this since it's used in every double and add operation in the extension field.
    //xi is u + 3 or Fp2Elem(1, 3)
    // Fp256::xi().inv() * 9
    fn xi_inv_times_9() -> Fp2Elem<Self> {
        Fp2Elem {
            //19500164908693981119838931622707971722847607432286901071563143508059255221534.str
            elem1: fp_256::Monty::new([
                2050346385, 731299471, 959575992, 34915099, 1787054046, 707674376, 1189605443,
                44293910, 138,
            ]),
            //6500054969564660373279643874235990574282535810762300357187714502686418407181
            elem2: fp_256::Monty::new([
                729307778, 258461402, 1559141440, 1381403208, 157052610, 1802371594, 636365429,
                127350700, 17,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            // 26098034838977895781559542626833399156321265654106457577426020397262786167059
            // num.digits(2^31) in sage gives the array
            elem1: fp_256::Monty::new([
                12717650, 1979656862, 1972108829, 1559171847, 290869350, 694266310, 579853055,
                1597302116, 4,
            ]),
            // 15931493369629630809226283458085260090334794394361662678240713231519278691715
            elem2: fp_256::Monty::new([
                916222744, 723717387, 574787027, 1552331516, 1261698828, 887614939, 1510504974,
                237248389, 8,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            // 19885131339612776214803633203834694332692106372356013117629940868870585019582
            elem1: fp_256::Monty::new([
                15189756, 1959629061, 767155255, 1427131279, 513871136, 1996531885, 1401068065,
                1422686260, 66,
            ]),
            // 21645619881471562101905880913352894726728173167203616652430647841922248593627
            elem2: fp_256::Monty::new([
                656635847, 1575335407, 606381995, 1750621660, 1486126693, 503904416, 1955368925,
                270969940, 28,
            ]),
        }
    }
    #[inline]
    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            // 8669379979083712429711189836753509758585994370025260553045152614783263110636
            elem1: fp_256::Monty::new([
                454717458, 161507933, 804946138, 817080316, 1413496639, 904558052, 1356825578,
                765259087, 11,
            ]),
            // 19998038925833620163537568958541907098007303196759855091367510456613536016040
            elem2: fp_256::Monty::new([
                392395988, 386079276, 1435458002, 829532913, 1153717094, 1170750470, 311764801,
                1868664732, 53,
            ]),
        }
    }

    #[inline]
    fn twisted_curve_const_coeff() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp_256::Monty::new([
                1925150376, 516250914, 1051564560, 1369812449, 731601065, 672046428, 625168271,
                1952553705, 93,
            ]),
            elem2: fp_256::Monty::new([
                1674758358, 86153800, 1235541696, 1892123501, 768178752, 600790531, 1643777575,
                1474105998, 5,
            ]),
        }
    }
}

impl ExtensionField for fp_480::Monty {
    // precalculate this since it's used in every double and add operation in the extension field.
    // xi is u + 3 or Fp2Elem(1, 3)
    // Fp480::xi().inv() * 9
    fn xi_inv_times_9() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp_480::Monty::new([
                1671524251, 1452836661, 1514278714, 1089055752, 983710563, 1342902855, 1277558075,
                1876974179, 947518822, 981090444, 247487949, 1283900828, 1334523677, 1392777601,
                1513546415, 5235,
            ]),
            elem2: fp_480::Monty::new([
                335877574, 1323354927, 650625437, 272173725, 1832380438, 2065643415, 655409061,
                1376608173, 1642768871, 464289801, 840813404, 665753910, 1051781983, 447188070,
                183786362, 17059,
            ]),
        }
    }
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            // 2705020609406098470693743943193507017690525853579041639836321147125100162418094245778443957282985233325521741487078451689773015537700623376387510
            elem1: fp_480::Monty::new([
                1789717966, 1667803516, 415596737, 273473839, 86323342, 1847146047, 411641533,
                883838890, 333532818, 2020025246, 1090726896, 1144837448, 1056047014, 650675300,
                1518220857, 28583,
            ]),
            // 1651643729828744562959031609260204931467006255025965356538853937438900508750440674159520451455470865884696804132950675577710427706655106873786415
            elem2: fp_480::Monty::new([
                1463808839, 1670428701, 447968177, 1822223094, 1576270537, 1038296259, 66655687,
                578662642, 153246326, 1500216407, 53886423, 1315635309, 1456804263, 176996090,
                1710325846, 31113,
            ]),
        }
    }

    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            // 2306651261022207350847683647334036061609898996050387019709069937614457385067216464366007100887697910705559503143400341307341852524867445116042081
            elem1: fp_480::Monty::new([
                721025432, 530063334, 1045885399, 453726440, 2141696003, 1626330876, 1074975251,
                1714081964, 1995410861, 609055642, 2058665923, 1876157870, 937690781, 1255299233,
                741827240, 14111,
            ]),
            // 2700715513864156317217817646762981219394581764002749630356081821581587105847754189716578562648186994801551242072586877237522675959303129100251619
            elem2: fp_480::Monty::new([
                147532118, 4451373, 893741577, 424324553, 481155820, 353715416, 620523272,
                346497951, 1670022807, 1427377181, 732861676, 2088692375, 582789470, 669478976,
                249410141, 28740,
            ]),
        }
    }

    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            // 1656507924366244928424688705439191250492553228839737584554076474712325077234544758394965182643615114744030751122897661836350026981040666763359635
            elem1: fp_480::Monty::new([
                736041138, 285900164, 1852287620, 1099722104, 1782561133, 1457388007, 1874229037,
                1965266811, 1231149838, 771491782, 467524787, 1737481601, 782773382, 79418783,
                1572898018, 31139,
            ]),
            // 411347727129503104504468123876138850111359831064167067331474757563790630947112631916366442374487601276802707186517326847256605909760387475785136
            elem2: fp_480::Monty::new([
                492638839, 304045155, 1057698408, 772372983, 1813080623, 1701111681, 801357526,
                1606643950, 1537923020, 1695901916, 157173875, 1177883133, 354458948, 163418612,
                376825454, 23056,
            ]),
        }
    }

    #[inline]
    fn twisted_curve_const_coeff() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp_480::Monty::new([
                1976657987, 2124705180, 1103755761, 1290923474, 2085255841, 1647224075, 1270424569,
                286550022, 1158572853, 451253923, 1853842034, 2007948773, 1667592921, 2116284018,
                790821013, 23589,
            ]),
            elem2: fp_480::Monty::new([
                1531442428, 2081544602, 1531699218, 302801582, 1652317917, 456481830, 1063041565,
                835589236, 1390322869, 278987042, 1335789303, 1086071918, 1573345690, 1085259625,
                1063395545, 27530,
            ]),
        }
    }
}
