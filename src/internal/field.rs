use crate::internal::Square;
use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::fp6elem::Fp6Elem;
use crate::internal::platform::{fp256_constants, fp480_constants};
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
            if a == b { b == a } else { b != a }
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
            elem1: fp256_constants::XI_INV_TIMES_9_ELEM1,
            elem2: fp256_constants::XI_INV_TIMES_9_ELEM2,
        }
    }
    #[inline]
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp256_constants::FROBENIUS_FACTOR_1_ELEM1,
            elem2: fp256_constants::FROBENIUS_FACTOR_1_ELEM2,
        }
    }
    #[inline]
    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp256_constants::FROBENIUS_FACTOR_2_ELEM1,
            elem2: fp256_constants::FROBENIUS_FACTOR_2_ELEM2,
        }
    }
    #[inline]
    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp256_constants::FROBENIUS_FACTOR_FP12_ELEM1,
            elem2: fp256_constants::FROBENIUS_FACTOR_FP12_ELEM2,
        }
    }

    #[inline]
    fn twisted_curve_const_coeff() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp256_constants::TWISTED_CURVE_CONST_COEFF_ELEM1,
            elem2: fp256_constants::TWISTED_CURVE_CONST_COEFF_ELEM2,
        }
    }
}

impl ExtensionField for fp_480::Monty {
    // precalculate this since it's used in every double and add operation in the extension field.
    // xi is u + 3 or Fp2Elem(1, 3)
    // Fp480::xi().inv() * 9
    fn xi_inv_times_9() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp480_constants::XI_INV_TIMES_9_ELEM1,
            elem2: fp480_constants::XI_INV_TIMES_9_ELEM2,
        }
    }
    fn frobenius_factor_1() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp480_constants::FROBENIUS_FACTOR_1_ELEM1,
            elem2: fp480_constants::FROBENIUS_FACTOR_1_ELEM2,
        }
    }

    fn frobenius_factor_2() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp480_constants::FROBENIUS_FACTOR_2_ELEM1,
            elem2: fp480_constants::FROBENIUS_FACTOR_2_ELEM2,
        }
    }

    fn frobenius_factor_fp12() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp480_constants::FROBENIUS_FACTOR_FP12_ELEM1,
            elem2: fp480_constants::FROBENIUS_FACTOR_FP12_ELEM2,
        }
    }

    #[inline]
    fn twisted_curve_const_coeff() -> Fp2Elem<Self> {
        Fp2Elem {
            elem1: fp480_constants::TWISTED_CURVE_CONST_COEFF_ELEM1,
            elem2: fp480_constants::TWISTED_CURVE_CONST_COEFF_ELEM2,
        }
    }
}
