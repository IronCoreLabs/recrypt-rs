use core::fmt;
use internal::bytedecoder::{BytesDecoder, DecodeErr};
use internal::field::Field;
use internal::hashable::Hashable;
use internal::pow_for_square;
use internal::ByteVector;
use internal::Square;
use num_traits::{Inv, One, Pow, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::result::Result;

/// This is the degree 2 extension of the base field FP. It is formed by attaching the variable to
/// Fp, subject to the constraint u^2 + 1 = 0. That is, FP2 = Fp[u]/(u^2 + 1)
///
/// A value in FP2 is represented as a polynomial a + b * u, where a and b are both elements of Fp.
#[derive(Clone, PartialEq, Eq, Copy, Default)]
#[repr(C)]
pub struct Fp2Elem<T> {
    pub elem1: T,
    pub elem2: T,
}

impl<T> fmt::Debug for Fp2Elem<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(a:{:?} + b:{:?}*u)", self.elem1, self.elem2)
    }
}

impl<T> fmt::LowerHex for Fp2Elem<T>
where
    T: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "(a:{:x} + b:{:x}*u)", self.elem1, self.elem2)
    }
}

impl<T> Neg for Fp2Elem<T>
where
    T: Neg<Output = T>,
{
    type Output = Fp2Elem<T>;
    fn neg(self) -> Self {
        Fp2Elem {
            elem1: -self.elem1,
            elem2: -self.elem2,
        }
    }
}

impl<T> Add for Fp2Elem<T>
where
    T: Add<Output = T>,
{
    type Output = Fp2Elem<T>;
    fn add(self, other: Fp2Elem<T>) -> Self {
        Fp2Elem {
            elem1: self.elem1 + other.elem1,
            elem2: self.elem2 + other.elem2,
        }
    }
}

impl<T> Sub for Fp2Elem<T>
where
    T: Sub<Output = T>,
{
    type Output = Fp2Elem<T>;
    fn sub(self, other: Fp2Elem<T>) -> Self {
        Fp2Elem {
            elem1: self.elem1 - other.elem1,
            elem2: self.elem2 - other.elem2,
        }
    }
}

impl<T> Mul<u64> for Fp2Elem<T>
where
    T: Mul<u64, Output = T>,
{
    type Output = Fp2Elem<T>;

    fn mul(self, other: u64) -> Self {
        Fp2Elem {
            elem1: self.elem1 * other,
            elem2: self.elem2 * other,
        }
    }
}

impl<T> Div<Fp2Elem<T>> for Fp2Elem<T>
where
    T: Mul<Output = T>
        + Inv<Output = T>
        + Sub<Output = T>
        + Add<Output = T>
        + Pow<u64, Output = T>
        + Add<Output = T>
        + Neg<Output = T>
        + Div<Output = T>
        + Copy,
{
    type Output = Fp2Elem<T>;
    fn div(self, other: Fp2Elem<T>) -> Self {
        self * other.inv()
    }
}

impl<T> Mul<Fp2Elem<T>> for Fp2Elem<T>
where
    T: Mul<Output = T> + Sub<Output = T> + Add<Output = T> + Copy,
{
    type Output = Fp2Elem<T>;
    fn mul(self, other: Fp2Elem<T>) -> Self {
        let z0 = self.elem2 * other.elem2;
        let z2 = self.elem1 * other.elem1;
        let z1 = (self.elem1 + self.elem2) * (other.elem1 + other.elem2);
        Fp2Elem {
            elem1: z1 - z2 - z0,
            elem2: z0 - z2,
        }
    }
}

impl<T> Zero for Fp2Elem<T>
where
    T: Add<Output = T> + Zero + PartialEq,
{
    fn zero() -> Self {
        Fp2Elem {
            elem1: T::zero(),
            elem2: T::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        *self == Fp2Elem::zero()
    }
}

impl<T> One for Fp2Elem<T>
where
    T: Zero + One + Sub<Output = T> + Add<Output = T> + PartialEq + Copy,
{
    fn one() -> Self {
        Fp2Elem {
            elem1: T::zero(),
            elem2: T::one(),
        }
    }

    fn is_one(&self) -> bool {
        *self == One::one()
    }
}

impl<T> Inv for Fp2Elem<T>
where
    T: Pow<u64, Output = T> + Add<Output = T> + Neg<Output = T> + Div<Output = T> + Copy,
{
    type Output = Fp2Elem<T>;
    fn inv(self) -> Fp2Elem<T> {
        let mag = self.elem1.pow(2) + self.elem2.pow(2);
        Fp2Elem {
            elem1: (-self.elem1 / mag),
            elem2: (self.elem2 / mag),
        }
    }
}

impl<T> Pow<u64> for Fp2Elem<T>
where
    T: Field,
{
    type Output = Fp2Elem<T>;
    fn pow(self, rhs: u64) -> Self {
        pow_for_square(self, rhs)
    }
}

impl<T> Square for Fp2Elem<T>
where
    T: Clone + Field,
{
    fn square(&self) -> Self {
        let a2 = self.elem1 * self.elem2;
        let a3 = a2 + a2;
        let b2 = self.elem2 + self.elem1;
        let b3 = self.elem2 - self.elem1;
        let b4 = b2 * b3;
        Fp2Elem {
            elem1: a3,
            elem2: b4,
        }
    }
}

impl<T> Field for Fp2Elem<T> where T: Field {}

impl<T> Fp2Elem<T>
where
    T: Field,
{
    /// This is the element to the p power.
    /// Some of the reasoning is as follows
    ///  x ^ p -x = 0 == x^p = x
    /// By the binomial expansion we get:
    ///  (x + (y * u)) ^ p == x^p + p * (middle terms) + (u^p * y^p)
    ///  u ^p == -u  which is because our p is congruent to 3 mod 4
    ///  x^p + -uy^p == x + -uy
    pub fn frobenius(&self) -> Fp2Elem<T> {
        Fp2Elem {
            elem1: -self.elem1,
            elem2: self.elem2,
        }
    }
}

impl<T> Hashable for Fp2Elem<T>
where
    T: Hashable + Copy,
{
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.elem1, self.elem2].to_bytes()
    }
}

impl<T> BytesDecoder for Fp2Elem<T>
where
    T: BytesDecoder + Sized,
{
    const ENCODED_SIZE_BYTES: usize = T::ENCODED_SIZE_BYTES * 2;

    fn decode(bytes: ByteVector) -> Result<Fp2Elem<T>, DecodeErr> {
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            let (t1, t2) = bytes.split_at(Self::ENCODED_SIZE_BYTES / 2);
            let fp2_elem: Fp2Elem<T> = Fp2Elem {
                elem1: T::decode(t1.to_vec())?,
                elem2: T::decode(t2.to_vec())?,
            };
            Result::Ok(fp2_elem)
        } else {
            Result::Err(DecodeErr::BytesNotCorrectLength {
                required_length: Self::ENCODED_SIZE_BYTES,
                bad_bytes: bytes,
            })
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use gridiron::fp_256::Fp256;
    use internal::test::arb_fp256;

    pub fn get_fp2s() -> [Fp2Elem<Fp256>; 6] {
        let fp2a = Fp2Elem {
            elem1: Fp256::from(100u32),
            elem2: Fp256::from(200u32),
        };
        let fp2b = Fp2Elem {
            elem1: Fp256::from(300u32),
            elem2: Fp256::from(400u32),
        };
        let fp2c = Fp2Elem {
            elem1: Fp256::from(500u32),
            elem2: Fp256::from(600u32),
        };
        let fp2d = Fp2Elem {
            elem1: Fp256::from(700u32),
            elem2: Fp256::from(800u32),
        };
        let fp2e = Fp2Elem {
            elem1: Fp256::from(900u32),
            elem2: Fp256::from(1000u32),
        };
        let fp2f = Fp2Elem {
            elem1: Fp256::from(1100u32),
            elem2: Fp256::from(1200u32),
        };

        [fp2a, fp2b, fp2c, fp2d, fp2e, fp2f]
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn hashable() {
        let fp2 = Fp2Elem {
            elem1: Fp256::from(256u32),
            elem2: Fp256::from(255u32),
        };

        let bytes = fp2.to_bytes();

        assert_eq!(bytes, vec![
            //elem1
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,1,0,
            //elem2
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,255]);
    }

    #[test]
    fn round_trip_bytes() {
        let fp2 = Fp2Elem {
            elem1: Fp256::from(256u32),
            elem2: Fp256::from(255u32),
        };

        let bytes = fp2.to_bytes();
        let decoded_fp2 = Fp2Elem::decode(bytes);
        assert!(decoded_fp2.is_ok());
        assert_eq!(fp2, decoded_fp2.unwrap());
    }

    #[test]
    fn test_add_fixed() {
        let fp2 = Fp2Elem {
            elem1: Fp256::from(2u32),
            elem2: Fp256::from(1u32),
        };
        assert_eq!(
            fp2 + fp2,
            Fp2Elem {
                elem1: Fp256::from(4u32),
                elem2: Fp256::from(2u32),
            }
        );
    }

    #[test]
    fn pow_by_five_should_be_five_muls() {
        let five = 5;
        let fp2 = Fp2Elem {
            elem1: Fp256::from(4u32),
            elem2: Fp256::from(2u32),
        };
        let five_times = fp2 * fp2 * fp2 * fp2 * fp2;
        assert_eq!(fp2.pow(five), five_times);
    }

    prop_compose! {
        [pub] fn arb_fp2()(e1 in arb_fp256(), e2 in arb_fp256()) -> Fp2Elem<Fp256> {
            Fp2Elem {
                elem1: e1,
                elem2: e2
            }
       }
    }

    proptest! {
        ///All of these are tests from field.rs
        #[test]
        fn prop_semigroup(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_semigroup(a,b,c))
        }
        #[test]
        fn prop_monoid_identity(a in arb_fp2()) {
            prop_assert!(Field::prop_monoid_identity(a))
        }
        #[test]
        fn prop_inv(a in arb_fp2(), b in arb_fp2()) {
            prop_assert!(Field::prop_inv(a,b))
        }
        #[test]
        fn prop_one_is_mul_identity(a in arb_fp2()) {
            prop_assert!(Field::prop_one_is_mul_identity(a))
        }
        #[test]
        fn prop_zero_is_add_identity(a in arb_fp2()) {
            prop_assert!(Field::prop_zero_is_add_identity(a))
        }
        #[test]
        fn prop_eq_reflexive(a in arb_fp2(), b in arb_fp2()) {
            prop_assert!(Field::prop_eq_reflexive(a,b))
        }
        #[test]
        fn prop_sub_same_as_neg_add(a in arb_fp2(), b in arb_fp2()) {
            prop_assert!(Field::prop_sub_same_as_neg_add(a,b))
        }
        #[test]
        fn prop_mul_distributive(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_mul_distributive(a,b,c))
        }
        #[test]
        fn prop_mul_assoc(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_mul_assoc(a,b,c))
        }
        #[test]
        fn prop_mul_commutative(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_mul_commutative(a,b,c))
        }
        #[test]
        fn prop_add_assoc(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_add_assoc(a,b,c))
        }
        #[test]
        fn prop_add_commutative(a in arb_fp2(), b in arb_fp2(), c in arb_fp2()) {
            prop_assert!(Field::prop_add_commutative(a,b,c))
        }
        #[test]
        fn prop_pow_is_mul(a in arb_fp2()) {
            prop_assert!(Field::prop_pow_is_mul(a))
        }
        #[test]
        fn prop_square_same_as_mul_self(a in arb_fp2()) {
            prop_assert!(Field::prop_square_same_as_mul_self(a))
        }
        #[test]
        fn prop_square2_same_as_pow4(a in arb_fp2()) {
            prop_assert!(Field::prop_square2_same_as_pow4(a))
        }
    }
}
