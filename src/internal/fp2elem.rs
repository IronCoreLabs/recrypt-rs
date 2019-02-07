use crate::internal::bytedecoder::{BytesDecoder, DecodeErr};
use crate::internal::field::Field;
use crate::internal::hashable::Hashable;
use crate::internal::pow_for_square;
use crate::internal::ByteVector;
use crate::internal::Square;
use core::fmt;
use gridiron::digits::constant_bool::ConstantBool;
use gridiron::digits::constant_time_primitives::ConstantSwap;
use num_traits::{Inv, One, Pow, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};
use std::result::Result;

/// This is the degree 2 extension of the base field FP. It is formed by attaching the variable to
/// Fp, subject to the constraint u^2 + 1 = 0. That is, FP2 = Fp[u]/(u^2 + 1)
///
/// A value in FP2 is represented as a polynomial a + b * u, where a and b are both elements of Fp.
///
/// Note that PartialEq and Eq are not constant time and equality checks of Fp2Elems will
/// reveal the value of the Fp2
#[derive(Clone, PartialEq, Eq, Copy, Default)]
#[repr(C)]
pub struct Fp2Elem<T> {
    pub elem1: T,
    pub elem2: T,
}

///This is an empty type which allows for Fp2 * Xi() in order to multiply the fp2 element * Fp2(1, 3).
pub struct Xi();

impl<T> Mul<Fp2Elem<T>> for Xi
where
    T: Mul<u32, Output = T> + Sub<Output = T> + Add<Output = T> + Copy,
{
    type Output = Fp2Elem<T>;
    #[inline]
    fn mul(self, fp2: Fp2Elem<T>) -> Fp2Elem<T> {
        fp2 * self
    }
}

impl<T> Mul<Xi> for Fp2Elem<T>
where
    T: Mul<u32, Output = T> + Sub<Output = T> + Add<Output = T> + Copy,
{
    type Output = Fp2Elem<T>;
    ///This is a shorthand for multiplying times u + 3.
    /// (a*u+b)*(u+3) = -a+3b + u*(3a+b)
    /// In this case we expand out the additions.
    #[inline]
    fn mul(self, _xi: Xi) -> Self {
        Fp2Elem {
            //3a+b
            elem1: self.elem1 + self.elem1 + self.elem1 + self.elem2,
            //-a+3b
            elem2: self.elem2 + self.elem2 + self.elem2 - self.elem1,
        }
    }
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

impl<T: ConstantSwap> ConstantSwap for Fp2Elem<T> {
    fn swap_if(&mut self, other: &mut Self, swap: ConstantBool<u32>) {
        self.elem1.swap_if(&mut other.elem1, swap);
        self.elem2.swap_if(&mut other.elem2, swap);
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

///This is not constant time. It reveals the u32, but not the point itself.
impl<T> Mul<u32> for Fp2Elem<T>
where
    T: Mul<u32, Output = T>,
{
    type Output = Fp2Elem<T>;

    fn mul(self, other: u32) -> Self {
        Fp2Elem {
            elem1: self.elem1 * other,
            elem2: self.elem2 * other,
        }
    }
}

impl<T> Div<Fp2Elem<T>> for Fp2Elem<T>
where
    T: Field,
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

impl<T> Fp2Elem<T> {
    pub fn map<U, F: Fn(T) -> U>(self, op: &F) -> Fp2Elem<U> {
        Fp2Elem {
            elem1: op(self.elem1),
            elem2: op(self.elem2),
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

    //This is not constant time and shouldn't be used for algorithms that are.
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

    //This is not constant time and shouldn't be used for algorithms that are.
    fn is_one(&self) -> bool {
        *self == One::one()
    }
}

impl<T> Inv for Fp2Elem<T>
where
    T: Pow<u32, Output = T>
        + Add<Output = T>
        + Neg<Output = T>
        + Mul<Output = T>
        + Inv<Output = T>
        + Copy,
{
    type Output = Fp2Elem<T>;
    fn inv(self) -> Fp2Elem<T> {
        let magnitude = self.elem1.pow(2) + self.elem2.pow(2);
        let mag_inv = magnitude.inv();
        Fp2Elem {
            elem1: (-self.elem1 * mag_inv),
            elem2: (self.elem2 * mag_inv),
        }
    }
}

///This is not constant time. It reveals the u32, but not the point itself.
impl<T> Pow<u32> for Fp2Elem<T>
where
    T: PartialEq + Zero + One + Mul<T, Output = T> + Sub<T, Output = T> + Copy + Square,
{
    type Output = Fp2Elem<T>;
    fn pow(self, rhs: u32) -> Self {
        pow_for_square(self, rhs)
    }
}

impl<T> Square for Fp2Elem<T>
where
    T: Add<Output = T> + Mul<Output = T> + Sub<Output = T> + Copy,
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
    use crate::internal::test::arb_fp256;
    use crate::internal::test::arb_fp480;
    use gridiron::fp_256;
    use gridiron::fp_256::Fp256;
    use gridiron::fp_480;
    use proptest::prop_compose;
    use proptest::proptest;

    #[test]
    #[rustfmt::skip]
    fn hashable() {
        let fp2 = Fp2Elem {
            elem1: fp_256::Monty::from(256u32),
            elem2: fp_256::Monty::from(255u32),
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
            elem1: fp_256::Monty::from(256u32),
            elem2: fp_256::Monty::from(255u32),
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

    #[test]
    fn mul_same_monty() {
        let fp2 = Fp2Elem {
            elem1: Fp256::from(4u32),
            elem2: Fp256::from(2u32),
        };
        let fp2_monty = fp2.map(&|fp| fp.to_monty());;
        let five_times = fp2 * fp2 * fp2 * fp2 * fp2;
        let five_times_monty = fp2_monty * fp2_monty * fp2_monty * fp2_monty * fp2_monty;
        assert_eq!(five_times_monty, five_times.map(&|fp| fp.to_monty()));
    }

    #[test]
    fn pow_by_five_should_be_same_monty() {
        let five = 5;
        let fp2 = Fp2Elem {
            elem1: Fp256::from(4u32),
            elem2: Fp256::from(2u32),
        };
        let fp2_monty = fp2.map(&|fp| fp.to_monty());;
        let five_times_monty = fp2_monty * fp2_monty * fp2_monty * fp2_monty * fp2_monty;
        assert_eq!(five_times_monty, fp2_monty.pow(five));
    }

    prop_compose! {
        [pub] fn arb_fp2()(e1 in arb_fp256(), e2 in arb_fp256()) -> Fp2Elem<fp_256::Monty> {
            Fp2Elem {
                elem1: e1,
                elem2: e2
            }
       }
    }

    prop_compose! {
        [pub] fn arb_fp2_480()(e1 in arb_fp480(), e2 in arb_fp480()) -> Fp2Elem<fp_480::Monty> {
            Fp2Elem {
                elem1: e1,
                elem2: e2
            }
        }
    }

    field_proptest!(arb_fp2, fp256, fp2);
    field_proptest!(arb_fp2_480, fp480, fp2);
}
