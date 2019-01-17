use crate::internal::bytedecoder::{BytesDecoder, DecodeErr};
use crate::internal::field::{ExtensionField, Field};
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::hashable::Hashable;
use crate::internal::ByteVector;
use crate::internal::{pow_for_square, sum_n, Square};
use core::fmt;
use num_traits::{Inv, One, Pow, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// This is the degree 6 extension of the base field, which is formed on top of the degree 2 extension
/// using the variable substitution v^3 = u + 3. That factor, u + 3, is also referred to as Xi.
/// A value in FP6 is represented as a polynomial a + b * v + c * v^2, where a, b, and c are all
/// FP2Elems. That is, FP6 = FP2[v]/(v^3 - (u + 3)).
///
/// Recall that u is the attached variable for FP2.
#[derive(Clone, PartialEq, Eq, Copy, Default)]
#[repr(C)]
pub struct Fp6Elem<T> {
    pub elem1: Fp2Elem<T>,
    pub elem2: Fp2Elem<T>,
    pub elem3: Fp2Elem<T>,
}

impl<T> fmt::Debug for Fp6Elem<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "({:?})*v^2 + ({:?}*v) + ({:?})",
            self.elem1, self.elem2, self.elem3
        )
    }
}

impl<T> fmt::LowerHex for Fp6Elem<T>
where
    T: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "({:x})*v^2 + ({:x}*v) + ({:x})",
            self.elem1, self.elem2, self.elem3
        )
    }
}

impl<T> Neg for Fp6Elem<T>
where
    T: Neg<Output = T>,
{
    type Output = Fp6Elem<T>;
    fn neg(self) -> Self {
        Fp6Elem {
            elem1: -self.elem1,
            elem2: -self.elem2,
            elem3: -self.elem3,
        }
    }
}

impl<T> Add for Fp6Elem<T>
where
    T: Add<Output = T>,
{
    type Output = Fp6Elem<T>;
    fn add(self, other: Fp6Elem<T>) -> Self {
        let new_fp1 = self.elem1 + other.elem1;
        let new_fp2 = self.elem2 + other.elem2;
        let new_fp3 = self.elem3 + other.elem3;

        Fp6Elem {
            elem1: new_fp1,
            elem2: new_fp2,
            elem3: new_fp3,
        }
    }
}

impl<T> Sub for Fp6Elem<T>
where
    T: Sub<Output = T>,
{
    type Output = Fp6Elem<T>;
    fn sub(self, other: Fp6Elem<T>) -> Self {
        let new_fp1 = self.elem1 - other.elem1;
        let new_fp2 = self.elem2 - other.elem2;
        let new_fp3 = self.elem3 - other.elem3;

        Fp6Elem {
            elem1: new_fp1,
            elem2: new_fp2,
            elem3: new_fp3,
        }
    }
}

///This is not constant time. It reveals the u32, but not the Fp6 itself.
impl<T> Mul<u32> for Fp6Elem<T>
where
    T: Copy + Add<Output = T> + Zero + PartialEq,
{
    type Output = Fp6Elem<T>;

    fn mul(self, other: u32) -> Self {
        sum_n(self, other)
    }
}

impl<T> Mul<Fp2Elem<T>> for Fp6Elem<T>
where
    T: Mul<Output = T> + Sub<Output = T> + Add<Output = T> + Copy,
{
    type Output = Fp6Elem<T>;
    fn mul(self, other: Fp2Elem<T>) -> Self {
        let a2 = self.elem1 * other;
        let b2 = self.elem2 * other;
        let c2 = self.elem3 * other;
        Fp6Elem {
            elem1: a2,
            elem2: b2,
            elem3: c2,
        }
    }
}

impl<T> Mul<Fp6Elem<T>> for Fp6Elem<T>
where
    T: Mul<Output = T> + Sub<Output = T> + Add<Output = T> + ExtensionField + Copy,
{
    type Output = Fp6Elem<T>;
    fn mul(self, other: Fp6Elem<T>) -> Self {
        // We're multiplying 2 expressions of the following form:
        // a1*v^2 + b1 * v + c1  and a2*v^2 + b2 * v + c2 where
        // v^3 == xi and
        // a1 == fp1,
        // a2 == elem.fp1,
        // b1 == fp2,
        // b2 == elem.fp2
        // c1 == fp3
        // c2 == elem.fp3

        let elem1 = self.elem1 * other.elem3 + self.elem2 * other.elem2 + self.elem3 * other.elem1;

        let elem2 = self.elem1 * other.elem1 * ExtensionField::xi()
            + self.elem2 * other.elem3
            + self.elem3 * other.elem2;

        let elem3 = (self.elem1 * other.elem2 + self.elem2 * other.elem1) * ExtensionField::xi()
            + self.elem3 * other.elem3;

        Fp6Elem {
            elem1,
            elem2,
            elem3,
        }
    }
}

impl<T> Zero for Fp6Elem<T>
where
    T: Add<Output = T> + Zero + PartialEq,
{
    fn zero() -> Self {
        Fp6Elem {
            elem1: Zero::zero(),
            elem2: Zero::zero(),
            elem3: Zero::zero(),
        }
    }

    //This is not constant time and shouldn't be used for algorithms that are.
    fn is_zero(&self) -> bool {
        *self == Zero::zero()
    }
}

impl<T> One for Fp6Elem<T>
where
    T: Zero + One + Sub<Output = T> + Add<Output = T> + PartialEq + ExtensionField + Copy,
{
    fn one() -> Self {
        Fp6Elem {
            elem1: Zero::zero(),
            elem2: Zero::zero(),
            elem3: One::one(),
        }
    }

    //This is not constant time and shouldn't be used for algorithms that are.
    fn is_one(&self) -> bool {
        *self == One::one()
    }
}

impl<T> Inv for Fp6Elem<T>
where
    T: Copy + ExtensionField,
{
    type Output = Fp6Elem<T>;
    fn inv(self) -> Fp6Elem<T> {
        let xi: Fp2Elem<T> = ExtensionField::xi();

        // Algorithm 5.23 from El Mrabet--Joye 2017 "Guide to Pairing-Based Cryptography."
        let (c, b, a) = (self.elem1, self.elem2, self.elem3);
        let v0 = a.square();
        let v1 = b.square();
        let v2 = c.square();
        let v3 = a * b;
        let v4 = a * c;
        let v5 = b * c;
        let cap_a = v0 - xi * v5;
        let cap_b = xi * v2 - v3;
        let cap_c = v1 - v4;
        let v6 = a * cap_a;
        let v61 = v6 + (xi * c * cap_b);
        let v62 = v61 + (xi * b * cap_c);
        let cap_f = v62.inv();
        let c0 = cap_a * cap_f;
        let c1 = cap_b * cap_f;
        let c2 = cap_c * cap_f;
        Fp6Elem {
            elem1: c2,
            elem2: c1,
            elem3: c0,
        }
    }
}

impl<T> Div<Fp6Elem<T>> for Fp6Elem<T>
where
    T: ExtensionField,
{
    type Output = Fp6Elem<T>;
    fn div(self, other: Fp6Elem<T>) -> Self {
        self * other.inv()
    }
}

///This is not constant time. It reveals the u32, but not the fp6 itself.
impl<T> Pow<u32> for Fp6Elem<T>
where
    T: ExtensionField,
{
    type Output = Fp6Elem<T>;
    fn pow(self, rhs: u32) -> Self {
        pow_for_square(self, rhs)
    }
}

impl<T> Square for Fp6Elem<T>
where
    T: Clone + ExtensionField,
{
    fn square(&self) -> Self {
        let xi: Fp2Elem<T> = ExtensionField::xi();

        let a_prime = Fp2Elem {
            elem1: self.elem1.elem1 * 2,
            elem2: self.elem1.elem2 * 2,
        };
        let a2 = a_prime * self.elem3 + self.elem2.square();
        let fp22 = self.elem1.square() * xi + self.elem2 * self.elem3 * 2;
        let fp32 = (a_prime * self.elem2) * xi + self.elem3.square();
        Fp6Elem {
            elem1: a2,
            elem2: fp22,
            elem3: fp32,
        }
    }
}

impl<T> Field for Fp6Elem<T> where T: ExtensionField {}

impl<T> Fp6Elem<T>
where
    T: ExtensionField,
{
    pub fn frobenius(&self) -> Fp6Elem<T> {
        let frobenius_factor_1 = ExtensionField::frobenius_factor_1();
        let frobenius_factor_2 = ExtensionField::frobenius_factor_2();
        let a = self.elem1.frobenius();
        let b = self.elem2.frobenius();
        let c = self.elem3.frobenius();
        let a1 = a * frobenius_factor_2;
        let b1 = b * frobenius_factor_1;
        Fp6Elem {
            elem1: a1,
            elem2: b1,
            elem3: c,
        }
    }
}

impl<T> Fp6Elem<T> {
    pub fn create(one: T, two: T, three: T, four: T, five: T, six: T) -> Fp6Elem<T> {
        Fp6Elem {
            elem1: Fp2Elem {
                elem1: one,
                elem2: two,
            },
            elem2: Fp2Elem {
                elem1: three,
                elem2: four,
            },
            elem3: Fp2Elem {
                elem1: five,
                elem2: six,
            },
        }
    }
}

impl<T> Fp6Elem<T>
where
    T: PartialEq + Zero + Copy,
{
    /// Converts this Fp6 to an Fp2 for frobenius. This is only possible if `elem1` and `elem2`
    /// are zero.
    ///
    /// ### Constant time analysis
    /// If called with an Fp6 that is not appropriate for conversion (non-zero `elem1` and `elem2`),
    /// the values of `elem1` and `elem2` are leaked and a panic!() will occur. Because of the definition
    /// of `Pairing.frobenius()`, this leaking condition would be a developer error.
    ///
    /// In the case where conversion is possible, the (zero) `elem1` and `elem2` are leaked, but
    /// the non-zero `elem3` is not.
    pub fn frobenius_to_fp2(&self) -> Fp2Elem<T> {
        if self.elem1 == Zero::zero() && self.elem2 == Zero::zero() {
            self.elem3
        } else {
            panic!("Developer error: frobenius_to_fp2 for Fp6 is not defined if elem1 and elem2 are not zero")
        }
    }
}

impl<T> Hashable for Fp6Elem<T>
where
    T: Hashable + Copy,
{
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.elem1, self.elem2, self.elem3].to_bytes()
    }
}

impl<T> BytesDecoder for Fp6Elem<T>
where
    T: BytesDecoder + Copy,
{
    const ENCODED_SIZE_BYTES: usize = T::ENCODED_SIZE_BYTES * 6;

    fn decode(bytes: ByteVector) -> Result<Fp6Elem<T>, DecodeErr> {
        // Converting to a byte vector just concatenates the byte vector representation of each
        // of the three coefficients a, b, and c together. So reversing just requires splitting
        // the byte vector in thirds and converting each smaller vector back to an element.
        // (Note that this is recursive, since the coefficients are each FP2 elements, which
        // in turn consist of two coefficients.)
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            // A little tricky here, since we need to split into 3 equal chunks for decoding
            let chunks: Vec<&[u8]> = bytes.chunks(Self::ENCODED_SIZE_BYTES / 3).collect();
            match &chunks[..] {
                [t1, t2, t3] => {
                    let fp2_elem: Fp6Elem<T> = Fp6Elem {
                        elem1: Fp2Elem::decode(t1.to_vec())?,
                        elem2: Fp2Elem::decode(t2.to_vec())?,
                        elem3: Fp2Elem::decode(t3.to_vec())?,
                    };
                    Result::Ok(fp2_elem)
                }
                _ => Result::Err(DecodeErr::BytesNotCorrectLength {
                    required_length: Self::ENCODED_SIZE_BYTES,
                    bad_bytes: bytes.clone(),
                }),
            }
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
    use crate::internal::fp2elem::test::{arb_fp2, arb_fp2_480};
    use gridiron::fp_256::Fp256;
    use gridiron::fp_480::Fp480;
    use proptest::prelude::*;

    #[test]
            #[cfg_attr(rustfmt, rustfmt_skip)]
            fn hashable() {
                let fp6 = Fp6Elem::create(
                     Fp256::from(256u32),
                     Fp256::from(255u32),
                     Fp256::from(2u64.pow(16)),
                     Fp256::from(2u64.pow(16) - 1),
                     Fp256::from(2u64.pow(32)),
                     Fp256::from(2u64.pow(32) - 1),
                );
                let bytes = fp6.to_bytes();

                assert_eq!(bytes, vec![
                    //one
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,1,0,
                    //two
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,255,
                    //three
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,1,0,0,
                    //four
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,255,255,
                    //five
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,1,0,0,0,0,
                    //six
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,0,0,0,0,
                    0,0,0,0,255,255,255,255]);
            }

    prop_compose! {
        [pub] fn arb_fp6()(e4 in arb_fp2(), e5 in arb_fp2(), e6 in arb_fp2()) -> Fp6Elem<Fp256> {
            Fp6Elem {
                elem1: e4,
                elem2: e5,
                elem3: e6
            }
       }
    }

    prop_compose! {
        [pub] fn arb_fp6_480()(e4 in arb_fp2_480(), e5 in arb_fp2_480(), e6 in arb_fp2_480()) -> Fp6Elem<Fp480> {
            Fp6Elem {
                elem1: e4,
                elem2: e5,
                elem3: e6
            }
       }
    }

    proptest! {
        #[test]
        fn bytes_hashable_decode_roundtrip(ref fp1 in arb_fp6()) {
            let bytes = fp1.to_bytes();
            let decoded = Fp6Elem::decode(bytes);

            assert!(decoded.is_ok());
            assert_eq!(*fp1, decoded.unwrap())
        }

        #[test]
        fn pow_test_1(ref fp1 in arb_fp6(), x in any::<u32>(), y in any::<u32>()) {
            //fp1^(x + y) == fp1^x * fp1^y

            let x = x & 0x7FFFFFFF; //mask to avoid overflows
            let y = y >> 1;
            let left = fp1.pow(x + y);
            let right = fp1.pow(x) * fp1.pow(y);

            prop_assert_eq!(left, right);
        }
    }

    field_proptest!(arb_fp6, fp256, fp6);
    field_proptest!(arb_fp6_480, fp480, fp6);
}
