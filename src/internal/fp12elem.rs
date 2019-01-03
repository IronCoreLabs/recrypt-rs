use crate::internal::bytedecoder::{BytesDecoder, DecodeErr};
use crate::internal::field::{ExtensionField, Field};
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::fp6elem::Fp6Elem;
use crate::internal::hashable::Hashable;
use crate::internal::ByteVector;
use crate::internal::{pow_for_square, sum_n, Square};
use core::fmt;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;
use num_traits::{Inv, One, Pow, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// An element of the degree 12 extension of our base finite field Fp. The degree 12 extension is formed on
/// the degree six extension using the substitution w^2 = v. That is, FP12 = FP6[w]/(w^2 - v)
///
/// A value in FP12 is represented as a polynomial a + b * w, where a and b are both FP6Elems.
///
/// Recall that v is the attached variable for FP6.
#[derive(Clone, PartialEq, Eq, Copy, Default)]
#[repr(C)]
pub struct Fp12Elem<T> {
    pub elem1: Fp6Elem<T>,
    pub elem2: Fp6Elem<T>,
}

impl<T> fmt::Debug for Fp12Elem<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?})*w + ({:?})", self.elem1, self.elem2)
    }
}

impl<T> fmt::LowerHex for Fp12Elem<T>
where
    T: fmt::LowerHex,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "({:x})*w + ({:x})", self.elem1, self.elem2)
    }
}

impl<T> Neg for Fp12Elem<T>
where
    T: Neg<Output = T>,
{
    type Output = Fp12Elem<T>;
    fn neg(self) -> Self {
        Fp12Elem {
            elem1: -self.elem1,
            elem2: -self.elem2,
        }
    }
}

impl<T> Add for Fp12Elem<T>
where
    T: Add<Output = T>,
{
    type Output = Fp12Elem<T>;
    fn add(self, other: Fp12Elem<T>) -> Self {
        Fp12Elem {
            elem1: self.elem1 + other.elem1,
            elem2: self.elem2 + other.elem2,
        }
    }
}

impl<T> Sub for Fp12Elem<T>
where
    T: Sub<Output = T>,
{
    type Output = Fp12Elem<T>;
    fn sub(self, other: Fp12Elem<T>) -> Self {
        Fp12Elem {
            elem1: self.elem1 - other.elem1,
            elem2: self.elem2 - other.elem2,
        }
    }
}

impl<T> Mul<Fp2Elem<T>> for Fp12Elem<T>
where
    T: Mul<Output = T> + Sub<Output = T> + Add<Output = T> + Copy,
{
    type Output = Fp12Elem<T>;

    fn mul(self, other: Fp2Elem<T>) -> Self {
        let y1 = self.elem1 * other;
        let y0 = self.elem2 * other;
        Fp12Elem {
            elem1: y1,
            elem2: y0,
        }
    }
}

impl<T> Mul<u64> for Fp12Elem<T>
where
    T: Copy + Add<Output = T> + Zero + PartialEq,
{
    type Output = Fp12Elem<T>;

    fn mul(self, other: u64) -> Self {
        sum_n(self, other)
    }
}

impl<T> Mul<Fp12Elem<T>> for Fp12Elem<T>
where
    T: Mul<Output = T>
        + Sub<Output = T>
        + Add<Output = T>
        + Copy
        + Mul<u64, Output = T>
        + ExtensionField,
{
    type Output = Fp12Elem<T>;
    fn mul(self, other: Fp12Elem<T>) -> Self {
        let (x1, x0) = (self.elem1, self.elem2);
        let (y1, y0) = (other.elem1, other.elem2);
        let z0 = x0 * y0;
        let z2 = x1 * y1;
        let z1 = (x1 + x0) * (y1 + y0);
        let w1 = z1 - z2 - z0;
        let (z01, z02, z03) = (z0.elem1, z0.elem2, z0.elem3);
        let (z21, z22, z23) = (z2.elem1, z2.elem2, z2.elem3);
        Fp12Elem {
            elem1: w1,
            elem2: Fp6Elem::create(
                z01.elem1 + z22.elem1,
                z01.elem2 + z22.elem2,
                z02.elem1 + z23.elem1,
                z02.elem2 + z23.elem2,
                z03.elem1 + z21.elem2 + (z21.elem1 * 3),
                z03.elem2 + (z21.elem2 * 3) - z21.elem1,
            ),
        }
    }
}

impl<T> Div<Fp12Elem<T>> for Fp12Elem<T>
where
    T: ExtensionField,
{
    type Output = Fp12Elem<T>;
    fn div(self, other: Fp12Elem<T>) -> Self {
        self * other.inv()
    }
}

impl<T> Zero for Fp12Elem<T>
where
    T: Add<Output = T> + Zero + PartialEq,
{
    fn zero() -> Self {
        Fp12Elem {
            elem1: Zero::zero(),
            elem2: Zero::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        *self == Zero::zero()
    }
}

impl<T> One for Fp12Elem<T>
where
    T: Zero
        + One
        + Sub<Output = T>
        + Add<Output = T>
        + PartialEq
        + Mul<u64, Output = T>
        + ExtensionField
        + Copy,
{
    fn one() -> Self {
        Fp12Elem {
            elem1: Zero::zero(),
            elem2: One::one(),
        }
    }

    fn is_one(&self) -> bool {
        *self == One::one()
    }
}

impl<T> Inv for Fp12Elem<T>
where
    T: ExtensionField,
{
    type Output = Fp12Elem<T>;
    fn inv(self) -> Fp12Elem<T> {
        // Algorithm 5.19 of El Mrabet--Joye 2017 "Guide to Pairing-Based Cryptography."
        let (b, a) = (self.elem1, self.elem2);
        let v0 = a.square();
        let v1 = b.square();
        let v00 = v0 - ExtensionField::v() * v1;
        let v11 = v00.inv();
        let c0 = a * v11;
        let c1 = -b * v11;
        Fp12Elem {
            elem1: c1,
            elem2: c0,
        }
    }
}

impl<T> Pow<u64> for Fp12Elem<T>
where
    T: ExtensionField,
{
    type Output = Fp12Elem<T>;
    fn pow(self, rhs: u64) -> Self {
        pow_for_square(self, rhs)
    }
}

impl<T> Square for Fp12Elem<T>
where
    T: Clone + Field + Mul<u64, Output = T> + ExtensionField,
{
    fn square(&self) -> Self {
        let a2 = self.elem1 * self.elem2 * 2;
        let b2 = self.elem1.square() * ExtensionField::v() + self.elem2.square();
        Fp12Elem {
            elem1: a2,
            elem2: b2,
        }
    }
}

impl<T> Field for Fp12Elem<T> where T: ExtensionField + Mul<u64, Output = T> {}

impl<T> Fp12Elem<T>
where
    T: ExtensionField,
{
    /// Frobenius endomorphism of the twisted curve.  This will be used in the pairing.
    /// Also the element to the p power.
    pub fn frobenius(&self) -> Fp12Elem<T> {
        let a = self.elem1.frobenius();
        let b = self.elem2.frobenius();
        let new_elem1 = a * ExtensionField::frobenius_factor_fp12();
        Fp12Elem {
            elem1: new_elem1,
            elem2: b,
        }
    }

    pub fn conjugate(&self) -> Fp12Elem<T> {
        Fp12Elem {
            elem1: -self.elem1,
            elem2: self.elem2,
        }
    }
}

impl<T> Fp12Elem<T> {
    /// create an Fp12Elem from 6 Fp2Elems instead of 2 Fp6Elems
    /// `one`, `two`, `three` will go on to make up the first Fp6
    /// `four`, `five`, `six` will make up the second Fp6
    pub fn create(
        one: Fp2Elem<T>,
        two: Fp2Elem<T>,
        three: Fp2Elem<T>,
        four: Fp2Elem<T>,
        five: Fp2Elem<T>,
        six: Fp2Elem<T>,
    ) -> Fp12Elem<T> {
        Fp12Elem {
            elem1: Fp6Elem {
                elem1: one,
                elem2: two,
                elem3: three,
            },
            elem2: Fp6Elem {
                elem1: four,
                elem2: five,
                elem3: six,
            },
        }
    }

    pub fn create_from_t(
        one: T,
        two: T,
        three: T,
        four: T,
        five: T,
        six: T,
        seven: T,
        eight: T,
        nine: T,
        ten: T,
        eleven: T,
        twelve: T,
    ) -> Fp12Elem<T> {
        Fp12Elem {
            elem1: Fp6Elem::create(one, two, three, four, five, six),
            elem2: Fp6Elem::create(seven, eight, nine, ten, eleven, twelve),
        }
    }
}

impl<T> Fp12Elem<T>
where
    T: PartialEq + Zero + Copy,
{
    pub fn to_fp2(&self) -> Option<Fp2Elem<T>> {
        if self.elem1 == Zero::zero() {
            self.elem2.to_fp2()
        } else {
            None
        }
    }
}

impl<T> Hashable for Fp12Elem<T>
where
    T: Hashable + Copy,
{
    fn to_bytes(&self) -> Vec<u8> {
        vec![self.elem1, self.elem2].to_bytes()
    }
}

impl Fp12Elem<Fp256> {
    pub fn to_bytes_fp256(&self) -> [u8; Fp12Elem::<Fp256>::ENCODED_SIZE_BYTES] {
        let hashable = &self.to_bytes()[..];
        let mut dest = [0u8; Fp12Elem::<Fp256>::ENCODED_SIZE_BYTES];
        dest.copy_from_slice(hashable);
        dest
    }
}
impl Fp12Elem<Fp480> {
    pub fn to_bytes_fp480(&self) -> [u8; Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES] {
        let hashable = &self.to_bytes()[..];
        let mut dest = [0u8; Fp12Elem::<Fp480>::ENCODED_SIZE_BYTES];
        dest.copy_from_slice(hashable);
        dest
    }
}

impl<T> BytesDecoder for Fp12Elem<T>
where
    T: BytesDecoder + Sized + Copy,
{
    const ENCODED_SIZE_BYTES: usize = T::ENCODED_SIZE_BYTES * 12;

    fn decode(bytes: ByteVector) -> Result<Fp12Elem<T>, DecodeErr> {
        // Converting to a byte vector just concatenates the byte vector representation of each
        // of the two coefficients a and b . So reversing just requires splitting the byte vector
        // in half and converting each smaller vector back to an element.
        // (Note that this is recursive, since the coefficients are each FP6 elements, which
        // consist of three coefficients.)
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            let (t1, t2) = bytes.split_at(Self::ENCODED_SIZE_BYTES / 2);
            let fp12_elem: Fp12Elem<T> = Fp12Elem {
                elem1: Fp6Elem::decode(t1.to_vec())?,
                elem2: Fp6Elem::decode(t2.to_vec())?,
            };
            Result::Ok(fp12_elem)
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
    use crate::internal::fp2elem::test::get_fp2s;
    use crate::internal::fp6elem::test::arb_fp6;
    use crate::internal::fp6elem::test::get_fp6s;
    use gridiron::fp_256::Fp256;
    use proptest::prelude::*;

    #[test]
    fn create_from_fp2s() {
        let [fp2a, fp2b, fp2c, fp2d, fp2e, fp2f] = get_fp2s();

        let [fp6a, fp6b] = get_fp6s(&fp2a, &fp2b, &fp2c, &fp2d, &fp2e, &fp2f);
        let expected = Fp12Elem::create(fp2a, fp2b, fp2c, fp2d, fp2e, fp2f);
        let result = Fp12Elem {
            elem1: fp6a,
            elem2: fp6b,
        };
        assert_eq!(expected, result);
    }

    prop_compose! {
        [pub] fn arb_fp12()(e1 in arb_fp6(), e2 in arb_fp6()) -> Fp12Elem<Fp256> {
            Fp12Elem {
                elem1: e1,
                elem2: e2
            }
       }
    }

    proptest! {

        #[test]
        fn bytes_hashable_decode_roundtrip(ref fp in arb_fp12()) {
            let bytes = fp.to_bytes();
            let decoded = Fp12Elem::decode(bytes);

            assert!(decoded.is_ok());
            assert_eq!(*fp, decoded.unwrap())


        }

        #[test]
        fn pow_test_1(ref fp1 in arb_fp12(), x in any::<u32>(), y in any::<u32>()) {
            //fp1^(x + y) == fp1^x * fp1^y

            let x = x as u64; //cast to avoid overflows
            let y = y as u64;
            let left = fp1.pow(x + y);
            let right = fp1.pow(x) * fp1.pow(y);

            prop_assert_eq!(left, right);
        }

        ///All of these are tests from field.rs
        #[test]
        fn prop_semigroup(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_semigroup(a,b,c))
        }
        #[test]
        fn prop_monoid_identity(a in arb_fp12()) {
            prop_assert!(Field::prop_monoid_identity(a))
        }
        #[test]
        fn prop_inv(a in arb_fp12(), b in arb_fp12()) {
            prop_assert!(Field::prop_inv(a,b))
        }
        #[test]
        fn prop_one_is_mul_identity(a in arb_fp12()) {
            prop_assert!(Field::prop_one_is_mul_identity(a))
        }
        #[test]
        fn prop_zero_is_add_identity(a in arb_fp12()) {
            prop_assert!(Field::prop_zero_is_add_identity(a))
        }
        #[test]
        fn prop_eq_reflexive(a in arb_fp12(), b in arb_fp12()) {
            prop_assert!(Field::prop_eq_reflexive(a,b))
        }
        #[test]
        fn prop_sub_same_as_neg_add(a in arb_fp12(), b in arb_fp12()) {
            prop_assert!(Field::prop_sub_same_as_neg_add(a,b))
        }
        #[test]
        fn prop_mul_distributive(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_mul_distributive(a,b,c))
        }
        #[test]
        fn prop_mul_assoc(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_mul_assoc(a,b,c))
        }
        #[test]
        fn prop_mul_commutative(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_mul_commutative(a,b,c))
        }
        #[test]
        fn prop_add_assoc(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_add_assoc(a,b,c))
        }
        #[test]
        fn prop_add_commutative(a in arb_fp12(), b in arb_fp12(), c in arb_fp12()) {
            prop_assert!(Field::prop_add_commutative(a,b,c))
        }
        #[test]
        fn prop_pow_is_mul(a in arb_fp12()) {
            prop_assert!(Field::prop_pow_is_mul(a))
        }
        #[test]
        fn prop_x_sub_y_eq_x_plus_y_mul_neg1(a in arb_fp12(), b in arb_fp12()) {
            prop_assert!(Field::prop_x_sub_y_eq_x_plus_y_mul_neg1(a,b))
        }
        #[test]
        fn prop_square_same_as_mul_self(a in arb_fp12()) {
            prop_assert!(Field::prop_square_same_as_mul_self(a))
        }
        #[test]
        fn prop_square2_same_as_pow4(a in arb_fp12()) {
            prop_assert!(Field::prop_square2_same_as_pow4(a))
        }
    }
}
