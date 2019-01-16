// Generates a Debug impl that only surfaces a field named `bytes` along with the type name surrounding it
macro_rules! bytes_only_debug {
    ($t: ident) => {
        impl fmt::Debug for $t {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($t))
                    .field("bytes", &&self.bytes[..])
                    .finish()
            }
        }
    };
}

macro_rules! new_from_slice {
    ($t: ident) => {
        /// construct $t from byte slice. Input slice must be exactly the correct length for the type.
        /// # Returns
        /// Ok($t) or Err($ApiError::InputWrongSize]
        pub fn new_from_slice(bytes: &[u8]) -> std::result::Result<$t, ApiErr> {
            if bytes.len() == $t::ENCODED_SIZE_BYTES {
                let mut dest = [0u8; $t::ENCODED_SIZE_BYTES];
                dest.copy_from_slice(bytes);
                Ok($t::new(dest))
            } else {
                Err(ApiErr::InputWrongSize(
                    &stringify!($t),
                    $t::ENCODED_SIZE_BYTES,
                ))
            }
        }
    };
}

macro_rules! _bytes_struct {
    ($t: ident) => {
        pub struct $t {
            bytes: [u8; $t::ENCODED_SIZE_BYTES],
        }
    };
    ($t: ident, $derive: meta) => {
        #[$derive]
        pub struct $t {
            bytes: [u8; $t::ENCODED_SIZE_BYTES],
        }
    };
}

macro_rules! _bytes_core {
    ($t: ident, $n: expr) => {
        impl $t {
            const ENCODED_SIZE_BYTES: usize = $n;

            /// construct $t from fixed size byte array
            pub fn new(bytes: [u8; $t::ENCODED_SIZE_BYTES]) -> Self {
                $t { bytes }
            }
            pub fn bytes(&self) -> &[u8; $t::ENCODED_SIZE_BYTES] {
                &self.bytes
            }
            new_from_slice!($t);
        }

        bytes_only_debug!($t);

        // Not constant time
        impl PartialEq for $t {
            fn eq(&self, other: &$t) -> bool {
                self.bytes[..] == other.bytes[..]
            }
        }

        impl Eq for $t {}
    };
}

/// macro for generation of "new-types" around a byte array with a standard pattern for construction and access
macro_rules! new_bytes_type {
    ($t: ident, $n: expr) => {
        _bytes_struct!($t, derive(Copy, Clone));
        _bytes_core!($t, $n);
    };
    ($t: ident, $n: expr, $derive: meta) => {
        _bytes_struct!($t, $n, $derive);
        _bytes_core!($t, $n);
    };
}

// macro to produce property-based tests for each FP type
#[allow(unused_macros)]
#[cfg(test)]
macro_rules! field_proptest {
        ($arb_fp_type:ident, $base_fp_mod:ident, $fp_mod:ident) => {
        #[allow(unused_imports)]
        mod $base_fp_mod { mod $fp_mod {
            use crate::internal::field::Field;
            use crate::internal::fp2elem::test::*;
            use crate::internal::fp12elem::test::*;
            use crate::internal::fp6elem::test::*;

            proptest! {
                #[test]
                fn prop_semigroup(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_semigroup(a,b,c))
            }
                #[test]
                fn prop_monoid_identity(a in $arb_fp_type()) {
                prop_assert!(Field::prop_monoid_identity(a))
            }
                #[test]
                fn prop_inv(a in $arb_fp_type(), b in $arb_fp_type()) {
                prop_assert!(Field::prop_inv(a,b))
            }
                #[test]
                fn prop_one_is_mul_identity(a in $arb_fp_type()) {
                prop_assert!(Field::prop_one_is_mul_identity(a))
            }
                #[test]
                fn prop_zero_is_add_identity(a in $arb_fp_type()) {
                prop_assert!(Field::prop_zero_is_add_identity(a))
            }
                #[test]
                fn prop_eq_reflexive(a in $arb_fp_type(), b in $arb_fp_type()) {
                prop_assert!(Field::prop_eq_reflexive(a,b))
            }
                #[test]
                fn prop_sub_same_as_neg_add(a in $arb_fp_type(), b in $arb_fp_type()) {
                prop_assert!(Field::prop_sub_same_as_neg_add(a,b))
            }
                #[test]
                fn prop_mul_distributive(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_mul_distributive(a,b,c))
            }
                #[test]
                fn prop_mul_assoc(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_mul_assoc(a,b,c))
            }
                #[test]
                fn prop_mul_commutative(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_mul_commutative(a,b,c))
            }
                #[test]
                fn prop_add_assoc(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_add_assoc(a,b,c))
            }
                #[test]
                fn prop_add_commutative(a in $arb_fp_type(), b in $arb_fp_type(), c in $arb_fp_type()) {
                prop_assert!(Field::prop_add_commutative(a,b,c))
            }
                #[test]
                fn prop_pow_is_mul(a in $arb_fp_type()) {
                prop_assert!(Field::prop_pow_is_mul(a))
            }
                #[test]
                fn prop_square_same_as_mul_self(a in $arb_fp_type()) {
                prop_assert!(Field::prop_square_same_as_mul_self(a))
            }
                #[test]
                fn prop_square2_same_as_pow4(a in $arb_fp_type()) {
                prop_assert!(Field::prop_square2_same_as_pow4(a))
            }
            }
        }}
        };
    }
