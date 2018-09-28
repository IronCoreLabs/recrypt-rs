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
                Err(ApiErr::InputWrongSize($t::ENCODED_SIZE_BYTES))
            }
        }
    };
}

/// macro for generation of "new-types" around byte arrays, but with the option of specifying custom derive
macro_rules! new_bytes_type_with_derive {
    ($t: ident, $n: expr, $derive: meta) => {

        #[allow(unused_attributes)] //should squelch error for empty derive, but does not appear to work: https://github.com/rust-lang/rust/issues/54651
        #[$derive]
        pub struct $t {
            bytes: [u8; $t::ENCODED_SIZE_BYTES],
        }

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
        new_bytes_type_with_derive!($t, $n, derive(Clone, Copy));
    };
}

/// macro for generation of "new-types" around a byte array with a standard pattern for construction and access
macro_rules! new_bytes_type_no_derive {
    ($t: ident, $n: expr) => {
        new_bytes_type_with_derive!($t, $n, derive());
    };
}