use crate::internal::ByteVector;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;
use quick_error::quick_error;
use std::convert::From;
use std::convert::TryInto;
use std::result::Result;

/// Decode a ByteVector into an implementing type.
/// Inverse of Hashable.
pub trait BytesDecoder
where
    Self: Sized,
{
    /// Expected size (in bytes) of the byte representation of the implementing type
    const ENCODED_SIZE_BYTES: usize;

    /// Decode bytes into Self
    fn decode(bytes: ByteVector) -> Result<Self, DecodeErr>;
}

impl BytesDecoder for gridiron::fp_256::Monty {
    const ENCODED_SIZE_BYTES: usize = 32;
    fn decode(bytes: ByteVector) -> Result<Self, DecodeErr> {
        let byte_array: Result<[u8; Self::ENCODED_SIZE_BYTES], ByteVector> = bytes.try_into();
        byte_array
            .map(|array| Fp256::from(array).to_monty())
            .map_err(|b| DecodeErr::BytesNotCorrectLength {
                required_length: Self::ENCODED_SIZE_BYTES,
                bad_bytes: b,
            })
    }
}

impl BytesDecoder for gridiron::fp_480::Monty {
    const ENCODED_SIZE_BYTES: usize = 60;

    fn decode(bytes: Vec<u8>) -> Result<Self, DecodeErr> {
        if bytes.len() == Self::ENCODED_SIZE_BYTES {
            let mut byte_arr: [u8; Self::ENCODED_SIZE_BYTES] = [0u8; Self::ENCODED_SIZE_BYTES];
            byte_arr.copy_from_slice(&bytes);
            Result::Ok(Fp480::from(byte_arr).to_monty())
        } else {
            Result::Err(DecodeErr::BytesNotCorrectLength {
                required_length: Self::ENCODED_SIZE_BYTES,
                bad_bytes: bytes,
            })
        }
    }
}

quick_error! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum DecodeErr {
        BytesNotCorrectLength {
            required_length: usize,
            bad_bytes: ByteVector,
        }
        BytesInvalid {
            message: String,
            bad_bytes: ByteVector,
        }
    }
}
