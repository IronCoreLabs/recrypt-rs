use crate::internal::fp::fr_256::Fr256;
use gridiron::fp_256::Fp256;

/// A bit representation of a numeric value
pub trait BitRepr {
    fn to_bits(&self) -> Vec<u8>;
}

impl BitRepr for Fp256 {
    fn to_bits(&self) -> Vec<u8> {
        (*self).iter_bit().map(|x| x.0 as u8).collect()
    }
}

impl BitRepr for Fr256 {
    fn to_bits(&self) -> Vec<u8> {
        (*self).iter_bit().map(|x| x.0 as u8).collect()
    }
}
