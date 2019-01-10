use crate::internal::fp::fr_256::Fr256;
use gridiron::digits::constant_bool::ConstantBool;
use gridiron::fp_256::Fp256;

/// A bit representation of a numeric value
pub trait BitRepr {
    fn to_bits(&self) -> Vec<ConstantBool<u32>>;
}

impl BitRepr for Fp256 {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).iter_bit().collect()
    }
}

impl BitRepr for Fr256 {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).iter_bit().collect()
    }
}
