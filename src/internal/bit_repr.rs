use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use gridiron::digits::constant_bool::ConstantBool;

/// A bit representation of a numeric value
pub trait BitRepr {
    fn to_bits(&self) -> Vec<ConstantBool<u32>>;
}

impl BitRepr for gridiron::fp_256::Monty {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).to_norm().iter_bit().collect()
    }
}

impl BitRepr for gridiron::fp_480::Monty {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).to_norm().iter_bit().collect()
    }
}

impl BitRepr for Fr256 {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).iter_bit().collect()
    }
}

impl BitRepr for Fr480 {
    fn to_bits(&self) -> Vec<ConstantBool<u32>> {
        (*self).iter_bit().collect()
    }
}
