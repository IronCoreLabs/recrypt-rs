use gridiron::fp_256::Fp256;
use internal::fp::fr_256::Fr256;

///A trait that signifies the ability to create a Nonadjacent form from a value
///
///This is possible for all numeric types.
pub trait NonAdjacentForm {
    fn to_naf(&self) -> Vec<i8>;
}

impl NonAdjacentForm for Fp256 {
    fn to_naf(&self) -> Vec<i8> {
        (*self).create_naf()
    }
}

impl NonAdjacentForm for Fr256 {
    fn to_naf(&self) -> Vec<i8> {
        (*self).create_naf()
    }
}
