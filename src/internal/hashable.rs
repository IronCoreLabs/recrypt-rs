use crate::internal::ByteVector;
use crate::internal::fp::fr_256::Fr256;
use crate::internal::fp::fr_480::Fr480;
use crate::nonemptyvec::NonEmptyVec;
use gridiron::fp_256;
use gridiron::fp_480;

/// Typeclass for converting an implementing type to a stable byte representation
/// which can be used for hashing (and thus the hash value will also remain consistent)
/// Inverse of BytesDecoder
pub trait Hashable {
    /// Convert self to a stable byte representation.
    fn to_bytes(&self) -> ByteVector;
}

impl Hashable for u8 {
    fn to_bytes(&self) -> ByteVector {
        vec![*self]
    }
}

impl<T> Hashable for [T]
where
    T: Hashable,
{
    fn to_bytes(&self) -> ByteVector {
        let mut result: Vec<u8> = Vec::new();
        for t in self.iter() {
            let mut bytes = t.to_bytes();
            result.append(&mut bytes);
        }
        result
    }
}

impl<T> Hashable for &[T]
where
    T: Hashable,
{
    fn to_bytes(&self) -> ByteVector {
        <[T] as Hashable>::to_bytes(self)
    }
}

impl<T> Hashable for Vec<T>
where
    T: Hashable,
{
    fn to_bytes(&self) -> ByteVector {
        let mut result: Vec<u8> = Vec::new();
        for t in self.iter() {
            let mut bytes = t.to_bytes();
            result.append(&mut bytes);
        }
        result
    }
}

impl<T: Hashable + Clone> Hashable for NonEmptyVec<T> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec().to_bytes()
    }
}

impl<'a, T: Hashable, U: Hashable> Hashable for &'a (T, U) {
    fn to_bytes(&self) -> ByteVector {
        vec![self.0.to_bytes(), self.1.to_bytes()].to_bytes()
    }
}

impl<'a, T: Hashable, U: Hashable> Hashable for (&'a T, &'a U) {
    fn to_bytes(&self) -> ByteVector {
        vec![self.0.to_bytes(), self.1.to_bytes()].to_bytes()
    }
}

impl<'a, T: Hashable, U: Hashable, V: Hashable> Hashable for (&'a T, &'a U, &'a V) {
    fn to_bytes(&self) -> ByteVector {
        vec![self.0.to_bytes(), self.1.to_bytes(), self.2.to_bytes()].to_bytes()
    }
}

impl<'a, T: Hashable, U: Hashable, V: Hashable, W: Hashable> Hashable
    for (&'a T, &'a U, &'a V, &'a W)
{
    fn to_bytes(&self) -> ByteVector {
        vec![
            self.0.to_bytes(),
            self.1.to_bytes(),
            self.2.to_bytes(),
            self.3.to_bytes(),
        ]
        .to_bytes()
    }
}

impl<'a, T: Hashable, U: Hashable, V: Hashable, W: Hashable, X: Hashable> Hashable
    for (&'a T, &'a U, &'a V, &'a W, &'a X)
{
    fn to_bytes(&self) -> ByteVector {
        vec![
            self.0.to_bytes(),
            self.1.to_bytes(),
            self.2.to_bytes(),
            self.3.to_bytes(),
            self.4.to_bytes(),
        ]
        .to_bytes()
    }
}

impl<T: Hashable + Copy> Hashable for Option<T> {
    fn to_bytes(&self) -> ByteVector {
        self.map_or(vec![0], |x| x.to_bytes())
    }
}

/// Like Hashable, but converts to *exactly* 32 bytes.
/// Note that if you are Hashable32 you are also Hashable
pub trait Hashable32 {
    fn to_bytes_32(&self) -> [u8; 32];
}

/// All Hashable32s are Hashable
impl<T: Hashable32> Hashable for T {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_32().to_vec()
    }
}

///This definition is a bit strange, but is required to maintain compatibility with our current idea of what an `fp256`
///hashable needs to look like. Note that this costs a multiplication of Montgomery form so it's more expensive than normal
/// but that's acceptable because of the amount of time we save overall.
impl Hashable32 for gridiron::fp_256::Monty {
    fn to_bytes_32(&self) -> [u8; fp_256::PRIMEBYTES] {
        self.to_norm().to_bytes_array()
    }
}

impl Hashable32 for Fr256 {
    fn to_bytes_32(&self) -> [u8; fp_256::PRIMEBYTES] {
        self.to_bytes_array()
    }
}

impl Hashable60 for fp_480::Monty {
    fn to_bytes_60(&self) -> [u8; fp_480::PRIMEBYTES] {
        self.to_norm().to_bytes_array()
    }
}

impl Hashable for fp_480::Monty {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_60().to_vec()
    }
}

impl Hashable for Fr480 {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_60().to_vec()
    }
}

impl Hashable60 for Fr480 {
    fn to_bytes_60(&self) -> [u8; 60] {
        self.to_bytes_array()
    }
}

pub trait Hashable60 {
    fn to_bytes_60(&self) -> [u8; 60];
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn byte_hashable(ref v in any::<u8>()) {
            let hashable: ByteVector = Hashable::to_bytes(v);
            assert_eq!(vec![v.clone()], hashable);
        }

        #[test]
        fn bytevector_hashable(bv in prop::collection::vec(any::<u8>(), 0..32)) {
            let hashable = bv.to_bytes();
            assert_eq!(bv, hashable);
        }

        #[test]
        fn bytevector_of_bytevector_hashable(bv1 in prop::collection::vec(any::<u8>(), 0..32), bv2 in prop::collection::vec(any::<u8>(), 0..32)) {
            let concat = [&bv1[..], &bv2[..]].concat();
            assert_eq!(concat, vec![bv1, bv2].to_bytes());
        }
    }
}
