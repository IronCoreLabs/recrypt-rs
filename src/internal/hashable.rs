use crate::internal::fp::fr_256::Fr256;
use crate::internal::ByteVector;
use crate::nonemptyvec::NonEmptyVec;
use gridiron::fp_256;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;

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

impl<'a, T> Hashable for [&'a T]
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

impl Hashable32 for Fp256 {
    fn to_bytes_32(&self) -> [u8; fp_256::PRIMEBYTES] {
        self.to_bytes_array()
    }
}

impl Hashable32 for Fr256 {
    fn to_bytes_32(&self) -> [u8; fp_256::PRIMEBYTES] {
        self.to_bytes_array()
    }
}
impl Hashable for Fp480 {
    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!()
    }
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
