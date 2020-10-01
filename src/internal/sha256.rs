use crate::internal::hashable::Hashable;
use sha2;
use sha2::Digest;

pub trait Sha256Hashing {
    fn hash<T: Hashable>(&self, t: &T) -> [u8; 32];
}

pub struct Sha256;

impl Sha256Hashing for Sha256 {
    fn hash<T: Hashable>(&self, t: &T) -> [u8; 32] {
        let mut hasher = sha2::Sha256::default();
        hasher.update(t.to_bytes().as_slice());
        let hash_result = hasher.finalize();
        //This is currently the best way I know of to do this... Sorry.
        {
            let mut result: [u8; 32] = [0; 32];
            result.copy_from_slice(&hash_result);
            result
        }
    }
}

#[cfg(test)]
mod test {
    use crate::internal::sha256::*;
    use hex;

    #[test]
    fn sha256_match_known_value() {
        assert_eq!(
            Sha256.hash(&1u8).to_vec(),
            hex::decode("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
                .unwrap()
        );
    }
}
