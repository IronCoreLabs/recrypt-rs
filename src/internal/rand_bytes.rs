use rand;
use rand::{CryptoRng, RngCore};

use std::default::Default;

/// Generation of random bytes for cryptographic operations
pub trait RandomBytesGen {
    fn random_bytes_32(&mut self) -> [u8; 32];
    fn random_bytes_60(&mut self) -> [u8; 60];
}

pub struct RandomBytes<T: CryptoRng + RngCore> {
    pub(crate) rng: T,
}

impl Default for RandomBytes<rand::rngs::ThreadRng> {
    fn default() -> Self {
        RandomBytes::<rand::rngs::ThreadRng>::new(rand::thread_rng())
    }
}

impl<CR: CryptoRng + RngCore> RandomBytes<CR> {
    pub fn new(rng: CR) -> Self {
        RandomBytes { rng }
    }
}

impl<CR: CryptoRng + RngCore> RandomBytesGen for RandomBytes<CR> {
    fn random_bytes_32(&mut self) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    fn random_bytes_60(&mut self) -> [u8; 60] {
        unimplemented!()
    }
}
