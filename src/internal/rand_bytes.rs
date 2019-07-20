use rand;
use rand::{CryptoRng, RngCore};

use crate::internal::take_lock;
use rand::FromEntropy;
use std::default::Default;
use std::ops::DerefMut;
use std::sync::Mutex;

/// Generation of random bytes for cryptographic operations
pub trait RandomBytesGen {
    fn random_bytes_32(&self) -> [u8; 32];
    fn random_bytes_60(&self) -> [u8; 60];
}

pub struct RandomBytes<T: CryptoRng + RngCore> {
    pub(crate) rng: Mutex<T>,
}

impl Default for RandomBytes<rand_chacha::ChaChaRng> {
    fn default() -> Self {
        RandomBytes::new(rand_chacha::ChaChaRng::from_entropy())
    }
}

impl<CR: CryptoRng + RngCore> RandomBytes<CR> {
    pub fn new(rng: CR) -> Self {
        RandomBytes {
            rng: Mutex::new(rng),
        }
    }
}

impl<CR: CryptoRng + RngCore> RandomBytesGen for RandomBytes<CR> {
    fn random_bytes_32(&self) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0u8; 32];
        take_lock(&self.rng).deref_mut().fill_bytes(&mut bytes);
        bytes
    }

    fn random_bytes_60(&self) -> [u8; 60] {
        let mut bytes: [u8; 60] = [0u8; 60];
        take_lock(&self.rng).deref_mut().fill_bytes(&mut bytes);
        bytes
    }
}
