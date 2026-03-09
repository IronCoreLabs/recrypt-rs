use rand;
use rand::CryptoRng;

use crate::internal::take_lock;
use rand::SeedableRng;
use rand::rngs::SysRng;
use rand::{TryCryptoRng, TryRng};
use std::convert::Infallible;
use std::default::Default;
use std::ops::DerefMut;
use std::sync::Mutex;

/// Reseed threshold in bytes — matches ThreadRng's 64 KiB interval.
const RESEED_THRESHOLD: usize = 64 * 1024;

/// Generation of random bytes for cryptographic operations
pub trait RandomBytesGen {
    fn random_bytes_32(&self) -> [u8; 32];
    fn random_bytes_60(&self) -> [u8; 60];
}

/// A CSPRNG wrapper that automatically reseeds from system entropy periodically.
/// Implements [`CryptoRng`] so it can be used anywhere a `CryptoRng` is expected.
pub struct ReseedingRng<T: CryptoRng + SeedableRng> {
    inner: T,
    bytes_generated: usize,
}

impl<T: CryptoRng + SeedableRng> Default for ReseedingRng<T> {
    fn default() -> Self {
        ReseedingRng::new(
            T::try_from_rng(&mut SysRng).expect("Failed to seed RNG from system entropy"),
        )
    }
}

impl<T: CryptoRng + SeedableRng> ReseedingRng<T> {
    pub fn new(rng: T) -> Self {
        ReseedingRng {
            inner: rng,
            bytes_generated: 0,
        }
    }

    fn reseed_if_needed(&mut self) {
        if self.bytes_generated >= RESEED_THRESHOLD {
            if let Ok(reseeded) = T::try_from_rng(&mut SysRng) {
                self.inner = reseeded;
            }
            // On reseed failure, continue with existing state rather than panicking.
            // The current state is still cryptographically valid and the likelihood of
            // SysRng erroring is very low.
            self.bytes_generated = 0;
        }
    }
}

impl<T: CryptoRng + SeedableRng> TryRng for ReseedingRng<T> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.reseed_if_needed();
        let val = self.inner.next_u32();
        self.bytes_generated = self.bytes_generated.saturating_add(4);
        Ok(val)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.reseed_if_needed();
        let val = self.inner.next_u64();
        self.bytes_generated = self.bytes_generated.saturating_add(8);
        Ok(val)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.reseed_if_needed();
        self.inner.fill_bytes(dst);
        self.bytes_generated = self.bytes_generated.saturating_add(dst.len());
        Ok(())
    }
}

impl<T: CryptoRng + SeedableRng> TryCryptoRng for ReseedingRng<T> {}

pub struct RandomBytes<T: CryptoRng> {
    pub(crate) rng: Mutex<T>,
}

impl Default for RandomBytes<ReseedingRng<rand_chacha::ChaChaRng>> {
    fn default() -> Self {
        RandomBytes::new(ReseedingRng::default())
    }
}

impl<CR: CryptoRng> RandomBytes<CR> {
    pub fn new(rng: CR) -> Self {
        RandomBytes {
            rng: Mutex::new(rng),
        }
    }
}

impl<CR: CryptoRng> RandomBytesGen for RandomBytes<CR> {
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
