use gridiron::fp_256;
use internal::rand_bytes::RandomBytesGen;
fp!(
    fr_256, // Name of mod
    Fr256,  // Name of class
    256,    // Number of bits for prime
    4,      // Number of limbs (ceil(bits/64))
    [
        1886713967064937057,
        3354493509585025316,
        12281294985516866593,
        10355184993929758713
    ],
    [
        15618948758334012843,
        1416387596196228984,
        2174143271902072373,
        14414317039193118239,
        1
    ]
);

impl fr_256::Fr256 {
    ///Generate an Fr256 with no bias from `RandomBytesGen`.
    pub fn from_rand_no_bias<R: RandomBytesGen>(random_bytes: &mut R) -> fr_256::Fr256 {
        let mut fr: fr_256::Fr256;
        //We want to generate a value that is in Fr, but we don't want to allow values that
        //are greater than Fr because it can give a bias to schnorr signing. If we generate a value
        //which is >= the Fr256 PRIME, throw it away and try again.
        while {
            let bytes: [u8; 32] = random_bytes.random_bytes_32();
            fr = fr_256::Fr256::from(bytes);
            fr.to_bytes_array() != bytes
        } {}
        fr
    }
}

impl From<[u8; 64]> for fr_256::Fr256 {
    fn from(src: [u8; 64]) -> Self {
        // our input is the exact length we need for our
        // optimized barrett reduction
        let limbs = ::gridiron::eight_limbs_from_sixtyfour_bytes(src);
        fr_256::Fr256::new(fr_256::Fr256::reduce_barrett(&limbs))
    }
}

impl From<fp_256::Fp256> for fr_256::Fr256 {
    fn from(src: fp_256::Fp256) -> Self {
        From::from(src.to_bytes_array())
    }
}
