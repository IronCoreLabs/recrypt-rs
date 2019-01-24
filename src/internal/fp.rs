use crate::internal::rand_bytes::RandomBytesGen;
use gridiron::fp31;
use gridiron::fp_256;
use gridiron::fp_480;

// r: 65000549695646603732796438742359905742570406053903786389881062969044166799969 (also "curve_order" for Fp256)
fp31!(
    fr_256, // Name of mod
    Fr256,  // Name of class
    256,    // Number of bits for prime
    9,      // Number of limbs (ceil(bits/64))
    // prime in limbs, least sig first
    // sage: 65000549695646603732796438742359905742570406053903786389881062969044166799969.digits(2^31)
    [
        1470919265, 878569654, 1621943440, 1953263767, 407749138, 1308464908, 685899370,
        1518399909, 143
    ],
    // barrett reduction for reducing values up to twice
    // the number of prime bits (double limbs):
    // floor(2^(31*numlimbs*2)/p)
    //
    //sage: floor(2^(31*9*2)/p).digits(2^31)
    [
        2001388716, 2127935188, 656710022, 1592897923, 336510510, 1906875712, 1016481908,
        1139000707, 1048853973, 14943480
    ],
    // W = 31 (bytes)
    // montgomery R = 2^(W*N) where W = word size and N = limbs
    //            R = 2^(31*9) = 2^279
    // montgomery R^-1 mod p
    //
    // sage: mont_r = 2^(9*31)
    // sage: mont_r_inv = 971334446112864535459730953411759453321203419526069760625906204869452142602604249088^-1 % p
    // sage: mont_r_inv.digits(2^31)
    [
        15365123, 1200204171, 957839710, 1956483681, 380955886, 1912989863, 1467667868, 830668271,
        61
    ],
    // montgomery R^2 mod p
    // sage: mont_r_squared = mont_r^2 % p
    // sage: mont_r_squared.digits(2^31)
    [
        1770447572, 496375461, 2107782367, 1971926976, 1431428989, 1530023807, 975789685,
        962787448, 62
    ],
    // -p[0]^-1
    // sage: m = p.digits(2^31)[0]
    //          (-m).inverse_mod(2^31)
    757616223
);
// r = 3121577065842246806003085452055281276803074876175537384188619957989004525299611739143164276204220965332554591187396064132658995685351714167608049
// This is also "curve_order" for Fp480
fp31!(
    fr_480, // Name of mod
    Fr480,  // Name of class
    480,    // Number of bits for prime
    16,     // Number of limbs (ceil(bits/31))
    [
        // prime number in limbs, least sig first
        // get this from sage with p.digits(2^31)
        303452913, 1136536553, 1175441836, 1648331283, 1378554948, 665368735, 1063821851, 556691390,
        190358044, 1260077487, 1583277252, 222489098, 760385720, 330553579, 429458313, 32766
    ],
    // barrett reduction for reducing values up to twice
    // the number of prime bits (double limbs):
    // floor(2^(31*numlimbs*2)/p).digits(2^31)
    [
        1197018551, 750986212, 1291405097, 1641098313, 1952135722, 1345577543, 672618400,
        351667504, 1678886807, 231227174, 1893732143, 1300610845, 325218135, 866248622, 1596183093,
        1288991726, 65539
    ],
    // W = 31 (bytes)
    // montgomery R = 2^(W*N) where W = word size and N = limbs
    // montgomery R = R = 2^(31*16) = 2^496
    // montgomery R^-1 mod p
    //
    // sage: mont_r = 2^496
    // sage: mont_r_inv = mont_r^-1 % p
    // sage: mont_r_inv.digits(2^31)
    [
        1993082669, 148658199, 1545864062, 1328403877, 1966735026, 1348874698, 531286620,
        750137843, 1004132174, 1560224833, 2014075, 1848411426, 1733309265, 1811487384, 799788540,
        19667
    ],
    // montgomery R^2 mod p
    // sage: mont_r_squared = mont_r^2 % p
    // sage: mont_r_squared.digits(2^31)
    [
        1124825273, 988937813, 894529151, 636400857, 262882198, 301704988, 412821006, 2861128,
        1848750227, 1614862374, 1570166973, 1675926980, 601581422, 75226069, 1754965692, 5458
    ],
    // -p[0]^-1
    // in sage: m = p.digits(2^31)[0]
    //          (-m).inverse_mod(2^31)
    1693426159
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
impl fr_480::Fr480 {
    ///Generate an Fr480 with no bias from `RandomBytesGen`.
    pub fn from_rand_no_bias<R: RandomBytesGen>(random_bytes: &mut R) -> fr_480::Fr480 {
        let mut fr: fr_480::Fr480;
        //We want to generate a value that is in Fr, but we don't want to allow values that
        //are greater than Fr because it can give a bias to schnorr signing. If we generate a value
        //which is >= the Fr480 PRIME, throw it away and try again.
        while {
            let bytes: [u8; 60] = random_bytes.random_bytes_60();
            fr = fr_480::Fr480::from(bytes);
            fr.to_bytes_array()[..] != bytes[..]
        } {}
        fr
    }
}
impl From<[u8; 64]> for fr_256::Fr256 {
    fn from(src: [u8; 64]) -> Self {
        // our input is the exact length we need for our
        // optimized barrett reduction
        let mut limbs = [0u32; 18];
        let limbs_17 = ::gridiron::from_sixty_four_bytes(src);
        limbs.copy_from_slice(&limbs_17);
        fr_256::Fr256::new(fr_256::Fr256::reduce_barrett(&limbs))
    }
}
impl From<[u8; 64]> for fr_480::Fr480 {
    fn from(src: [u8; 64]) -> Self {
        // our input is the exact length we need for our
        // optimized barrett reduction
        let mut limbs = [0u32; 32];
        let limbs_17 = ::gridiron::from_sixty_four_bytes(src);
        limbs.copy_from_slice(&limbs_17);
        fr_480::Fr480::new(fr_480::Fr480::reduce_barrett(&limbs))
    }
}
impl From<fp_256::Fp256> for fr_256::Fr256 {
    fn from(src: fp_256::Fp256) -> Self {
        From::from(src.to_bytes_array())
    }
}

impl From<fp_480::Fp480> for fr_480::Fr480 {
    fn from(src: fp_480::Fp480) -> Self {
        From::from(src.to_bytes_array())
    }
}
/// Function to be used for static values either as defined as constants or used in tests.
/// Don't use this to create Fp256 from dynamic values at runtime! It will panic on failure.
///
/// Arguments:
/// `hex_str` - need to be 63 or 64 bytes. Do not include a leading '0x'
///
/// Example:
///
/// use gridiron::fp_256;
/// use recrypt::internal::fp::fp_unsafe_from;
/// let fp_value = fp_256::Fp256::new([1883708157, 273156172, 2109116376, 1424078749, 1853636711, 680917384, 134358213, 1586179707, 57]);
/// assert_eq!(fp_value, fp256_unsafe_from("39bd165cf62008931544afcc46e7c4067a9c36f3bf6da3f60824042670471afd"))
///
pub fn fp256_unsafe_from(hex_str: &str) -> fp_256::Fp256 {
    // add in a leading zero as needed to be more compatible with sage
    let even_hex_str = if hex_str.len() % 2 != 0 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    let slice = &hex::decode(&even_hex_str)
        .unwrap_or_else(|_| panic!("hex_str '{}' cannot be decoded", &even_hex_str));
    if slice.len() == fp_256::PRIMEBYTES {
        let mut target = [0u8; fp_256::PRIMEBYTES];
        target.copy_from_slice(slice);
        fp_256::Fp256::from(target)
    } else {
        panic!(
            "Fp256 from failed! '{:?}' has size {} (bytes). Did you forget to pad your hex string to 63/64 chars?",
            slice,
            slice.len()
        )
    }
}

pub fn fp480_unsafe_from(hex_str: &str) -> fp_480::Fp480 {
    // add in a leading zero as needed to be more compatible with sage
    let even_hex_str = if hex_str.len() % 2 != 0 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    let slice = &hex::decode(&even_hex_str)
        .unwrap_or_else(|_| panic!("hex_str '{}' cannot be decoded", &even_hex_str));
    if slice.len() == fp_480::PRIMEBYTES {
        let mut target = [0u8; fp_480::PRIMEBYTES];
        target.copy_from_slice(slice);
        fp_480::Fp480::from(target)
    } else {
        panic!(
            "Fp480 from failed! '{:?}' has size {} (bytes). Did you forget to pad your hex string to 129/130 chars?",
            slice,
            slice.len()
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fp480_unsafe_from_known_value() {
        let truth = gridiron::fp_480::Fp480::new([
            2098743022, 1514595207, 158172177, 2077087904, 1481974950, 1373179512, 48841159,
            1821456760, 1081920276, 1225443286, 82365526, 424792007, 2137546047, 1459441907,
            1632731523, 28927,
        ]);
        let fp480 = fp480_unsafe_from("e1ff8546060eb7ea879ff685d3f32a39f8e13a3315a48563eb407ccb14d92272f00ba5071e8ec873c585524a6f79bb14025b61046d2371c3fd1846ee");
        assert_eq!(truth, fp480)
    }
}
