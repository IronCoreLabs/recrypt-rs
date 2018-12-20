use crate::internal::rand_bytes::RandomBytesGen;
use gridiron::fp31;
use gridiron::fp_256;

// r: 65000549695646603732796438742359905742570406053903786389881062969044166799969 (also "curve_order")
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
//TODO THIS ISN'T REALLY FR480 -- it's just a placeholder copy of Fp480 for now
// p = 3121577065842246806003085452055281276803074876175537384188619957989004527066410274868798956582915008874704066849018213144375771284425395508176023
//   =
fp31!(
    fr_480, // Name of mod
    Fr480,  // Name of class
    480,    // Number of bits for prime
    16,     // Number of limbs (ceil(bits/31))
    [
        // prime number in limbs, least sig first
        // get this from sage with p.digits(2^31)
        1055483031, 1386897616, 898494285, 1391857335, 488544832, 1799384686, 193115992, 565079768,
        190358044, 1260077487, 1583277252, 222489098, 760385720, 330553579, 429458313, 32766
    ],
    // barrett reduction for reducing values up to twice
    // the number of prime bits (double limbs):
    // floor(2^(31*numlimbs*2)/p).digits(2^31)
    [
        867470981, 808770461, 73326154, 873519719, 731426156, 154316581, 1066899290, 1406793571,
        1662108208, 231227174, 1893732143, 1300610845, 325218135, 866248622, 1596183093,
        1288991726, 65539
    ],
    // montgomery R = 2^(W*N) where W = word size and N = limbs
    //            R = 2^(16*31) = 2^496
    // montgomery R^-1 mod p
    // 540164672828597150601552066704871144340865164390233716165828766698348036766646674962138582407269471436938515957052715279568068096452253665449178
    [
        172371756, 1046460578, 1674812214, 732914258, 1831602581, 1542423573, 2092897579,
        735180796, 1991677061, 919723849, 802444109, 1677449578, 1892606677, 1820724059,
        1324905779, 16249
    ],
    // montgomery R^2 mod p
    // 457845372202231092221045514406304715517609899600516288088351276206864288839367561156406646278891945147846188034105187428603489846554823930520200
    [
        197589901, 1933752831, 580428568, 527417626, 249573438, 264164054, 609560334, 32358085,
        944568904, 1556682934, 1807973447, 1881920392, 10254137, 588677610, 1214264513, 6960
    ],
    // -p[0]^-1
    // in sage: m = p.digits(2^31)[0]
    //          (-m).inverse_mod(2^31)
    1345299673
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
            fr.to_bytes_array().to_vec() != bytes.to_vec()  //TODO to_vec for now since it has PartialEq for 60 bytes
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
/// Function to be used for static values either as defined as constants or used in tests.
/// Don't use this to create Fp256 from dynamic values at runtime! It will panic on failure.
///
/// Arguments:
/// `hex_str` - need to be 63 or 64 bytes. Do not include a leading '0x'
pub fn fp256_unsafe_from(hex_str: &str) -> fp_256::Fp256 {
    let even_hex_str = if hex_str.len() % 2 != 0 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };

    let slice = &hex::decode(&even_hex_str)
        .expect(&format!("hex_str '{}' cannot be decoded", &even_hex_str));
    if slice.len() == fp_256::PRIMEBYTES {
        let mut target = [0u8; fp_256::PRIMEBYTES];
        target.copy_from_slice(slice);
        fp_256::Fp256::from(target)
    } else {
        panic!(
            "Fp256 from failed! '{:?}' has size {} (bytes). Did you forget to pad your hex string to 63/64 bytes?",
            slice,
            slice.len()
        )
    }
}
