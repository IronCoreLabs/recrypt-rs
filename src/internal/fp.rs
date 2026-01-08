use crate::internal::rand_bytes::RandomBytesGen;
use gridiron::fp_256;
use gridiron::fp_480;

// r: 65000549695646603732796438742359905742570406053903786389881062969044166799969 (also "curve_order" for Fp256)
// r = 3121577065842246806003085452055281276803074876175537384188619957989004525299611739143164276204220965332554591187396064132658995685351714167608049
// This is also "curve_order" for Fp480

#[cfg(feature = "u32_backend")]
use gridiron::fp31;

#[cfg(feature = "u32_backend")]
fp31!(
    fr_256, // Name of mod
    Fr256,  // Name of class
    256,    // Number of bits for prime
    9,      // Number of limbs (ceil(bits/31))
    // prime in limbs, least sig first
    // sage: 65000549695646603732796438742359905742570406053903786389881062969044166799969.digits(2^31)
    [
        1470919265, 878569654, 1621943440, 1953263767, 407749138, 1308464908, 685899370,
        1518399909, 143
    ],
    // reduction_factor
    //2^(31*(2*9-1)) % p
    //60578513295813710592630177991574484510343482833477254561432642537919118791084
    [
        1663783340, 53996217, 1264037426, 366665174, 1029142601, 1377617547, 1943249747,
        1998363284, 133
    ],
    // W = 31 (bytes)
    // montgomery R = 2^(W*N) % p where W = word size and N = limbs
    //            R = 2^(31*9) = 2^279
    //R % p = 31746963425510762026994079049055217408067679606784446338012800016910603496968
    [
        12824072, 179276061, 340986673, 1040734720, 1691111650, 1964912876, 1176826515, 403865604,
        70
    ],
    // montgomery R^2 mod p
    // sage: mont_r_squared = mont_r^2 % p
    // sage: mont_r_squared.digits(2^31)
    //28246183317335424924291340695987904736439985320227675295280074811342632444628
    [
        1770447572, 496375461, 2107782367, 1971926976, 1431428989, 1530023807, 975789685,
        962787448, 62
    ],
    // -p[0]^-1
    // sage: m = p.digits(2^31)[0]
    //          (-m).inverse_mod(2^31)
    757616223
);

#[cfg(feature = "u32_backend")]
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
    // reduction factor
    //2^(31*(2*16-1)) mod p
    //1739983287038919322992505976901282940154362593622543841175737924115631069143952344086437140836561389835892307985982358767969839917501802215648860
    [
        1026829916, 1456777803, 134603837, 451267966, 1930150853, 723555411, 1114658449,
        1023661674, 1480375811, 856405064, 481343463, 446073531, 1812344668, 1053202982, 107882749,
        18264
    ],
    // W = 31 (bytes)
    // montgomery R = 2^(W*N) where W = word size and N = limbs
    // montgomery R = R = 2^(31*16) = 2^496
    // R % p = 1873675273853457188138609473867413143403568023004720367747079366994691680905908500537272220571975000122406141753790885740615895571071002169050925
    [
        1993082669, 148658199, 1545864062, 1328403877, 1966735026, 1348874698, 531286620,
        750137843, 1004132174, 1560224833, 2014075, 1848411426, 1733309265, 1811487384, 799788540,
        19667
    ],
    // montgomery R^2 mod p
    // sage: mont_r_squared = mont_r^2 % p
    // sage: mont_r_squared.digits(2^31)
    //520051719411445562589378058346609665043135801820214113570103511380810932165152775069448265214536405017342722519506114587617828450359738609924281
    [
        1124825273, 988937813, 894529151, 636400857, 262882198, 301704988, 412821006, 2861128,
        1848750227, 1614862374, 1570166973, 1675926980, 601581422, 75226069, 1754965692, 5458
    ],
    // -p[0]^-1
    // in sage: m = p.digits(2^31)[0]
    //          (-m).inverse_mod(2^31)
    1693426159
);

#[cfg(not(feature = "u32_backend"))]
use gridiron::fp62;

#[cfg(not(feature = "u32_backend"))]
fp62!(
    fr_256, // Name of mod
    Fr256,  // Name of class
    256,    // Number of bits for prime
    5,      // Number of limbs (ceil(bits/62))
    [
        // prime number in limbs, least significant first
        // get this from sage with p.digits(2^62)
        1886713967064937057, 4194602001485325456, 2809906994319573522, 3260738976388087402, 143
    ],
    [
        // Barrett reduction constant for reducing values up to twice
        // the number of prime bits (double limbs):
        // 2^(62*5*2 - 62) mod p = 2^558 mod p
        1065958187536409300, 4234680938117870815, 3285701108014636925, 2067570302055439989, 62
    ],
    [
        // Montgomery R = 2^(W*N) where W = word size and N = limbs
        //            R = 2^(5*62) = 2^310
        // Montgomery R mod p
        2936851089539971147, 583464008209364592, 2224920035069184107, 1017232563857971296, 76
    ],
    [
        // Montgomery R^2 mod p
        2068181803476500340, 90163823890415014, 3136226075385316144, 1159566150942268457, 86
    ],
    // -p[0]^-1 mod 2^62
    // in sage: m = p.digits(2^62)[0]
    //          (-m).inverse_mod(2^62)
    388461543364775519
);

#[cfg(not(feature = "u32_backend"))]
fp62!(
    fr_480, // Name of mod
    Fr480,  // Name of class
    480,    // Number of bits for prime
    8,      // Number of limbs (ceil(bits/62))
    [
        // prime number in limbs, least significant first
        // get this from sage with p.digits(2^62)
        2440693663225238257, 3539764477904802220, 1428868479681500228, 1195485658071212571,
        2705995798735790620, 477791701396546756, 709858406450761912, 70364878668681
    ],
    [
        // Barrett reduction constant for reducing values up to twice
        // the number of prime bits (double limbs):
        // 2^(62*8*2 - 62) mod p = 2^930 mod p
        4232791690240516199, 2570251445162385211, 1953698701289181842, 3756775821135378570,
        1658891262688879891, 4184329677974591309, 87805944455915183, 24606964424464
    ],
    [
        // Montgomery R = 2^(W*N) where W = word size and N = limbs
        //            R = 2^(8*62) = 2^496
        // Montgomery R mod p
        319241053486712621, 2852725605343167358, 2896686359122673330, 1610908752119777884,
        3350557317075162958, 3969433312113376123, 3890139537431606097, 42235360693756
    ],
    [
        // Montgomery R^2 mod p
        2123727783431207097, 1366660434875215487, 647906528512918422, 6144226007655950,
        3467890543784210579, 3599025786362190013, 161546753682401134, 11722720716476
    ],
    // -p[0]^-1 mod 2^62
    // in sage: m = p.digits(2^62)[0]
    //          (-m).inverse_mod(2^62)
    124432205055238639
);
impl fr_256::Fr256 {
    ///Generate an Fr256 with no bias from `RandomBytesGen`.
    pub fn from_rand_no_bias<R: RandomBytesGen>(random_bytes: &R) -> fr_256::Fr256 {
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
    pub fn from_rand_no_bias<R: RandomBytesGen>(random_bytes: &R) -> fr_480::Fr480 {
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

#[cfg(feature = "u32_backend")]
impl From<[u8; 64]> for fr_256::Fr256 {
    fn from(src: [u8; 64]) -> Self {
        let limbs = gridiron::from_sixty_four_bytes(src);
        let (x0_view, x1_and_x2_view) = limbs.split_at(fr_256::NUMLIMBS - 1);
        let (x1_view, x2_view) = x1_and_x2_view.split_at(fr_256::NUMLIMBS - 1);
        let (mut x0, mut x1, mut x2) = (
            [0u32; fr_256::NUMLIMBS],
            [0u32; fr_256::NUMLIMBS],
            [0u32; fr_256::NUMLIMBS],
        );
        x0[..fr_256::NUMLIMBS - 1].copy_from_slice(x0_view);
        x1[..fr_256::NUMLIMBS - 1].copy_from_slice(x1_view);
        x2[..1].copy_from_slice(x2_view);

        (fr_256::Fr256::new(x2) * fr_256::REDUCTION_CONST + fr_256::Fr256::new(x1))
            * fr_256::REDUCTION_CONST
            + fr_256::Fr256::new(x0)
    }
}

#[cfg(feature = "u32_backend")]
impl From<[u8; 64]> for fr_480::Fr480 {
    fn from(src: [u8; 64]) -> Self {
        let limbs = gridiron::from_sixty_four_bytes(src);
        let (x0_view, x1_view) = limbs.split_at(fr_480::NUMLIMBS - 1);
        let (mut x0, mut x1) = ([0u32; fr_480::NUMLIMBS], [0u32; fr_480::NUMLIMBS]);
        x0[..fr_480::NUMLIMBS - 1].copy_from_slice(x0_view);
        x1[..2].copy_from_slice(x1_view);

        fr_480::Fr480::new(x1) * fr_480::REDUCTION_CONST + fr_480::Fr480::new(x0)
    }
}

#[cfg(not(feature = "u32_backend"))]
impl From<[u8; 64]> for fr_256::Fr256 {
    fn from(src: [u8; 64]) -> Self {
        let limbs = gridiron::from_sixty_four_bytes(src);
        let (x0_view, x1_and_x2_view) = limbs.split_at(fr_256::NUMLIMBS - 1);
        let (x1_view, x2_view) = x1_and_x2_view.split_at(fr_256::NUMLIMBS - 1);
        let (mut x0, mut x1, mut x2) = (
            [0u64; fr_256::NUMLIMBS],
            [0u64; fr_256::NUMLIMBS],
            [0u64; fr_256::NUMLIMBS],
        );
        x0[..fr_256::NUMLIMBS - 1].copy_from_slice(x0_view);
        x1[..fr_256::NUMLIMBS - 1].copy_from_slice(x1_view);
        x2[..1].copy_from_slice(x2_view);

        (fr_256::Fr256::new(x2) * fr_256::REDUCTION_CONST + fr_256::Fr256::new(x1))
            * fr_256::REDUCTION_CONST
            + fr_256::Fr256::new(x0)
    }
}

#[cfg(not(feature = "u32_backend"))]
impl From<[u8; 64]> for fr_480::Fr480 {
    fn from(src: [u8; 64]) -> Self {
        let limbs = gridiron::from_sixty_four_bytes(src);
        let (x0_view, x1_view) = limbs.split_at(fr_480::NUMLIMBS - 1);
        let (mut x0, mut x1) = ([0u64; fr_480::NUMLIMBS], [0u64; fr_480::NUMLIMBS]);
        x0[..fr_480::NUMLIMBS - 1].copy_from_slice(x0_view);
        x1[..2].copy_from_slice(x1_view);

        fr_480::Fr480::new(x1) * fr_480::REDUCTION_CONST + fr_480::Fr480::new(x0)
    }
}
impl From<fp_256::Monty> for fr_256::Fr256 {
    fn from(src: fp_256::Monty) -> Self {
        From::from(src.to_norm().to_bytes_array())
    }
}

impl From<fp_480::Monty> for fr_480::Fr480 {
    fn from(src: fp_480::Monty) -> Self {
        From::from(src.to_norm().to_bytes_array())
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
        let hex_str =
            "e1ff8546060eb7ea879ff685d3f32a39f8e13a3315a48563eb407ccb14d92272f00ba5071e8ec873c585524a6f79bb14025b61046d2371c3fd1846ee";
        // Create truth from bytes (works regardless of limb size)
        let bytes = hex::decode(hex_str).unwrap();
        let mut arr = [0u8; 60];
        arr.copy_from_slice(&bytes);
        let truth = gridiron::fp_480::Fp480::from(arr);

        let fp480 = fp480_unsafe_from(hex_str);
        assert_eq!(truth, fp480)
    }
}
