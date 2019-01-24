use crate::internal::fp::{fp256_unsafe_from, fp480_unsafe_from};
use crate::internal::fp2elem::Fp2Elem;
use crate::internal::homogeneouspoint::HomogeneousPoint;
use crate::internal::homogeneouspoint::TwistedHPoint;
use gridiron::fp_256;
use gridiron::fp_256::Fp256;
use gridiron::fp_480::Fp480;
use lazy_static::lazy_static;
use num_traits::identities::One;
use num_traits::identities::Zero;
use num_traits::one;

/// Points that are used in our core algorithm for for `FP`.
///
/// `g1`            - the point which is in Fp2 and is used in the pairing.
/// `hash_element`  - another point in Fp2 that is used for hashing.
/// `generator`     - the generator point over FP.
#[derive(Debug)]
pub struct CurvePoints<FP> {
    pub generator: HomogeneousPoint<FP>,
    pub g1: TwistedHPoint<FP>,
    pub hash_element: TwistedHPoint<FP>,
}

lazy_static! {
    pub static ref FP_256_MONTY_CURVE_POINTS: CurvePoints<fp_256::Monty> = CurvePoints {
        // Fixed point in cyclic group G1 (the trace zero subgroup).
        // Start with a point that is on the twisted curve y^2 = x^3 + (3 / (u + 3)).
        // Turns out u + 1 is a valid x, with y = sqrt(x^3 + (3 / (u + 3)).
        // Take (x,y) and multiply by (p + p - r) to get an r-torsion element of the twisted curve over FP2.
        // Compute the anti-trace map of that r-torsion element to get a point in the trace-zero subgroup.
        generator: HomogeneousPoint::new(Fp256::one().to_monty(), Fp256::from(2u8).to_monty(),),
        g1: TwistedHPoint {
            x: Fp2Elem {
                //"25743265030535080187440590897139396943782163562799308681850377411492232521347",
                elem1: fp256_unsafe_from("38ea2bf1e67ebb77fae32f89096b96cc8912bf8b02baccca22ccdd9bf6536683").to_monty(),
                //34056889713323967780338301808336650802977437253339894663986165323395183925712
                elem2: fp256_unsafe_from("4b4b8437fabcdd026eeb59e9f6baf17bedb2d3cae8f4dc6baf3704498087d9d0").to_monty()
            },
            y: Fp2Elem {
                //36332093629799712472233840570439767783123758424653318224159027848500552319214
                elem1: fp256_unsafe_from("50533c7b970d1b6e0374b55e8f96013a5ff8b25c7c51df6552093717d80ec0ee").to_monty(),
                //19100300358747584658695151329066047798696640594509146799364306658205997167318
                elem2: fp256_unsafe_from("2a3a630bb4d90e84802b412c45886566c7a1297bd46b22dd19f949aeed7b72d6").to_monty()
            },
            z: Fp2Elem {
                //11969434517458907073927619028753373626677015846219303340439317866996854601254
                elem1: fp256_unsafe_from("1a7675b952f7801f1895497dcc1f168d17f7214761909e23386d349ab952b626").to_monty(),
                //14774454666095297364611775449425506027744765805321334870185419948913527571534
                elem2: fp256_unsafe_from("20aa0b8534909adae8a0142c3118302a42460c7232af903f0211927a97a3444e").to_monty()
            }
        },

        // Used to hash integers to a point in FP2
        // Generated by multiplying g1 by the SHA256 hash of the date/time "Mon Feb 19 16:30:21 MST 2018\n",
        // encoded in ASCII/UTF-8, converted to a BigInt.
        hash_element: TwistedHPoint {
            x: Fp2Elem {
                //26115920809144023111516349163868890892335785984202627188956566235163006540541
                elem1: fp256_unsafe_from("39bd165cf62008931544afcc46e7c4067a9c36f3bf6da3f60824042670471afd").to_monty(),
                //15905362109061908101726321997764649315090633150407344591241408991746779381256
                elem2: fp256_unsafe_from("232a1dada370347e57083bfc16fff22e7ff743d6ebae8eeba05ad501df5dfe08").to_monty()
            },
            y: Fp2Elem {
                //4632230948348518150642153940906247958418069554996068756252789717528925762701
                elem1: fp256_unsafe_from("a3dbff3400c6b5d254d4a8737b0272726bef7612168750d945512ecab74f48d").to_monty(),
                //3026141039160762752629025637420408604709576372807872293769066469244216243501
                elem2: fp256_unsafe_from("6b0bc318d9331d01ae6646f9b0d6cfe1c8b0e4eaee542fe03a8302f4a83752d").to_monty()
            },
            z: Fp2Elem {
                //43872202626887887868122322275088633257981831137687656289783477940483447530228
                elem1: fp256_unsafe_from("60fec9664750a01047481318531471ab94ddf69c82b1cc92dea03735192722f4").to_monty(),
                //20191379131685497308054970475671582162258136917730106438050079114233947942452
                elem2: fp256_unsafe_from("2ca3ea64a93d8451fb631c6923796388179f2ef65d72a05dd36af235146cee34").to_monty()
            }
        }
    };
    pub static ref FP_480_CURVE_POINTS: CurvePoints<Fp480> =
    CurvePoints {
        // Fixed point in cyclic group G1 (the trace zero subgroup).
        // Start with a point that is on the twisted curve y^2 = x^3 + (3 / (u + 3)).
        // Turns out u + 1 is a valid x, with y = sqrt(x^3 + (3 / (u + 3)).
        // Take (x,y) and multiply by (p + p - r) to get an r-torsion element of the twisted curve over FP2.
        // Compute the anti-trace map of that r-torsion element to get a point in the trace-zero subgroup.
        generator: HomogeneousPoint::new(one(), Fp480::from(2u8),),
        g1: TwistedHPoint {
            x: Fp2Elem {
                // 2836796539847730496121374298065944583953504150765508351672461175175719456840753019328265331693934514908570706456436537314841014056269083482678066
                elem1: fp480_unsafe_from("e8a1e6285c4061a07c584136417db3e867cf77b12288380e518dab8538228e96abad778e1fe576deff39e638e030933cb8fa5c388fa8b06991ea6332"),
                // 2673768771775032355420306564841108930438651217980189126243896874678717443069132673614464990588309533043439946857284622768054880686771881306409642
                elem2: fp480_unsafe_from("db4365e116bcb8a9f1cd16c16f659be8441624488f0fa10cee176e6219c78cda3a75041e41eb847603b2eabe65b2f31867cbfc784f453487387ecaaa")
            },
            y: Fp2Elem {
                // 3080607037190881313834826417530769563132997895310223092587326825944478280552006660025218522727539672756392754158719384720663526682905220416822282
                elem1: fp480_unsafe_from("fca04d212ab8b13be77f82635c3ce496f0b3c0611aaf492f47067a062d754a28d442b701cb48a06809ffce876bb536c6b1371107e314f92a160c5c0a"),
                // 2906149584369018327289172171212098825323249826660713579814103802892067659387776431613853400363371122569649698984076618174478076051599518261188038
                elem2: fp480_unsafe_from("ee51da494993536a1fb297d54eb0c6804e8c6c6fd3d158900c9a421e276e058c620cf10104b27e945d8d124909a2a93fbda08b6ce6e072eeeafa15c6")
            },
            z: Fp2Elem {
                //
                elem1: Fp480::zero(),
                //
                elem2: Fp480::one()
            }
        },

        // Used to hash integers to a point in FP2
        // Generated by multiplying g1 by the SHA256 hash of the date/time "Mon Mar 26 13:33:43 MDT 2018\n",
        // encoded in ASCII/UTF-8, converted to a BigInt.
        hash_element: TwistedHPoint {
            x: Fp2Elem {
                // 2755895806273995492284787079187941247738254659153318682910850469784894541505170101984499629579667341065183727568252238059654392233777140703184622
                elem1: fp480_unsafe_from("e1ff8546060eb7ea879ff685d3f32a39f8e13a3315a48563eb407ccb14d92272f00ba5071e8ec873c585524a6f79bb14025b61046d2371c3fd1846ee"),
                // 630223019374291956078632635377008181978279936792489208439110695275442238629433173084638817027401619964084048824893758705005177091915333122454106
                elem2: fp480_unsafe_from("33ae8021a5b3f7d0bf99611976f6bd542e6a391b5af42d778ea5265b1f0d9098f4d74578be80932d1e6ac4efe7c7237e7da8a2ad49e0e9a6d270f25a")
            },
            y: Fp2Elem {
                // 659567418809487070027824196603118281636508923398279856378657485535700744304348227321440219246561941778839111505653577989859933696546799454574627
                elem1: fp480_unsafe_from("361689c368efd496748a650f060d7033574872c85e9ecc10b12bf923687d147efe21ee3c93d94c2dadafc4e2b563b32c42e77832766b434fde40d823"),
                // 2632696014493840722302529499863944843283552594579584896121087553911353425460849587377878627157950485322470437984154786925535244302963434645693127
                elem2: fp480_unsafe_from("d7e52485fdd198506e27b1dd34610a84e0555ece060067051768485e849e1a2710f2be426e1c7916ec14669844c0c37beddc834876d91facd6ad22c7")
            },
            z: Fp2Elem {
                // 2723878025330396352455760809227014699447653800671598495327573996671655085492645713095099955627015617726770647513458138760772123814185152132721554
                elem1: fp480_unsafe_from("df5f5c15c4df23c5f1135907a581cc838e3689435f18d610a30d378e8fd1c190245edb38dc5644a7907a10566dd28075de3db675bb875ef555d0ab92"),
                // 2520811096583992837832885181589663735998061148584558864774875442611283633943850563303274829680791759077833709816521531207043963496532513260928366
                elem2: fp480_unsafe_from("ceb84d4f5892e3ba709eb41979576c04d7897ce6dc763e867cfe34deecacde57d435ca92c15ecbecebf12c316746b8022da2c4df6ec685a261657d6e")
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generator_times_2() {
        //37777967648492203239675772600961898148040325589588086812374811831221462604944
        let fp256 =
            fp256_unsafe_from("5385926b9f6135086d1912901e5a433ffcebc19a30fadbd0ee8cee26ba719c90");
        let result = FP_256_MONTY_CURVE_POINTS.generator * fp256.to_monty();
        let expected_result = HomogeneousPoint::new(
            //56377452267431283559088187378398270325210563762492926393848580098576649271541
            fp256_unsafe_from("7ca481d71abbae43395152eb7baa230d60543d43e2e8f89a18d182ecf8c3b8f5"),
            //46643694276241842996939080253335644316475473619096522181405937227991761798154
            fp256_unsafe_from("671f653900901fc3688542e5939ba6c064a7768f34fe45492a49e1f6d4d7c40a"),
        );
        assert_eq!(
            result.map(&|monty: fp_256::Monty| monty.to_norm()),
            expected_result
        )
    }
}
