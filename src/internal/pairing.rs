use gridiron::fp_256::Fp256;
use internal::field::{ExtensionField, Field};
use internal::fp12elem::Fp12Elem;
use internal::fp2elem::Fp2Elem;
use internal::fp6elem::Fp6Elem;
use internal::homogeneouspoint::HomogeneousPoint;
use internal::Square;
use num_traits::{Inv, One, Zero};

#[derive(Debug)]
pub struct Pairing<T> {
    pairing_frobenius_factor_1: Fp12Elem<T>,
    pairing_frobenius_factor_2: Fp12Elem<T>,
}

impl<T> Pairing<T>
where
    T: Field + ExtensionField + PairingConfig,
{
    pub fn new() -> Pairing<T> {
        // w^2 = v
        let w = Fp12Elem {
            elem1: One::one(),
            elem2: Zero::zero(),
        };
        let w_squared = w.square();
        let w_cubed = w_squared * w;
        Pairing {
            pairing_frobenius_factor_1: w_squared.frobenius() * w_squared.inv(),
            pairing_frobenius_factor_2: w_cubed.frobenius() * w_cubed.inv(),
        }
    }

    /// This is the optimal Ate pairing, as introduced in the paper "The Eta Pairing Revisited" by
    /// Hess, et al., from 2006. Our implementation is based on the paper "High-Speed Software
    /// Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves" by Beuchat et al,
    /// from 2010.
    pub fn pair(
        &self,
        point_p: HomogeneousPoint<T>,
        point_q: HomogeneousPoint<Fp2Elem<T>>,
    ) -> Fp12Elem<T> {
        let (px, py) = point_p
            .normalize()
            .unwrap_or_else(|| panic!("Pairing is undefined on the zero point."));
        let mut f1: Fp12Elem<T> = One::one();
        let mut f2: Fp2Elem<T> = One::one();
        let neg_q = -point_q;
        let point_result: HomogeneousPoint<Fp2Elem<T>> = <T as PairingConfig>::naf_for_loop()
            .iter()
            .fold(point_q, |acc, naf_value| {
                let mut point_r = acc;
                let mut point_s = point_r.double();
                let (ell1, ell2) = self.double_line_eval(px, py, point_r);
                f1 = ell1 * f1.square();
                f2 = ell2 * f2.square();
                point_r = point_s;
                if *naf_value == -1 {
                    point_s = neg_q + point_r;
                    let (ell1, ell2) = self.add_line_eval(px, py, neg_q, point_r);
                    f1 = f1 * ell1;
                    f2 = f2 * ell2;
                    point_r = point_s;
                    point_r
                } else if *naf_value == 1 {
                    point_s = point_q + point_r;
                    let (ell1, ell2) = self.add_line_eval(px, py, point_q, point_r);
                    f1 = f1 * ell1;
                    f2 = f2 * ell2;
                    point_r = point_s;
                    point_r
                } else {
                    point_r
                }
            });
        let point_q1 = self.frobenius(point_q);
        let point_q2 = self.frobenius(point_q1);
        let point_s = point_q1 + point_result;
        let (ell1, ell2) = self.add_line_eval(px, py, point_q1, point_result);
        f1 = f1 * ell1;
        f2 = f2 * ell2;
        let point_r = point_s;
        let (ell3, ell4) = self.add_line_eval(px, py, -point_q2, point_r);
        f1 = f1 * ell3;
        f2 = f2 * ell4;
        let f = f1 * Fp12Elem {
            elem1: Zero::zero(),
            elem2: Fp6Elem {
                elem1: Zero::zero(),
                elem2: Zero::zero(),
                elem3: f2.inv(),
            },
        };
        self.final_exp(f)
    }

    /// Returns the value at p of the function whose zero-set is the line through q and r.
    /// Script l with addition in the denominator from Miller's Algorithm
    /// Used in step 6 or 8 of Algorithm 1 in High-Speed Software Implementation of
    /// the Optimal Ate Pairing over Barreto–Naehrig Curves
    fn add_line_eval(
        &self,
        px: T,
        py: T,
        q: HomogeneousPoint<Fp2Elem<T>>,
        r: HomogeneousPoint<Fp2Elem<T>>,
    ) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match (q, r) {
            (
                HomogeneousPoint {
                    x: qx,
                    y: qy,
                    z: qz,
                },
                HomogeneousPoint {
                    x: rx,
                    y: ry,
                    z: rz,
                },
            ) => {
                let numerator = ry * qz - qy * rz;
                let denominator = rx * qz - qx * rz;
                self.finalize_eval(q, px, py, numerator, denominator)
            }
        }
    }

    /// returns the value at P of the function whose zero-set is the line through Q and R.
    /// Script l with multiplication in the denominator from Miller's Algorithm
    /// Used in step 4 of Algorithm 1 in High-Speed Software Implementation of
    /// the Optimal Ate Pairing over Barreto–Naehrig Curves
    fn double_line_eval(
        &self,
        px: T,
        py: T,
        r: HomogeneousPoint<Fp2Elem<T>>,
    ) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match r {
            HomogeneousPoint { x, y, z } => {
                let numerator = x.square() * 3;
                let denominator = y * z * 2;
                self.finalize_eval(r, px, py, numerator, denominator)
            }
        }
    }

    /// last step for double_line_eval or add_line_eval
    fn finalize_eval(
        &self,
        q: HomogeneousPoint<Fp2Elem<T>>,
        px: T,
        py: T,
        numerator: Fp2Elem<T>,
        denominator: Fp2Elem<T>,
    ) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match q {
            HomogeneousPoint { x, y, z } => {
                let new_numerator = Fp12Elem::create(
                    Zero::zero(),
                    x * numerator - y * denominator,
                    -z * numerator * Fp2Elem {
                        elem1: Zero::zero(),
                        elem2: px,
                    },
                    Zero::zero(),
                    Zero::zero(),
                    z * denominator * Fp2Elem {
                        elem1: Zero::zero(),
                        elem2: py,
                    },
                );
                (new_numerator, z * denominator)
            }
        }
    }

    /// Final exponentiation: compute the value f^((p^12 - 1) / r). This maps f to one of the rth roots of unity.
    /// The exponent is factored, which allows the computation to be done in two parts (each with several steps):
    ///    The easy part, which consists entirely of calls to frobenius and inverse.
    ///    The hard part, which involves expressing the exponent as a polynomial in x = 1868033.
    pub fn final_exp(&self, initial_f: Fp12Elem<T>) -> Fp12Elem<T> {
        let mut f = initial_f;
        //Easy part
        //"Computing f^((p^6-1)(p^2+1))..."
        let mut g = (0..6).fold(f, { |acc, _| acc.frobenius() });
        f = g * f.inv(); //  f = f^(p^6-1)
        f = f.frobenius().frobenius() * f; //  f = f^(p^2+1)

        //Hard part: compute f = f^((p^4 - p^2 + 1)/r) - Section 7 of Devegili Scott Dahab Pairings over BN curves - Algorithm 3
        //At this point, f has the convenient property that f^(p^6+1) == 1.
        //Thus, f^(-1) == f^p^6 == frobenius^6(f)
        //We also express the exponent as a polynomial in x=1868033.  See Section 7 and in particular Algorithm 3 in Devegili--Scott--Dahab "Implementing Pairings over Barreto--Naehrig Curves"
        //(p^4 - p^2 + 1)/r = p^3 + p^2(6t^2+1) + p(-36t^3-18t^2-12t+1) + (-36t^3-30t^2-18t-2), where t is the BNParam
        let f_inv = f.conjugate(); // f is unitary (See explanation in Beuchet--Gonzalez-Diaz--Mitsunari et. al. bottom of page 4), so f^(-1) == \overline{f}
        g = Pairing::square(f_inv); //g = f^(-2)
        g = Pairing::square(g) * g; //g = g^3
        g = PairingConfig::bn_pow(g); //g = g^x, where x = 1868033 = cube root of BNParam
        g = PairingConfig::bn_pow(g); //g = g^x
        g = PairingConfig::bn_pow(g); //g = g^x = f^(-6x^3)
        let a = g * Pairing::square(Pairing::square(f_inv)) * f_inv; //a = f^-(6*x^3-5)
        let mut b = a.frobenius(); //b = a^p
        b = a * b; //b = a^(p+1)
        let g1 = f.frobenius(); //g1 = f^p
        let g2 = g1.frobenius(); //g2 = g2^p
        let g3 = g2.frobenius(); //g3 = g2^p = f^(p^3)
        let g4 = b * Pairing::square(g1) * g2; //g4 = b*g1^2*g2
        let mut g5 = Pairing::square(g4); //g5 = g4^2
        g5 = Pairing::square(g5) * g5; //g5 = g5^3 = g4^6
        g5 = PairingConfig::bn_pow(g5); //g5^x
        g5 = PairingConfig::bn_pow(g5); //g5^x
        g5 = PairingConfig::bn_pow(g5); //g5^x
        g5 = PairingConfig::bn_pow(g5); //g5^x
        g5 = PairingConfig::bn_pow(g5); //g5^x
        g5 = PairingConfig::bn_pow(g5); //g5^x
        let g6 = g1 * f;
        g3 * g5
            * g4
            * b
            * Pairing::square(Pairing::square(Pairing::square(g6)))
            * g6
            * a
            * Pairing::square(Pairing::square(f))
    }

    /// Squaring for use in final exponentiation.  Shortcut taken from Section 3 of Granger--Scott
    /// "Faster Squaring in the Cyclomatic Subgroup of Sixth Degree Extensions"
    fn square(fp12: Fp12Elem<T>) -> Fp12Elem<T> {
        let Fp12Elem { elem1: b, elem2: a } = fp12;
        let a2 = a * b * 2;
        let b2 = b.square() * 2;
        let Fp6Elem {
            elem1: z,
            elem2: y,
            elem3: x,
        } = b2;
        let z2 = z * ExtensionField::xi() + One::one();
        Fp12Elem {
            elem1: a2,
            elem2: Fp6Elem {
                elem1: y,
                elem2: x,
                elem3: z2,
            },
        }
    }

    fn frobenius(&self, point: HomogeneousPoint<Fp2Elem<T>>) -> HomogeneousPoint<Fp2Elem<T>> {
        match point {
            HomogeneousPoint { x, y, z } => {
                let new_x = (self.pairing_frobenius_factor_1 * x.frobenius())
                    .to_fp2()
                    .unwrap_or_else(|| {
                        panic!("frobenius not defined when the x of `point` can't convert to fp2.")
                    });
                let new_y = (self.pairing_frobenius_factor_2 * y.frobenius())
                    .to_fp2()
                    .unwrap_or_else(|| {
                        panic!("frobenius not defined when the y of `point` can't convert to fp2.")
                    });
                HomogeneousPoint {
                    x: new_x,
                    y: new_y,
                    z: z.frobenius(),
                }
            }
        }
    }
}
///This type represents the information to configure the pairing for a particular FpType.
pub trait PairingConfig
where
    Self: Sized,
{
    /// This is based on the BNParam. It's the cuberoot of BNParam. It should always be called
    /// in multiples of 3.
    fn bn_pow(fp12: Fp12Elem<Self>) -> Fp12Elem<Self>;

    ///The naf which is used for the miller loop. In both our cases it's the NAF of 6*BNParam + 2 reversed with the last 2 dropped off.
    fn naf_for_loop() -> Vec<i8>;
}

impl PairingConfig for Fp256 {
    fn bn_pow(fp12: Fp12Elem<Self>) -> Fp12Elem<Self> {
        //This is a hardcode of the square and multiply for bnPow
        let mut x = fp12;
        let mut res = x;
        (0..8).for_each(|_i| x = x.square());
        res = res * x;
        (0..7).for_each(|_i| x = x.square());
        res = res * x;
        (0..3).for_each(|_i| x = x.square());
        res = res * x.conjugate();
        (0..3).for_each(|_i| x = x.square());
        res * x
    }
    //NAF of 6*BNParam + 2
    fn naf_for_loop() -> Vec<i8> {
        // if comparing to recrypt-scala, the last two elements were left off manually
        let mut r = vec![
            0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
            0, 0, -1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0,
            -1, 0, 0, 0, 0, 1, 0, 0, 0,
        ];
        r.reverse();
        r
    }
}

#[cfg(test)]
mod test {
    use internal::curve::FP_256_CURVE_POINTS;
    use internal::pairing::*;
    use num_traits::Pow;
    use proptest::prelude::*;

    lazy_static! {
        static ref GOOD_HPOINT: HomogeneousPoint<Fp2Elem<Fp256>> = HomogeneousPoint {
            x: Fp2Elem {
                //39898887170429929807040143276261848585078991568615066857293752634765338134660
                elem1: Fp256::new(
                    [17890392025672108164,
                     4787948036817346167,
                     8366096701615182022,
                     6356259441439829802]
                ),
                //4145079839513126747718408015399244712098849008922890496895080944648891367549
                elem2: Fp256::new(
                    [14035135402528964733,
                     4746334641392288740,
                     6120543498253192015,
                     660349316332656566]
                )
            },
            y: Fp2Elem {
                //54517427188233403272140512636254575372766895942651963572804557077716421872651
                elem1: Fp256::new(
                    [16952233059114847243,
                     2810844024569186144,
                     3109547706713703584,
                     8685127226932706650]
                ),
                //29928198841033477396304275898313889635561368630804063259494165651195801046334
                elem2: Fp256::new(
                    [8480542997026377022,
                     12522050111062560742,
                     7603132947494574385,
                     4767837148841406580]
                )
            },
            z: Fp2Elem {
                //25757029117904574834370194644693146689936696995375576562303493881177613755324
                elem1: Fp256::new(
                    [5440923253441258428,
                     1854180132710566912,
                     8660667980330561665,
                     4103331474253682059]
                ),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2: Fp256::new(
                    [6918828829783045468,
                     5626760804594195213,
                     10464662306512466019,
                     3236774570495773861]
                )
            }
        };
        static ref BASE_POINT: HomogeneousPoint<Fp256> = FP_256_CURVE_POINTS.generator;
        static ref BASE_POINT_X: Fp256 = BASE_POINT.x;
        static ref BASE_POINT_Y: Fp256 = BASE_POINT.y;
    }

    #[test]
    fn pair_match_known_good_value() {
        // matches values verified by recrypt-scala
        let expected_good_result = Fp12Elem::create_from_t(
            //20621517740542501009268492188240231175004875885443969425948886451683622135253
            Fp256::new([
                18092919563963868629,
                7535312703102788932,
                186825010492696858,
                3285197310773262209,
            ]),
            //34374877744619883729582518521480375735530540362125629015072222432427068254516
            Fp256::new([
                17874798795115358516,
                10509553017551504414,
                17012896929314934145,
                5476233968112089136,
            ]),
            //3061516916225902041514148805993070634368655849312514173666756917317148753791
            Fp256::new([
                2796847722043686783,
                16414031163437355558,
                14261424020660524668,
                487727783503465407,
            ]),
            //36462333850830053304472867079357777410712443208968594405185610332940263631144
            Fp256::new([
                416187413262903592,
                14122611974139580613,
                17310812515621325570,
                5808784911876835769,
            ]),
            //61512103449194136219283269928242996434577060883392017268158197606945715641345
            Fp256::new([
                7642361093456649217,
                5130777198153281356,
                11536797972669047883,
                9799443444165379604,
            ]),
            //6400685679296646713554926627062187315936943674688629293503755450503276487519
            Fp256::new([
                8431854297172108127,
                7450944574332271141,
                2874140390769630277,
                1019688058138881344,
            ]),
            //53751186939356616119935218564341196608994152768328518524478036628068165341835
            Fp256::new([
                3519691940394553995,
                11232323575149724221,
                14985771333848137161,
                8563058112685733978,
            ]),
            //24086990466602794093787211540995552936111869178774386613517233502609109093865
            Fp256::new([
                5738022665900723689,
                11696368252523858187,
                9012076498597896774,
                3837278967586940365,
            ]),
            //61396452992397102589850224464045014903468298857108669606429537125544948220026
            Fp256::new([
                6727065639392985210,
                4848553194461313843,
                11191929622260275755,
                9781019263441166863,
            ]),
            //15909384434160564083979503677021998800821775569159782381560100961841901513229
            Fp256::new([
                17260445456023464461,
                3557834823344504179,
                3352261581837594978,
                2534511165315774091,
            ]),
            //60608834117224548548490931258722195552088501100182383267798941700183023164589
            Fp256::new([
                5004153509371452589,
                16294162787904550875,
                220950411748700060,
                9655544337531903215,
            ]),
            //17433339776741835027827317970122814431745024562995872600925458287403992082321
            Fp256::new([
                716814800932300689,
                17116457880960511458,
                14343763253984106508,
                2777291258235104886,
            ]),
        );

        let pairing: Pairing<Fp256> = Pairing::new();

        let result = pairing.pair(FP_256_CURVE_POINTS.generator, GOOD_HPOINT.clone());

        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn add_line_match_known_good_value_1() {
        // matches values verified by recrypt-scala
        let expected_good_result = (
            Fp12Elem::create_from_t(
                Fp256::zero(),
                Fp256::zero(),
                //10225613897589023975141864306784331698114333350322193013849355029116866989558
                Fp256::new([
                    3288760344906501622,
                    4049923365833442785,
                    3573872080799926802,
                    1629034278661266234,
                ]),
                //23874417408544625227955020078213054360178217578435813388951341839988775845640
                Fp256::new([
                    9992375511092690696,
                    2806119742226919855,
                    3101545338863858606,
                    3803414125655224568,
                ]),
                //19583696538442210257421816149687930861898894457540838395018829873613832108851
                Fp256::new([
                    15591681428232256307,
                    3405282880558496686,
                    2249021042823921788,
                    3119862854546489090,
                ]),
                //22526875801371184821181570246816236576448644880717020355432045498197577562711
                Fp256::new([
                    9067752070964574807,
                    6901637723626584816,
                    2487984883391350399,
                    3588738362224981324,
                ]),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                //51350284864274176077585216690595295345910970011195603140224124332586682398734
                Fp256::new([
                    7448608193845245966,
                    1584560149758266033,
                    3219850307270125695,
                    8180572345162238495,
                ]),
                //9195404449948098526566482694993850148148550213325878247570491211174099400997
                Fp256::new([
                    7782614701672610085,
                    3538259696167217107,
                    186694525242892151,
                    1464912444880367239,
                ]),
            ),
            Fp2Elem {
                //25675142432137088038792608345297647672955485005597801570112062166293341199367
                elem1: Fp256::new([
                    12947676133777398791,
                    10015652111733908824,
                    10833297190489838655,
                    4090286172581119247,
                ]),
                //37097977072797351129681460718676877945486954160474440909723818119019141736390
                elem2: Fp256::new([
                    13992413155791939526,
                    10356865865926528696,
                    6233994755379879372,
                    5910048719405062976,
                ]),
            },
        );
        let result = Pairing::new().add_line_eval(
            BASE_POINT_X.clone(),
            BASE_POINT_Y.clone(),
            GOOD_HPOINT.clone(),
            GOOD_HPOINT.double(),
        );
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn add_line_match_known_good_value_2() {
        let expected_good_result = (
            // matches values verified by recrypt-scala
            Fp12Elem::create_from_t(
                Fp256::zero(),
                Fp256::zero(),
                //55744800738974830414511837562097001444513814113731905690103202632714685000112
                Fp256::new([
                    15630639943027009968,
                    14292070079695863770,
                    11721091412814006249,
                    8880659114495115055,
                ]),
                //5931115851264405664176255926844469633299602620131317110698302035851504058485
                Fp256::new([
                    7107636030567415925,
                    1464144658996724884,
                    10411033629726338358,
                    944881268663879358,
                ]),
                //5922043367691349962919743457016954000050519680657775073386104333409065506275
                Fp256::new([
                    5229650377476281827,
                    12791247957376224569,
                    17177777325552329615,
                    943435938644467649,
                ]),
                //20288974314653081232608663556936861878151531295868263204413435854177100288352
                Fp256::new([
                    8005525830157652320,
                    9013813103882513378,
                    17434091728928009052,
                    3232220086584791332,
                ]),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                //26356633409924402912277270815241187276017192428798815740104200671052283049228
                Fp256::new([
                    6324643528146744588,
                    14645202827134267211,
                    1869972908993777203,
                    4198853949003390951,
                ]),
                //15795322029202928214286645072236506167028617449376846994561520041437363044626
                Fp256::new([
                    8774395113178005778,
                    10949562912724902373,
                    8976356151131653927,
                    2516339975845541708,
                ]),
            ),
            Fp2Elem {
                //45317051037626942699433282368426742998780524510558790284447501032407331744487
                elem1: Fp256::new([
                    11190601173794269927,
                    12734546591014732624,
                    15302205312903117447,
                    7219422744441998564,
                ]),
                //57314508651404382971317523526158597484748409902108919167661676452517534974217
                elem2: Fp256::new([
                    4052559912334213385,
                    5341057475150744324,
                    17011711572166777856,
                    9130728012308327847,
                ]),
            },
        );
        let (point_x, point_y) = BASE_POINT
            .double()
            .double()
            .normalize()
            .expect("normalize failed");
        let result = Pairing::new().add_line_eval(
            point_x,
            point_y,
            GOOD_HPOINT.double(),
            GOOD_HPOINT.double().double(),
        );
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn double_line_match_known_good_value() {
        // matches values verified by recrypt-scala
        let expected_good_result = (
            Fp12Elem::create_from_t(
                Fp256::zero(),
                Fp256::zero(),
                //17712485624843220480183304963635457557059227558921981718335334461785067564761
                Fp256::new([
                    13098836774174666457,
                    9378052520178947442,
                    5573416033286639088,
                    2821761757498757424,
                ]),
                //60062497247414669535857527984449046910652829387114413501954200738470746113195
                Fp256::new([
                    5956141394721227947,
                    3326122033530754980,
                    8805897195709645151,
                    9568507852727149022,
                ]),
                //22388663537106305339863882629391283032654826869605943340705330045870326159547
                Fp256::new([
                    7563618654437513403,
                    12080606621935636475,
                    16890678015719267680,
                    3566719878203013284,
                ]),
                //53713945989969989737781120925512388913929867004299271526634203788037019854146
                Fp256::new([
                    7063771114483410242,
                    8854629281678465949,
                    15845641119780970102,
                    8557125287162661223,
                ]),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                Fp256::zero(),
                //20917605796411899317217008737010033956820097935526175686366958730322466630407
                Fp256::new([
                    12454462230319917831,
                    10332399405830923195,
                    7622384506540849352,
                    3332366859452109414,
                ]),
                //56032303778290759243918533214786117372540626820242016384835510414304520082514
                Fp256::new([
                    4789108550517298258,
                    6618092375566957191,
                    264970246287928312,
                    8926460991131135218,
                ]),
            ),
            Fp2Elem {
                //42959077746029251525006723739684969849822728021574589629122051878593325351095
                elem1: Fp256::new([
                    16328336920115593399,
                    4530563683903605932,
                    728467709174082165,
                    6843775926690934064,
                ]),
                //28016151889145379621959266607393058686270313410121008192417755207152260041257
                elem2: Fp256::new([
                    11617926312113424937,
                    3309046187783478595,
                    132485123143964156,
                    4463230495565567609,
                ]),
            },
        );

        let result = Pairing::new().double_line_eval(
            BASE_POINT_X.clone(),
            BASE_POINT_Y.clone(),
            GOOD_HPOINT.clone(),
        );
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn frobenius_match_good_value() {
        let generator = HomogeneousPoint {
            x: Fp2Elem {
                //39898887170429929807040143276261848585078991568615066857293752634765338134660
                elem1: Fp256::new([
                    17890392025672108164,
                    4787948036817346167,
                    8366096701615182022,
                    6356259441439829802,
                ]),
                //4145079839513126747718408015399244712098849008922890496895080944648891367549
                elem2: Fp256::new([
                    14035135402528964733,
                    4746334641392288740,
                    6120543498253192015,
                    660349316332656566,
                ]),
            },
            y: Fp2Elem {
                //54517427188233403272140512636254575372766895942651963572804557077716421872651
                elem1: Fp256::new([
                    16952233059114847243,
                    2810844024569186144,
                    3109547706713703584,
                    8685127226932706650,
                ]),
                //29928198841033477396304275898313889635561368630804063259494165651195801046334
                elem2: Fp256::new([
                    8480542997026377022,
                    12522050111062560742,
                    7603132947494574385,
                    4767837148841406580,
                ]),
            },
            z: Fp2Elem {
                //25757029117904574834370194644693146689936696995375576562303493881177613755324
                elem1: Fp256::new([
                    5440923253441258428,
                    1854180132710566912,
                    8660667980330561665,
                    4103331474253682059,
                ]),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2: Fp256::new([
                    6918828829783045468,
                    5626760804594195213,
                    10464662306512466019,
                    3236774570495773861,
                ]),
            },
        };

        let expected_result = HomogeneousPoint {
            x: Fp2Elem {
                //3493288303413595898714519891264492301560207456168827437424957567620529428904
                elem1: Fp256::new([
                    3629791859830856104,
                    11002933970927806464,
                    6955090550392621616,
                    556512933942180730,
                ]),
                //57579932449471156509924950033302853001562583061231887808723506993246370069786
                elem2: Fp256::new([
                    11290361648572071194,
                    9081455878347555965,
                    14532349765017500230,
                    9173012462880550882,
                ]),
            },
            y: Fp2Elem {
                //51856762088277527784977807176637663292245671912163591131470367010215157555522
                elem1: Fp256::new([
                    17588998935007977794,
                    17177535013604960694,
                    9708833906244006439,
                    8261258822035494365,
                ]),
                //49397214075582907890167267499315856190388550710652209341826106816887973948785
                elem2: Fp256::new([
                    16224874243152358769,
                    14807691382181160480,
                    5308175553624115841,
                    7869430217628924665,
                ]),
            },
            z: Fp2Elem {
                //39243520577742028898426244097666759052888661112247427009573651145686570316459
                elem1: Fp256::new([
                    14761288356470010539,
                    15321291902975273373,
                    3620627005186304928,
                    6251853519676076654,
                ]),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2: Fp256::new([
                    6918828829783045468,
                    5626760804594195213,
                    10464662306512466019,
                    3236774570495773861,
                ]),
            },
        };

        let result = Pairing::new().frobenius(generator);

        assert_eq!(expected_result, result);
    }

    proptest! {
      //"follow the law pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)"
      //"follow the law pair(a * P, a * Q) == pair(P, Q) ^ (a^2)"
      #[test]
      fn law_bilinearity(a in any::<u32>().prop_filter("", |a| !(*a == 0))) {
        let a: u64 = a as u64;
        let pairing: Pairing<Fp256> = Pairing::new();
        let p = FP_256_CURVE_POINTS.generator;
        let a_sqr = Fp256::from(a.pow(2));
        let a_sqr_u64: u64 = a.pow(2) as u64;
        let a = Fp256::from(a);
        let a_times_p = p * a;
        let a_sqr_times_p = p * a_sqr;
        let q = FP_256_CURVE_POINTS.g1;
        let a_times_q = q * a;
        let pair_a_times_p_and_a_times_q  = pairing.pair(a_times_p, a_times_q);

        // pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)"
        prop_assert_eq!(pairing.pair(p, a_times_q), pairing.pair(a_times_p, q));
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(a_sqr_times_p, q));

        // pair(a * P, a * Q) == pair(P, Q) ^ (a^2)
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(p, q).pow(a_sqr_u64));
      }
    }
}
