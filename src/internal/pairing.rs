use crate::internal::field::ExtensionField;
use crate::internal::fp12elem::Fp12Elem;
use crate::internal::fp2elem::{Fp2Elem, Xi};
use crate::internal::fp6elem::Fp6Elem;
use crate::internal::homogeneouspoint::Double;
use crate::internal::homogeneouspoint::HomogeneousPoint;
use crate::internal::homogeneouspoint::PointErr;
use crate::internal::homogeneouspoint::TwistedHPoint;
use crate::internal::Square;
use gridiron::fp_256;
use gridiron::fp_480;
use num_traits::{Inv, One, Zero};

#[derive(Debug)]
pub struct Pairing<T> {
    pairing_frobenius_factor_1: Fp12Elem<T>,
    pairing_frobenius_factor_2: Fp12Elem<T>,
}

impl<T> Pairing<T>
where
    T: ExtensionField + PairingConfig,
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
        point_q: TwistedHPoint<T>,
    ) -> Result<Fp12Elem<T>, PointErr> {
        point_p
            .normalize()
            .map_or(Err(PointErr::ZeroPoint), |(px, py)| {
                let mut f1: Fp12Elem<T> = One::one();
                let mut f2: Fp2Elem<T> = One::one();
                let neg_q = -point_q;
                let point_result: TwistedHPoint<T> = <T as PairingConfig>::naf_for_loop()
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
                let f = f1
                    * Fp12Elem {
                        elem1: Zero::zero(),
                        elem2: Fp6Elem {
                            elem1: Zero::zero(),
                            elem2: Zero::zero(),
                            elem3: f2.inv(),
                        },
                    };
                Ok(self.final_exp(f))
            })
    }

    /// Returns the value at p of the function whose zero-set is the line through q and r.
    /// Script l with addition in the denominator from Miller's Algorithm
    /// Used in step 6 or 8 of Algorithm 1 in High-Speed Software Implementation of
    /// the Optimal Ate Pairing over Barreto–Naehrig Curves
    fn add_line_eval(
        &self,
        px: T,
        py: T,
        q: TwistedHPoint<T>,
        r: TwistedHPoint<T>,
    ) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match (q, r) {
            (
                TwistedHPoint {
                    x: qx,
                    y: qy,
                    z: qz,
                },
                TwistedHPoint {
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
    fn double_line_eval(&self, px: T, py: T, r: TwistedHPoint<T>) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match r {
            TwistedHPoint { x, y, z } => {
                let numerator = x.square() * 3;
                let denominator = y * z * 2;
                self.finalize_eval(r, px, py, numerator, denominator)
            }
        }
    }

    /// last step for double_line_eval or add_line_eval
    fn finalize_eval(
        &self,
        q: TwistedHPoint<T>,
        px: T,
        py: T,
        numerator: Fp2Elem<T>,
        denominator: Fp2Elem<T>,
    ) -> (Fp12Elem<T>, Fp2Elem<T>) {
        match q {
            TwistedHPoint { x, y, z } => {
                let new_numerator = Fp12Elem::create(
                    Zero::zero(),
                    x * numerator - y * denominator,
                    -z * numerator
                        * Fp2Elem {
                            elem1: Zero::zero(),
                            elem2: px,
                        },
                    Zero::zero(),
                    Zero::zero(),
                    z * denominator
                        * Fp2Elem {
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
        let z2 = z * Xi + One::one();
        Fp12Elem {
            elem1: a2,
            elem2: Fp6Elem {
                elem1: y,
                elem2: x,
                elem3: z2,
            },
        }
    }

    fn frobenius(&self, point: TwistedHPoint<T>) -> TwistedHPoint<T> {
        match point {
            TwistedHPoint { x, y, z } => {
                let new_x = (self.pairing_frobenius_factor_1 * x.frobenius()).frobenius_to_fp2();
                let new_y = (self.pairing_frobenius_factor_2 * y.frobenius()).frobenius_to_fp2();
                TwistedHPoint {
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

impl PairingConfig for fp_256::Monty {
    fn bn_pow(fp12: Fp12Elem<Self>) -> Fp12Elem<Self> {
        //This is a hardcode of the square and multiply for bnPow
        let mut x = fp12;
        let mut res = x;
        (0..8).for_each(|_| x = x.square());
        res = res * x;
        (0..7).for_each(|_| x = x.square());
        res = res * x;
        (0..3).for_each(|_| x = x.square());
        res = res * x.conjugate();
        (0..3).for_each(|_| x = x.square());
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

impl PairingConfig for fp_480::Monty {
    fn bn_pow(fp12: Fp12Elem<Self>) -> Fp12Elem<Self> {
        //This is a hardcode of the square and multiply for bnPow
        let mut x = fp12;
        let mut res = x;
        (0..3).for_each(|_| x = x.square());
        res = res * x;
        (0..4).for_each(|_| x = x.square());
        res = res * x;
        (0..2).for_each(|_| x = x.square());
        res = res * x;
        (0..4).for_each(|_| x = x.square());
        res = res * x;
        (0..5).for_each(|_| x = x.square());
        res = res * x;
        (0..4).for_each(|_| x = x.square());
        res = res * x.conjugate();
        (0..2).for_each(|_| x = x.square());
        res = res * x;
        (0..3).for_each(|_| x = x.square());
        res = res * x;
        (0..2).for_each(|_| x = x.square());
        res = res * x.conjugate();
        (0..4).for_each(|_| x = x.square());
        res = res * x.conjugate();
        (0..5).for_each(|_| x = x.square());
        res = res * x.conjugate();
        (0..2).for_each(|_| x = x.square());
        res * x
    }

    fn naf_for_loop() -> Vec<i8> {
        // if comparing to recrypt-scala, the last two elements were removed manually instead of at runtime
        let mut r = vec![
            0, 0, 0, -1, 0, 1, 0, 0, 0, -1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0,
            1, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, -1, 0,
            0, -1, 0, 0, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0,
            1, 0, -1, 0, 0, 1, 0//, 1, 0,
        ];
        r.reverse();
        r
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::curve::{FP_256_CURVE_POINTS, FP_480_CURVE_POINTS};
    use crate::internal::fp::fp256_unsafe_from;
    use crate::internal::homogeneouspoint::Double;
    use lazy_static::lazy_static;
    use num_traits::Pow;
    use proptest::prelude::*;

    lazy_static! {
        static ref GOOD_TWISTED_HPOINT: TwistedHPoint<fp_256::Fp256> = TwistedHPoint {
            x: Fp2Elem {
                //39898887170429929807040143276261848585078991568615066857293752634765338134660
                elem1:
                fp256_unsafe_from("5835f848fb3e6f2a741a589fe85710c64272355f3186de77f84770c28eaac884"),
                //4145079839513126747718408015399244712098849008922890496895080944648891367549
                elem2:
                fp256_unsafe_from("92a08345bae17b654f089e235b54b4f41de5e358d5183e4c2c6d1498a3f807d")
            },
            y: Fp2Elem {
                //54517427188233403272140512636254575372766895942651963572804557077716421872651
                elem1:
                fp256_unsafe_from("7887c5327665bd5a2b27552a06cd04a027021fbf7379c760eb426e26862c8c0b"),
                //29928198841033477396304275898313889635561368630804063259494165651195801046334
                elem2:
                fp256_unsafe_from("422ac2a0339a70746983c121f37b9931adc7423b39864fe675b0f0ec882f0d3e")
            },
            z: Fp2Elem {
                //25757029117904574834370194644693146689936696995375576562303493881177613755324
                elem1:
                fp256_unsafe_from("38f1f63c4692158b7830dfa45533f08119bb5f01bfcccc004b820adf2b8763bc"),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2:
                fp256_unsafe_from("2ceb55529c6b0ca59139f2ec721870634e164523d1ed9b0d60049e29c4f3355c")
            }
        };

        static ref GOOD_TWISTED_HPOINT_MONTY: TwistedHPoint<fp_256::Monty> = GOOD_TWISTED_HPOINT.map(&|fp| fp.to_monty());
        static ref BASE_POINT: HomogeneousPoint<fp_256::Monty> = FP_256_CURVE_POINTS.generator;
        static ref BASE_POINT_X: fp_256::Monty = BASE_POINT.x;
        static ref BASE_POINT_Y: fp_256::Monty = BASE_POINT.y;
    }

    #[test]
    fn pair_match_known_good_value() {
        // matches values verified by recrypt-scala
        let expected_good_result = Fp12Elem::create_from_t(
            //20621517740542501009268492188240231175004875885443969425948886451683622135253
            fp256_unsafe_from("2d975d8c65b577810297bc5b7193691a6892cefacbee2544fb16f67ba7c825d5"),
            //34374877744619883729582518521480375735530540362125629015072222432427068254516
            fp256_unsafe_from("4bff7dc7983fb830ec19f39e78268d8191d96ec9974ac41ef8100acca66e6934"),
            //3061516916225902041514148805993070634368655849312514173666756917317148753791
            fp256_unsafe_from("6c4c1d5c2d00bbfc5eac19626b1967ce3ca5a60bce0122626d0662f53463f7f"),
            //36462333850830053304472867079357777410712443208968594405185610332940263631144
            fp256_unsafe_from("509cf319e11149b9f03c5c442efecb02c3fd98c4034490c505c6983f4f862928"),
            //61512103449194136219283269928242996434577060883392017268158197606945715641345
            fp256_unsafe_from("87fe9de48e020614a01af0a1ae62a44b47342ead7d99af4c6a0f1eec6cbfdc01"),
            //6400685679296646713554926627062187315936943674688629293503755450503276487519
            fp256_unsafe_from("e26a8e2e7136d4027e2ff75226d1c456767129d1232fa257503f6cf34cb635f"),
            //53751186939356616119935218564341196608994152768328518524478036628068165341835
            fp256_unsafe_from("76d617fc05a8f85acff827a14f3ffdc99be13ac7bb0b823d30d8752bf205d28b"),
            //24086990466602794093787211540995552936111869178774386613517233502609109093865
            fp256_unsafe_from("3540c0e3e718e5cd7d1153d3d392e246a251d8f4a5d7490b4fa18d369a270de9"),
            //61396452992397102589850224464045014903468298857108669606429537125544948220026
            fp256_unsafe_from("87bd2932b2a9e20f9b51b8b1adfeda2b434985710e73bb335d5b568eb8c1407a"),
            //15909384434160564083979503677021998800821775569159782381560100961841901513229
            fp256_unsafe_from("232c6479f7e8768b2e85a025cb9e7162315ff7ebeef6bd73ef896bb14748aa0d"),
            //60608834117224548548490931258722195552088501100182383267798941700183023164589
            fp256_unsafe_from("85ff626aef9f9cef0310f93a9541ef9ce2207eb9b57077db4572531a879c1cad"),
            //17433339776741835027827317970122814431745024562995872600925458287403992082321
            fp256_unsafe_from("268aebaf44e6ae76c70f48aed806180ced89dfc17f962de209f2a3437b4fe791"),
        )
        .map(&|fp| fp.to_monty());

        let pairing: Pairing<fp_256::Monty> = Pairing::new();

        let result = pairing
            .pair(
                FP_256_CURVE_POINTS.generator,
                GOOD_TWISTED_HPOINT_MONTY.clone(),
            )
            .unwrap();
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn monty_pair_match_known_good_value() {
        // matches values verified by recrypt-scala
        let expected_good_result = Fp12Elem::create_from_t(
            //20621517740542501009268492188240231175004875885443969425948886451683622135253
            fp256_unsafe_from("2d975d8c65b577810297bc5b7193691a6892cefacbee2544fb16f67ba7c825d5")
                .to_monty(),
            //34374877744619883729582518521480375735530540362125629015072222432427068254516
            fp256_unsafe_from("4bff7dc7983fb830ec19f39e78268d8191d96ec9974ac41ef8100acca66e6934")
                .to_monty(),
            //3061516916225902041514148805993070634368655849312514173666756917317148753791
            fp256_unsafe_from("6c4c1d5c2d00bbfc5eac19626b1967ce3ca5a60bce0122626d0662f53463f7f")
                .to_monty(),
            //36462333850830053304472867079357777410712443208968594405185610332940263631144
            fp256_unsafe_from("509cf319e11149b9f03c5c442efecb02c3fd98c4034490c505c6983f4f862928")
                .to_monty(),
            //61512103449194136219283269928242996434577060883392017268158197606945715641345
            fp256_unsafe_from("87fe9de48e020614a01af0a1ae62a44b47342ead7d99af4c6a0f1eec6cbfdc01")
                .to_monty(),
            //6400685679296646713554926627062187315936943674688629293503755450503276487519
            fp256_unsafe_from("e26a8e2e7136d4027e2ff75226d1c456767129d1232fa257503f6cf34cb635f")
                .to_monty(),
            //53751186939356616119935218564341196608994152768328518524478036628068165341835
            fp256_unsafe_from("76d617fc05a8f85acff827a14f3ffdc99be13ac7bb0b823d30d8752bf205d28b")
                .to_monty(),
            //24086990466602794093787211540995552936111869178774386613517233502609109093865
            fp256_unsafe_from("3540c0e3e718e5cd7d1153d3d392e246a251d8f4a5d7490b4fa18d369a270de9")
                .to_monty(),
            //61396452992397102589850224464045014903468298857108669606429537125544948220026
            fp256_unsafe_from("87bd2932b2a9e20f9b51b8b1adfeda2b434985710e73bb335d5b568eb8c1407a")
                .to_monty(),
            //15909384434160564083979503677021998800821775569159782381560100961841901513229
            fp256_unsafe_from("232c6479f7e8768b2e85a025cb9e7162315ff7ebeef6bd73ef896bb14748aa0d")
                .to_monty(),
            //60608834117224548548490931258722195552088501100182383267798941700183023164589
            fp256_unsafe_from("85ff626aef9f9cef0310f93a9541ef9ce2207eb9b57077db4572531a879c1cad")
                .to_monty(),
            //17433339776741835027827317970122814431745024562995872600925458287403992082321
            fp256_unsafe_from("268aebaf44e6ae76c70f48aed806180ced89dfc17f962de209f2a3437b4fe791")
                .to_monty(),
        );

        let pairing: Pairing<fp_256::Monty> = Pairing::new();

        let result = pairing
            .pair(
                FP_256_CURVE_POINTS.generator,
                GOOD_TWISTED_HPOINT_MONTY.clone(),
            )
            .unwrap();

        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn add_line_match_known_good_value_1() {
        // matches values verified by recrypt-scala
        let (expected_good_result_num, expected_good_result_denom) = (
            Fp12Elem::create_from_t(
                fp_256::Monty::zero(),
                fp_256::Monty::zero(),
                //10225613897589023975141864306784331698114333350322193013849355029116866989558
                fp256_unsafe_from(
                    "169b7e0ba28a1b3a3198f1b8e8c40a12383437d8040e85e12da4061bed8b0df6",
                )
                .to_monty(),
                //23874417408544625227955020078213054360178217578435813388951341839988775845640
                fp256_unsafe_from(
                    "34c870fef561f0f82b0ae70d91bfb3ae26f15709c0a571af8aac0c95e0fdff08",
                )
                .to_monty(),
                //19583696538442210257421816149687930861898894457540838395018829873613832108851
                fp256_unsafe_from(
                    "2b4bfabc892dff021f3620b8fde6007c2f41febce7687baed860c7a694d6bb33",
                )
                .to_monty(),
                //22526875801371184821181570246816236576448644880717020355432045498197577562711
                fp256_unsafe_from(
                    "31cdc286c83cb54c22871911cd15467f5fc78af17532baf07dd720772d27fa57",
                )
                .to_monty(),
                fp_256::Monty::zero(),
                fp_256::Monty::zero(),
                fp_256::Monty::zero(),
                fp_256::Monty::zero(),
                //51350284864274176077585216690595295345910970011195603140224124332586682398734
                fp256_unsafe_from(
                    "71873b3494c78a1f2caf34cb82c4a87f15fd7d0f9394cab1675ec5b01935b80e",
                )
                .to_monty(),
                //9195404449948098526566482694993850148148550213325878247570491211174099400997
                fp256_unsafe_from(
                    "14546a1b7024ae87029745ae7a9cdf77311a6c727920e7d36c0166d64cedb925",
                )
                .to_monty(),
            ),
            Fp2Elem {
                //25675142432137088038792608345297647672955485005597801570112062166293341199367
                elem1: fp256_unsafe_from(
                    "38c39d9a4a63c50f96579a65c162543f8afebe87c9ca6558b3af62d80c9adc07",
                )
                .to_monty(),
                //37097977072797351129681460718676877945486954160474440909723818119019141736390
                elem2: fp256_unsafe_from(
                    "5204b5ff5d641b40568399336e10ddcc8fbafaa1cceb4eb8c22f09a1557b27c6",
                )
                .to_monty(),
            },
        );
        let (result_num, result_denom) = Pairing::new().add_line_eval(
            BASE_POINT_X.clone(),
            BASE_POINT_Y.clone(),
            GOOD_TWISTED_HPOINT_MONTY.clone(),
            GOOD_TWISTED_HPOINT_MONTY.double(),
        );
        //Normalize the values so that we don't have to care about _how_ we got to the result. Different * and double algorithms will
        //give different values here, but when you normalize it should come out to the same.
        let result = result_num * result_denom.inv();
        let expected_good_result = expected_good_result_num * expected_good_result_denom.inv();
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn add_line_match_known_good_value_2() {
        let (expected_good_result_num, expected_good_result_denom) = (
            // matches values verified by recrypt-scala
            Fp12Elem::create_from_t(
                Zero::zero(),
                Zero::zero(),
                //55744800738974830414511837562097001444513814113731905690103202632714685000112
                fp256_unsafe_from(
                    "7b3e7069b2d0ff2fa2a9ae89f8a907e9c657a203cd42bfdad8eb3036a82829b0",
                ),
                //5931115851264405664176255926844469633299602620131317110698302035851504058485
                fp256_unsafe_from(
                    "d1ce481f5a186be907b6bed1c7bed361451afcf5b49049462a3654fdabd0075",
                ),
                //5922043367691349962919743457016954000050519680657775073386104333409065506275
                fp256_unsafe_from(
                    "d17c1fcd73d9fc1ee63b977404e638fb183a43f0d59cd394893734f78f615e3",
                ),
                //20288974314653081232608663556936861878151531295868263204413435854177100288352
                fp256_unsafe_from(
                    "2cdb270b30c4d124f1f2560ec4546b5c7d177f42c0adabe26f195753d2c2d160",
                ),
                Zero::zero(),
                Zero::zero(),
                Zero::zero(),
                Zero::zero(),
                //26356633409924402912277270815241187276017192428798815740104200671052283049228
                fp256_unsafe_from(
                    "3a45536b8e17dfe719f37a74042d8e33cb3e3660aee26f4b57c5a5c78a28f50c",
                ),
                //15795322029202928214286645072236506167028617449376846994561520041437363044626
                fp256_unsafe_from(
                    "22ebd5e03a63774c7c926c5c5598472797f4a974b2c261e579c4e9dddfe60112",
                ),
            )
            .map(&|fp| fp.to_monty()),
            Fp2Elem {
                //45317051037626942699433282368426742998780524510558790284447501032407331744487
                elem1: fp256_unsafe_from(
                    "64308abc65d74ce4d45c5aa853af7a87b0ba32a76d1843509b4d007a2b13aae7",
                ),
                //57314508651404382971317523526158597484748409902108919167661676452517534974217
                elem2: fp256_unsafe_from(
                    "7eb6dcc02258ada7ec15bd8b00671c004a1f3f79bb4e0b04383d95c4d5ab4109",
                ),
            }
            .map(&|fp| fp.to_monty()),
        );
        let (point_x, point_y) = BASE_POINT
            .double()
            .double()
            .normalize()
            .expect("normalize failed");
        let (result_num, result_denom) = Pairing::new().add_line_eval(
            point_x,
            point_y,
            GOOD_TWISTED_HPOINT_MONTY.double(),
            GOOD_TWISTED_HPOINT_MONTY.double().double(),
        );
        //Normalize the values so that we don't have to care about _how_ we got to the result. Different * and double algorithms will
        //give different values here, but when you normalize it should come out to the same.
        let result = result_num * result_denom.inv();
        let expected_good_result = expected_good_result_num * expected_good_result_denom.inv();
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn double_line_match_known_good_value() {
        // matches values verified by recrypt-scala
        let expected_good_result = (
            Fp12Elem::create_from_t(
                Zero::zero(),
                Zero::zero(),
                //17712485624843220480183304963635457557059227558921981718335334461785067564761
                fp256_unsafe_from(
                    "2728e95e3c7ed1304d58c05a61844df0822589147e391572b5c86aa53f812ed9",
                ),
                //60062497247414669535857527984449046910652829387114413501954200738470746113195
                fp256_unsafe_from(
                    "84ca2b32285661de7a34d4d806e1c15f2e28c25df03357a452a8770aa05bc4ab",
                ),
                //22388663537106305339863882629391283032654826869605943340705330045870326159547
                fp256_unsafe_from(
                    "317f88d4f99d78a4ea67be2a26725d60a7a6efb783b48ffb68f75f17aa4418bb",
                ),
                //53713945989969989737781120925512388913929867004299271526634203788037019854146
                fp256_unsafe_from(
                    "76c1041c6fd7c967dbe706a506de1e767ae1f66af8379b9d62078e673572e542",
                ),
                Zero::zero(),
                Zero::zero(),
                Zero::zero(),
                Zero::zero(),
                //20917605796411899317217008737010033956820097935526175686366958730322466630407
                fp256_unsafe_from(
                    "2e3ef200c6ed526669c82652d5cef8c88f640e84260263bbacd7236972bceb07",
                ),
                //56032303778290759243918533214786117372540626820242016384835510414304520082514
                fp256_unsafe_from(
                    "7be128fa1dc0acf203ad5d08fe0a2bf85bd82ff39063ba87427654da585e9452",
                ),
            )
            .map(&|fp| fp.to_monty()),
            Fp2Elem {
                //42959077746029251525006723739684969849822728021574589629122051878593325351095
                elem1: fp256_unsafe_from(
                    "5ef9f9f208c86d300a1c09859ba9ea753edfcbaaa35c0cace299e7eae862c0b7",
                ),
                //28016151889145379621959266607393058686270313410121008192417755207152260041257
                elem2: fp256_unsafe_from(
                    "3df0947d0ee0567901d6ae847f0515fc2dec17f9c831dd43a13b2a6d2c2f4a29",
                ),
            }
            .map(&|fp| fp.to_monty()),
        );

        let result = Pairing::new().double_line_eval(
            BASE_POINT_X.clone(),
            BASE_POINT_Y.clone(),
            GOOD_TWISTED_HPOINT_MONTY.clone(),
        );
        assert_eq!(expected_good_result, result);
    }

    #[test]
    fn frobenius_match_good_value() {
        let generator = TwistedHPoint {
            x: Fp2Elem {
                //39898887170429929807040143276261848585078991568615066857293752634765338134660
                elem1: fp256_unsafe_from(
                    "5835f848fb3e6f2a741a589fe85710c64272355f3186de77f84770c28eaac884",
                )
                .to_monty(),
                //4145079839513126747718408015399244712098849008922890496895080944648891367549
                elem2: fp256_unsafe_from(
                    "92a08345bae17b654f089e235b54b4f41de5e358d5183e4c2c6d1498a3f807d",
                )
                .to_monty(),
            },
            y: Fp2Elem {
                //54517427188233403272140512636254575372766895942651963572804557077716421872651
                elem1: fp256_unsafe_from(
                    "7887c5327665bd5a2b27552a06cd04a027021fbf7379c760eb426e26862c8c0b",
                )
                .to_monty(),
                //29928198841033477396304275898313889635561368630804063259494165651195801046334
                elem2: fp256_unsafe_from(
                    "422ac2a0339a70746983c121f37b9931adc7423b39864fe675b0f0ec882f0d3e",
                )
                .to_monty(),
            },
            z: Fp2Elem {
                //25757029117904574834370194644693146689936696995375576562303493881177613755324
                elem1: fp256_unsafe_from(
                    "38f1f63c4692158b7830dfa45533f08119bb5f01bfcccc004b820adf2b8763bc",
                )
                .to_monty(),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2: fp256_unsafe_from(
                    "2ceb55529c6b0ca59139f2ec721870634e164523d1ed9b0d60049e29c4f3355c",
                )
                .to_monty(),
            },
        };

        let expected_result = TwistedHPoint {
            x: Fp2Elem {
                //3493288303413595898714519891264492301560207456168827437424957567620529428904
                elem1: fp256_unsafe_from(
                    "7b921909c88bb7a6085720184d40a3098b24626883ae800325f9c770dd299a8",
                )
                .to_monty(),
                //57579932449471156509924950033302853001562583061231887808723506993246370069786
                elem2: fp256_unsafe_from(
                    "7f4d163bfa39efe2c9ad471d97997a467e07d001784a047d9caf6c19b8d4fd1a",
                )
                .to_monty(),
            },
            y: Fp2Elem {
                //51856762088277527784977807176637663292245671912163591131470367010215157555522
                elem1: fp256_unsafe_from(
                    "72a5e320ecfcd5dd86bcb4ff84f13227ee62dd159ac229b6f418ad5743dfe142",
                )
                .to_monty(),
                //49397214075582907890167267499315856190388550710652209341826106816887973948785
                elem2: fp256_unsafe_from(
                    "6d35d516c27f3af949aa6d8ac72d8a81cd7f7cdb8a856620e12a55293c7b2d71",
                )
                .to_monty(),
            },
            z: Fp2Elem {
                //39243520577742028898426244097666759052888661112247427009573651145686570316459
                elem1: fp256_unsafe_from(
                    "56c30ba70411726e323f0d140c50eba0d4a029cf60e8e99dccdaa18d328132ab",
                )
                .to_monty(),
                //20317563273514500379895253969863230147776170908243485486513578790623697384796
                elem2: fp256_unsafe_from(
                    "2ceb55529c6b0ca59139f2ec721870634e164523d1ed9b0d60049e29c4f3355c",
                )
                .to_monty(),
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
        let pairing: Pairing<fp_256::Monty> = Pairing::new();
        let p = FP_256_CURVE_POINTS.generator;
        let a_sqr = fp_256::Monty::from(a).pow(2);
        let a_fp256 = fp_256::Monty::from(a);
        let a_times_p = p * a_fp256;
        let a_sqr_times_p = p * a_sqr;
        let q = FP_256_CURVE_POINTS.g1;
        let a_times_q = q * a_fp256;
        let pair_a_times_p_and_a_times_q  = pairing.pair(a_times_p, a_times_q).unwrap();

        // pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)"
        prop_assert_eq!(pairing.pair(p, a_times_q).unwrap(), pairing.pair(a_times_p, q).unwrap());
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(a_sqr_times_p, q).unwrap());

        // pair(a * P, a * Q) == pair(P, Q) ^ (a^2)
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(p, q).unwrap().pow(a).pow(a));
      }

      //"follow the law pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)"
      //"follow the law pair(a * P, a * Q) == pair(P, Q) ^ (a^2)"
      #[test]
      fn fp480_law_bilinearity(a in any::<u32>().prop_filter("", |a| !(*a == 0))) {
        let a_u64 = a as u64;
        let pairing: Pairing<fp_480::Monty> = Pairing::new();
        let p = FP_480_CURVE_POINTS.generator;
        let a_sqr = fp_480::Monty::from(a_u64).pow(2);
        let a_fp480 = fp_480::Monty::from(a);
        let a_times_p = p * a_fp480;
        let a_sqr_times_p = p * a_sqr;
        let q = FP_480_CURVE_POINTS.g1;
        let a_times_q = q * a_fp480;
        let pair_a_times_p_and_a_times_q  = pairing.pair(a_times_p, a_times_q).unwrap();

        // pair(a * P, a * Q) == pair(a^2 * P, Q) == pair(P,a^2 * Q)"
        prop_assert_eq!(pairing.pair(p, a_times_q).unwrap(), pairing.pair(a_times_p, q).unwrap());
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(a_sqr_times_p, q).unwrap());

        // pair(a * P, a * Q) == pair(P, Q) ^ (a^2)
        prop_assert_eq!(pair_a_times_p_and_a_times_q, pairing.pair(p, q).unwrap().pow(a).pow(a));
      }
    }
}
