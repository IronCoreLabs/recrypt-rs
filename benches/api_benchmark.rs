#[macro_use]
extern crate criterion;
extern crate recrypt;

use criterion::Criterion;
use recrypt::api::Api as Api256;
use recrypt::api::CryptoOps;
use recrypt::api::Ed25519Ops;
use recrypt::api::KeyGenOps;
use recrypt::api_480::Api480;
use recrypt::api_480::CryptoOps as CryptoOps480;
use recrypt::api_480::Ed25519Ops as Ed25519Ops480;
use recrypt::api_480::KeyGenOps as KeyGenOps480;
use std::cell::RefCell;

macro_rules! recrypt_bench {
    (api = $api:ident; suite_desc = $suite_desc:ident; bits = $bits:tt) => {
        fn $suite_desc(c: &mut Criterion) {
            c.bench_function(concat!($bits, "-bit generate key pair"), |b| {
                let mut api = $api::new();
                b.iter(|| api.generate_key_pair());
            });

            c.bench_function(concat!($bits, "-bit generate plaintext"), |b| {
                let mut api = $api::new();
                b.iter(|| api.gen_plaintext());
            });

            c.bench_function(concat!($bits, "-bit generate ed25519 keypair"), |b| {
                let mut api = $api::new();
                b.iter(|| {
                    api.generate_ed25519_key_pair();
                });
            });

            c.bench_function(concat!($bits, "-bit generate transform key"), |b| {
                let api = RefCell::new($api::new());
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                b.iter_with_setup(
                    || {
                        let (from_pvk, _) = api.borrow_mut().generate_key_pair().unwrap();
                        let (_, to_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                        (from_pvk, to_pbk)
                    },
                    |(from, to)| {
                        api.borrow_mut()
                            .generate_transform_key(&from, to, &signing_keypair)
                            .unwrap();
                    },
                );
            });

            c.bench_function(concat!($bits, "-bit compute public key"), |b| {
                let api = RefCell::new($api::new());
                b.iter_with_setup(
                    || {
                        let (pvk, _) = api.borrow_mut().generate_key_pair().unwrap();
                        pvk
                    },
                    |pvk| api.borrow_mut().compute_public_key(&pvk),
                );
            });

            c.bench_function(concat!($bits, "-bit derive symmetric key"), |b| {
                let api = RefCell::new($api::new());
                b.iter_with_setup(
                    || api.borrow_mut().gen_plaintext(),
                    |pt| api.borrow_mut().derive_symmetric_key(&pt),
                );
            });

            c.bench_function(concat!($bits, "-bit encrypt (level 0)"), |b| {
                let api = RefCell::new($api::new());
                let (_, pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                b.iter_with_setup(
                    || api.borrow_mut().gen_plaintext(),
                    |pt| {
                        api.borrow_mut()
                            .encrypt(&pt, pbk, &signing_keypair)
                            .unwrap();
                    },
                );
            });

            c.bench_function(concat!($bits, "-bit decrypt (level 0)"), |b| {
                let mut api = $api::new();
                let (pvk, pbk) = api.generate_key_pair().unwrap();
                let signing_keypair = api.generate_ed25519_key_pair();
                let pt = api.gen_plaintext();
                let encrypted_value = api.encrypt(&pt, pbk, &signing_keypair).unwrap();
                b.iter(|| api.decrypt(encrypted_value.clone(), &pvk).unwrap());
            });

            c.bench_function(concat!($bits, "-bit transform (level 1)"), |b| {
                let api = RefCell::new($api::new());
                let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (_, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                let tk = api
                    .borrow_mut()
                    .generate_transform_key(&level_0_pvk, level_1_pbk, &signing_keypair)
                    .unwrap();
                b.iter_with_setup(
                    || {
                        let pt = api.borrow_mut().gen_plaintext();
                        api.borrow_mut()
                            .encrypt(&pt, level_0_pbk, &signing_keypair)
                            .unwrap()
                    },
                    |ev| {
                        api.borrow_mut()
                            .transform(ev, tk.clone(), &signing_keypair)
                            .unwrap()
                    },
                );
            });

            c.bench_function(concat!($bits, "-bit decrypt (level 1)"), |b| {
                let api = RefCell::new($api::new());
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let tk = api
                    .borrow_mut()
                    .generate_transform_key(&level_0_pvk, level_1_pbk, &signing_keypair)
                    .unwrap();
                b.iter_with_setup(
                    || {
                        let pt = api.borrow_mut().gen_plaintext();
                        let ev = api
                            .borrow_mut()
                            .encrypt(&pt, level_0_pbk, &signing_keypair)
                            .unwrap();
                        api.borrow_mut()
                            .transform(ev, tk.clone(), &signing_keypair)
                            .unwrap()
                    },
                    |ev| {
                        api.borrow_mut().decrypt(ev, &level_1_pvk).unwrap();
                    },
                );
            });

            c.bench_function(concat!($bits, "-bit transform (level 2)"), |b| {
                let api = RefCell::new($api::new());
                let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (_, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                let tk_0_to_1 = api
                    .borrow_mut()
                    .generate_transform_key(&level_0_pvk, level_1_pbk, &signing_keypair)
                    .unwrap();
                let tk_1_to_2 = api
                    .borrow_mut()
                    .generate_transform_key(&level_1_pvk, level_2_pbk, &signing_keypair)
                    .unwrap();
                b.iter_with_setup(
                    || {
                        let pt = api.borrow_mut().gen_plaintext();
                        api.borrow_mut()
                            .encrypt(&pt, level_0_pbk, &signing_keypair)
                            .unwrap()
                    },
                    |ev| {
                        let ev_to_1 = api
                            .borrow_mut()
                            .transform(ev, tk_0_to_1.clone(), &signing_keypair)
                            .unwrap();
                        api.borrow_mut()
                            .transform(ev_to_1, tk_1_to_2.clone(), &signing_keypair)
                            .unwrap();
                    },
                );
            });

            c.bench_function(concat!($bits, "-bit decrypt (level 2)"), |b| {
                let api = RefCell::new($api::new());
                let signing_keypair = api.borrow_mut().generate_ed25519_key_pair();
                let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let (level_2_pvk, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                let tk_0_to_1 = api
                    .borrow_mut()
                    .generate_transform_key(&level_0_pvk, level_1_pbk, &signing_keypair)
                    .unwrap();
                let tk_1_to_2 = api
                    .borrow_mut()
                    .generate_transform_key(&level_1_pvk, level_2_pbk, &signing_keypair)
                    .unwrap();
                b.iter_with_setup(
                    || {
                        let pt = api.borrow_mut().gen_plaintext();
                        let ev_to_0 = api
                            .borrow_mut()
                            .encrypt(&pt, level_0_pbk, &signing_keypair)
                            .unwrap();
                        let ev_to_1 = api
                            .borrow_mut()
                            .transform(ev_to_0, tk_0_to_1.clone(), &signing_keypair)
                            .unwrap();
                        api.borrow_mut()
                            .transform(ev_to_1, tk_1_to_2.clone(), &signing_keypair)
                            .unwrap()
                    },
                    |ev_to_2| {
                        api.borrow_mut().decrypt(ev_to_2, &level_2_pvk).unwrap();
                    },
                );
            });
        }
    };
}

recrypt_bench! {api = Api480; suite_desc = criterion_benchmark_fp480; bits = "480"}
recrypt_bench! {api = Api256; suite_desc = criterion_benchmark_fp256; bits = "256"}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = criterion_benchmark_fp256//, criterion_benchmark_fp480
}
criterion_main!(benches);
