#[macro_use]
extern crate criterion;
extern crate recrypt;

use criterion::Criterion;
use recrypt::api::Api;
use recrypt::api::CryptoOps;
use recrypt::api::Ed25519Ops;
use recrypt::api::KeyGenOps;
use std::cell::RefCell;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate key pair", |b| {
        let mut api = Api::new();
        b.iter(|| api.generate_key_pair());
    });

    c.bench_function("generate plaintext", |b| {
        let mut api = Api::new();
        b.iter(|| api.gen_plaintext());
    });

    c.bench_function("generate ed25519 keypair", |b| {
        let mut api = Api::new();
        b.iter(|| {
            api.generate_ed25519_key_pair();
        });
    });

    c.bench_function("generate transform key", |b| {
        let api = RefCell::new(Api::new());
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        b.iter_with_setup(
            || {
                let (from_pvk, _) = api.borrow_mut().generate_key_pair().unwrap();
                let (_, to_pbk) = api.borrow_mut().generate_key_pair().unwrap();
                (from_pvk, to_pbk)
            },
            |(from, to)| {
                api.borrow_mut()
                    .generate_transform_key(&from, to, pbsk, &pvsk)
                    .unwrap();
            },
        );
    });

    c.bench_function("compute public key", |b| {
        let api = RefCell::new(Api::new());
        b.iter_with_setup(
            || {
                let (pvk, _) = api.borrow_mut().generate_key_pair().unwrap();
                pvk
            },
            |pvk| api.borrow_mut().compute_public_key(&pvk),
        );
    });

    c.bench_function("derive symmetric key", |b| {
        let api = RefCell::new(Api::new());
        b.iter_with_setup(
            || api.borrow_mut().gen_plaintext(),
            |pt| api.borrow_mut().derive_symmetric_key(&pt),
        );
    });

    c.bench_function("encrypt (level 0)", |b| {
        let api = RefCell::new(Api::new());
        let (_, pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        b.iter_with_setup(
            || api.borrow_mut().gen_plaintext(),
            |pt| {
                api.borrow_mut().encrypt(&pt, pbk, pbsk, &pvsk).unwrap();
            },
        );
    });

    c.bench_function("decrypt (level 0)", |b| {
        let mut api = Api::new();
        let (pvk, pbk) = api.generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.generate_ed25519_key_pair();
        let pt = api.gen_plaintext();
        let encrypted_value = api.encrypt(&pt, pbk, pbsk, &pvsk).unwrap();
        b.iter(|| api.decrypt(encrypted_value.clone(), &pvk).unwrap());
    });

    c.bench_function("transform (level 1)", |b| {
        let api = RefCell::new(Api::new());
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (_, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let tk = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                api.borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap()
            },
            |ev| {
                api.borrow_mut()
                    .transform(ev, tk.clone(), pbsk, &pvsk)
                    .unwrap()
            },
        );
    });

    c.bench_function("decrypt (level 1)", |b| {
        let api = RefCell::new(Api::new());
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let tk = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                let ev = api
                    .borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap();
                api.borrow_mut()
                    .transform(ev, tk.clone(), pbsk, &pvsk)
                    .unwrap()
            },
            |ev| {
                api.borrow_mut().decrypt(ev, &level_1_pvk).unwrap();
            },
        );
    });

    c.bench_function("transform (level 2)", |b| {
        let api = RefCell::new(Api::new());
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (_, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let tk_0_to_1 = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_1_to_2 = api
            .borrow_mut()
            .generate_transform_key(&level_1_pvk, level_2_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                api.borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap()
            },
            |ev| {
                let ev_to_1 = api
                    .borrow_mut()
                    .transform(ev, tk_0_to_1.clone(), pbsk, &pvsk)
                    .unwrap();
                api.borrow_mut()
                    .transform(ev_to_1, tk_1_to_2.clone(), pbsk, &pvsk)
                    .unwrap();
            },
        );
    });

    c.bench_function("decrypt (level 2)", |b| {
        let api = RefCell::new(Api::new());
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_2_pvk, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let tk_0_to_1 = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_1_to_2 = api
            .borrow_mut()
            .generate_transform_key(&level_1_pvk, level_2_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                let ev_to_0 = api
                    .borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap();
                let ev_to_1 = api
                    .borrow_mut()
                    .transform(ev_to_0, tk_0_to_1.clone(), pbsk, &pvsk)
                    .unwrap();
                api.borrow_mut()
                    .transform(ev_to_1, tk_1_to_2.clone(), pbsk, &pvsk)
                    .unwrap()
            },
            |ev_to_2| {
                api.borrow_mut().decrypt(ev_to_2, &level_2_pvk).unwrap();
            },
        );
    });

    c.bench_function("transform (level 3)", |b| {
        let api = RefCell::new(Api::new());
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_2_pvk, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (_, level_3_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let tk_0_to_1 = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_1_to_2 = api
            .borrow_mut()
            .generate_transform_key(&level_1_pvk, level_2_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_2_to_3 = api
            .borrow_mut()
            .generate_transform_key(&level_2_pvk, level_3_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                api.borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap()
            },
            |ev| {
                let ev_to_1 = api
                    .borrow_mut()
                    .transform(ev, tk_0_to_1.clone(), pbsk, &pvsk)
                    .unwrap();
                let ev_to_2 = api
                    .borrow_mut()
                    .transform(ev_to_1, tk_1_to_2.clone(), pbsk, &pvsk)
                    .unwrap();
                api.borrow_mut()
                    .transform(ev_to_2, tk_2_to_3.clone(), pbsk, &pvsk)
                    .unwrap();
            },
        );
    });

    c.bench_function("decrypt (level 3)", |b| {
        let api = RefCell::new(Api::new());
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        let (level_0_pvk, level_0_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_1_pvk, level_1_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_2_pvk, level_2_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (level_3_pvk, level_3_pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let tk_0_to_1 = api
            .borrow_mut()
            .generate_transform_key(&level_0_pvk, level_1_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_1_to_2 = api
            .borrow_mut()
            .generate_transform_key(&level_1_pvk, level_2_pbk, pbsk, &pvsk)
            .unwrap();
        let tk_2_to_3 = api
            .borrow_mut()
            .generate_transform_key(&level_2_pvk, level_3_pbk, pbsk, &pvsk)
            .unwrap();
        b.iter_with_setup(
            || {
                let pt = api.borrow_mut().gen_plaintext();
                let ev_to_0 = api
                    .borrow_mut()
                    .encrypt(&pt, level_0_pbk, pbsk, &pvsk)
                    .unwrap();
                let ev_to_1 = api
                    .borrow_mut()
                    .transform(ev_to_0, tk_0_to_1.clone(), pbsk, &pvsk)
                    .unwrap();
                let ev_to_2 = api
                    .borrow_mut()
                    .transform(ev_to_1, tk_1_to_2.clone(), pbsk, &pvsk)
                    .unwrap();
                api.borrow_mut()
                    .transform(ev_to_2, tk_2_to_3.clone(), pbsk, &pvsk)
                    .unwrap()
            },
            |ev_to_3| {
                api.borrow_mut().decrypt(ev_to_3, &level_3_pvk).unwrap();
            },
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = criterion_benchmark
}
criterion_main!(benches);
