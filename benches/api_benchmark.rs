#[macro_use]
extern crate criterion;
extern crate recrypt;

use criterion::Criterion;
use recrypt::api::Api;
use recrypt::api::CryptoOps;
use recrypt::api::Ed25519Ops;
use recrypt::api::KeyGenOps;

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
    c.bench_function("encrypt (level 0)", |b| {
        use std::rc::Rc;
        use std::cell::RefCell;

        let mut api = Rc::new(RefCell::new(Api::new()));
        let (_, pbk) = api.borrow_mut().generate_key_pair().unwrap();
        let (pvsk, pbsk) = api.borrow_mut().generate_ed25519_key_pair();
        b.iter_with_setup(
            || {
                api.borrow_mut().gen_plaintext()
            },
            |pt| {
                api.borrow_mut().encrypt(pt, pbk, pbsk, pvsk);
            },
        );
    });
//    c.bench_function("decrypt (level 0)", |b| {
//        let mut api = Api::new();
//        let (pvk, pbk) = api.generate_key_pair().unwrap();
//        let (pvsk, pbsk) = api.generate_ed25519_key_pair();
//        let pt = api.gen_plaintext();
//        let encrypted_value = api.encrypt(pt, pbk, pbsk, pvsk).unwrap();
//        b.iter(|| {
//            api.decrypt(encrypted_value, pvk);
//        });
//    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// rename Api to Recrypt
// gen_plaintext -> generate_plaintext
// use prelude
