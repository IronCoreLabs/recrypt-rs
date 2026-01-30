use rand::SeedableRng;
use rand_chacha;
use recrypt::prelude::*;
use std::sync::Arc;
use std::thread;
#[test]
fn generate_plaintexts() {
    let recrypt = Arc::new(Recrypt::new_with_rand(rand_chacha::ChaChaRng::from_os_rng()));

    let mut threads = vec![];
    for _i in 0..10 {
        let recrypt_ref_clone = recrypt.clone();
        threads.push(thread::spawn(move || {
            let _pt = recrypt_ref_clone.gen_plaintext();
        }));
    }

    let pt = recrypt.clone().gen_plaintext();
    dbg!(pt);

    let mut joined_count = 0;
    for t in threads {
        t.join().expect("join failed");
        joined_count += 1;
    }

    assert_eq!(joined_count, 10);
}
