use rand::FromEntropy;
use rand_chacha;
use recrypt::prelude::*;
use std::sync::Arc;
use std::thread;
#[test]
fn generate_plaintexts() {
    let recrypt = Arc::new(Recrypt::new_with_rand(
        rand_chacha::ChaChaRng::from_entropy(),
    ));

    let mut threads = vec![];
    for _i in 0..5000 {
        let recrypt_ref_clone = recrypt.clone();
        threads.push(thread::spawn(move || {
            let pt = recrypt_ref_clone.gen_plaintext();
            //            dbg!(&_i);
        }));
    }

    let pt = recrypt.clone().gen_plaintext();
    dbg!(pt);

    let mut joined_count = 0;
    for t in threads {
        t.join();
        joined_count += 1;
    }

    dbg!(joined_count);
}
