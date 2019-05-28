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

    for _i in 0..10 {
        let recrypt_ref_clone = recrypt.clone();
        thread::spawn(move || {
            let pt = recrypt_ref_clone.gen_plaintext();
            dbg!(pt)
        });
    }

    let pt = recrypt.clone().gen_plaintext();
    dbg!(pt);
}
