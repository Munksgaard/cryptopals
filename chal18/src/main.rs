extern crate raes;
extern crate base64;

use raes::{ctr, aes};

fn main() {
    let encoded = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let cipher = base64::decode(encoded);
    let key = b"YELLOW SUBMARINE";

    let plain = ctr::ctr(aes::encrypt, &cipher, key, 0);

    println!("{}", String::from_utf8(plain).unwrap());
}
