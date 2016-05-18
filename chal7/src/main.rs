#![feature(inclusive_range_syntax)]

extern crate raes;
extern crate base64;

use std::io::{stdin, Read};
use raes::{ecb, aes};

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Input encrypted data");

    let cipher = base64::decode(&buf);

    let key = b"YELLOW SUBMARINE";

    let decrypted = ecb::ecb(aes::decrypt, &cipher, key);

    println!("{}", String::from_utf8(decrypted).unwrap());
}
