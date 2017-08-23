#![feature(inclusive_range_syntax)]

extern crate base64;
extern crate raes;
extern crate pkcs7pad;

use std::io::{stdin, Read};
use raes::{aes, ecb, ctr};

static RANDOM_KEY: [u8; 16] = [21, 74, 153, 147,
                               244, 100, 141, 128,
                               30, 176, 207, 176,
                               202, 11, 105, 107];

// Now, write the code that allows you to "seek" into the ciphertext, decrypt,
// and re-encrypt with different plaintext. Expose this as a function, like,
// "edit(ciphertext, key, offset, newtext)".
fn edit(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let mut decrypted = ctr::ctr(aes::encrypt, ciphertext, &RANDOM_KEY, 0);

    for (x,y) in decrypted.iter_mut().skip(offset).zip(newtext) {
        *x = *y
    }

    ctr::ctr(aes::encrypt, &decrypted, &RANDOM_KEY, 0)
}

fn breakit(ciphertext: &[u8]) -> Vec<u8> {
    let len = ciphertext.len();
    let a: Vec<u8> = std::iter::repeat(b'A').take(len).collect();
    let edited = edit(ciphertext, 0, &a);
    let xor: Vec<u8> = edited.iter().zip(&a).map(|(x, y)| x ^ y).collect();
    ciphertext.iter().zip(xor).map(|(x, y)| x ^ y).collect()
}

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf).expect("Input encrypted data");

    let decoded = base64::decode(&buf);

    let decrypted = ecb::ecb(aes::decrypt, &decoded, b"YELLOW SUBMARINE");
    let unpadded = pkcs7pad::unpad(&decrypted).expect("Couldn't unpad");

    let encrypted = ctr::ctr(aes::encrypt, &unpadded, &RANDOM_KEY, 0);

    let plain = breakit(&encrypted);

    if let Ok(s) = String::from_utf8(plain) {
        println!("Recovered string:\n{}", s);
    } else {
        println!("Something went wrong");
    }
}
