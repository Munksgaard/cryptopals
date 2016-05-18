extern crate raes;
extern crate base64;

use std::io::{stdin, Read};

use raes::{cbc, aes};

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Pass potentially xor'ed lines on stdin");

    let cipher = base64::decode(&buf);

    let key = b"YELLOW SUBMARINE";
    let iv = &[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    let decrypted = cbc::decrypt(aes::decrypt, &cipher, key, iv);

    println!("{}", String::from_utf8(decrypted).unwrap());
}
