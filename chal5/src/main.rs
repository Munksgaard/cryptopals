extern crate hexstr;

use std::io::{stdin, Read};

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Pass potentially xor'ed lines on stdin");

    let cipher: Vec<u8> = b"ICE"
        .iter()
        .cycle()
        .zip(buf.iter())
        .map(|(c, b)| c ^ b)
        .collect();

    hexstr::print_bytes(&cipher);
}
