#![feature(inclusive_range_syntax)]

extern crate hexstr;

use std::io::{stdin, Read};

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Input encrypted data");

    for (linenum, line) in buf.split(|&b| b == b'\n').enumerate() {
        let cipher = hexstr::parse(line);

        let mut blocks: Vec<&[u8]> = cipher.chunks(16).collect();
        let orig_len = blocks.len();
        blocks.sort();
        blocks.dedup();
        if blocks.len() < orig_len {
            println!("Line {} is ECB encrypted.\n{:?}", linenum, line);
        }
    }
}
