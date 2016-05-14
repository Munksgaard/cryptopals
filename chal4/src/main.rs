#![feature(inclusive_range_syntax)]

extern crate hexstr;
extern crate freqalyze;

use std::io::{stdin, Read};

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Pass potentially xor'ed lines on stdin");

    let mut best = (0, 0, 0);

    let lines: Vec<&[u8]> = buf.split(|&b| b == b'\n').collect();

    for (n, ref line) in lines.iter().enumerate() {
        let bytes = hexstr::parse(line);
        for key in 0...255 {
            let tmp: Vec<u8> = bytes.iter().map(|x| x ^ key).collect();
            let score = freqalyze::score(&tmp);

            if score > best.0 {
                best = (score, n, key);
            }
        }
    }

    println!("{}",
             String::from_utf8(hexstr::parse(lines[best.1])
                               .iter()
                               .map(|x| x ^ best.2)
                               .collect())
             .unwrap());
}
