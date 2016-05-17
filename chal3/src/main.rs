#![feature(inclusive_range_syntax)]

extern crate hexstr;
extern crate freqalyze;

fn main() {
    let s = hexstr::parse(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let key = freqalyze::find_key(&s);

    let decoded: Vec<u8> = s.iter().map(|x| x ^ key).collect();

    println!("{}", String::from_utf8(decoded).unwrap());
}
