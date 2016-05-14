#![feature(inclusive_range_syntax)]

extern crate hexstr;
extern crate freqalyze;

fn main() {
    let s = hexstr::parse(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

    let mut v: Vec<(Vec<u8>, u64)> = Vec::new();

    for i in 0...255 {
        let tmp: Vec<u8> = s.iter().map(|x| { x ^ i }).collect();
        let score = freqalyze::score(&tmp);
        v.push((tmp, score));
    }

    v.sort_by(|&(_, a), &(_, b)| {b.cmp(&a)});
    let &(ref string, score) = v.first().unwrap();
    println!("Score: {}", score);
    hexstr::print_bytes(string);
    println!("{}", String::from_utf8(string.to_vec()).unwrap());
}
