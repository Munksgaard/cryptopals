extern crate raes;
extern crate base64;
extern crate freqalyze;

use std::io::{stdin, Read};

use raes::{aes, ctr};

static RANDOM_KEY: &'static [u8] =
    &[158, 73, 57, 192,
      45, 231, 2, 140,
      46, 219, 247, 18,
      186, 54, 49, 118];


fn exterleave(input: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut buf = Vec::new();
    for _ in 0..n {
        buf.push(Vec::new());
    }

    for (i, x) in (0..n).cycle().zip(input) {
        buf[i].push(*x);
    }

    buf
}

#[test]
fn test_exterleave() {
    let input = &[0,1,2,3,4,5,6,7,8,9];
    let output = exterleave(input, 2);
    assert_eq!(output, vec!(vec!(0,2,4,6,8), vec!(1,3,5,7,9)));

    let input = &[0,1,2,3,4,5,6,7,8,9];
    let output = exterleave(input, 3);
    assert_eq!(output, vec!(vec!(0,3,6,9), vec!(1,4,7), vec!(2, 5, 8)));
}

/// Takes a vector of vectors and interleaves them
///
/// ```
/// interleave(vec!(vec!(0,3), vec!(1,4), vec!(2,5))) = vec!(0,1,2,3,4,5);
/// ```
fn interleave(input: Vec<Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();

    let len = input.len();

    let mut i = 0;
    loop {
        if let Some(y) = input.get(i % len) {
            if let Some(x) = y.get(i / len) {
                buf.push(*x);
                i += 1;
            } else {
                break;
            }
        }
    }
    buf
}

#[test]
fn test_interleave_1() {
    let input = &[0,1,2,3,4,5,6,7,8,9];
    let exterleaved = exterleave(input, 4);

    let interleaved = interleave(exterleaved);

    assert_eq!(interleaved, input);
}

#[test]
fn test_interleave_2() {
    assert_eq!(interleave(vec!(vec!(0,3), vec!(1,4), vec!(2,5))),
               vec!(0,1,2,3,4,5));
}

fn guess_repxor_with_keysize(input: &[u8], keysize: usize) -> Option<String> {
    let split = exterleave(input, keysize);

    let keys: Vec<u8> = split.iter().map(|bytes| freqalyze::find_key(bytes)).collect();

    let mut result = Vec::new();

    for (bytes, key) in split.iter().zip(keys.iter()) {
        let tmp: Vec<u8> = bytes.iter().map(|x| x ^ key).collect();
        result.push(tmp);
    }

    if let Some(s) = String::from_utf8(interleave(result).to_vec()).ok() {
        Some(s)
    } else {
        None
    }
}

fn main() {
    let mut buf = Vec::new();

    stdin().read_to_end(&mut buf)
        .expect("Input encrypted data");

    let encrypted: Vec<Vec<u8>> = buf
        .split(|&c| c == b'\n')
        .filter_map(|s|
                    if s.len() > 0 {
                        Some(ctr::ctr(aes::encrypt,
                                      &base64::decode(s),
                                      RANDOM_KEY,
                                      0))
                    } else {
                        None
                    })
        .collect();

    let min_size = encrypted.iter().map(|s| s.len()).min().unwrap();

    let cropped: Vec<u8> = encrypted.iter().flat_map(|s| (s[..min_size]).to_vec()).collect();

    let result = guess_repxor_with_keysize(&cropped, min_size).unwrap();

    println!("{}", result);

}
