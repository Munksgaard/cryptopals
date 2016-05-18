#![feature(slice_patterns)]

extern crate raes;
extern crate base64;
extern crate pkcs7pad;
extern crate rand;

use rand::Rng;
use raes::{ecb, aes};

static B64_PLAIN: &'static[u8] = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
static RANDOM_KEY: &'static[u8] = &[237, 95, 149, 233,
                                    237, 193, 119, 201,
                                    208, 161, 88, 215,
                                    226, 224, 134, 233];

/*
 * Copy your oracle function to a new function that encrypts buffers under ECB
 * mode using a consistent but unknown key (for instance, assign a single random
 * key, once, to a global variable).
 *
 * Now take that same function and have it append to the plaintext, BEFORE
 * ENCRYPTING, the string above. Base64 decode the string before appending it. Do
 * not base64 decode the string by hand; make your code do it. The point is that
 * you don't know its contents.
 *
 * What you have now is a function that produces:
 *
 *     AES-128-ECB(your-string || unknown-string, random-key)
 *
 * It turns out: you can decrypt "unknown-string" with repeated calls to the
 * oracle function!
 *
 * Here's roughly how:
 *
 *     Feed identical bytes of your-string to the function 1 at a time --- start
 *     with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block
 *     size of the cipher. You know it, but do this step anyway.
 *
 *     Detect that the function is using ECB. You already know, but do this step
 *     anyways.
 *
 *     Knowing the block size, craft an input block that is exactly 1 byte short
 *     (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
 *     what the oracle function is going to put in that last byte position.
 *
 *     Make a dictionary of every possible last byte by feeding different
 *     strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC",
 *     remembering the first block of each invocation.
 *
 *     Match the output of the one-byte-short input to one of the entries in
 *     your dictionary. You've now discovered the first byte of unknown-string.
 *
 *     Repeat for the next byte.
 */

fn main() {
    break_oracle(oracle);
}

fn oracle(input: &[u8]) -> Vec<u8> {
    let mut buf = input.to_vec();
    buf.extend_from_slice(base64::decode(B64_PLAIN).as_slice());

    let padded = pkcs7pad::pad(buf.as_slice(), 16);

    ecb::ecb(aes::encrypt, padded.as_slice(), RANDOM_KEY)
}

fn detect_blocksize<F>(f: F) -> u8
    where F : Fn(&[u8]) -> Vec<u8> {
    let mut input = vec!('A' as u8);
    let orig_size = f(&input).len();
    while f(&input).len() == orig_size {
        input.push('A' as u8);
    }
    (f(&input).len() - orig_size) as u8
}

fn is_ecb<F>(f: F) -> bool
    where F : Fn(&[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut input = Vec::new();

    for _ in 0..4 {
        input.extend_from_slice(b"BUFFALO BUFFALO BUFFALO BUFFALO ");
        let tmp: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        input.extend_from_slice(&tmp);
    }
    input.extend_from_slice(base64::decode(B64_PLAIN).as_slice());

    let tmp = f(input.as_slice());

    let mut blocks: Vec<&[u8]> = tmp.chunks(16).collect();

    let orig_len = blocks.len();
    blocks.sort();
    blocks.dedup();
    orig_len != blocks.len()
}

fn break_oracle<F>(f: F)
    where F: Fn(&[u8]) -> Vec<u8> {

    println!("Tring to break the oracle...");
    let blocksize = detect_blocksize(|x| f(x));

    println!("Discovered the blocksize: {}", blocksize);

    let cipherlen = f(b"").len();

    println!("The cipherlen is {}", cipherlen);
    assert_eq!(blocksize, 16);
    assert!(is_ecb(|x| f(x)));

    println!("The oracle uses ECB...");

    let mut result: Vec<u8> = Vec::new();

    // For each block
    let number_of_blocks = (cipherlen as u8) / blocksize;
    println!("Number of blocks: {}", number_of_blocks);
    for block in 0u8..number_of_blocks {
        let bytes_in_block = if block < number_of_blocks-1 {
            blocksize
        } else {
            blocksize - (cipherlen as u8 % blocksize)
        };

        // For each byte in the block
        for byte in 1..(bytes_in_block+1) {
            let pad: Vec<u8> = (0..(blocksize - byte) as usize)
                .map(|_| 'A' as u8)
                .collect();
            let tmp = f(&pad);

            let from = (block * 16) as usize;
            let to = (block * 16 + byte - 1) as usize;

            let mut dict = Vec::new();
            for x in 0..256 {
                if block == 0 {
                    let mut buf: Vec<u8> = (0..(blocksize - byte) as usize)
                        .map(|_| 'A' as u8)
                        .collect();
                    buf.extend_from_slice(&result[from..to]);
                    buf.push(x as u8);
                    dict.push(f(&buf)[from..from+16].to_vec());
                } else {
                    let mut buf = result[(result.len() - 15)..].to_vec();
                    buf.push(x as u8);
                    dict.push(f(&buf)[..16].to_vec());
                }
            }

            match dict.iter().position(|ref x| x.as_slice() == &tmp[from..from+16]) {
                Some(x) => result.push(x as u8),
                None => (),
            }
        }
    }
    println!("\n{}", String::from_utf8(result).unwrap());
}
