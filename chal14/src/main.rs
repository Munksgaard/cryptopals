extern crate raes;
extern crate base64;
extern crate pkcs7pad;
extern crate rand;

use std::io::Write;

use rand::Rng;
use raes::{ecb, aes};

/*
 *
 * Byte-at-a-time ECB decryption (Harder)
 *
 * Take your oracle function from #12. Now generate a random count of random
 * bytes and prepend this string to every plaintext. You are now doing:
 *
 * AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
 *
 * Same goal: decrypt the target-bytes.
 * Stop and think for a second.
 *
 * What's harder than challenge #12 about doing this? How would you overcome
 * that obstacle? The hint is: you're using all the tools you already have; no
 * crazy math is required.
 *
 * Think "STIMULUS" and "RESPONSE".
 */

static RANDOM_PREFIX: &'static[u8] = &[97, 16, 255, 130, 251,
                                       200, 11, 244, 159, 153,
                                       92, 137, 69, 80, 242,
                                       32, 123, 54, 12, 54];

static B64_PLAIN: &'static[u8] = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

static RANDOM_KEY: &'static[u8] = &[237, 95, 149, 233,
                                    237, 193, 119, 201,
                                    208, 161, 88, 215,
                                    226, 224, 134, 233,];

fn oracle(input: &[u8]) -> Vec<u8> {
    let mut buf = RANDOM_PREFIX.to_vec();
    buf.extend_from_slice(input);
    buf.extend_from_slice(base64::decode(B64_PLAIN).as_slice());

    let padded = pkcs7pad::pad(buf.as_slice(), 16);

    ecb::ecb(aes::encrypt, padded.as_slice(), RANDOM_KEY)
}

fn detect_blocksize<F>(f: F) -> usize
    where F : Fn(&[u8]) -> Vec<u8> {
    let mut input = vec!(b'A');
    let orig_size = f(&input).len();
    while f(&input).len() == orig_size {
        input.push('A' as u8);
    }
    (f(&input).len() - orig_size)
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

fn make_buf(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for _ in 0..n {
        buf.push(b'A');
    }

    buf
}

fn find_necessary_padding<F>(blocksize: usize, f: F) -> usize
    where F: Fn(&[u8]) -> Vec<u8> {

    // Find prefix-blocks:
    let edge_block = find_prefix_blocks(blocksize, &f) - 1;

    println!("The edge block is {}", edge_block);

    let mut last = f(b"")[edge_block * 16.. (edge_block + 1) * 16].to_vec();

    let mut padding = 1;
    loop {
        let buf = make_buf(padding);
        let new = f(&buf)[edge_block * 16.. (edge_block + 1) * 16].to_vec();

        if new == last {
            return padding - 1;
        } else {
            last = new.clone();
            padding += 1;
        }
    }

    panic!("Did not find padding");
}

#[test]
    fn finds_correct_padding() {
    assert_eq!(find_necessary_padding(16, oracle), 16 - RANDOM_PREFIX.len() % 16);
}

fn find_prefix_blocks<F>(blocksize: usize, f: F) -> usize
    where F: Fn(&[u8]) -> Vec<u8> {

    println!("Trying to find out how many prefix blocks there are");

    let tmp = f(b"");
    let orig_blocks: Vec<&[u8]> = tmp.chunks(blocksize).collect();

    println!("f(\"\").len() = {}", tmp.len());

    let tmp2 = f(b"A");
    let new_blocks: Vec<&[u8]> = tmp2.chunks(blocksize).collect();

    println!("tmp2.len() = {}", tmp2.len());

    for (i, block) in new_blocks.iter().enumerate() {
        if block != &orig_blocks[i] {
            println!("Yay, {}", i);
            return i + 1;       // Add one because of the padding
        } else {
            println!("Nay, {}", i);
        }
    }

    panic!("Prefix not found");

}

fn break_oracle<F>(f: F, blocksize: usize, pad_len: usize, prefix_blocks: usize)
    where F: Fn(&[u8]) -> Vec<u8> {


    let tmp = make_buf(pad_len);
    let cipherlen = f(b"").len();

    assert_eq!(blocksize, 16);
    assert!(is_ecb(|x| f(x)));

    println!("The oracle uses ECB...");

    let mut result: Vec<u8> = Vec::new();

    // For each block
    for block in 0..((cipherlen)/blocksize) {
        // For each byte in the block
        for byte in 1..(blocksize+1) {

            // Create input with prefix_padding + block_padding
            let mut input = make_buf(pad_len);
            let pad = make_buf(blocksize - byte);
            input.extend_from_slice(&pad);

            let tmp = f(&input);
            let target_block = tmp.chunks(blocksize).nth(prefix_blocks + block).unwrap();

            let from = (block * 16) as usize;
            let to = (block * 16 + byte - 1) as usize;

            // For every byte 0..256, create the corresponding input:
            // input = prefix_padding + block_padding + found_so_far + byte

            let mut flag = false;

            for x in 0..256 {
                let mut input = make_buf(pad_len);
                let block_padding = make_buf(blocksize - byte);
                input.extend_from_slice(&block_padding);
                input.extend_from_slice(&result);

                input.push(x as u8);
                let offset = prefix_blocks * blocksize;

                let guess_block = f(&input);

                if guess_block[offset + from..offset + from + 16].to_vec() == target_block {
                    println!("block {}, byte {}: {} ({}) ", block, byte, (x as u8) as char, x as u8);
                    std::io::stdout().flush().unwrap();
                    result.push(x as u8);
                    flag = true;
                    break;
                }
            }

            if !flag {
                break;
            }
        }
    }
    println!("\n{}", String::from_utf8(result).unwrap());
}

fn main() {
    println!("plain length: {}", base64::decode(B64_PLAIN).len());

    println!("Attempting to break oracle");

    let blocksize = detect_blocksize(oracle);
    println!("Blocksize is {}", blocksize);

    if is_ecb(oracle) {
        println!("It's ECB!");
    } else {
        panic!("It's not ECB :(");
    }

    let prefix_len = find_necessary_padding(blocksize, oracle);
    println!("Padding needed {}", prefix_len);

    let prefix_blocks = find_prefix_blocks(blocksize, oracle);
    println!("Prefix blocks {}", prefix_blocks);

    break_oracle(oracle, blocksize, prefix_len, prefix_blocks)
}
