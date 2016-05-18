extern crate raes;
extern crate rand;

use rand::Rng;

use raes::{cbc, ecb, aes};

fn main() {
    println!("{}", if ecb_encrypted(random_encrypt) { "ECB" } else { "CBC" })
}

fn rand_key() -> Vec<u8> {
    (0..16).map(|_| rand::random()).collect()
}

fn random_encrypt(input: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let key = rand_key();
    let ecb = rng.gen();

    let n = rng.gen_range(5, 11);

    let mut padded: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
    padded.extend_from_slice(input);
    let tmp: Vec<u8> = (0..16-n).map(|_| rng.gen()).collect();
    padded.extend_from_slice(&tmp);

    // println!("{}", match mode { ECB => "ECB", CBC => "CBC" });

    if ecb {
        ecb::ecb(aes::encrypt, &padded, &key)
    } else {
        let iv = rand_key();
        cbc::encrypt(aes::encrypt, &padded, &key, &iv)
    }
}

/// Returns true if the input is ECB encrypted, false if not
fn ecb_encrypted<F>(f: F) -> bool where F: Fn(&[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut input = Vec::new();

    for _ in 0..4 {
        input.extend_from_slice(b"BUFFALO BUFFALO BUFFALO BUFFALO ");
        let tmp: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        input.extend_from_slice(&tmp);
    }

    let tmp = f(input.as_slice());
    let mut blocks: Vec<&[u8]> = tmp.chunks(16).collect();

    let orig_len = blocks.len();
    blocks.sort();
    blocks.dedup();
    orig_len != blocks.len()
}
