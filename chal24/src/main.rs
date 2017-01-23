#![feature(inclusive_range_syntax)]

extern crate mersenne;
extern crate time;
extern crate rand;

use rand::{thread_rng, Rng};

fn mt19973_crypt(seed: u16, plain: &[u8]) -> Vec<u8> {
    let mut rng = mersenne::seed_mt(seed as u32);

    let mut i = 0;
    let mut rand = rng.extract_number();

    let mut result = Vec::new();
    for b in plain {
        result.push((((rand >> (8 * i)) & 0xFF) as u8) ^ b);

        i += 1;
        if i >= 4 {
            i = 0;
            rand = rng.extract_number();
        };
    }

    result
}

#[test]
fn test_encrypt() {
    fn u32_to_bytes(value: u32) -> Vec<u8> {
        let mut buf = Vec::new();

        for i in 0..4 {
            let mask = 0xFF << (i * 8);
            let byte = (value & mask) >> (i * 8);
            buf.push(byte as u8);
        }

        buf
    }

    let expected = {
        let mut rng = mersenne::seed_mt(0xABCDu16 as u32);
        let mut rand = rng.extract_number();
        let mut n = rand ^ 0xDEADBEEF;
        let mut v = u32_to_bytes(n);
        rand = rng.extract_number();
        n = rand ^ 0xCABBACEF;
        v.extend_from_slice(&u32_to_bytes(n));
        v
    };

    let result = mt19973_crypt(0xABCD, &[0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xAC, 0xBB, 0xCA]);

    assert_eq!(expected, result);
}

#[test]
fn test_crypt_decrypt() {
    let v = vec!(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08);
    let encrypted = mt19973_crypt(0xABCD, &v);
    let decrypted = mt19973_crypt(0xABCD, &encrypted);

    assert_eq!(v, decrypted);
}

fn encrypt_with_prefix(plain: &[u8]) -> Vec<u8> {
    let seed = 0xABCD;
    let mut v: Vec<u8> = Vec::new();
    let mut rng = thread_rng();

    for _ in 0..rng.gen_range(40, 200) {
        v.push(rng.gen())
    }

    v.extend_from_slice(plain);

    mt19973_crypt(seed, &v)
}

fn find_seed() -> u16 {
    let known = &[0x41, 0x41, 0x41, 0x41,
                  0x41, 0x41, 0x41, 0x41,
                  0x41, 0x41, 0x41, 0x41,
                  0x41, 0x41, 0x41, 0x41];
    let encrypted = encrypt_with_prefix(known);

    // Find the length of the prefix
    let prefix_length = encrypted.len() - known.len();

    // Fra 0..2^16, lav en mersenne_rng, extract et passende antal words, se om det der
    let known_encrypted = {
        let mut v = Vec::new();
        for _ in 0..prefix_length {
            v.push(0x00);
        };

        v.extend_from_slice(&encrypted[prefix_length .. ]);
        v
    };

    for i in 0...65535 {
        let tmp = mt19973_crypt(i, &known_encrypted);
        if &tmp[prefix_length .. ] == known {
            return i;
        }
    }

    panic!("Unreachable");
}

fn password_reset_token() -> Vec<u32> {
    let mut rng = mersenne::seed_mt(time::now_utc().to_timespec().sec as u32);
    let mut v = Vec::new();
    for _ in 0..4 {
        v.push(rng.extract_number());
    }

    v
}

fn is_token_generated(token: &[u32], seconds_to_check: u32) -> bool {
    for i in 0..seconds_to_check {
        let mut rng = mersenne::seed_mt(time::now_utc().to_timespec().sec as u32 - i);
        let mut v = Vec::new();
        for _ in 0..4 {
            v.push(rng.extract_number());
        }

        if &v[..] == token {
            return true;
        }
    }

    false
}

fn main() {
    let seed = find_seed();

    println!("Found seed: {}", seed);

    let token = password_reset_token();
    println!("Is token generated? {}", is_token_generated(&token, 10));
}
