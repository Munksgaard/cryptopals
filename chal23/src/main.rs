#![feature(inclusive_range_syntax)]
#![allow(dead_code)]

extern crate mersenne;
extern crate time;

const U: u32 = 11;
const D: u32 = 0xFFFFFFFF;
const S: u32 = 7;
const B: u32 = 0x9D2C5680;
const T: u32 = 15;
const C: u32 = 0xEFC60000;
const L: u32 = 18;

fn unshift_right(n: u32, shift: u32) -> u32 {
    // We find the bits one block of size `shift` at a time, starting from the left
    let mut result = 0u32;
    let mut last = 0u32;
    let mut window = 0xFFFFFFFF >> (32 - shift) << (32 - shift);
    for _ in 0...(32 / shift) {
        last = (last >> shift) ^ (n & window);
        result = result | last;
        window = window >> shift;
    }
    result
}

fn unshift_left(n: u32, shift: u32, mask: u32) -> u32 {
    let mut result = 0u32;
    let mut last = 0u32;
    let mut window = 0xFFFFFFFF >> (32 - shift);
    for _ in 0...(32 / shift) {
        last = (last << shift) & mask ^ (n & window);
        result = result | last;
        window = window << shift;
    }
    result
}

fn untemper(y: u32) -> u32 {
    // unshift_11(y);
    let result = y;
    let result = unshift_right(result, L);
    let result = unshift_left(result, T, C);
    let result = unshift_left(result, S, B);
    let result = unshift_right(result, U);

    result
}

mod test {
    use super::*;

    fn temper(y: u32) -> u32 {
        let mut y: u32 = y;

        y = y ^ (y >> U);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        y
    }

    #[test]
    fn test_untemper() {
        println!("");
        println!("123456789 {:032b}", 123456789);
        println!("tempered: {:032b}", temper(123456789));
        assert_eq!(untemper(temper(123456789)), 123456789);
    }
}

fn main() {
    let mut rng = mersenne::seed_mt(time::now_utc().to_timespec().sec as u32);

    let mut v = Vec::new();
    for _ in 0..624 {
        v.push(untemper(rng.extract_number()));
    }

    let mut guessed_rng = mersenne::from_vec(&v);

    println!("Guessing next random: {}", guessed_rng.extract_number());
    println!("New random: {}", rng.extract_number());
}
