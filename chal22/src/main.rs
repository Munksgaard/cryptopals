extern crate mersenne;
extern crate rand;
extern crate time;

use rand::Rng;

// Wait a random number of seconds between, I don't know, 40 and 1000.
// Seeds the RNG with the current Unix timestamp
// Waits a random number of seconds again.
// Returns the first 32 bit output of the RNG.

fn random() -> u32 {
    let mut rng = rand::thread_rng();
    let random_number = rng.gen_range(40, 1000);

    std::thread::sleep(std::time::Duration::from_secs(random_number));

    let mut my_rng = mersenne::seed_mt(time::now_utc().to_timespec().sec as u32);

    let random_number = rng.gen_range(40, 1000);
    std::thread::sleep(std::time::Duration::from_secs(random_number));

    my_rng.extract_number()
}

fn break_timestamp_seed<F>(f: F) where F: Fn() -> u32 {
    let n = f();

    println!("Got n: {}", n);

    let now = time::now_utc().to_timespec().sec;

    let mut seed = now;

    while mersenne::seed_mt(seed as u32).extract_number() != n {
        seed -= 1;
    }

    println!("Guessed seed: {}", seed);
}

fn main() {
    break_timestamp_seed(random);
}
